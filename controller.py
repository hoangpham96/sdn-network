import csv
import time
from threading import Thread
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp, arp

# Set to True to enable B4 traffic engineering (UDP rate-limiting via OpenFlow meter).
# Set to False to test baseline behaviour without any TE enforcement.
ENABLE_B4 = False

# Meter ID used to rate-limit UDP traffic on sw5 (B4 traffic engineering)
UDP_METER_ID = 1
# UDP rate cap in kbps — 50 Mbps keeps UDP from starving TCP on shared 100 Mbps edge links
UDP_RATE_KBPS = 50000

class SDNController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNController, self).__init__(*args, **kwargs)
        self.datapaths = {}

        # B2: per-flow stats dictionaries keyed by (ip_src, ip_dst, proto_str)
        # Stored separately so TCP and UDP counters can be read independently
        self.flow_stats = {}

        # Start the monitoring thread
        self.monitor_thread = Thread(target=self._monitor)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

        # Open CSV file for logging (B2)
        self.csv_file = open('stats.csv', 'w', newline='')
        self.csv_writer = csv.writer(self.csv_file)
        self.csv_writer.writerow(['timestamp', 'flow_match', 'byte_count', 'packet_count'])

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        self.datapaths[dpid] = datapath

        # Table-miss: drop all unmatched traffic (priority 0, empty action list)
        match = parser.OFPMatch()
        actions = []
        self.add_flow(datapath, 0, match, actions)

        # Proactively install all permitted flow rules
        self.install_proactive_flows(datapath)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, meter_id=None):
        """Send an OFPFlowMod to install a flow entry.

        meter_id: when set, prepends an OFPInstructionMeter so the flow is
        policed by that meter before the action is applied (used for B4 TE).
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = []
        if meter_id is not None:
            inst.append(parser.OFPInstructionMeter(meter_id))
        inst.append(parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions))

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def _install_udp_meter(self, datapath):
        """B4: Install an OpenFlow meter on sw5 that drops UDP bytes exceeding UDP_RATE_KBPS.

        All UDP flows on sw5 reference this meter, capping UDP bandwidth and
        preventing it from crowding out TCP on shared 100 Mbps edge links.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        bands = [
            parser.OFPMeterBandDrop(rate=UDP_RATE_KBPS, burst_size=1000)
        ]
        meter_mod = parser.OFPMeterMod(
            datapath=datapath,
            command=ofproto.OFPMC_ADD,
            flags=ofproto.OFPMF_KBPS,
            meter_id=UDP_METER_ID,
            bands=bands
        )
        datapath.send_msg(meter_mod)

    def install_proactive_flows(self, datapath):
        dpid = datapath.id
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Topology port assignments (derived from link order in topology.py):
        #   SW1: port1=h1,   port2=sw3, port3=sw4
        #   SW2: port1=h2,   port2=sw3, port3=sw4
        #   SW3: port1=sw5,  port2=sw1, port3=sw2
        #   SW4: port1=sw5,  port2=sw1, port3=sw2
        #   SW5: port1=mgmt, port2=server, port3=sw3, port4=sw4
        #
        # Permitted paths (proactive, B1):
        #   h1   <-> sw1 <-> sw3 <-> sw5 <-> server
        #   h2   <-> sw2 <-> sw4 <-> sw5 <-> server  (separate path = basic TE)
        #   h1   <-> sw1 <-> sw3 <-> sw2 <-> h2
        #   mgmt <-> sw5 <-> server

        # ARP is flooded on every switch so hosts can resolve MACs
        self.add_flow(datapath, priority=10,
                      match=parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP),
                      actions=[parser.OFPActionOutput(ofproto.OFPP_FLOOD)])

        ip_server = '10.0.0.11'
        ip_h1     = '10.0.0.1'
        ip_h2     = '10.0.0.2'
        ip_mgmt   = '10.0.0.254'

        if dpid == 1:
            # SW1
            # h1 <-> server (via sw3, port 2)
            self._add_ip_flows(datapath, ip_h1,     ip_server, out_port=2)
            self._add_ip_flows(datapath, ip_server,  ip_h1,    out_port=1)
            # h1 <-> h2 via sw3
            self._add_ip_flows(datapath, ip_h1,      ip_h2,    out_port=2)
            self._add_ip_flows(datapath, ip_h2,      ip_h1,    out_port=1)
            # h1 <-> mgmt via sw3 -> sw5
            self._add_ip_flows(datapath, ip_h1,      ip_mgmt,  out_port=2)
            self._add_ip_flows(datapath, ip_mgmt,    ip_h1,    out_port=1)

        elif dpid == 2:
            # SW2 — h2 uses sw4 path (traffic engineering: keeps h1/h2 on separate core links)
            # h2 <-> server (via sw5, port 2)
            self._add_ip_flows(datapath, ip_h2,     ip_server, out_port=3)
            self._add_ip_flows(datapath, ip_server,  ip_h2,    out_port=1)
            # h1 <-> h2 via sw3
            self._add_ip_flows(datapath, ip_h1,      ip_h2,    out_port=1)
            self._add_ip_flows(datapath, ip_h2,      ip_h1,    out_port=2)
            # h2 <-> mgmt via sw4 -> sw5
            self._add_ip_flows(datapath, ip_h2,      ip_mgmt,  out_port=3)
            self._add_ip_flows(datapath, ip_mgmt,    ip_h2,    out_port=1)

        elif dpid == 3:
            # SW3 — carries h1 traffic only
            # h1 <-> server (via sw5, port 1)
            self._add_ip_flows(datapath, ip_h1,     ip_server, out_port=1)
            self._add_ip_flows(datapath, ip_server,  ip_h1,    out_port=2)
            # h1 <-> h2 via sw3
            self._add_ip_flows(datapath, ip_h1,      ip_h2,    out_port=3)
            self._add_ip_flows(datapath, ip_h2,      ip_h1,    out_port=2)
            # h1 <-> mgmt via sw3 -> sw5
            self._add_ip_flows(datapath, ip_h1,      ip_mgmt,  out_port=1)
            self._add_ip_flows(datapath, ip_mgmt,    ip_h1,    out_port=2)

        elif dpid == 4:
            # SW4 — carries h2 traffic only
            # h2 <-> server (via sw5, port 2)
            self._add_ip_flows(datapath, ip_h2,     ip_server, out_port=1)
            self._add_ip_flows(datapath, ip_server,  ip_h2,    out_port=3)
            # h2 <-> mgmt via sw4 -> sw5
            self._add_ip_flows(datapath, ip_h2,      ip_mgmt,  out_port=1)
            self._add_ip_flows(datapath, ip_mgmt,    ip_h2,    out_port=3)

        elif dpid == 5:
            # SW5 — hub switch
            # B4: optionally install a meter to rate-limit UDP traffic before referencing it in flow entries
            meter = None
            if ENABLE_B4:
                # Install UDP meter before referencing it in flow entries
                self._install_udp_meter(datapath)
                meter = UDP_METER_ID

            # mgmt <-> server
            self._add_ip_flows(datapath, ip_mgmt,   ip_server, out_port=2, udp_meter_id=meter)
            self._add_ip_flows(datapath, ip_server,  ip_mgmt,  out_port=1, udp_meter_id=meter)

            # h1 <-> server (via sw3, port 3)
            self._add_ip_flows(datapath, ip_h1,     ip_server, out_port=2, udp_meter_id=meter)
            self._add_ip_flows(datapath, ip_server,  ip_h1,    out_port=3, udp_meter_id=meter)

            # h2 <-> server (via sw4, port 4)
            self._add_ip_flows(datapath, ip_h2,     ip_server, out_port=2, udp_meter_id=meter)
            self._add_ip_flows(datapath, ip_server,  ip_h2,    out_port=4, udp_meter_id=meter)

            # h1 <-> mgmt (h1 arrives via sw3, port 3)
            self._add_ip_flows(datapath, ip_h1,      ip_mgmt,  out_port=1)
            self._add_ip_flows(datapath, ip_mgmt,    ip_h1,    out_port=3)

            # h2 <-> mgmt (h2 arrives via sw4, port 4)
            self._add_ip_flows(datapath, ip_h2,      ip_mgmt,  out_port=1)
            self._add_ip_flows(datapath, ip_mgmt,    ip_h2,    out_port=4)

    def _add_ip_flows(self, datapath, ip_src, ip_dst, out_port, udp_meter_id=None):
        """Install TCP, UDP, and ICMP flow entries for a src→dst pair.

        udp_meter_id: when set, attaches a meter to the UDP entry only (B4 TE).
        ICMP flows are added so that ping / pingall (A3) works end-to-end.
        """
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(out_port)]

        # TCP (proto 6)
        match_tcp = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=ip_src, ipv4_dst=ip_dst,
            ip_proto=6
        )
        self.add_flow(datapath, priority=100, match=match_tcp, actions=actions)

        # UDP (proto 17) — optionally policed by a meter for traffic engineering
        match_udp = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=ip_src, ipv4_dst=ip_dst,
            ip_proto=17
        )
        self.add_flow(datapath, priority=100, match=match_udp, actions=actions,
                      meter_id=udp_meter_id)

        # ICMP (proto 1) — required for pingall / A3 topology verification
        match_icmp = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=ip_src, ipv4_dst=ip_dst,
            ip_proto=1
        )
        self.add_flow(datapath, priority=100, match=match_icmp, actions=actions)

    def _monitor(self):
        """Daemon thread: poll sw5 flow stats every 10 seconds (B2)."""
        while True:
            time.sleep(10)
            if 5 in self.datapaths:
                datapath = self.datapaths[5]
                parser = datapath.ofproto_parser
                req = parser.OFPFlowStatsRequest(datapath)
                datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """B2: Receive flow stats from sw5, update per-flow dictionaries, log to CSV."""
        body = ev.msg.body
        dpid = ev.msg.datapath.id

        if dpid != 5:
            return

        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')

        # Only inspect priority-100 flows (TCP, UDP — excludes table-miss and ARP)
        priority_flows = sorted(
            [f for f in body if f.priority == 100],
            key=lambda f: (f.match.get('ipv4_src', ''), f.match.get('ip_proto', 0))
        )

        for stat in priority_flows:
            ip_src    = stat.match.get('ipv4_src')
            ip_dst    = stat.match.get('ipv4_dst')
            ip_proto  = stat.match.get('ip_proto')

            if ip_proto == 6:
                proto_str = 'TCP'
            elif ip_proto == 17:
                proto_str = 'UDP'
            else:
                continue  # skip ICMP from stats (monitor TCP/UDP only per B2)

            flow_key  = (ip_src, ip_dst, proto_str)
            flow_name = f"{ip_src}->{ip_dst} ({proto_str})"

            # B2: store counters in the dictionary (cumulative, as reported by OVS)
            self.flow_stats[flow_key] = {
                'byte_count':   stat.byte_count,
                'packet_count': stat.packet_count,
            }

            self.csv_writer.writerow([timestamp, flow_name,
                                      stat.byte_count, stat.packet_count])

        self.csv_file.flush()
