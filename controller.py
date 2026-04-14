import csv
import time
from threading import Thread
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp, arp

class SDNController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNController, self).__init__(*args, **kwargs)
        self.datapaths = {}
        # Start the monitoring thread
        self.monitor_thread = Thread(target=self._monitor)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        # Open CSV file
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

        # Install table-miss flow entry (drop all)
        match = parser.OFPMatch()
        actions = [] # Empty actions means drop
        self.add_flow(datapath, 0, match, actions)

        # Proactively install flow rules for allowed traffic
        self.install_proactive_flows(datapath)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def install_proactive_flows(self, datapath):
        dpid = datapath.id
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Define port mappings based on our deterministic topology.py
        # Server is 10.0.0.11
        # H1 is 10.0.0.1, H2 is 10.0.0.2, mgmt is 10.0.0.254
        
        # Allow ARP everywhere (broadcast)
        self.add_flow(datapath, priority=10, 
                      match=parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP),
                      actions=[parser.OFPActionOutput(ofproto.OFPP_FLOOD)])

        # IPs
        ip_server = '10.0.0.11'
        ip_h1 = '10.0.0.1'
        ip_h2 = '10.0.0.2'
        ip_mgmt = '10.0.0.254'
        
        # Routing logic (Paths):
        # h1 <-> sw1 <-> sw3 <-> sw5 <-> server
        # h2 <-> sw2 <-> sw4 <-> sw5 <-> server
        # mgmt <-> sw5 <-> server
        
        # We process each DPID to push exact flow entries
        
        if dpid == 1:
            # SW1
            # 1:h1, 2:sw3, 3:sw4
            # h1 to Server (out port 2)
            self._add_tcp_udp_flows(datapath, ip_h1, ip_server, 2)
            # Server to h1 (out port 1)
            self._add_tcp_udp_flows(datapath, ip_server, ip_h1, 1)

        elif dpid == 2:
            # SW2
            # 1:h2, 2:sw3, 3:sw4
            # h2 to Server (out port 3 to sw4 for Traffic Engineering!) 
            # Or out port 2 to sw3 if we want them to share sw3.
            # Let's use separate paths for traffic engineering (B4).
            self._add_tcp_udp_flows(datapath, ip_h2, ip_server, 3)
            # Server to h2 (out port 1)
            self._add_tcp_udp_flows(datapath, ip_server, ip_h2, 1)

        elif dpid == 3:
            # SW3
            # 1:sw5, 2:sw1, 3:sw2
            # sw1(h1) to Server (out port 1)
            self._add_tcp_udp_flows(datapath, ip_h1, ip_server, 1)
            # Server to sw1(h1) (out port 2)
            self._add_tcp_udp_flows(datapath, ip_server, ip_h1, 2)

        elif dpid == 4:
            # SW4
            # 1:sw5, 2:sw1, 3:sw2
            # sw2(h2) to Server (out port 1)
            self._add_tcp_udp_flows(datapath, ip_h2, ip_server, 1)
            # Server to sw2(h2) (out port 3)
            self._add_tcp_udp_flows(datapath, ip_server, ip_h2, 3)

        elif dpid == 5:
            # SW5
            # 1:mgmt, 2:server, 3:sw3, 4:sw4
            
            # mgmt <-> server
            self._add_tcp_udp_flows(datapath, ip_mgmt, ip_server, 2)
            self._add_tcp_udp_flows(datapath, ip_server, ip_mgmt, 1)
            
            # sw3(h1) <-> server
            self._add_tcp_udp_flows(datapath, ip_h1, ip_server, 2)
            self._add_tcp_udp_flows(datapath, ip_server, ip_h1, 3)
            
            # sw4(h2) <-> server
            self._add_tcp_udp_flows(datapath, ip_h2, ip_server, 2)
            self._add_tcp_udp_flows(datapath, ip_server, ip_h2, 4)

    def _add_tcp_udp_flows(self, datapath, ip_src, ip_dst, out_port):
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(out_port)]
        
        # TCP priority 100
        match_tcp = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=ip_src,
            ipv4_dst=ip_dst,
            ip_proto=6 # TCP
        )
        self.add_flow(datapath, priority=100, match=match_tcp, actions=actions)
        
        # UDP priority 100
        match_udp = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=ip_src,
            ipv4_dst=ip_dst,
            ip_proto=17 # UDP
        )
        self.add_flow(datapath, priority=100, match=match_udp, actions=actions)

    def _monitor(self):
        while True:
            time.sleep(10)
            if 5 in self.datapaths:
                datapath = self.datapaths[5]
                parser = datapath.ofproto_parser
                req = parser.OFPFlowStatsRequest(datapath)
                datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        
        if dpid != 5:
            return
            
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        for stat in sorted([flow for flow in body if flow.priority == 100],
                           key=lambda flow: (flow.match.get('ipv4_src', ''), flow.match.get('ip_proto', 0))):
            ip_src = stat.match.get('ipv4_src')
            ip_dst = stat.match.get('ipv4_dst')
            ip_proto = stat.match.get('ip_proto')
            
            proto_str = "TCP" if ip_proto == 6 else "UDP" if ip_proto == 17 else str(ip_proto)
            flow_name = f"{ip_src}->{ip_dst} ({proto_str})"
            
            self.csv_writer.writerow([timestamp, flow_name, stat.byte_count, stat.packet_count])
            self.csv_file.flush()
