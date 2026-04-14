from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp, ipv4, tcp, udp
from ryu.lib.packet import ether_types

import csv
import time
from threading import Thread


class SDNAssessmentController(app_manager.RyuApp):
    """
    A controller application for the Ryu SDN controller based on the SDN Assessment.
    Proactively installs flows for TCP/UDP between hosts and the Server.
    Monitors traffic statistics on sw5.
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # ##### SECTION -1 #################

    def __init__(self, *args, **kwargs):
        super(SDNAssessmentController, self).__init__(*args, **kwargs)
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
    def switch_features_handler(self, event):
        print(" *** in feature handler *** ")
        datapath = event.msg.datapath
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

    # ######### SECTION -2 ###############

    def install_proactive_flows(self, datapath):
        dpid = datapath.id
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Allow ARP everywhere (broadcast)
        match_arp = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        actions_arp = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath, 10, match_arp, actions_arp)

        # IPs
        ip_server = '10.0.0.11'
        ip_h1 = '10.0.0.1'
        ip_h2 = '10.0.0.2'
        ip_mgmt = '10.0.0.254'
        
        # We process each DPID to push exact flow entries
        if dpid == 1:
            self._add_tcp_udp_flows(datapath, ip_h1, ip_server, 2)
            self._add_tcp_udp_flows(datapath, ip_server, ip_h1, 1)

        elif dpid == 2:
            self._add_tcp_udp_flows(datapath, ip_h2, ip_server, 3)
            self._add_tcp_udp_flows(datapath, ip_server, ip_h2, 1)

        elif dpid == 3:
            self._add_tcp_udp_flows(datapath, ip_h1, ip_server, 1)
            self._add_tcp_udp_flows(datapath, ip_server, ip_h1, 2)

        elif dpid == 4:
            self._add_tcp_udp_flows(datapath, ip_h2, ip_server, 1)
            self._add_tcp_udp_flows(datapath, ip_server, ip_h2, 3)

        elif dpid == 5:
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
        self.add_flow(datapath, 100, match_tcp, actions)
        
        # UDP priority 100
        match_udp = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=ip_src,
            ipv4_dst=ip_dst,
            ip_proto=17 # UDP
        )
        self.add_flow(datapath, 100, match_udp, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        """Install a flow rule on the datapath."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        idle_timeout = 0
        hard_timeout = 0
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout,
                                    match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout,
                                    instructions=inst)
        self.logger.info("added flow for %s", mod)
        datapath.send_msg(mod)

    def _monitor(self):
        while True:
            time.sleep(10)
            if 5 in self.datapaths:
                datapath = self.datapaths[5]
                parser = datapath.ofproto_parser
                req = parser.OFPFlowStatsRequest(datapath)
                datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, event):
        body = event.msg.body
        dpid = event.msg.datapath.id
        
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
