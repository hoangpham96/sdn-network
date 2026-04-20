#!/usr/bin/env python3

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

class SDNTopo(Topo):
    def build(self):
        # Add Hosts with assigned IP and mac
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        mgmt = self.addHost('mgmt', ip='10.0.0.254/24', mac='00:00:00:00:00:03')
        server = self.addHost('server', ip='10.0.0.11/24', mac='00:00:00:00:00:04')

        # Add Switches
        sw1 = self.addSwitch('sw1')
        sw2 = self.addSwitch('sw2')
        sw3 = self.addSwitch('sw3')
        sw4 = self.addSwitch('sw4')
        sw5 = self.addSwitch('sw5')

        # Add Host to Switch Links
        self.addLink(h1, sw1, bw=10)                  # Bandwidth 10 Mbps
        self.addLink(h2, sw2, bw=10)                  # Bandwidth 10 Mbps
        self.addLink(mgmt, sw5, bw=10)                # Bandwidth 10 Mbps
        self.addLink(server, sw5, bw=1000)            # Bandwidth 1 Gbps

        # Add Inter-Switch Links (with 2ms delay)
        self.addLink(sw5, sw3, bw=1000, delay='2ms')  # Bandwidth 1 Gbps
        self.addLink(sw5, sw4, bw=1000, delay='2ms')  # Bandwidth 1 Gbps
        self.addLink(sw3, sw1, bw=100, delay='2ms')   # Bandwidth 100 Mbps
        self.addLink(sw3, sw2, bw=100, delay='2ms')   # Bandwidth 100 Mbps
        self.addLink(sw4, sw1, bw=100, delay='2ms')   # Bandwidth 100 Mbps
        self.addLink(sw4, sw2, bw=100, delay='2ms')   # Bandwidth 100 Mbps

if __name__ == '__main__':
    setLogLevel('info')

    topo = SDNTopo()

    # Initilize Mininet with the topology and controller
    # Use TCLink to support bandwidth and delay parameters
    net = Mininet(topo=topo, controller=RemoteController, switch=OVSSwitch, link=TCLink)
    
    # Start network and Pre-populates all ARP tables
    net.start()
    net.staticArp()

    # STP is disabled: proactive OpenFlow flows + staticArp() already provide
    # loop-free forwarding. STP would block redundant inter-switch links and
    # prevent flows from using them.
    for sw in net.switches:
        sw.cmd('ovs-vsctl set bridge {} stp_enable=false'.format(sw.name))
    
    CLI(net)

    net.stop()