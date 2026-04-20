#!/usr/bin/env python3

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

class SDNTopo(Topo):
    def build(self):
        # Add Hosts
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        mgmt = self.addHost('mgmt', ip='10.0.0.254/24', mac='00:00:00:00:00:03')
        server = self.addHost('server', ip='10.0.0.11/24', mac='00:00:00:00:00:04')

        # Add Switches
        sw1 = self.addSwitch('sw1', protocols='OpenFlow13')
        sw2 = self.addSwitch('sw2', protocols='OpenFlow13')
        sw3 = self.addSwitch('sw3', protocols='OpenFlow13')
        sw4 = self.addSwitch('sw4', protocols='OpenFlow13')
        sw5 = self.addSwitch('sw5', protocols='OpenFlow13')

        # Add Host to Switch Links
        self.addLink(h1, sw1, bw=10)                  # 10 Mbps
        self.addLink(h2, sw2, bw=10)                  # 10 Mbps
        self.addLink(mgmt, sw5, bw=10)                # 10 Mbps
        self.addLink(server, sw5, bw=1000)            # 1 Gbps

        # Add Inter-Switch Links (with 2ms delay)
        self.addLink(sw5, sw3, bw=1000, delay='2ms')  # 1 Gbps
        self.addLink(sw5, sw4, bw=1000, delay='2ms')  # 1 Gbps
        self.addLink(sw3, sw1, bw=100, delay='2ms')   # 100 Mbps
        self.addLink(sw3, sw2, bw=100, delay='2ms')   # 100 Mbps
        self.addLink(sw4, sw1, bw=100, delay='2ms')   # 100 Mbps
        self.addLink(sw4, sw2, bw=100, delay='2ms')   # 100 Mbps

def run():
    topo = SDNTopo()
    # Use TCLink to support bandwidth and delay parameters
    net = Mininet(topo=topo, controller=RemoteController, switch=OVSSwitch, link=TCLink)
    
    # Start network
    net.start()

    # The assignment mentions "Spanning Tree Protocol (STP) on OVS bridges" as a pointer
    # So we should run it via mininet to avoid loops, or Ryu can handle STP.
    # The pointer: "Enable Spanning Tree Protocol (STP) on the OVS bridges (ovs-vsctl set bridge s1 stp_enable=true)"
    for sw in net.switches:
        sw.cmd('ovs-vsctl set bridge {} stp_enable=true'.format(sw.name))

    # A2. Host and Server Setup
    info('*** Starting simple HTTP server on Server\n')
    server = net.get('server')
    # Run the HTTP server in the background
    server.cmd('python3 -m http.server 80 &')

    # A3. Topology Correctness
    info('*** Topology is running. Use net or dump to verify.\n')
    
    CLI(net)

    # Teardown
    info('*** Stopping HTTP server\n')
    server.cmd('kill %python3')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
