#!/usr/bin/env python3

# Import necessary Mininet modules
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

# Define a custom topology class inheriting from Mininet's Topo
class SDNTopo(Topo):
    def build(self):
        # Add Hosts with assigned IP addresses and MAC addresses
        # h1 and h2 are the user hosts
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        # mgmt is the management host
        mgmt = self.addHost('mgmt', ip='10.0.0.254/24', mac='00:00:00:00:00:03')
        # server is the central server host
        server = self.addHost('server', ip='10.0.0.11/24', mac='00:00:00:00:00:04')

        # Add Open vSwitch (OVS) switches to the topology
        # These will be controlled by the Ryu controller
        sw1 = self.addSwitch('sw1')
        sw2 = self.addSwitch('sw2')
        sw3 = self.addSwitch('sw3')
        sw4 = self.addSwitch('sw4')
        sw5 = self.addSwitch('sw5')

        # Add Host to Switch Links with specific bandwidth (bw) constraints
        # TCLink is used to enable these traffic control features
        self.addLink(h1, sw1, bw=10)                  # Bandwidth 10 Mbps for h1
        self.addLink(h2, sw2, bw=10)                  # Bandwidth 10 Mbps for h2
        self.addLink(mgmt, sw5, bw=10)                # Bandwidth 10 Mbps for mgmt
        self.addLink(server, sw5, bw=1000)            # Bandwidth 1 Gbps for server

        # Add Inter-Switch Links with bandwidth and delay parameters
        # sw5 acts as a central hub connecting to core switches sw3 and sw4
        self.addLink(sw5, sw3, bw=1000, delay='2ms')  # 1 Gbps, 2ms delay
        self.addLink(sw5, sw4, bw=1000, delay='2ms')  # 1 Gbps, 2ms delay
        # Edge switches sw1 and sw2 connect to core switches
        self.addLink(sw3, sw1, bw=100, delay='2ms')   # 100 Mbps, 2ms delay
        self.addLink(sw3, sw2, bw=100, delay='2ms')   # 100 Mbps, 2ms delay
        self.addLink(sw4, sw1, bw=100, delay='2ms')   # 100 Mbps, 2ms delay
        self.addLink(sw4, sw2, bw=100, delay='2ms')   # 100 Mbps, 2ms delay

if __name__ == '__main__':
    # Set the logging level to info to see Mininet output
    setLogLevel('info')

    # Instantiate the custom topology
    topo = SDNTopo()

    # Initialize Mininet with the defined topology
    # RemoteController tells Mininet to look for an external controller (Ryu)
    # OVSSwitch specifies the switch implementation
    # TCLink enables bandwidth and delay parameters for links
    net = Mininet(topo=topo, controller=RemoteController, switch=OVSSwitch, link=TCLink)
    
    # Start the network and Pre-populate all ARP tables to avoid discovery overhead
    net.start()
    net.staticArp()

    # STP is disabled: proactive OpenFlow flows + staticArp() already provide
    # loop-free forwarding. STP would block redundant inter-switch links and
    # prevent flows from using them.
    for sw in net.switches:
        # Execute shell command on each switch to disable STP
        sw.cmd('ovs-vsctl set bridge {} stp_enable=false'.format(sw.name))
    
    # Open the Mininet Command Line Interface (CLI)
    CLI(net)

    # Stop the network and clean up when the CLI is exited
    net.stop()