#!/usr/bin/python                                                                            
                                                                                             
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import RemoteController
import os

class SingleSwitchTopo(Topo): # Star topology
    "Single switch connected to n hosts."
    def build(self, n=2):
        switch = self.addSwitch('s1')
        # Python's range(N) generates 0..N-1
        for h in range(n):
            host = self.addHost('h%s' % (h + 1))
            self.addLink(host, switch)

class Fulltopology(Topo): # Full conected topology

    def build(self, n=2):
        switch = self.addSwitch('s1')
        
        for i in range(1, n):
            host = self.addHost('h%s' % i)
            self.addLink(host, switch)
        for i in range(1, n):
            for j in range(i+1, n):
                host1 = self.addHost('h%s' % i)
                host2 = self.addHost('h%s' % j)
                self.addLink(host1, host2)

class Lineartopology(Topo):

    def build(self):
        switch = self.addSwitch('s1')
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        self.addLink(h1, switch)
        self.addLink(h2, switch)

class TwoSwitchTopo(Topo): # Two switches connected to hosts

    def build(self):
        switch1 = self.addSwitch('s1')
        switch2 = self.addSwitch('s2')
        host1 = self.addHost('h1')
        host2 = self.addHost('h2')
        host3 = self.addHost('h3')
        host4 = self.addHost('h4')
        host5 = self.addHost('h5')
        self.addLink(switch1,switch2)
        self.addLink(host1,switch1)
        self.addLink(host2,switch1)
        self.addLink(host3,switch2)
        self.addLink(host4,switch2)
        self.addLink(host5,switch2)
        self.addLink(host5,switch1)
        self.addLink(host2,host5)

def simpleTest():

    option = input("1 - Star topology\n2 - Full topology\n3 - Linear topology\n4 - TwoSwitchtopo\n\nOption: ")
    match option:
            case '1':
                topo = SingleSwitchTopo(n=6)
            case '2':
                topo = Fulltopology(n=4)
            case '3':
                topo = Lineartopology()
            case '4':
                topo = TwoSwitchTopo()
            case _:
                print("Invalid option\n\n")
                return
    net = Mininet(topo, controller=None)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)
    net.start()
    print("Dumping host connections")
    dumpNodeConnections(net.hosts)
    print("Testing network connectivity")
    net.pingAll()
    net.stop()

if __name__ == '__main__':
    while True:
        os.system('clear')
        setLogLevel('info')
        simpleTest()
        input("Press Enter to continue...")
        if (continue_ := input("Do you want to continue? (y/n): ")) != 'y':
            break
    print("Exiting...")