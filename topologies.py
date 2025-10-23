#!/usr/bin/python
#~/pox/pox.py forwarding.exemple                                                                  
                                                                                             
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import RemoteController
import os

from mininet.node import Node

import subprocess
import socket
import time

class LinuxRouter(Node):
    """A Node with IP forwarding enabled to act as a router."""
    def config(self, **params):
        super().config(**params)
        self.cmd('sysctl -w net.ipv4.ip_forward=1')

    def terminate(self):
        self.cmd('sysctl -w net.ipv4.ip_forward=0')
        super().terminate()

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

class TwoSubnetsTopo(Topo): # Two subnets connected to hosts
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

        router = self.addNode('r1', cls=LinuxRouter, ip=None)
        self.addLink(router, switch1, intfName1='r1-eth0')
        self.addLink(router, switch2, intfName1='r1-eth1')

def test_http_traffic():
    print("Testing HTTP traffic...")
    h3_process = subprocess.Popen(["mnexec", "-a", "$(pgrep -f mininet:h3)", "python3", "-m", "http.server", "80"],\
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    time.sleep(5)  # Wait for server to start

    print("Testing HTTP access from h1 to h3...")
    result = os.system("mnexec -a $(pgrep -f mininet:h1) wget -O - 10.0.0.3")
    if result == 0:
        print("HTTP access successful")
    else:
        print("HTTP access failed")

def check_firewall_rules():
    print("Dumping firewall rules on switch s1...")
    subprocess.run(["sudo", "ovs-ofctl", "dump-flows", "s1"])

def add_firewall_rules(src_ip, dst_ip, protocol="tcp"):
    rule = f"{src_ip} {dst_ip} {protocol}\n"
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("127.0.0.1", 6634))  # Assuming POX listens on this port
        s.sendall(rule.encode())

    print(f"Rule added: Block {protocol} from {src_ip} to {dst_ip}")

def test_firewall(net):
    option_test = '1'
    while option_test != '0':
        os.system('clear')
        option_test = input("1 - ping pair (1 - 2)\n2 - ping pair (2 - 4)\n3 - HTTP traffic\n4- Check firewall rules \
        \n5- ADD firewall rules\n6 - All tests\n\nOption: ")
        match option_test:
            case '1':
                h1 = net.get('h1')
                h2 = net.get('h2')
                net.ping([h1, h2])
            case '2':
                h2 = net.get('h2')
                h6 = net.get('h6')
                print("Testing ping from h2: {} to h6: {}".format(h2.IP(), h6.IP()))
                net.ping([h2, h6])
                #net.pingAll()
            case '3':
                test_http_traffic()
            case '4':
                check_firewall_rules()
            case '5':
                src_ip = net.get('h1').IP()
                dst_ip = net.get('h3').IP()
                print(f"Source IP: {src_ip}, Destination IP: {dst_ip}")
                add_firewall_rules(src_ip, dst_ip, "ipv4")
            case '6':
                net.pingAll()
                """h1 = net.get('h1')
                h2 = net.get('h2')
                h4 = net.get('h4')
                net.ping([h1, h2])
                net.ping([h2, h4])
                test_http_traffic()
                check_firewall_rules()
                add_firewall_rules()"""
            case _:
                print("Invalid option\n\n")
                return
        input("Press Enter to continue...")
def simpleTest():

    option = input("1 - Star topology\n2 - Full topology\n3 - Linear topology\n4 - TwoSwitchtopo\n\nOption: ")
    match option:
            case '1':
                topo = SingleSwitchTopo(n=6)
            case '2':
                topo = Fulltopology(n=5)
            case '3':
                topo = Lineartopology()
            case '4':
                topo = TwoSwitchTopo()
            case '5':
                topo = TwoSubnetsTopo()
            case _:
                print("Invalid option\n\n")
                return
    net = Mininet(topo, controller=None)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)
    net.start()
    #test_firewall(net)
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