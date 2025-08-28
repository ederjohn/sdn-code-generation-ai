from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
import socket
import threading

log = core.getLogger()

class Firewall(EventMixin):
    def __init__(self):
        self.listenTo(core.openflow)
        self.firewall_rules = []
        self.known_macs = set()
        
        # Start a simple TCP server to accept new firewall rules
        self.start_rule_server()

    def start_rule_server(self):
        def rule_server():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(('127.0.0.1', 6634))
            s.listen(1)
            while True:
                conn, addr = s.accept()
                data = conn.recv(1024).decode().strip()
                if data:
                    self._add_rule_from_string(data)
                conn.close()
        
        thread = threading.Thread(target=rule_server)
        thread.daemon = True
        thread.start()

    def _handle_ConnectionUp(self, event):
        log.info("Firewall rules installed on %s", dpidToStr(event.dpid))
        self.install_initial_rules(event.connection)

    def install_initial_rules(self, connection):
        # Drop all traffic by default (can be modified as needed) e foi modificado, para cobrir os pings
        msg = of.ofp_flow_mod()
        msg.priority = 10  # Higher than default drop
        msg.match.dl_type = 0x0800  # IPv4
        msg.match.nw_proto = 1      # ICMP
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        connection.send(msg)

        # Add your initial firewall rules here
        # Example: self.add_rule("10.0.0.1", "10.0.0.2", "tcp")

    def _add_rule_from_string(self, rule_str):
        parts = rule_str.split()
        if len(parts) == 3:
            src_ip, dst_ip, protocol = parts
            self.add_rule(src_ip, dst_ip, protocol)
        else:
            log.warn("Invalid rule format: %s", rule_str)

    def add_rule(self, src_ip, dst_ip, protocol="tcp"):
        """Add a new firewall rule to block specific traffic"""
        rule = (src_ip, dst_ip, protocol.lower())
        if rule not in self.firewall_rules:
            self.firewall_rules.append(rule)
            log.info("Added firewall rule: Block %s from %s to %s", protocol, src_ip, dst_ip)
            
            # Install this rule on all switches
            for connection in core.openflow.connections:
                self._install_rule(connection, src_ip, dst_ip, protocol)

    def _install_rule(self, connection, src_ip, dst_ip, protocol):
        """Install the rule on a specific switch"""
        msg = of.ofp_flow_mod()
        
        # Match the specific traffic
        msg.match = of.ofp_match()
        msg.match.dl_type = 0x0800  # IPv4
        msg.match.nw_src = src_ip
        msg.match.nw_dst = dst_ip
        
        if protocol == "tcp":
            msg.match.nw_proto = 6  # TCP
        elif protocol == "udp":
            msg.match.nw_proto = 17  # UDP
        elif protocol == "icmp":
            msg.match.nw_proto = 1  # ICMP
            
        # No actions means drop the packet
        msg.priority = 100  # Higher priority than default rule
        
        connection.send(msg)

    def _handle_PacketIn(self, event):
        """Learn MAC addresses and manage packet flow"""
        packet = event.parsed
        
        # Learn MAC addresses
        if packet.src not in self.known_macs:
            self.known_macs.add(packet.src)
            log.info("Learned MAC: %s", packet.src)
        
        
        # Adicionado para o envio dos pacotes!
        # Handle ARP
        if packet.type == packet.ARP_TYPE:
            self._forward_packet(event)
            return
        #####
        
        # Check firewall rules for IP packets
        if packet.type == packet.IP_TYPE:
            ip_packet = packet.payload
            for rule in self.firewall_rules:
                src_ip, dst_ip, protocol = rule
                if (ip_packet.srcip == src_ip and 
                    ip_packet.dstip == dst_ip and 
                    (protocol == "any" or 
                     (protocol == "tcp" and ip_packet.protocol == 6) or
                     (protocol == "udp" and ip_packet.protocol == 17) or
                     (protocol == "icmp" and ip_packet.protocol == 1))):
                    log.debug("Blocked packet by rule: %s", rule)
                    return  # Drop the packet
            
            # If not blocked, allow the packet (implement your forwarding logic here)
            self._forward_packet(event)

    def _forward_packet(self, event):
        """Basic forwarding implementation"""
        packet = event.parsed
        connection = event.connection
        
        # Create a flow mod message to allow this traffic
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        msg.data = event.ofp
        connection.send(msg)

def launch():
    core.registerNew(Firewall)