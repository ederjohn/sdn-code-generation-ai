from pox.core import core
import socket

# teste_Co.py
# POX Layer 3 Firewall Controller

import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class Layer3Firewall(object):
    def __init__(self, connection):
        self.connection = connection
        self.mac_to_port = {}  # MAC learning table
        self.firewall_rules = set()  # (src_ip, dst_ip, protocol)
        connection.addListeners(self)
        self.initialize_rules()

    def initialize_rules(self):
        # Example: Block TCP from 10.0.0.1 to 10.0.0.2
        self.add_firewall_rules("10.0.0.1", "10.0.0.2", "tcp")

    def add_firewall_rules(self, src_ip, dst_ip, protocol="tcp"):
        rule = (src_ip, dst_ip, protocol)
        self.firewall_rules.add(rule)
        # Optionally notify external system (as in your example)
        rule_str = f"{src_ip} {dst_ip} {protocol}\n"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(("127.0.0.1", 6633))
                s.sendall(rule_str.encode())
            log.info(f"Rule added: Block {protocol} from {src_ip} to {dst_ip}")
        except Exception as e:
            log.warning(f"Could not notify external system: {e}")

    def _handle_PacketIn(self, event):
        packet = event.parsed
        in_port = event.port

        # MAC learning
        self.mac_to_port[packet.src] = in_port

        # Layer 3 firewall: Check IP and protocol
        ip_packet = packet.find('ipv4')
        tcp_packet = packet.find('tcp')
        udp_packet = packet.find('udp')

        if ip_packet:
            src_ip = str(ip_packet.srcip)
            dst_ip = str(ip_packet.dstip)
            protocol = "tcp" if tcp_packet else "udp" if udp_packet else "other"
            if (src_ip, dst_ip, protocol) in self.firewall_rules:
                log.info(f"Blocked {protocol} from {src_ip} to {dst_ip}")
                return  # Drop packet

        # Forwarding logic
        dst_mac = packet.dst
        if dst_mac in self.mac_to_port:
            out_port = self.mac_to_port[dst_mac]
            msg = of.ofp_packet_out(data=event.ofp)
            msg.actions.append(of.ofp_action_output(port=out_port))
            self.connection.send(msg)
        else:
            # Flood if destination unknown
            msg = of.ofp_packet_out(data=event.ofp)
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            self.connection.send(msg)

def launch():
    def start_switch(event):
        log.info("Controlling %s" % (event.connection,))
        Layer3Firewall(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)