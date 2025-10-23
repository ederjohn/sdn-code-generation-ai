from pox.core import core
import pox.openflow.libopenflow_01 as of
import socket

log = core.getLogger()

# Firewall rule storage
firewall_rules = []

def add_firewall_rules(src_ip, dst_ip, protocol="tcp"):
    rule = (src_ip, dst_ip, protocol.lower())
    if rule not in firewall_rules:
        firewall_rules.append(rule)
        print(f"Rule added: Block {protocol.upper()} from {src_ip} to {dst_ip}")

class L3Firewall(object):
    def __init__(self, connection):
        self.connection = connection
        self.mac_to_port = {}  # MAC learning table
        connection.addListeners(self)
        log.info("L3 Firewall initialized on %s", connection)

    def is_blocked(self, packet):
        ip = packet.find('ipv4')
        if not ip:
            return False  # Not an IP packet, allow by default
        protocol = None
        if ip.protocol == ip.TCP_PROTOCOL:
            protocol = "tcp"
        elif ip.protocol == ip.UDP_PROTOCOL:
            protocol = "udp"
        elif ip.protocol == ip.ICMP_PROTOCOL:
            protocol = "icmp"

        for rule in firewall_rules:
            if rule == (str(ip.srcip), str(ip.dstip), protocol):
                log.debug("Blocked: %s -> %s (%s)", ip.srcip, ip.dstip, protocol)
                return True
        return False

    def _handle_PacketIn(self, event):
        packet = event.parsed
        in_port = event.port

        # Learn MAC addresses
        self.mac_to_port[packet.src] = in_port

        # Drop if rule matches
        if self.is_blocked(packet):
            drop = of.ofp_packet_out()
            drop.buffer_id = event.ofp.buffer_id
            drop.in_port = in_port
            self.connection.send(drop)
            return

        # Forwarding logic
        if packet.dst in self.mac_to_port:
            out_port = self.mac_to_port[packet.dst]
            action = of.ofp_action_output(port=out_port)
            msg = of.ofp_packet_out(
                data=event.ofp,
                action=[action],
                in_port=in_port
            )
            self.connection.send(msg)
        else:
            # Flood if destination unknown
            msg = of.ofp_packet_out()
            msg.data = event.ofp
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            msg.in_port = in_port
            self.connection.send(msg)

def launch():
    def start_switch(event):
        log.info("Controlling %s", event.connection)
        L3Firewall(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
    log.info("POX L3 Firewall module launched.")
