from pox.core import core
from pox.openflow import *
from pox.lib.packet import ipv4
from pox.lib.revent import EventMixin

log = core.getLogger()

class Firewall(EventMixin):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)
        self.blocked_ips = set()  # Set of blocked IPs

    def _handle_packet_in(self, event):
        packet = event.parsed
        if not isinstance(packet, ipv4):
            return  # Ignore non-IP packets

        src_ip = packet.srcip
        dst_ip = packet.dstip

        # Check if the destination IP is in the blocked list
        if dst_ip in self.blocked_ips:
            log.info("Blocking packet from %s to %s", src_ip, dst_ip)
            # Drop the packet
            self.connection.send(ofp_packet_out(data=event.ofp, actions=[]))
        else:
            log.info("Allowing packet from %s to %s", src_ip, dst_ip)
            # Forward the packet
            msg = of.ofp_packet_out()
            msg.data = event.ofp
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))  # Or specific port
            self.connection.send(msg)

    def add_blocked_ip(self, ip):
        self.blocked_ips.add(ip)
        log.info("Added %s to blocked IPs", ip)

def launch():
    def start_switch(event):
        log.info("Controlling %s" % (event.connection,))
        firewall = Firewall(event.connection)
        firewall.add_blocked_ip("10.0.0.5")  # Block this IP
        
    core.openflow.addListeners(start_switch)
