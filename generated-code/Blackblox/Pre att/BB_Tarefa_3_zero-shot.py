from pox.core import core
from pox.openflow import *
from pox.lib.packet import ipv4
from pox.lib.revent import EventMixin

log = core.getLogger()

class Layer3Firewall(EventMixin):
    def __init__(self, connection):
        self.connection = connection
        self.connection.addListeners(self)
        self.allowed_ips = set()  # Set of allowed IP addresses

    def _handle_packet_in(self, event):
        packet = event.parsed
        if not isinstance(packet, ipv4.ipv4):
            return  # Not an IPv4 packet

        src_ip = packet.srcip
        dst_ip = packet.dstip

        log.info("Packet from %s to %s", src_ip, dst_ip)

        # Check if the source IP is allowed
        if src_ip not in self.allowed_ips:
            log.warning("Dropping packet from %s", src_ip)
            return  # Drop the packet

        # Forward the packet if allowed
        self.connection.send(event.ofp)

    def add_allowed_ip(self, ip):
        self.allowed_ips.add(ip)
        log.info("Added allowed IP: %s", ip)

def launch():
    def start_switch(event):
        log.info("Controlling %s" % (event.connection,))
        firewall = Layer3Firewall(event.connection)

        # Example: Add allowed IPs (you can modify this as needed)
        firewall.add_allowed_ip("10.0.0.1")  # Example allowed IP
        firewall.add_allowed_ip("10.0.0.2")  # Example allowed IP

    core.openflow.addListeners(start_switch)