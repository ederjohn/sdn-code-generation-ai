from pox.core import core
from pox.openflow import *
from pox.lib.packet import icmp
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4

log = core.getLogger()

class BlockPing (object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

    def _handle_packet_in(self, event):
        packet = event.parsed

        # Check if the packet is an Ethernet packet
        if not isinstance(packet, ethernet):
            return

        # Check if the packet is an IP packet
        if not isinstance(packet.payload, ipv4):
            return

        ip_packet = packet.payload

        # Check if the packet is an ICMP packet
        if isinstance(ip_packet.payload, icmp):
            src_ip = ip_packet.srcip
            dst_ip = ip_packet.dstip

            # Determine if the source and destination IPs are even or odd
            src_host = int(str(src_ip).split('.')[-1])
            dst_host = int(str(dst_ip).split('.')[-1])

            # Block pings between even and odd hosts
            if (src_host % 2 == 0 and dst_host % 2 != 0) or (src_host % 2 != 0 and dst_host % 2 == 0):
                log.info("Blocking ICMP packet from %s to %s", src_ip, dst_ip)
                return  # Drop the packet

        # If not blocked, forward the packet
        self.connection.send(event.ofp)

    def _handle_connection_up(self):
        log.info("Switch %s has connected.", self.connection)

def launch():
    def start_switch(event):
        log.info("Controlling %s", event.connection)
        BlockPing(event.connection)

    core.openflow.addListeners(start_switch)