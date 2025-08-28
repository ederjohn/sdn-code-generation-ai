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
        if not packet:
            return

        # Check if the packet is an ICMP packet
        if isinstance(packet.next, ipv4) and isinstance(packet.next.next, icmp):
            src_ip = packet.next.srcip
            dst_ip = packet.next.dstip

            # Determine if the source and destination hosts are even or odd
            src_host = int(str(src_ip).split('.')[-1])
            dst_host = int(str(dst_ip).split('.')[-1])

            # Block pings between even and odd hosts
            if (src_host % 2 == 0 and dst_host % 2 != 0) or (src_host % 2 != 0 and dst_host % 2 == 0):
                log.info("Blocking ping from %s to %s", src_ip, dst_ip)
                return  # Drop the packet

        # Forward the packet if it's not blocked
        self.connection.send(event.ofp)

    def _handle_connection_up(self):
        log.info("Switch %s connected.", self.connection)

def launch():
    def start_switch(event):
        BlockPing(event.connection)

    core.openflow.addListeners(start_switch)