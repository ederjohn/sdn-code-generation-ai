from pox.core import core
from pox.openflow import *
from pox.lib.packet import *
from pox.lib.util import dpid_to_str

log = core.getLogger()

class BlockPing(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

    def _handle_packet_in(self, event):
        packet = event.parsed

        # Check if the packet is an ICMP packet
        if isinstance(packet.next, icmp.icmp):
            src_ip = packet.next.srcip
            dst_ip = packet.next.dstip

            # Determine if the source and destination IPs are even or odd
            src_host = int(str(src_ip).split('.')[-1])
            dst_host = int(str(dst_ip).split('.')[-1])

            # Block pings between even and odd hosts
            if (src_host % 2 == 0 and dst_host % 2 != 0) or (src_host % 2 != 0 and dst_host % 2 == 0):
                log.info("Blocking ping from %s to %s", src_ip, dst_ip)
                return  # Drop the packet

        # If not blocked, forward the packet
        self.connection.send(event.ofp)

    def _handle_connection_up(self):
        log.info("Switch %s connected.", dpid_to_str(self.connection.dpid))

def launch():
    def start_switch(event):
        log.info("Controlling switch %s", dpid_to_str(event.dpid))
        BlockPing(event.connection)

    core.openflow.addListeners(start_switch)
