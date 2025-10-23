from pox.core import core
from pox.openflow import *
from pox.lib.packet import icmp
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4

log = core.getLogger()

class PingBlocker(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

    def _handle_packet(self, packet, event):
        if isinstance(packet.next, ipv4):
            ip_packet = packet.next
            src_ip = ip_packet.srcip
            dst_ip = ip_packet.dstip

            # Determine if the hosts are even or odd based on their IP addresses
            src_host = int(str(src_ip).split('.')[-1])
            dst_host = int(str(dst_ip).split('.')[-1])

            # Block pings between even and odd hosts
            if (src_host % 2 == 0 and dst_host % 2 != 0) or (src_host % 2 != 0 and dst_host % 2 == 0):
                log.info("Blocking ping from %s to %s", src_ip, dst_ip)
                # Drop the packet
                return True  # Returning True indicates the packet should be dropped

        return False  # Return False to allow other packets

    def _handle_packet_in(self, event):
        packet = event.parsed
        if packet is None:
            return

        # Check if the packet should be blocked
        if self._handle_packet(packet, event):
            # Send a flow mod to drop the packet
            msg = ofp_flow_mod()
            msg.match = ofp_match.from_packet(packet)
            msg.idle_timeout = 5  # Set a short timeout for the flow
            msg.hard_timeout = 10  # Set a hard timeout for the flow
            self.connection.send(msg)
            return

        # If not blocked, forward the packet normally
        msg = ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

    def _handle_connection_up(self):
        log.info("Switch %s connected.", self.connection)

    def _handle_connection_down(self):
        log.info("Switch %s disconnected.", self.connection)

def launch():
    def start_switch(event):
        log.info("Controlling switch %s", event.dpid)
        PingBlocker(event.connection)

    core.openflow.addListeners(start_switch)
