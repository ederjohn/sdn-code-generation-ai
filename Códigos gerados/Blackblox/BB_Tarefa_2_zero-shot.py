"""
POX Controller to block ping (ICMP echo request/reply) between even hosts and odd hosts.

Logic:
- Hosts are identified by the last octet of their IPv4 address.
- If one host's last IP octet is even and the other is odd, block ping traffic between them.
- Other traffic is forwarded normally.

Usage:
- Run this controller with POX.
- Connect hosts with IPv4 addresses that differ by the last octet.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet, ipv4, icmp
from pox.lib.packet.ethernet import ethernet as eth_type
from pox.lib.addresses import IPAddr

log = core.getLogger()

class BlockPingEvenOdd (object):
    def __init__ (self, connection):
        # Keep track of connection to switch
        self.connection = connection
        # Listen to packet in events
        connection.addListeners(self)
        log.info("BlockPingEvenOdd controller started for %s", connection)

    def _handle_PacketIn (self, event):
        packet = event.parsed

        # Defensive check
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        # Only handle IPv4 packets with ICMP
        ip_packet = packet.find('ipv4')
        if ip_packet is None:
            # Not an IP packet, allow forwarding
            self.forward_packet(event, packet)
            return

        # Look for ICMP packet inside
        icmp_packet = ip_packet.find('icmp')
        if icmp_packet is None:
            # Not ICMP, allow forwarding
            self.forward_packet(event, packet)
            return

        # This is an ICMP packet (likely ping)
        src_ip = ip_packet.srcip
        dst_ip = ip_packet.dstip

        # Check last octet of IP addresses
        try:
            src_last_octet = int(str(src_ip).split('.')[-1])
            dst_last_octet = int(str(dst_ip).split('.')[-1])
        except Exception as e:
            log.error("Error parsing IP addresses %s -> %s: %s", src_ip, dst_ip, e)
            # Allow packet if IP parsing fails
            self.forward_packet(event, packet)
            return

        # Determine parity of hosts
        src_even = (src_last_octet % 2 == 0)
        dst_even = (dst_last_octet % 2 == 0)

        # Block ping between even and odd hosts
        if src_even != dst_even:
            # Different parity, block ping
            log.info("Blocked ICMP ping between %s and %s", src_ip, dst_ip)
            # Do not install flow, drop packet by not forwarding
            # Optionally, can send a flow mod to drop matching packets for efficiency
            # Let's send a flow mod to drop ICMP between these hosts
            msg = of.ofp_flow_mod()
            msg.match.dl_type = 0x0800  # IP
            msg.match.nw_proto = 1      # ICMP
            msg.match.nw_src = src_ip
            msg.match.nw_dst = dst_ip
            # Empty instructions means drop
            msg.idle_timeout = 60
            msg.hard_timeout = 600
            self.connection.send(msg)

            # Also drop this packet explicitly by not forwarding

            return

        # Otherwise, allow forwarding
        self.forward_packet(event, packet)

    def forward_packet(self, event, packet):
        """
        Simple flood forward for allowed packets.
        """
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        # Send to all ports except incoming
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        msg.in_port = event.port
        self.connection.send(msg)

def launch ():
    """
    Starts the component
    """
    def start_switch(event):
        log.info("Controlling %s" % (event.connection,))
        BlockPingEvenOdd(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
