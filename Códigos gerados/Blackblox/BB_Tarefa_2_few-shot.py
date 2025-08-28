"""
POX Controller to block pings between even hosts and odd hosts,
and speed up the timeout when the ping block occurs.

- Blocks ICMP echo request packets between odd and even hosts.
- For blocked flows, installs a drop rule with a short idle timeout to speed up the timeout.
- Allows other packets to be forwarded normally.

Usage:
    pox.py log.level --DEBUG pox_block_odd_even_ping
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet, ipv4, icmp
from pox.lib.addresses import IPAddr

log = core.getLogger()

# Timeout values in seconds
NORMAL_IDLE_TIMEOUT = 30
BLOCK_IDLE_TIMEOUT = 3  # Speed up timeout for blocked flows

def is_host_even(ip):
    """
    Determine if a host is even or odd number based on its last octet IP address.
    Assumes IPs in 10.0.0.x
    """
    try:
        last_octet = int(str(ip).split('.')[-1])
        return (last_octet % 2) == 0
    except Exception:
        return False  # Default: treat as odd if parsing fails

class BlockOddEvenPing (object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

    def _handle_PacketIn(self, event):
        packet = event.parsed

        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        # Handle only IP packets
        ip_pkt = packet.find('ipv4')
        if ip_pkt is None:
            # Not an IP packet, ignore or flood
            self.flood_packet(event)
            return

        # Handle only ICMP packets (ping)
        icmp_pkt = packet.find('icmp')
        if icmp_pkt is None:
            # Not ICMP, normal forwarding
            self.forward_packet(event)
            return

        src_ip = ip_pkt.srcip
        dst_ip = ip_pkt.dstip

        # Determine if src and dst hosts are odd/even
        src_even = is_host_even(src_ip)
        dst_even = is_host_even(dst_ip)

        # Check if one is even and the other is odd
        if src_even != dst_even:
            # Block the ping between even and odd hosts
            log.info(f"Blocking ping between even-odd hosts: {src_ip} -> {dst_ip}")

            # Install drop flow with short timeout (BLOCK_IDLE_TIMEOUT)
            fm = of.ofp_flow_mod()
            fm.match = of.ofp_match.from_packet(packet, event.port)
            fm.idle_timeout = BLOCK_IDLE_TIMEOUT
            fm.hard_timeout = 0
            fm.priority = 1000
            # No actions = drop
            self.connection.send(fm)

            # Also drop the current packet
            return

        else:
            # Allow ping within even-even or odd-odd hosts
            self.forward_packet(event)

    def forward_packet(self, event):
        """
        Normal forwarding by installing flow entry to flood.
        """
        packet = event.parsed
        fm = of.ofp_flow_mod()
        fm.match = of.ofp_match.from_packet(packet, event.port)
        fm.idle_timeout = NORMAL_IDLE_TIMEOUT
        fm.hard_timeout = 0
        fm.priority = 10
        # Flood by outputting packet to all ports except ingress port
        fm.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(fm)

        # Also resend the packet now to avoid delay
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        action = of.ofp_action_output(port=of.OFPP_FLOOD)
        msg.actions.append(action)
        self.connection.send(msg)

    def flood_packet(self, event):
        """
        Floods the packet out all ports except ingress.
        """
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)


def launch():
    def start_switch(event):
        log.info("Controlling %s" % (event.connection,))
        BlockOddEvenPing(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
