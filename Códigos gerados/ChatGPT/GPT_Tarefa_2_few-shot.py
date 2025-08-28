# Save this as ping_blocker.py inside the pox/ext directory

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

def is_even(host_ip):
    """ Helper function to determine if the last octet is even """
    last_octet = int(host_ip.split('.')[-1])
    return last_octet % 2 == 0

class PingBlocker (object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

    def _handle_PacketIn(self, event):
        packet = event.parsed

        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        # Only process ICMP (ping) packets
        icmp = packet.find('icmp')
        ipv4 = packet.find('ipv4')
        if not icmp or not ipv4:
            # Let non-ICMP packets through
            self.allow(event)
            return

        src_ip = ipv4.srcip.toStr()
        dst_ip = ipv4.dstip.toStr()

        src_even = is_even(src_ip)
        dst_even = is_even(dst_ip)

        # Check if communication is between odd and even hosts
        if src_even != dst_even:
            log.info(f"Blocking ICMP between {src_ip} and {dst_ip}")
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match.from_packet(packet, event.port)
            msg.idle_timeout = 5  # Short timeout
            msg.hard_timeout = 10
            msg.priority = 1000
            # No actions = drop
            self.connection.send(msg)

            # Also drop current packet
            drop_packet = of.ofp_packet_out()
            drop_packet.buffer_id = event.ofp.buffer_id
            drop_packet.in_port = event.port
            self.connection.send(drop_packet)
            return
            
        # Otherwise, allow the packet
        self.allow(event)

    def allow(self, event):
        packet = event.parsed
        in_port = event.port

        # Learn the source MAC address to avoid flooding next time
        self.connection.send(of.ofp_flow_mod(
            match=of.ofp_match.from_packet(packet, in_port),
            idle_timeout=30,
            hard_timeout=60,
            priority=500,
            actions=[of.ofp_action_output(port=of.OFPP_FLOOD)]
        ))

        # Immediately forward the packet
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)


def launch ():
    def start_switch(event):
        log.info(f"Controlling {event.connection}")
        PingBlocker(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
