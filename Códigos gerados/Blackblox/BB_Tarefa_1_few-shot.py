"""
A simple POX controller that manages packet forwarding between hosts
and learns MAC addresses dynamically.

This controller implements a learning switch:
- It learns the MAC address to switch port mappings from incoming packets.
- For packets destined to known MAC addresses, it forwards them to the correct port.
- For unknown destinations, it floods the packet to all ports except the incoming one.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class LearningSwitch (object):
    def __init__ (self, connection):
        # Keep track of the connection to the switch so we can send packets
        self.connection = connection

        # Our table mapping MAC addresses to switch ports
        self.mac_to_port = {}

        # Listen for packet-in messages
        connection.addListeners(self)

    def _handle_PacketIn (self, event):
        packet = event.parsed

        def flood():
            # Flood packet out all ports except the input port
            msg = of.ofp_packet_out()
            msg.data = event.ofp
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            msg.in_port = event.port
            self.connection.send(msg)

        src_mac = packet.src
        dst_mac = packet.dst
        in_port = event.port

        # Learn the source MAC address to avoid flooding next time
        self.mac_to_port[src_mac] = in_port

        if dst_mac.is_multicast:
            # Flood multicast packets
            flood()
            return

        if dst_mac in self.mac_to_port:
            out_port = self.mac_to_port[dst_mac]
            if out_port == in_port:
                # Drop packets coming in the same port as destination
                log.warning("Drop packet: src and dst on same port %s", str(packet))
                return
            # Install flow to avoid PacketIn next time
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match.from_packet(packet, in_port)
            msg.actions.append(of.ofp_action_output(port=out_port))
            msg.idle_timeout = 10
            msg.hard_timeout = 30
            self.connection.send(msg)

            # Send the packet out immediately
            msg = of.ofp_packet_out()
            msg.data = event.ofp
            msg.actions.append(of.ofp_action_output(port=out_port))
            msg.in_port = in_port
            self.connection.send(msg)
        else:
            # Flood if destination MAC is unknown
            flood()

def launch ():
    """
    Starts the component
    """
    def start_switch (event):
        log.info("Controlling %s" % (event.connection,))
        LearningSwitch(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
