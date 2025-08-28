# Basic POX controller implementing a L2 learning switch.
# Save this file as learning_switch.py and run with POX:
#    ./pox.py learning_switch

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class LearningSwitch (object):
    def __init__ (self, connection):
        # Keep track of the connection to the switch so we can send messages
        self.connection = connection

        # Our table maps MAC addresses to ports
        self.mac_to_port = {}

        # Listen for packet in events
        connection.addListeners(self)

        log.debug("LearningSwitch created for %s", connection)

    def _handle_PacketIn (self, event):
        """
        Handle packet in messages from the switch to implement learning switch logic:
        - Learn the source MAC to port mapping
        - Forward packets to destination port if known, else flood
        """
        packet = event.parsed

        # Learn the source MAC address to avoid flooding next time
        self.mac_to_port[packet.src] = event.port

        if packet.dst in self.mac_to_port:
            # We know the port for the destination MAC, send packet out only on that port
            out_port = self.mac_to_port[packet.dst]
            log.debug("Installing flow: %s -> %s out port %s", packet.src, packet.dst, out_port)

            # Install a flow entry so switches forward similar packets in the future
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match.from_packet(packet, event.port)
            msg.idle_timeout = 10
            msg.hard_timeout = 30
            msg.actions.append(of.ofp_action_output(port = out_port))
            msg.data = event.ofp  # Forward the current packet to the target port
            self.connection.send(msg)
        else:
            # Flood the packet out all ports except the input port
            log.debug("Flooding packet %s from %s", packet.dst, packet.src)
            msg = of.ofp_packet_out()
            msg.data = event.ofp
            msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            msg.in_port = event.port
            self.connection.send(msg)

def launch():
    """
    Starts the component. Called by POX runtime on startup.
    """
    def start_switch(event):
        log.debug("Connection %s" % (event.connection,))
        LearningSwitch(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
