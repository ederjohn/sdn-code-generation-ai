from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class LearningSwitch(object):
    def __init__(self, connection):
        self.connection = connection
        self.mac_to_port = {}  # Dictionary to store MAC address to port mappings
        connection.addListeners(self)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        src_mac = packet.src
        dst_mac = packet.dst
        in_port = event.port

        # Learn the MAC address of the source host
        self.mac_to_port[src_mac] = in_port

        if dst_mac in self.mac_to_port:
            out_port = self.mac_to_port[dst_mac]
            log.info(f"Forwarding packet from {src_mac} to {dst_mac} via port {out_port}")
        else:
            out_port = of.OFPP_FLOOD  # Flood the packet if the destination is unknown
            log.info(f"Flooding packet from {src_mac} to {dst_mac}")

        # Create OpenFlow message to forward packet
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)

class SimpleController(object):
    def __init__(self):
        core.openflow.addListeners(self)

    def _handle_ConnectionUp(self, event):
        log.info(f"Switch {event.dpid} has connected")
        LearningSwitch(event.connection)

# Launch the controller
def launch():
    log.info("Starting SimpleController")
    core.registerNew(SimpleController)