# pox/ext/learning_switch.py

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str

log = core.getLogger()

class LearningSwitch(object):
    def __init__(self, connection):
        self.connection = connection
        self.mac_to_port = {}  # MAC address to port mapping
        connection.addListeners(self)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp
        self.mac_to_port[packet.src] = event.port  # Learn the MAC address

        if packet.dst in self.mac_to_port:
            # If the destination MAC is known, forward the packet to the correct port
            out_port = self.mac_to_port[packet.dst]
            log.info("Forwarding packet from %s to %s on port %s", packet.src, packet.dst, out_port)
            self._send_packet(packet_in, out_port)
        else:
            # If the destination MAC is unknown, flood the packet to all ports
            log.info("Flooding packet from %s to %s", packet.src, packet.dst)
            self._send_packet(packet_in, of.OFPP_ALL)

    def _send_packet(self, packet_in, out_port):
        msg = of.ofp_packet_out()
        msg.data = packet_in
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)
        self.connection.send(msg)

def launch():
    def start_switch(event):
        log.info("Starting Learning Switch on %s", dpid_to_str(event.dpid))
        LearningSwitch(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)