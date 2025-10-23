from pox.core import core
from pox.lib.addresses import EthAddr

import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class LearningSwitch(object):
    def __init__(self, connection):
        self.connection = connection
        self.mac_to_port = {}
        connection.addListeners(self)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        in_port = event.port

        # Learn the source MAC address
        self.mac_to_port[packet.src] = in_port

        # Check if we know the destination MAC address
        if packet.dst in self.mac_to_port:
            out_port = self.mac_to_port[packet.dst]
            log.debug("Sending packet to %s out port %s", packet.dst, out_port)
            msg = of.ofp_packet_out()
            msg.data = event.ofp
            action = of.ofp_action_output(port=out_port)
            msg.actions.append(action)
            self.connection.send(msg)
        else:
            # Flood the packet if the destination MAC is unknown
            log.debug("Flooding packet to %s", packet.dst)
            msg = of.ofp_packet_out()
            msg.data = event.ofp
            action = of.ofp_action_output(port=of.OFPP_FLOOD)
            msg.actions.append(action)
            self.connection.send(msg)

def launch():
    def start_switch(event):
        log.debug("Controlling %s", event.connection)
        LearningSwitch(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)