# mylearningswitch.py

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.addresses import EthAddr

log = core.getLogger()

class LearningSwitch(object):
    def __init__(self, connection):
        self.connection = connection
        self.mac_to_port = {}
        connection.addListeners(self)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp
        self.mac_to_port[packet.src] = event.port

        if packet.dst in self.mac_to_port:
            log.info("Installing flow for %s.%i -> %s.%i" %
            (packet.src, event.port, packet.dst, self.mac_to_port[packet.dst]))
            flow_mod = of.ofp_flow_mod()
            flow_mod.match = of.ofp_match.from_packet(packet)
            flow_mod.actions.append(of.ofp_action_output(port=self.mac_to_port[packet.dst]))
            self.connection.send(flow_mod)
        else:
            log.info("Flooding packet for %s" % packet.dst)
            msg = of.ofp_packet_out()
            msg.data = packet_in.data
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            msg.in_port = event.port
            self.connection.send(msg)

def launch():
    def start_switch(event):
        log.info("Controlling %s" % (event.connection,))
        LearningSwitch(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
