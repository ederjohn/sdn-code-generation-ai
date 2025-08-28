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
        self.learn(packet.src, event.port)
        
        if packet.dst.is_multicast:
            self.flood(packet_in)
        else:
            if packet.dst not in self.mac_to_port:
                self.flood(packet_in)
            else:
                port = self.mac_to_port[packet.dst]
                if port != event.port:  # Don't send back out the input port
                    self.forward(packet_in, port)

    def learn(self, mac, port):
        self.mac_to_port[mac] = port

    def flood(self, packet_in):
        msg = of.ofp_packet_out()
        msg.data = packet_in.data
        msg.actions.append(of.ofp_action_output(port=of.OFPP_ALL))
        msg.in_port = packet_in.in_port
        self.connection.send(msg)

    def forward(self, packet_in, out_port):
        msg = of.ofp_packet_out()
        msg.data = packet_in.data
        msg.actions.append(of.ofp_action_output(port=out_port))
        msg.in_port = packet_in.in_port
        self.connection.send(msg)

class l2_learning(object):
    def __init__(self):
        core.openflow.addListeners(self)

    def _handle_ConnectionUp(self, event):
        log.debug("Connection %s" % (event.connection,))
        LearningSwitch(event.connection)

def launch():
    core.registerNew(l2_learning)