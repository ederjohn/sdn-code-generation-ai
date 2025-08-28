from pox.core import core

import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class SimpleController(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        log.info("Packet in %s", packet)

        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        msg.data = event.ofp
        self.connection.send(msg)

def launch():
    def start_switch(event):
        log.info("Controlling %s", event.connection)
        SimpleController(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)