from pox.core import core
import pox.openflow.libopenflow_01 as of

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
        
        src = packet.src
        dst = packet.dst
        in_port = event.port
        
        self.mac_to_port[src] = in_port
        
        if dst in self.mac_to_port:
            out_port = self.mac_to_port[dst]
            log.info(f"Forwarding packet from {src} to {dst} via port {out_port}")
            msg = of.ofp_packet_out()
            msg.actions.append(of.ofp_action_output(port=out_port))
            msg.data = event.ofp
            msg.in_port = in_port
            self.connection.send(msg)
        else:
            log.info(f"Flooding packet from {src} to {dst}")
            msg = of.ofp_packet_out()
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            msg.data = event.ofp
            msg.in_port = in_port
            self.connection.send(msg)

class SimpleController(object):
    def __init__(self):
        core.openflow.addListeners(self)
    
    def _handle_ConnectionUp(self, event):
        log.info(f"Switch {event.dpid} connected")
        LearningSwitch(event.connection)

def launch():
    log.info("Starting POX SDN Controller")
    core.registerNew(SimpleController)

