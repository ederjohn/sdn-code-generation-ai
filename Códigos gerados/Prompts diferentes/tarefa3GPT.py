from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

# Define firewall rules (example: block traffic from/to these MAC addresses)
BLOCKED_MACS = ["00:11:22:33:44:55", "66:77:88:99:AA:BB"]

class Firewall (object):
    def __init__(self):
        core.openflow.addListeners(self)
        log.info("Firewall module enabled")

    def _handle_ConnectionUp(self, event):
        log.info("Switch %s connected", event.dpid)
        
        for mac in BLOCKED_MACS:
            self.block_mac(event, mac)
    
    def block_mac(self, event, mac):
        """Install a rule to drop packets from/to the blocked MAC"""
        msg = of.ofp_flow_mod()
        msg.match.dl_src = mac
        msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE))  # Drop packet
        event.connection.send(msg)
        
        msg = of.ofp_flow_mod()
        msg.match.dl_dst = mac
        msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE))  # Drop packet
        event.connection.send(msg)
        
        log.info("Blocking MAC: %s", mac)

# Launch the POX component
def launch():
    core.registerNew(Firewall)  

