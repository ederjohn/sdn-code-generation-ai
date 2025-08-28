from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class PingBlocker(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        ip_packet = packet.find('ipv4')
        icmp_packet = packet.find('icmp')

        if ip_packet and icmp_packet:
            src_host = int(ip_packet.srcip.toStr().split('.')[-1])
            dst_host = int(ip_packet.dstip.toStr().split('.')[-1])

            if (src_host % 2 == 0 and dst_host % 2 != 0) or (src_host % 2 != 0 and dst_host % 2 == 0):
                log.info(f"Blocking ICMP between {ip_packet.srcip} and {ip_packet.dstip}")
                return  # Drop the packet

        # Allow other traffic
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

class PingBlockerController(object):
    def __init__(self):
        core.openflow.addListeners(self)

    def _handle_ConnectionUp(self, event):
        log.info(f"Switch {event.dpid} has connected")
        PingBlocker(event.connection)

def launch():
    log.info("Starting PingBlockerController")
    core.registerNew(PingBlockerController)