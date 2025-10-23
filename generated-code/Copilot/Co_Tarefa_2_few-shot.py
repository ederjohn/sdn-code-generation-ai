from pox.core import core
from pox.lib.packet import ethernet, ipv4, icmp
from pox.lib.addresses import IPAddr
from pox.lib.revent import EventMixin

import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class PingBlocker(EventMixin):
    def __init__(self):
        self.listenTo(core.openflow)
        log.info("PingBlocker initialized")

    def _handle_ConnectionUp(self, event):
        log.info(f"Switch {event.dpid} connected")

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        if packet.type == ethernet.IP_TYPE:
            ip_packet = packet.payload
            if isinstance(ip_packet, ipv4):
                src_ip = ip_packet.srcip
                dst_ip = ip_packet.dstip

                if isinstance(ip_packet.payload, icmp):
                    src_host = int(str(src_ip).split('.')[-1])
                    dst_host = int(str(dst_ip).split('.')[-1])

                    # Block pings between even and odd hosts
                    if (src_host % 2 == 0 and dst_host % 2 != 0) or (src_host % 2 != 0 and dst_host % 2 == 0):
                        log.info(f"Blocking ICMP between {src_ip} and {dst_ip}")

                        # Install a flow to drop packets with a short timeout
                        fm = of.ofp_flow_mod()
                        fm.match = of.ofp_match.from_packet(packet, event.port)
                        fm.idle_timeout = 5  # Short timeout
                        fm.hard_timeout = 10
                        fm.priority = 1000
                        fm.actions = []  # No actions = drop
                        event.connection.send(fm)
                        return

        # Allow other traffic
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)

def launch():
    core.registerNew(PingBlocker)