from pox.core import core
from pox.lib.packet import ethernet, ipv4, arp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.revent import EventMixin
from pox.lib.util import dpid_to_str

log = core.getLogger()

class Firewall(EventMixin):
    def __init__(self):
        self.listenTo(core.openflow)
        self.blocked = set()  # Set of blocked (src_ip, dst_ip) pairs
        log.info("Firewall initialized")

    def _handle_ConnectionUp(self, event):
        log.info(f"Switch {dpid_to_str(event.dpid)} has connected")

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        if isinstance(packet.next, ipv4):
            src_ip = packet.next.srcip
            dst_ip = packet.next.dstip

            if (src_ip, dst_ip) in self.blocked:
                log.info(f"Blocking packet from {src_ip} to {dst_ip}")
                return  # Drop the packet

        # Allow the packet by installing a flow rule
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        msg.data = event.ofp  # Optional: Only needed if sending the first packet
        event.connection.send(msg)

    def block_traffic(self, src_ip, dst_ip):
        self.blocked.add((IPAddr(src_ip), IPAddr(dst_ip)))
        log.info(f"Blocking traffic from {src_ip} to {dst_ip}")

def launch():
    core.registerNew(Firewall)
