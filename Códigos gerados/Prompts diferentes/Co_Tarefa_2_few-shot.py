from pox.core import core
from pox.lib.packet import icmp, ethernet, ipv4
from pox.lib.addresses import IPAddr
from pox.lib.revent import EventMixin
from pox.openflow import libopenflow_01 as of

log = core.getLogger()

class PingBlocker(EventMixin):
    def __init__(self):
        self.listenTo(core.openflow)
        log.info("PingBlocker initialized")

    def _handle_ConnectionUp(self, event):
        log.info(f"Switch {event.dpid} connected")
        self.install_ping_block_rules(event)

    def install_ping_block_rules(self, event):
        # Rule to block ICMP (ping) between even and odd hosts
        for src in range(1, 255):
            for dst in range(1, 255):
                if (src % 2 == 0 and dst % 2 != 0) or (src % 2 != 0 and dst % 2 == 0):
                    match = of.ofp_match()
                    match.dl_type = ethernet.IP_TYPE
                    match.nw_proto = ipv4.ICMP_PROTOCOL
                    match.nw_src = IPAddr(f"10.0.0.{src}")
                    match.nw_dst = IPAddr(f"10.0.0.{dst}")

                    # Create a flow modification message
                    flow_mod = of.ofp_flow_mod()
                    flow_mod.match = match
                    flow_mod.idle_timeout = 5  # Speed up timeout
                    flow_mod.hard_timeout = 10
                    flow_mod.priority = 1000  # High priority
                    flow_mod.actions.append(of.ofp_action_output(port=of.OFPP_NONE))  # Drop packets

                    event.connection.send(flow_mod)
                    log.info(f"Blocking ICMP between 10.0.0.{src} and 10.0.0.{dst}")

        # Send a management packet to notify about the rules
        self.send_management_packet(event.connection)

    def send_management_packet(self, connection):
        # Create a custom management packet (e.g., an ICMP echo reply)
        management_packet = ethernet()
        management_packet.type = ethernet.IP_TYPE
        management_packet.src = "00:00:00:00:00:01"
        management_packet.dst = "ff:ff:ff:ff:ff:ff"

        ip_packet = ipv4()
        ip_packet.protocol = ipv4.ICMP_PROTOCOL
        ip_packet.srcip = IPAddr("10.0.0.1")
        ip_packet.dstip = IPAddr("10.0.0.255")

        icmp_packet = icmp()
        icmp_packet.type = icmp.ECHO_REPLY
        icmp_packet.payload = "Ping block rules installed"

        ip_packet.payload = icmp_packet
        management_packet.payload = ip_packet

        msg = of.ofp_packet_out()
        msg.data = management_packet.pack()
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        connection.send(msg)
        log.info("Management packet sent")

def launch():
    core.registerNew(PingBlocker)