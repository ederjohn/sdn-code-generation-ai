from pox.core import core
from pox.lib.packet import ethernet, ipv4, arp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.revent import EventMixin
from pox.openflow.libopenflow_01 import ofp_packet_out, ofp_flow_mod, ofp_match, ofp_action_output
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet

log = core.getLogger()

class Layer3Firewall(EventMixin):
    def __init__(self):
        self.listenTo(core.openflow)
        self.blocked_ips = set()  # Add IPs to block here, e.g., {"10.0.0.2"}

    def _handle_ConnectionUp(self, event):
        log.info(f"Switch {event.dpid} has connected.")

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet.")
            return

        if packet.type == ethernet.IP_TYPE:
            ip_packet = packet.find('ipv4')
            if ip_packet and ip_packet.srcip in self.blocked_ips:
                log.info(f"Blocking packet from {ip_packet.srcip}")
                return  # Drop the packet

            # Install a flow to allow the packet
            self._install_flow(event, ip_packet)

        elif packet.type == ethernet.ARP_TYPE:
            log.info("Handling ARP packet.")
            self._handle_arp(event)

    def _install_flow(self, event, ip_packet):
        match = ofp_match.from_packet(event.parsed, event.port)
        flow_mod = ofp_flow_mod()
        flow_mod.match = match
        flow_mod.idle_timeout = 10
        flow_mod.hard_timeout = 30
        flow_mod.actions.append(ofp_packet_out(data=event.data))
        event.connection.send(flow_mod)
        log.info(f"Flow installed for IP {ip_packet.srcip} -> {ip_packet.dstip}")

    def _handle_arp(self, event):
        arp_packet = event.parsed.find('arp')
        if not arp_packet:
            log.warning("Received a non-ARP packet in _handle_arp.")
            return

        if arp_packet.opcode == arp.REQUEST:
            log.info(f"Handling ARP request for IP {arp_packet.protodst}")

            # Create an ARP reply
            arp_reply = arp()
            arp_reply.hwtype = arp_packet.hwtype
            arp_reply.prototype = arp_packet.prototype
            arp_reply.hwlen = arp_packet.hwlen
            arp_reply.protolen = arp_packet.protolen
            arp_reply.opcode = arp.REPLY
            arp_reply.hwdst = arp_packet.hwsrc
            arp_reply.protodst = arp_packet.protosrc
            arp_reply.hwsrc = event.connection.eth_addr  # MAC of the switch
            arp_reply.protosrc = arp_packet.protodst

            # Create Ethernet frame
            eth = ethernet()
            eth.type = ethernet.ARP_TYPE
            eth.dst = arp_packet.hwsrc
            eth.src = event.connection.eth_addr
            eth.payload = arp_reply

            # Send the ARP reply
            msg = ofp_packet_out()
            msg.data = eth.pack()
            msg.actions.append(ofp_action_output(port=event.port))
            event.connection.send(msg)

            log.info(f"Sent ARP reply for IP {arp_reply.protosrc} to {arp_reply.hwdst}")
        else:
            log.info("Ignoring non-ARP request packet.")

def launch():
    log.info("Starting Layer 3 Firewall...")
    core.registerNew(Layer3Firewall)