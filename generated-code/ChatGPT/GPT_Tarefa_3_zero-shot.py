# Filename: l3_firewall.py

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet, ipv4
from pox.lib.addresses import IPAddr

log = core.getLogger()

# Example Layer 3 firewall rules
# Each tuple is (src_ip, dst_ip) to block
FIREWALL_RULES = [
    ("10.0.0.1", "10.0.0.2"),
    ("10.0.0.3", "10.0.0.4"),
]

class L3Firewall (object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

    def _handle_PacketIn(self, event):
        packet = event.parsed

        if not packet:
            log.warning("Ignoring incomplete packet")
            return

        ip_packet = packet.find('ipv4')
        if ip_packet is None:
            # Not an IP packet; forward as is (or drop if desired)
            self._allow_packet(event)
            return

        src_ip = str(ip_packet.srcip)
        dst_ip = str(ip_packet.dstip)

        # Check against firewall rules
        for rule in FIREWALL_RULES:
            if (src_ip == rule[0] and dst_ip == rule[1]) or \
               (src_ip == rule[1] and dst_ip == rule[0]):
                log.info(f"Blocked IP packet: {src_ip} -> {dst_ip}")
                return  # Drop packet

        self._allow_packet(event)

    def _allow_packet(self, event):
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(event.parsed, event.port)
        msg.idle_timeout = 30
        msg.hard_timeout = 60
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        msg.buffer_id = event.ofp.buffer_id
        self.connection.send(msg)
        log.info("Flow installed for allowed IP packet")

def launch():
    def start_switch(event):
        log.info("L3 Firewall running on %s", event.connection)
        L3Firewall(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
