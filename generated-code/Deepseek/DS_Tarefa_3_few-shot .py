from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr, IPAddr
import time

log = core.getLogger()

class Firewall(EventMixin):
    def __init__(self):
        self.listenTo(core.openflow)
        self.firewall_rules = []
        self.initialize_rules()
        log.info("Firewall controller initialized")

    def initialize_rules(self):
        # Initialize with default rules
        # Example: Allow ARP and ICMP (ping) by default
        self.add_rule(eth_type=0x0806)  # Allow ARP
        self.add_rule(eth_type=0x0800, ip_proto=1)  # Allow ICMP
        log.info("Initial firewall rules set")

    def add_rule(self, **kwargs):
        """
        Add a new firewall rule.
        Supported parameters:
        - eth_src: Source MAC address
        - eth_dst: Destination MAC address
        - eth_type: Ethernet type
        - ip_src: Source IP address
        - ip_dst: Destination IP address
        - ip_proto: IP protocol number
        """
        self.firewall_rules.append(kwargs)
        log.info("Added new rule: %s", kwargs)

    def _handle_ConnectionUp(self, event):
        # When a switch connects, install the firewall rules
        for rule in self.firewall_rules:
            self.install_rule(event.connection, rule)
        log.info("Firewall rules installed on switch %s", dpidToStr(event.dpid))

    def install_rule(self, connection, rule):
        # Create a flow table entry based on the rule
        msg = of.ofp_flow_mod()
        
        # Set match criteria
        match = of.ofp_match()
        
        if 'eth_src' in rule:
            match.dl_src = EthAddr(rule['eth_src'])
        if 'eth_dst' in rule:
            match.dl_dst = EthAddr(rule['eth_dst'])
        if 'eth_type' in rule:
            match.dl_type = rule['eth_type']
        if 'ip_src' in rule:
            match.nw_src = IPAddr(rule['ip_src'])
        if 'ip_dst' in rule:
            match.nw_dst = IPAddr(rule['ip_dst'])
        if 'ip_proto' in rule:
            match.nw_proto = rule['ip_proto']
        
        msg.match = match
        
        # Set action (allow by default for rules in the list)
        msg.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))
        
        # Send to switch
        connection.send(msg)

    def _handle_PacketIn(self, event):
        # Handle packets that don't match any flow
        packet = event.parsed
        
        # Default policy: block
        log.warning("Blocked packet from %s to %s", packet.src, packet.dst)
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        connection.send(msg)

def launch():
    core.registerNew(Firewall)