from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger()

class FirewallController(object):
    """
    A simple firewall controller that blocks specific traffic flows.
    """
    
    def __init__(self):
        core.openflow.addListeners(self)
        self.firewall_rules = []
        
        # Add default firewall rules (can be extended/modified)
        self._initialize_default_rules()
        
    def _initialize_default_rules(self):
        """
        Initialize some default firewall rules.
        Format: (src_ip, dst_ip, src_port, dst_port, protocol, action)
        
        # Block all traffic from 10.0.0.1 to 10.0.0.2
        self.firewall_rules.append(('10.0.0.1', '10.0.0.2', None, None, 'ip', of.OFPFC_DELETE))
        
        # Block TCP traffic on port 80 (HTTP) from any to 10.0.0.3
        self.firewall_rules.append((None, '10.0.0.3', None, 80, 'tcp', of.OFPFC_DELETE))
        """
        # Allow ICMP (ping) between all hosts
        self.firewall_rules.append((None, None, None, None, 'icmp', of.OFPFC_ADD))
        
        # Add more rules as needed...
        
    def _handle_ConnectionUp(self, event):
        """
        Handle new switch connections and install firewall rules.
        """
        log.info("Firewall rules installed on %s", dpidToStr(event.dpid))
        
        for rule in self.firewall_rules:
            src_ip, dst_ip, src_port, dst_port, protocol, action = rule
            
            # Create match criteria
            match = of.ofp_match()
            
            if protocol == 'ip':
                match.dl_type = 0x0800  # IPv4
            elif protocol == 'tcp':
                match.dl_type = 0x0800  # IPv4
                match.nw_proto = 6      # TCP
            elif protocol == 'udp':
                match.dl_type = 0x0800  # IPv4
                match.nw_proto = 17     # UDP
            elif protocol == 'icmp':
                match.dl_type = 0x0800  # IPv4
                match.nw_proto = 1      # ICMP
            
            if src_ip is not None:
                match.nw_src = IPAddr(src_ip)
            if dst_ip is not None:
                match.nw_dst = IPAddr(dst_ip)
            if src_port is not None:
                match.tp_src = src_port
            if dst_port is not None:
                match.tp_dst = dst_port
                
            # Create flow modification message
            msg = of.ofp_flow_mod()
            msg.match = match
            msg.command = action
            
            if action == of.OFPFC_DELETE:
                msg.priority = 65535  # High priority for deny rules
            else:
                msg.priority = 1      # Lower priority for allow rules
                
            # Send the rule to the switch
            event.connection.send(msg)
            
        # Add a default allow rule (lower priority than specific rules)
        msg = of.ofp_flow_mod()
        msg.priority = 0
        event.connection.send(msg)
        
    def add_rule(self, src_ip=None, dst_ip=None, src_port=None, dst_port=None, 
                protocol='ip', action=of.OFPFC_DELETE):
        """
        Add a new firewall rule dynamically.
        """
        rule = (src_ip, dst_ip, src_port, dst_port, protocol, action)
        self.firewall_rules.append(rule)
        
        # Install the rule on all connected switches
        for connection in core.openflow._connections.values():
            self._install_rule(connection, rule)
            
    def _install_rule(self, connection, rule):
        """
        Install a single rule on a specific switch connection.
        """
        src_ip, dst_ip, src_port, dst_port, protocol, action = rule
        
        match = of.ofp_match()
        
        if protocol == 'ip':
            match.dl_type = 0x0800
        elif protocol == 'tcp':
            match.dl_type = 0x0800
            match.nw_proto = 6
        elif protocol == 'udp':
            match.dl_type = 0x0800
            match.nw_proto = 17
        elif protocol == 'icmp':
            match.dl_type = 0x0800
            match.nw_proto = 1
            
        if src_ip is not None:
            match.nw_src = IPAddr(src_ip)
        if dst_ip is not None:
            match.nw_dst = IPAddr(dst_ip)
        if src_port is not None:
            match.tp_src = src_port
        if dst_port is not None:
            match.tp_dst = dst_port
            
        msg = of.ofp_flow_mod()
        msg.match = match
        msg.command = action
        msg.priority = 65535 if action == of.OFPFC_DELETE else 1
        
        connection.send(msg)

def launch():
    """
    Start the firewall controller.
    """
    core.registerNew(FirewallController)
    log.info("Firewall controller running")
