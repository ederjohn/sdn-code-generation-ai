#!/usr/bin/env python

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.packet import *
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr

log = core.getLogger()

class FirewallRule(object):
    """
    A simple firewall rule container class
    """
    def __init__(self, dl_type=0, nw_src=None, nw_dst=None, 
                 nw_proto=0, tp_src=0, tp_dst=0, priority=0):
        self.dl_type = dl_type      # Ethernet type (e.g., IPV4)
        self.nw_src = nw_src        # Source IP address (can be wildcarded)
        self.nw_dst = nw_dst        # Destination IP address
        self.nw_proto = nw_proto    # IP protocol (e.g., TCP, UDP, ICMP)
        self.tp_src = tp_src        # Transport layer source port
        self.tp_dst = tp_dst        # Transport layer destination port
        self.priority = priority    # Rule priority (higher = checked first)

    def __str__(self):
        return (f"FirewallRule(dl_type={self.dl_type}, nw_src={self.nw_src}, "
                f"nw_dst={self.nw_dst}, nw_proto={self.nw_proto}, "
                f"tp_src={self.tp_src}, tp_dst={self.tp_dst}, "
                f"priority={self.priority})")

class Layer3Firewall(EventMixin):
    """
    A simple Layer 3 firewall implemented as a POX controller component
    """
    def __init__(self):
        self.listenTo(core.openflow)
        self.rules = []
        
        # Initialize with some default rules
        self._initialize_default_rules()
        
    def _initialize_default_rules(self):
        """
        Initialize the firewall with some default rules
        """
        # Allow ARP (required for normal operation)
        self.add_rule(dl_type=pkt.ethernet.ARP_TYPE, priority=100)
        
        # Allow ICMP (ping)
        self.add_rule(dl_type=pkt.ethernet.IP_TYPE, 
                     nw_proto=pkt.ipv4.ICMP_PROTOCOL, priority=90)
        
        # Example: Block all traffic from 10.0.0.1 to 10.0.0.2
        # self.add_rule(dl_type=pkt.ethernet.IP_TYPE, 
        #              nw_src="10.0.0.1", nw_dst="10.0.0.2", 
        #              priority=50, action="drop")
        
        # Default deny rule (lowest priority)
        self.add_rule(priority=0, action="drop")
    
    def add_rule(self, dl_type=0, nw_src=None, nw_dst=None, nw_proto=0, 
                 tp_src=0, tp_dst=0, priority=10, action="allow"):
        """
        Add a new firewall rule
        """
        rule = FirewallRule(dl_type=dl_type, nw_src=nw_src, nw_dst=nw_dst,
                          nw_proto=nw_proto, tp_src=tp_src, tp_dst=tp_dst,
                          priority=priority)
        
        # Insert rule in priority order (higher priorities first)
        for i, r in enumerate(self.rules):
            if r.priority < priority:
                self.rules.insert(i, rule)
                break
        else:
            self.rules.append(rule)
        
        log.info(f"Added firewall rule: {rule}")
        
        # Install the rule on all connected switches
        self._install_rule_on_switches(rule, action)
    
    def _install_rule_on_switches(self, rule, action):
        """
        Install a firewall rule on all connected switches
        """
        for connection in core.openflow._connections.values():
            self._install_rule(connection, rule, action)
    
    def _install_rule(self, connection, rule, action):
        """
        Install a firewall rule on a specific switch
        """
        msg = of.ofp_flow_mod()
        
        # Match criteria
        if rule.dl_type:
            msg.match.dl_type = rule.dl_type
        
        if rule.dl_type == pkt.ethernet.IP_TYPE:
            if rule.nw_src:
                msg.match.nw_src = IPAddr(rule.nw_src)
            if rule.nw_dst:
                msg.match.nw_dst = IPAddr(rule.nw_dst)
            if rule.nw_proto:
                msg.match.nw_proto = rule.nw_proto
                if rule.nw_proto in (pkt.ipv4.TCP_PROTOCOL, pkt.ipv4.UDP_PROTOCOL):
                    if rule.tp_src:
                        msg.match.tp_src = rule.tp_src
                    if rule.tp_dst:
                        msg.match.tp_dst = rule.tp_dst
        
        # Action
        if action == "allow":
            # For allowed traffic, just forward to normal processing
            msg.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))
        else:
            # For denied traffic, no actions means drop
            pass
        
        msg.priority = rule.priority
        msg.hard_timeout = 0  # Never expire
        msg.idle_timeout = 0  # Never expire
        
        connection.send(msg)
    
    def _handle_ConnectionUp(self, event):
        """
        Handle new switch connections by installing all existing rules
        """
        log.info(f"Firewall rules installed on switch {dpidToStr(event.dpid)}")
        for rule in self.rules:
            action = "allow" if rule.priority > 0 else "drop"
            self._install_rule(event.connection, rule, action)
    
    def _handle_PacketIn(self, event):
        """
        Handle packets that don't match any flow rule
        """
        packet = event.parsed
        
        # For learning purposes, we can log unmatched packets
        if not packet.parsed:
            log.debug("Incomplete packet")
            return
        
        if packet.type == packet.IP_TYPE:
            ip_packet = packet.payload
            log.debug(f"Unmatched IP packet: {ip_packet.srcip} -> {ip_packet.dstip} "
                     f"proto: {ip_packet.protocol}")
        elif packet.type == packet.ARP_TYPE:
            log.debug("Unmatched ARP packet")
        else:
            log.debug(f"Unmatched packet of type {packet.type}")

def launch():
    """
    Starts the firewall component
    """
    core.registerNew(Layer3Firewall)
    log.info("Layer 3 Firewall controller running")