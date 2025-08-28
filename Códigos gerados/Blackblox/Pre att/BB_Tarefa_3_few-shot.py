from pox.core import core
from pox.openflow import *
from pox.lib.packet import ipv4
from pox.lib.packet.ethernet import ethernet
from pox.lib.util import dpid_to_str
import socket

log = core.getLogger()

class Firewall (object):
    def __init__(self, connection):
        self.connection = connection
        self.connection.addListeners(self)
        self.mac_to_port = {}
        self.firewall_rules = []  # Store firewall rules

        # Initialize control rules
        self.initialize_firewall_rules()

    def initialize_firewall_rules(self):
        # Example rules to block traffic
        add_firewall_rules("127.0.0.1", "127.0.0.2")  # Block traffic from host A to host B
        add_firewall_rules("127.0.0.5", "127.0.0.2")  # Block traffic from host E to host B

    def _handle_packet_in(self, event):
        packet = event.parsed
        if not isinstance(packet, ethernet):
            return

        # Learn MAC addresses
        self.mac_to_port[packet.src] = event.port

        # Check if the packet is an IP packet
        if isinstance(packet.payload, ipv4):
            ip_packet = packet.payload
            src_ip = ip_packet.srcip
            dst_ip = ip_packet.dstip

            # Check if the packet matches any firewall rules
            if self.is_packet_blocked(src_ip, dst_ip):
                log.info(f"Dropping packet from {src_ip} to {dst_ip}")
                return  # Drop the packet

            # Forward the packet
            out_port = self.mac_to_port.get(packet.dst)
            if out_port is not None:
                self.connection.send(of.ofp_packet_out(data=event.ofp, actions=[of.ofp_action_output(port=out_port)]))
            else:
                log.warning(f"Unknown destination {packet.dst} - flooding")
                self.connection.send(of.ofp_packet_out(data=event.ofp, actions=[of.ofp_action_output(port=of.OFPP_FLOOD)]))

    def is_packet_blocked(self, src_ip, dst_ip):
        # Check if the packet matches any of the firewall rules
        for rule in self.firewall_rules:
            if rule['src_ip'] == src_ip and rule['dst_ip'] == dst_ip:
                return True
        return False

    def _handle_connection_up(self, event):
        log.info("Controller connected to switch %s", dpid_to_str(event.dpid))

def launch():
    def start_switch(event):
        Firewall(event.connection)

    core.openflow.addListeners(start_switch)