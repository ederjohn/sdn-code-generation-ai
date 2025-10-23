#!/usr/bin/env python

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr

log = core.getLogger()

class LearningSwitch (EventMixin):
    def __init__ (self, connection):
        self.connection = connection
        self.macToPort = {}  # Maps MAC addresses to switch ports
        connection.addListeners(self)
        
    def _handle_PacketIn (self, event):
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return
            
        # Learn the source MAC and port
        self.macToPort[packet.src] = event.port
        
        if packet.dst.is_multicast:
            # Flood multicast packets
            self.flood_packet(event)
        else:
            if packet.dst in self.macToPort:
                # Send packet out the known port
                log.debug("Installing flow for %s -> %s" % (packet.src, packet.dst))
                port = self.macToPort[packet.dst]
                self.install_flow(packet.src, packet.dst, event.port, port)
                self.send_packet(event, port)
            else:
                # Flood if destination unknown
                self.flood_packet(event)
    
    def flood_packet (self, event):
        """
        Flood the packet to all ports except the input port
        """
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
        msg.in_port = event.port
        self.connection.send(msg)
    
    def send_packet (self, event, out_port):
        """
        Send the packet out the specified port
        """
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port = out_port))
        msg.in_port = event.port
        self.connection.send(msg)
    
    def install_flow (self, src, dst, in_port, out_port):
        """
        Install a flow entry in the switch
        """
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match()
        msg.match.dl_src = src
        msg.match.dl_dst = dst
        
        msg.actions.append(of.ofp_action_output(port = out_port))
        msg.idle_timeout = 10  # Timeout in seconds
        msg.hard_timeout = 30  # Max time before removal
        
        self.connection.send(msg)

class SDNController (object):
    def __init__ (self):
        core.openflow.addListeners(self)
    
    def _handle_ConnectionUp (self, event):
        log.info("Switch %s has connected", dpidToStr(event.dpid))
        LearningSwitch(event.connection)

def launch ():
    """
    Starts the SDN controller
    """
    core.registerNew(SDNController)
    log.info("SDN Controller started")