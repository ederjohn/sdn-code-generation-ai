from pox.core import core
from pox.openflow import *
from pox.lib.util import dpid_to_str
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4

log = core.getLogger()

class SimpleSwitch(object):
   def __init__(self, connection):
       self.connection = connection
       connection.addListeners(self)
       self.mac_to_port = {}

   def _handle_packet_in(self, event):
       packet = event.parsed
       if not packet:
           return

       # Learn the MAC address
       self.mac_to_port[packet.src] = event.port
       log.debug("Learned MAC %s on port %d", packet.src, event.port)

       # Forward the packet
       if packet.dst in self.mac_to_port:
           out_port = self.mac_to_port[packet.dst]
       else:
           out_port = of.OFPP_FLOOD

       # Create a flow entry
       msg = of.ofp_flow_mod()
       msg.match = of.ofp_match.from_packet(packet)
       msg.idle_timeout = 10
       msg.hard_timeout = 30
       msg.actions.append(of.ofp_action_output(port=out_port))
       self.connection.send(msg)

       # Send the packet out
       if out_port != of.OFPP_FLOOD:
           msg = of.ofp_packet_out()
           msg.data = event.ofp
           msg.actions.append(of.ofp_action_output(port=out_port))
           self.connection.send(msg)

   def _handle_connection_up(self):
       log.debug("Switch %s has connected", dpid_to_str(self.connection.dpid))

def launch():
   def start_switch(event):
       log.debug("Controlling %s", dpid_to_str(event.dpid))
       SimpleSwitch(event.connection)

   core.openflow.addListeners(start_switch)