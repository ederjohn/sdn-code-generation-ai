# simple_controller.py

from pox.core import core
from pox.openflow import *
from pox.lib.revent import *
from pox.lib.util import dpid_to_str

log = core.getLogger()

class SimpleController(EventMixin):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

    def _handle_packet_in(self, event):
        # Log the packet
        log.info("Packet in from %s: %s", dpid_to_str(event.dpid), event.packet)

        # Forward the packet to all ports except the one it came from
        for port in self.connection.ports:
            if port != event.port:
                self.connection.send(event.ofp)

    def _handle_connection_up(self, event):
        log.info("Switch %s has connected.", dpid_to_str(event.dpid))

        # Install a flow to handle packet_in events
        self.connection.addListeners(self)

    def _handle_connection_down(self, event):
        log.info("Switch %s has disconnected.", dpid_to_str(event.dpid))

    def _handle_switch_features(self, event):
        log.info("Switch %s features received.", dpid_to_str(event.dpid))

def launch():
    def start_switch(event):
        log.info("Controlling switch %s", dpid_to_str(event.dpid))
        SimpleController(event.connection)

    core.openflow.addListeners(start_switch)