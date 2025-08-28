from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.addresses import IPAddr

log = core.getLogger()

class PingBlocker(object):
    def __init__(self):
        core.openflow.addListeners(self)
        # Timeout values (in seconds)
        self.normal_timeout = 60
        self.blocked_timeout = 5  # Shorter timeout for blocked flows
    
    def _handle_ConnectionUp(self, event):
        log.info("Switch %s has come up.", dpid_to_str(event.dpid))
    
    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return
        
        # Check if it's an ICMP packet
        if packet.type == packet.IP_TYPE:
            ip_packet = packet.payload
            if ip_packet.protocol == ip_packet.ICMP_PROTOCOL:
                # Get source and destination IPs
                src_ip = ip_packet.srcip
                dst_ip = ip_packet.dstip
                
                # Extract last octet to determine if host is even or odd
                src_last_octet = int(str(src_ip).split('.')[-1])
                dst_last_octet = int(str(dst_ip).split('.')[-1])
                
                # Check if one is even and the other is odd
                if (src_last_octet % 2) != (dst_last_octet % 2):
                    log.info("Blocking ping between %s (host %d) and %s (host %d)", 
                           src_ip, src_last_octet, dst_ip, dst_last_octet)
                    
                    # Install flow to block this ICMP traffic
                    msg = of.ofp_flow_mod()
                    msg.match = of.ofp_match.from_packet(packet)
                    msg.idle_timeout = self.blocked_timeout
                    msg.hard_timeout = self.blocked_timeout
                    event.connection.send(msg)
                    return
        
        # If we get here, allow the traffic with normal timeout
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = self.normal_timeout
        msg.hard_timeout = self.normal_timeout
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        msg.data = event.ofp
        event.connection.send(msg)

def launch():
    core.registerNew(PingBlocker)