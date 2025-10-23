from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
from pox.lib.packet.ipv4 import ipv4

log = core.getLogger()

class PingBlocker(object):
    def __init__(self):
        core.openflow.addListeners(self)
    
    def _handle_ConnectionUp(self, event):
        log.info("Switch %s has connected", event.dpid)
        
        # Clear existing flows
        msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
        event.connection.send(msg)
        
        # Add default rule to forward all non-ICMP traffic
        msg = of.ofp_flow_mod()
        msg.priority = 1
        msg.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))
        event.connection.send(msg)
        
        # Add default rule to send all unmatched packets to controller
        msg = of.ofp_flow_mod()
        msg.priority = 0
        msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        event.connection.send(msg)
    
    def _handle_PacketIn(self, event):
        packet = event.parsed
        
        # Only process IPv4 packets
        if not isinstance(packet.next, ipv4):
            # Forward non-IP traffic
            self._forward_packet(event)
            return
        
        ip_pkt = packet.next
        
        # Only process ICMP packets
        if ip_pkt.protocol != 1:
            # Forward non-ICMP packets
            self._forward_packet(event)
            return
        
        src_ip = ip_pkt.srcip
        dst_ip = ip_pkt.dstip
        
        # Check if one IP is even and other is odd
        src_last = src_ip.toInt() & 0xFF
        dst_last = dst_ip.toInt() & 0xFF
        src_even = (src_last % 2) == 0
        dst_even = (dst_last % 2) == 0
        
        if src_even != dst_even:
            # Block ICMP between even and odd hosts
            log.info("Blocking ICMP between %s and %s", src_ip, dst_ip)
            
            # Install flow to block in both directions
            self._install_block_flow(event.connection, src_ip, dst_ip)
            self._install_block_flow(event.connection, dst_ip, src_ip)
        else:
            # Allow ICMP between same parity hosts
            log.debug("Allowing ICMP between %s and %s", src_ip, dst_ip)
            
            # Install flow to allow
            self._install_allow_flow(event.connection, src_ip, dst_ip)
            
            # Forward the current packet
            self._forward_packet(event)
    
    def _forward_packet(self, event):
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=of.OFPP_ALL))
        event.connection.send(msg)
    
    def _install_block_flow(self, conn, src, dst):
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match(dl_type=0x0800, nw_proto=1, nw_src=src, nw_dst=dst)
        msg.priority = 100  # Higher than default
        conn.send(msg)
    
    def _install_allow_flow(self, conn, src, dst):
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match(dl_type=0x0800, nw_proto=1, nw_src=src, nw_dst=dst)
        msg.priority = 200  # Higher than block rule
        msg.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))
        conn.send(msg)

def launch():
    core.registerNew(PingBlocker)
    log.info("PingBlocker component loaded")
