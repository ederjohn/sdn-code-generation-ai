from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

def is_even(ip):
    """Check if the last octet of an IP address is even."""
    try:
        last_octet = int(ip.split(".")[-1])
        return last_octet % 2 == 0
    except ValueError:
        return False

def _handle_PacketIn(event):
    packet = event.parsed
    if not packet.parsed:
        log.warning("Ignoring incomplete packet")
        return
    
    ip_packet = packet.find('ipv4')
    icmp_packet = packet.find('icmp')
    
    if ip_packet and icmp_packet:
        src_ip = ip_packet.srcip
        dst_ip = ip_packet.dstip
        
        if is_even(str(src_ip)) != is_even(str(dst_ip)):
            log.info(f"Blocking ICMP Ping from {src_ip} to {dst_ip}")
            msg = of.ofp_flow_mod()
            msg.match.dl_type = 0x0800  # IPv4
            msg.match.nw_proto = 1  # ICMP
            msg.match.nw_src = src_ip
            msg.match.nw_dst = dst_ip
            event.connection.send(msg)
            return
    
    # Default behavior: Forward packet normally
    msg = of.ofp_packet_out()
    msg.data = event.ofp
    msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
    event.connection.send(msg)

def launch():
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    log.info("Ping-blocking POX Controller is running")