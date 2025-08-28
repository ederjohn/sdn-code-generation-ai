from pox.core import core
from pox.lib.packet import ethernet, ipv4
from pox.lib.addresses import EthAddr
import pox.openflow.libopenflow_01 as of
import socket

log = core.getLogger()

# Dictionary to map MAC addresses to ports for each switch connection
mac_to_port = {}

# Set of firewall rules: tuples of (src_ip (str), dst_ip (str), protocol (str))
firewall_rules = set()

def add_firewall_rule(src_ip, dst_ip, protocol="tcp"):
    """
    Add a firewall rule to block traffic matching src_ip, dst_ip and protocol.
    Sends the rule to the POX controller via socket to port 6633 (example).
    """
    global firewall_rules
    rule_tuple = (src_ip, dst_ip, protocol)
    if rule_tuple not in firewall_rules:
        firewall_rules.add(rule_tuple)
        rule = f"{src_ip} {dst_ip} {protocol}\n"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(("127.0.0.1", 6633))  # Assuming POX listens on this port
                s.sendall(rule.encode())
            log.info(f"Rule added: Block {protocol} from {src_ip} to {dst_ip}")
        except Exception as e:
            log.error(f"Failed to send firewall rule: {e}")

def _handle_PacketIn(event):
    packet = event.parsed
    dpid = event.connection.dpid

    if dpid not in mac_to_port:
        mac_to_port[dpid] = {}

    # Learn the source MAC to port mapping
    src_mac = packet.src
    in_port = event.port
    mac_to_port[dpid][src_mac] = in_port

    # Process only IP packets (layer 3)
    if packet.type == ethernet.IP_TYPE:
        ip_packet = packet.payload
        src_ip = str(ip_packet.srcip)
        dst_ip = str(ip_packet.dstip)

        # Determine protocol type string
        proto_int = ip_packet.protocol
        if proto_int == ipv4.TCP_PROTOCOL:
            protocol = "tcp"
        elif proto_int == ipv4.UDP_PROTOCOL:
            protocol = "udp"
        elif proto_int == ipv4.ICMP_PROTOCOL:
            protocol = "icmp"
        else:
            # Other protocols are allowed by default
            protocol = None

        # If protocol matches and firewall rule exists, drop the packet
        if protocol and (src_ip, dst_ip, protocol) in firewall_rules:
            # Drop packet by not installing flow and sending no action
            log.info(f"Dropping {protocol} packet from {src_ip} to {dst_ip}")
            msg = of.ofp_packet_out()
            msg.data = event.ofp  # send the original packet_out
            msg.in_port = in_port
            # No action => drop
            event.connection.send(msg)
            return

    # Forwarding logic
    dst_mac = packet.dst
    out_port = None

    if dst_mac.is_multicast:
        # Flood multicast traffic
        out_port = of.OFPP_FLOOD
    else:
        out_port = mac_to_port[dpid].get(dst_mac)

    msg = of.ofp_packet_out()
    msg.data = event.ofp
    msg.in_port = in_port

    if out_port is not None:
        msg.actions.append(of.ofp_action_output(port=out_port))
        log.info(f"Forwarding packet from {src_mac} to {dst_mac} on port {out_port}")
    else:
        # Destination not known: flood
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        log.info(f"Flooding packet from {src_mac} to {dst_mac} - destination unknown")

    event.connection.send(msg)

def launch():
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    log.info("Layer3 Firewall POX component started")

