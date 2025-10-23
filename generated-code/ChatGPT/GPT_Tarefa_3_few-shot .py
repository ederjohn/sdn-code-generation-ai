from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

# Firewall class
class SimpleFirewall(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)
        self.rules = []  # (src_ip, dst_ip)

        # Initialize with some control rules
        self.initialize_rules()

    def initialize_rules(self):
        # Default rule: block traffic from 10.0.0.1 to 10.0.0.2
        self.add_rule("10.0.0.1", "10.0.0.2")

    def add_rule(self, src_ip, dst_ip):
        """Add a firewall rule to block traffic from src_ip to dst_ip"""
        self.rules.append((src_ip, dst_ip))
        log.info("Rule added to block traffic from %s to %s", src_ip, dst_ip)

        # Create flow mod to drop matching packets
        msg = of.ofp_flow_mod()
        msg.match.dl_type = 0x0800  # IP packets
        msg.match.nw_src = src_ip
        msg.match.nw_dst = dst_ip
        msg.actions = []  # No actions = drop
        self.connection.send(msg)

    def _handle_PacketIn(self, event):
        """Handle incoming packets"""
        packet = event.parsed
        ip = packet.find('ipv4')

        if ip is None:
            # If not IP packet, flood
            msg = of.ofp_packet_out()
            msg.data = event.ofp
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            self.connection.send(msg)
            return

        # Check against firewall rules
        for rule in self.rules:
            if ip.src.toStr() == rule[0] and ip.dst.toStr() == rule[1]:
                log.info("Blocked packet from %s to %s", rule[0], rule[1])
                return  # Drop the packet (do nothing)

        # If no rule matches, flood
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

# Listen for new switch connections
def launch():
    def start_firewall(event):
        log.info("Firewall connected to switch %s", event.connection)
        SimpleFirewall(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_firewall)
