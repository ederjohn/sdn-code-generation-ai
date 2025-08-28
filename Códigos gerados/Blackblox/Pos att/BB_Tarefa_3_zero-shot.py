from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
import csv

log = core.getLogger()
policyFile = "firewall-policies.csv"

def _handle_ConnectionUp(event):
    log.info("Connection from %s", dpidToStr(event.dpid))
    install_firewall_rules(event.connection)

def install_firewall_rules(connection):
    with open(policyFile, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            src_mac = row['mac_0']
            dst_mac = row['mac_1']
            # Create flow rule to block traffic between src_mac and dst_mac
            msg = of.ofp_flow_mod()
            msg.match.dl_src = src_mac
            msg.match.dl_dst = dst_mac
            msg.priority = 100
            msg.actions.append(of.ofp_action_output(port=of.OFPP_DROP))
            connection.send(msg)
            log.info("Installed rule: Block %s to %s", src_mac, dst_mac)

def launch():
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    log.info("Layer 3 Firewall running.")
