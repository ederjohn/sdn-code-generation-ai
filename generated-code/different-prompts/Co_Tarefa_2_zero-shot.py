from pox.core import core

import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class PingBlocker(object):
    def __init__(self):
        core.openflow.addListeners(self)

    def _handle_ConnectionUp(self, event):
        log.info("Switch %s has connected", event.dpid)

        # Create a flow rule to block ICMP (ping) between even and odd hosts
        for src in range(1, 256):
            for dst in range(1, 256):
                if (src % 2 == 0 and dst % 2 != 0) or (src % 2 != 0 and dst % 2 == 0):
                    match = of.ofp_match()
                    match.dl_type = 0x0800  # IPv4
                    match.nw_proto = 1     # ICMP
                    match.nw_src = f"10.0.0.{src}"
                    match.nw_dst = f"10.0.0.{dst}"

                    flow_mod = of.ofp_flow_mod()
                    flow_mod.match = match
                    flow_mod.priority = 100
                    flow_mod.actions = []  # Drop packet

                    event.connection.send(flow_mod)
                    log.info("Blocking ICMP between %s and %s", match.nw_src, match.nw_dst)

def launch():
    log.info("Starting PingBlocker module")
    core.registerNew(PingBlocker)