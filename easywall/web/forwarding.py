"""TODO: Doku."""
from flask import render_template, request
from easywall.web.login import login
from easywall.web.webutils import Webutils
from easywall.rules_handler import RulesHandler


def forwarding(saved: bool = False) -> str:
    """TODO: Doku."""
    utils = Webutils()
    rules = RulesHandler()
    if utils.check_login(request):
        payload = utils.get_default_payload("Port Forwarding")
        payload.lead = """
            This page allows you to forward ports from the local system to another host.<br>
            <b>Warning: The forwarding rule is dropped if the local port is not open!</b><br>
            <br>
        """
        payload.forwardings = rules.get_rules_for_web("forwarding")
        payload.custom = False
        if rules.diff_new_current("forwarding"):
            payload.custom = True
        payload.saved = saved
        return render_template('forwarding.html', vars=payload)
    return login()


def forwarding_save() -> str:
    """TODO: Doku."""
    utils = Webutils()
    if utils.check_login(request) is True:
        action = "add"
        ruletype = "tcp"
        netinterface = ""
        source_port = ""
        dest_ip = ""
        dest_port = ""

        for key, value in request.form.items():
            if key == "remove":
                action = "remove"
                ruletype = value
            elif key == "tcpudp":
                action = "add"
                ruletype = value
            elif key == "netinterface":
                netinterface = value
            elif key == "source-port":
                source_port = str(value)
            elif key == "destination-ip":
                dest_ip = str(value)
            elif key == "destination-port":
                dest_port = str(value)
            else:
                if ":" in key:
                    netinterface = key.split(":")[0]
                    ruletype = key.split(":")[1]
                    source_port = key.split(":")[2]
                    dest_ip = key.split(":")[3]
                    dest_port = key.split(":")[4]

        if action == "add":
            add_forwarding(source_port, dest_ip, dest_port, ruletype, netinterface)
        else:
            remove_forwarding(source_port, dest_ip, dest_port, ruletype, netinterface)

        return forwarding(True)
    return login()


def add_forwarding(source_port: str, dest_ip: str, dest_port: str, ruletype: str, netinterface: str) -> None:
    """TODO: Doku."""
    rules = RulesHandler()
    rulelist = rules.get_rules_for_web("forwarding")
    rulelist.append("{}:{}:{}:{}:{}".format(netinterface, ruletype, source_port, dest_ip, dest_port))
    rules.save_new_rules("forwarding", rulelist)


def remove_forwarding(source_port: str, dest_ip: str, dest_port: str, ruletype: str, netinterface: str) -> None:
    """TODO: Doku."""
    rules = RulesHandler()
    rulelist = rules.get_rules_for_web("forwarding")
    rulelist.remove("{}:{}:{}:{}:{}".format(netinterface, ruletype, source_port, dest_ip, dest_port))
    rules.save_new_rules("forwarding", rulelist)
