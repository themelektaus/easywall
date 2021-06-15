"""TODO: Doku."""
from datetime import datetime
from logging import debug, info
from socket import gethostbyname

from easywall.acceptance import Acceptance
from easywall.config import Config
from easywall.iptables_handler import Chain, Iptables, Target
from easywall.rules_handler import RulesHandler
from easywall.utility import file_exists, rename_file, execute_os_command, get_ip_address


class Easywall():
    """
    the class contains the main functions for the easywall core
    such as applying a new configuration or listening on rule file changes
    """

    def __init__(self, config: Config) -> None:
        """TODO: Doku."""
        self.cfg = config
        self.iptables = Iptables(self.cfg)
        self.acceptance = Acceptance(self.cfg)
        self.ipv6 = self.cfg.get_value("IPV6", "enabled")
        self.filepath = ""
        self.filename = ""
        self.date = ""
        self.rules = RulesHandler()

    def apply(self) -> None:
        """TODO: Doku."""
        self.acceptance.start()
        self.rotate_backup()
        self.iptables.save()
        self.rules.backup_current_rules()
        self.rules.apply_new_rules()
        self.apply_iptables()
        self.acceptance.wait()

        if self.acceptance.status() == "not accepted":
            self.iptables.restore()
            self.rules.rollback_from_backup()
            info("Configuration was not accepted, rollback applied")
        else:
            self.restart_docker()
            self.postprocess_iptables()
            info("New configuration was applied.")

    def apply_iptables(self) -> None:
        """TODO: Doku."""
        # and reset iptables for clean setup
        self.iptables.reset()

        # drop intbound traffic and allow outbound traffic
        self.iptables.add_policy(Chain.INPUT, Target.DROP)
        self.iptables.add_policy(Chain.FORWARD, Target.DROP)
        self.iptables.add_policy(Chain.OUTPUT, Target.ACCEPT)

        self.iptables.add_chain("DOCKER-USER")
        self.iptables.add_custom(f"-A FORWARD -j DOCKER-USER")

        # accept traffic from loopback interface (localhost)
        self.iptables.add_append(Chain.INPUT, "-i lo -j ACCEPT")

        # accept established or related connections
        self.iptables.add_append(
            Chain.INPUT, "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")

        # Block remote packets claiming to be from a loopback address.
        self.iptables.add_append(Chain.INPUT, "-s 127.0.0.0/8 ! -i lo -j DROP", False, True)
        self.iptables.add_append(Chain.INPUT, "-s ::1/128 ! -i lo -j DROP", True)

        lan = self.cfg.get_value("NETINTERFACES", "lan")
        wan = self.cfg.get_value("NETINTERFACES", "wan")
        vpn = self.cfg.get_value("NETINTERFACES", "vpn")
        docker1 = self.cfg.get_value("NETINTERFACES", "docker1")
        docker2 = self.cfg.get_value("NETINTERFACES", "docker2")

        # Apply ICMP Rules
        self.apply_icmp()

        # forewarded ports
        self.apply_forwarding()
        
        # masquerade LAN and WAN
        self.apply_masquerade(lan)
        self.apply_masquerade(wan)
        
        # SSH Brute Force Prevention
        self.apply_ssh_brute()

        # ICMP Flood Prevention
        self.apply_icmp_flood()

        # drop invalid packets
        self.apply_invalid_packets_drop()

        # prevent port scans
        self.apply_port_scan_prevention()

        # Apply Broadcast, Multicast and Anycast Rules
        self.apply_cast()

        # Block IP-addresses from blacklist
        self.apply_blacklist()

        # accept IP-addresses from whitelist
        self.apply_whitelist()

        # accept TCP Ports
        self.apply_rules("tcp", docker1, docker2)

        # accept UDP Ports
        self.apply_rules("udp", docker1, docker2)

        # Apply Custom Rules
        self.apply_custom_rules()

        # log all dropped connections when enabled
        if self.cfg.get_value("IPTABLES", "log_blocked_connections"):
            self.iptables.add_append(
                Chain.INPUT,
                "-m limit --limit {}/minute -j LOG --log-prefix \"easywall blocked: \"".
                format(self.cfg.get_value("IPTABLES", "log_blocked_connections_log_limit")))

        # accept lan, vpn and reverse proxy (docker2)
        self.iptables.add_custom(f"-A DOCKER-USER -i {lan} -j ACCEPT")
        self.iptables.add_custom(f"-A DOCKER-USER -o {lan} -j ACCEPT")
        self.iptables.add_custom(f"-A DOCKER-USER -i {vpn} -j ACCEPT")
        self.iptables.add_custom(f"-A DOCKER-USER -o {vpn} -j ACCEPT")
        self.iptables.add_custom(f"-A DOCKER-USER -o {wan} -j ACCEPT")
        self.iptables.add_custom(f"-A DOCKER-USER -i {wan} -o {docker2} -j ACCEPT")
        self.iptables.add_custom(f"-A DOCKER-USER -i {wan} -j DROP")

        # reject all packages which not match the rules
        self.iptables.add_append(Chain.INPUT, "-j DROP")

    def apply_forwarding(self) -> None:
        """TODO: Doku."""
        for r in self.get_forward_rules():
            netinterface = r[0] if f"-i {r[0]}" else ""
            self.iptables.insert(
                table="nat",
                chain=Chain.PREROUTING,
                rule=f"{netinterface} -p {r[1]} --dport {r[2]} -j DNAT --to-destination {r[3]}:{r[4]}"
            )

    def apply_masquerade(self, netinterface: str) -> None:
        self.iptables.insert(table="nat", chain=Chain.POSTROUTING, rule=f"-o {netinterface} -j MASQUERADE")

    def apply_ssh_brute(self) -> None:
        """TODO: Doku."""
        if self.cfg.get_value("IPTABLES", "ssh_brute_force_prevention"):
            connection_limit = self.cfg.get_value(
                "IPTABLES", "ssh_brute_force_prevention_connection_limit")
            log_enable = self.cfg.get_value("IPTABLES", "ssh_brute_force_prevention_log")
            log_limit = self.cfg.get_value("IPTABLES", "ssh_brute_force_prevention_log_limit")
            log_prefix = "easywall ssh-brute blocked: "

            self.iptables.add_chain("SSHBRUTE")
            self.iptables.add_append(Chain.SSHBRUTE, "-m recent --name SSH --set")
            if log_enable:
                self.iptables.add_append(
                    Chain.SSHBRUTE,
                    "-m recent --name SSH --update --seconds 60 --hitcount " +
                    "{} -m limit --limit {}/minute -j LOG --log-prefix \"{}\"".format(
                        connection_limit, log_limit, log_prefix))
            self.iptables.add_append(
                Chain.SSHBRUTE,
                "-m recent --name SSH --update --seconds 60 --hitcount {} -j DROP".format(
                    connection_limit)
            )
            self.iptables.add_append(Chain.SSHBRUTE, "-j ACCEPT")

    def apply_invalid_packets_drop(self) -> None:
        """TODO: Doku."""
        if self.cfg.get_value("IPTABLES", "drop_invalid_packets"):
            log_enable = self.cfg.get_value("IPTABLES", "drop_invalid_packets_log")
            log_limit = self.cfg.get_value("IPTABLES", "drop_invalid_packets_log_limit")
            log_prefix = "easywall invalid packet blocked: "

            self.iptables.add_chain("INVALIDDROP")

            if log_enable:
                self.iptables.add_append(
                    Chain.INVALIDDROP,
                    "-m state --state INVALID -m limit --limit {}/m -j LOG --log-prefix \"{}\"".
                    format(log_limit, log_prefix))

            self.iptables.add_append(Chain.INVALIDDROP, "-m state --state INVALID -j DROP")

            self.iptables.add_append(
                Chain.INPUT, "-m state --state INVALID -j INVALIDDROP",
            )

    def apply_port_scan_prevention(self) -> None:
        """TODO: Doku."""
        if self.cfg.get_value("IPTABLES", "port_scan_prevention"):
            log_enable = self.cfg.get_value("IPTABLES", "port_scan_prevention_log")
            log_limit = self.cfg.get_value("IPTABLES", "port_scan_prevention_log_limit")
            log_prefix = "easywall port scan blocked: "

            self.iptables.add_chain("PORTSCAN")

            if log_enable:
                self.iptables.add_append(
                    Chain.PORTSCAN,
                    "-m limit --limit {}/m -j LOG --log-prefix \"{}\"".format(
                        log_limit, log_prefix)
                )

            self.iptables.add_append(Chain.PORTSCAN, "-j DROP")

            # nmap Null scans / no flags
            self.iptables.add_append(Chain.INPUT, "-p tcp --tcp-flags ALL NONE -j PORTSCAN")
            # nmap FIN stealth scan
            self.iptables.add_append(Chain.INPUT, "-p tcp --tcp-flags ALL FIN -j PORTSCAN")
            # SYN + FIN
            self.iptables.add_append(Chain.INPUT, "-p tcp --tcp-flags SYN,FIN SYN,FIN -j PORTSCAN")
            # SYN + RST
            self.iptables.add_append(Chain.INPUT, "-p tcp --tcp-flags SYN,RST SYN,RST -j PORTSCAN")
            # FIN + RST
            self.iptables.add_append(Chain.INPUT, "-p tcp --tcp-flags FIN,RST FIN,RST -j PORTSCAN")
            # FIN + URG + PSH
            self.iptables.add_append(Chain.INPUT, "-p tcp --tcp-flags ALL FIN,URG,PSH -j PORTSCAN")
            # XMAS
            self.iptables.add_append(
                Chain.INPUT, "-p tcp --tcp-flags ALL URG,ACK,PSH,RST,SYN,FIN -j PORTSCAN")
            # ALL
            self.iptables.add_append(Chain.INPUT, "-p tcp --tcp-flags ALL ALL -j PORTSCAN")
            # FIN/PSH/URG without ACK
            self.iptables.add_append(Chain.INPUT, "-p tcp --tcp-flags ACK,FIN FIN -j PORTSCAN")
            self.iptables.add_append(Chain.INPUT, "-p tcp --tcp-flags ACK,PSH PSH -j PORTSCAN")
            self.iptables.add_append(Chain.INPUT, "-p tcp --tcp-flags ACK,URG URG -j PORTSCAN")

    def apply_icmp_flood(self) -> None:
        """TODO: Doku."""
        if self.cfg.get_value("IPTABLES", "icmp_flood_prevention"):
            connection_limit = self.cfg.get_value(
                "IPTABLES", "icmp_flood_prevention_connection_limit")
            log_enable = self.cfg.get_value("IPTABLES", "icmp_flood_prevention_log")
            log_limit = self.cfg.get_value("IPTABLES", "icmp_flood_prevention_log_limit")
            log_prefix = "easywall icmp-flood blocked: "

            self.iptables.add_chain("ICMPFLOOD")
            self.iptables.add_append(Chain.ICMPFLOOD, "-m recent --set --name ICMP --rsource")
            if log_enable:
                self.iptables.add_append(
                    Chain.ICMPFLOOD, "-m recent --update --seconds 1 --hitcount " +
                    "{} --name ICMP --rsource --rttl -m limit ".format(connection_limit) +
                    "--limit {}/minute -j LOG --log-prefix \"{}\"".
                    format(log_limit, log_prefix))
            self.iptables.add_append(
                Chain.ICMPFLOOD,
                "-m recent --update --seconds 1 --hitcount {} --name ICMP --rsource --rttl -j DROP".
                format(connection_limit)
            )
            self.iptables.add_append(Chain.ICMPFLOOD, "-j ACCEPT")

            self.iptables.add_append(
                Chain.INPUT, "-p icmp --icmp-type 8  -m conntrack --ctstate NEW -j ICMPFLOOD",
                onlyv4=True
            )
            if self.ipv6:
                self.iptables.add_append(
                    Chain.INPUT, "-p ipv6-icmp --icmpv6-type 128 -j ICMPFLOOD",
                    onlyv6=True
                )

    def apply_icmp(self) -> None:
        """
        this function adds rules to iptables for incoming ICMP requests
        """
        icmpv4types = [0, 3, 11, 12]
        # 0 = echo-reply
        # 3 = destination-unreachable
        # 11 = time-exceeded
        # 12 = parameter problem

        icmpv6types = [1, 2, 3, 4, 128, 129]
        # 1 = destination-unreachable
        # 2 = packet-too-big
        # 3 = time-exceeded
        # 4 = parameter-problem
        # 128 = echo-request
        # 129 = echo-reply

        if self.cfg.get_value("IPV6", "icmp_allow_router_advertisement"):
            icmpv6types.append(133)
            icmpv6types.append(134)
            # 133 = router solicitation
            # 134 = router advertisement

        if self.cfg.get_value("IPV6", "icmp_allow_neighbor_advertisement"):
            icmpv6types.append(135)
            icmpv6types.append(136)
            # 135 = neighbor solicitation
            # 136 = neighbor advertisement

        for icmptype in icmpv4types:
            self.iptables.add_append(
                Chain.INPUT, "-p icmp --icmp-type {} -m conntrack --ctstate NEW -j ACCEPT".format(
                    icmptype), False, True)

        if self.ipv6 is True:
            for icmptype in icmpv6types:
                self.iptables.add_append(
                    Chain.INPUT, "-p ipv6-icmp --icmpv6-type {} -j ACCEPT".format(icmptype), True)

    def apply_cast(self) -> None:
        """TODO: Doku."""
        if self.cfg.get_value("IPTABLES", "drop_broadcast_packets"):
            self.iptables.add_append(
                Chain.INPUT,
                "-m addrtype --dst-type BROADCAST -j DROP",
                onlyv4=True
            )

        if self.cfg.get_value("IPTABLES", "drop_multicast_packets"):
            self.iptables.add_append(
                Chain.INPUT,
                "-m addrtype --dst-type MULTICAST -j DROP",
                onlyv4=True
            )
            self.iptables.add_append(
                Chain.INPUT,
                "-d 224.0.0.0/4 -j DROP",
                onlyv4=True
            )
            if self.ipv6 is True:
                self.iptables.add_append(
                    Chain.INPUT,
                    "-m addrtype --dst-type MULTICAST -j DROP",
                    onlyv6=True
                )

        if self.cfg.get_value("IPTABLES", "drop_anycast_packets"):
            self.iptables.add_append(
                Chain.INPUT,
                "-m addrtype --dst-type ANYCAST -j DROP",
                onlyv4=True
            )
            if self.ipv6 is True:
                self.iptables.add_append(
                    Chain.INPUT,
                    "-m addrtype --dst-type ANYCAST -j DROP",
                    onlyv6=True
                )

    def apply_blacklist(self) -> None:
        """
        this function adds rules to iptables which block incoming traffic
        from a list of ip addresses
        """
        for ipaddr in self.rules.get_current_rules("blacklist"):
            log_enable = self.cfg.get_value("IPTABLES", "log_blacklist_connections")
            log_limit = self.cfg.get_value("IPTABLES", "log_blacklist_connections_log_limit")
            log_prefix = "easywall blacklist blocked: "

            if ":" in ipaddr:
                if log_enable:
                    self.iptables.add_append(
                        chain=Chain.INPUT,
                        rule="-s {} -m limit --limit {}/m -j LOG --log-prefix \"{}\"".
                        format(ipaddr, log_limit, log_prefix),
                        onlyv6=True)
                self.iptables.add_append(
                    Chain.INPUT,
                    "-s {} -j DROP".format(ipaddr),
                    onlyv6=True
                )
            else:
                if log_enable:
                    self.iptables.add_append(
                        chain=Chain.INPUT,
                        rule="-s {} -m limit --limit {}/m -j LOG --log-prefix \"{}\"".
                        format(ipaddr, log_limit, log_prefix),
                        onlyv4=True)
                self.iptables.add_append(
                    Chain.INPUT,
                    "-s {} -j DROP".format(ipaddr),
                    onlyv4=True
                )

    def apply_whitelist(self) -> None:
        """
        this function adds rules to iptables which explicitly accepts a connection
        from this list ip addresses
        """
        for ipaddr in self.rules.get_current_rules("whitelist"):
            if ":" in ipaddr:
                self.iptables.add_append(Chain.INPUT, "-s {} -j ACCEPT".format(ipaddr), onlyv6=True)
            else:
                self.iptables.add_append(Chain.INPUT, "-s {} -j ACCEPT".format(ipaddr), onlyv4=True)

    def apply_rules(self, ruletype: str, docker1: str, docker2: str) -> None:
        """
        this function adds rules for incoming tcp and udp connections to iptables
        which accept a connection to this list of ports

        [INFO] the function also processes port ranges split by ":" separator.
        """
        for port in self.rules.get_current_rules(ruletype):
            jail = "ACCEPT"
            if port["ssh"]:
                jail = "SSHBRUTE"
            
            if ":" in port["port"]:
                rule = f"-p {ruletype} --match multiport --dports {port['port']}"
            else:
                rule = f"-p {ruletype} --dport {port['port']}"

            if port["allowedhost"]:
                host = gethostbyname(port["allowedhost"])
                rule = f"-s {host} {rule}"
            
            if port["netinterface"]:
                netinterface = self.cfg.get_value("NETINTERFACES", port["netinterface"]);
                self.apply_rules_add(netinterface, rule, jail)
                self.apply_rules_add(docker1, rule, jail)
                self.apply_rules_add(docker2, rule, jail)
                self.iptables.add_custom(f"-A DOCKER-USER -i {netinterface} {rule} -j {jail}")
                self.iptables.add_custom(f"-A DOCKER-USER -i {docker1} {rule} -j {jail}")
                self.iptables.add_custom(f"-A DOCKER-USER -i {docker2} {rule} -j {jail}")
            else:
                self.apply_rules_add(None, rule, jail)
                self.iptables.add_custom(f"-A DOCKER-USER {rule} -j {jail}")

    def apply_rules_add(self, interface: str, rule: str, jail: str) -> None:
        if interface:
            rule = f"-i {interface} {rule}"
        self.iptables.add_append(
            chain=Chain.INPUT,
            rule=f"{rule} -m conntrack --ctstate NEW -j {jail}"
        )

    def apply_custom_rules(self) -> None:
        """TODO: Doku."""
        for rule in self.rules.get_current_rules("custom"):
            if rule != "":
                if not rule.startswith("#"):
                    self.iptables.add_custom(rule=rule)

    def restart_docker(self) -> None:
        execute_os_command("service docker restart")

    def postprocess_iptables(self) -> None:
        lan = self.cfg.get_value("NETINTERFACES", "lan")
        wan = self.cfg.get_value("NETINTERFACES", "wan")
        lan_ip = get_ip_address(lan)
        wan_ip = get_ip_address(wan)
        self.iptables.add_custom("-I DOCKER-USER -s 10.0.0.0/24 -j ACCEPT")
        self.iptables.add_custom("-I DOCKER-USER -s 10.8.0.0/24 -j ACCEPT")
        
        for r in self.get_forward_rules():
            netinterface = r[0] if f"-i {r[0]}" else ""
            self.iptables.add_custom(f"-I DOCKER-USER {netinterface} -p {r[1]} -d {r[3]} --dport {r[4]} -j DROP")
            for port in self.rules.get_current_rules(r[1]):
                if port["port"] == r[2]:
                    netinterface = "-i {}".format(self.cfg.get_value("NETINTERFACES", port["netinterface"])) if port["netinterface"] else ""
                    allowedhost = host = "-s {}".format(gethostbyname(port["allowedhost"])) if port["allowedhost"] else ""
                    self.iptables.add_custom(f"-I DOCKER-USER {netinterface} -p {r[1]} -d {r[3]} --dport {r[4]} {allowedhost} -j ACCEPT")
        
        self.iptables.add_custom("-I FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
        self.iptables.add_custom(f"-t nat -A POSTROUTING -s 10.0.0.0/24 ! -d 10.0.0.0/24 -j SNAT --to-source {lan_ip}")
        self.iptables.add_custom(f"-t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to-source {wan_ip}")

    def get_forward_rules(self):
        for ipaddr in self.rules.get_current_rules("forwarding"):
            netinterface = self.cfg.get_value("NETINTERFACES", ipaddr.split(":")[0])
            proto = ipaddr.split(":")[1]
            source = ipaddr.split(":")[2]
            dest_ip = gethostbyname(ipaddr.split(":")[3])
            dest = ipaddr.split(":")[4]
            yield (netinterface, proto, source, dest_ip, dest)

    def rotate_backup(self) -> None:
        """TODO: Doku."""
        self.filepath = "backup"
        self.filename = "iptables_v4_backup"
        self.date = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

        self.rename_backup_file()
        if self.ipv6 is True:
            self.filename = "iptables_v6_backup"
            self.rename_backup_file()

        debug("backup file rotated in folder {} \n prefix added: {}".format(
            self.filepath, self.date))

    def rename_backup_file(self) -> None:
        """TODO: Doku."""
        old_filename = "{}/{}".format(self.filepath, self.filename)
        new_filename = "{}/{}_{}".format(self.filepath, self.date, self.filename)
        if file_exists(old_filename):
            rename_file(old_filename, new_filename)
