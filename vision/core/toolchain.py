"""Toolchain registry.

Vision orchestrates other people's tools rather than reimplementing them. This
module knows what those tools are, how to detect them, and how to install them
on whatever the operator happens to be running.

Install methods are ordered by preference per platform. `apt` wins on Kali
because the packages are maintained and signed; `go`/`pipx` are used where the
distro package is absent or hopelessly stale (ProjectDiscovery tooling moves
weekly and the Debian packages lag by months).

Nothing here installs automatically. `vision doctor` reports; `vision setup`
installs only what the operator confirms.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Phase(str, Enum):
    DISCOVERY = "discovery"
    ENUM = "enumeration"
    VULN = "vulnerability"
    EXPLOIT = "exploitation"
    CREDS = "credentials"
    POSTEX = "post-exploitation"
    TRAFFIC = "traffic"


class Need(str, Enum):
    CORE = "core"          # vision is crippled without it
    STANDARD = "standard"  # expected in a normal engagement
    OPTIONAL = "optional"  # nice to have / situational


@dataclass
class Tool:
    name: str
    binary: str
    phase: Phase
    purpose: str
    need: Need = Need.STANDARD
    apt: Optional[str] = None
    pipx: Optional[str] = None
    pip: Optional[str] = None
    go: Optional[str] = None
    gem: Optional[str] = None
    cargo: Optional[str] = None
    brew: Optional[str] = None
    manual: Optional[str] = None       # URL/instructions when no package exists
    version_flag: str = "--version"
    version_argv: list[str] = field(default_factory=list)  # overrides version_flag
    version_re: str = r"(\d+\.\d+(?:\.\d+)?)"
    alt_binaries: list[str] = field(default_factory=list)
    notes: str = ""

    # ---- detection ----

    def which(self) -> Optional[str]:
        for b in [self.binary, *self.alt_binaries]:
            p = shutil.which(b)
            if p:
                return p
        return None

    @property
    def installed(self) -> bool:
        return self.which() is not None

    def version(self, timeout: int = 8) -> Optional[str]:
        path = self.which()
        if not path:
            return None
        attempts = [self.version_argv] if self.version_argv else []
        attempts += [[f] for f in (self.version_flag, "-V", "-v", "--help")]
        for argv in attempts:
            try:
                r = subprocess.run([path, *argv], capture_output=True,
                                   text=True, timeout=timeout)
            except (subprocess.TimeoutExpired, OSError):
                continue
            m = re.search(self.version_re, (r.stdout or "") + (r.stderr or ""))
            if m:
                return m.group(1)
        return "installed"

    # ---- install planning ----

    def install_plan(self, pm: str, is_root: bool = False) -> Optional[list[str]]:
        """Returns the argv to install this tool with the given package
        manager, or None if unsupported by that manager.

        sudo is prefixed only when we actually need it — prefixing it as root,
        or on a box without sudo installed, just makes the install fail."""
        needs_sudo = not is_root and shutil.which("sudo") is not None
        pre = ["sudo"] if needs_sudo else []
        table = {
            "apt": (pre + ["apt-get", "install", "-y", self.apt or ""], self.apt),
            "pipx": (["pipx", "install", self.pipx or ""], self.pipx),
            "pip": ([_pip(), "install", "--user", self.pip or ""], self.pip),
            "go": (["go", "install", "-v", self.go or ""], self.go),
            "gem": (pre + ["gem", "install", self.gem or ""], self.gem),
            "cargo": (["cargo", "install", self.cargo or ""], self.cargo),
            "brew": (["brew", "install", self.brew or ""], self.brew),
        }
        argv, spec = table.get(pm, (None, None))
        return argv if spec else None


def _pip() -> str:
    return "pip3" if shutil.which("pip3") else "pip"


# ---------------------------------------------------------------------------
# The registry
# ---------------------------------------------------------------------------

# Kali ships curated metapackages. On Kali, one metapackage per phase is far
# faster and more reliable than 40 individual apt calls, and it pulls in the
# wordlists and config that the standalone packages leave out.
KALI_METAPACKAGES: dict[str, tuple[str, str]] = {
    "discovery": ("kali-tools-information-gathering",
                  "nmap, masscan, amass, dnsx, netdiscover, arp-scan, fping"),
    "enumeration": ("kali-tools-information-gathering",
                    "enum4linux, smbmap, smbclient, snmp, ldap-utils, nbtscan"),
    "vulnerability": ("kali-tools-vulnerability",
                      "nuclei, nikto, sslscan, testssl.sh"),
    "exploitation": ("kali-tools-exploitation",
                     "metasploit-framework, exploitdb, impacket, evil-winrm"),
    "credentials": ("kali-tools-passwords",
                    "hydra, medusa, ncrack, hashcat, john, wordlists"),
    "post-exploitation": ("kali-tools-post-exploitation",
                          "chisel, proxychains, sshuttle, socat"),
    "traffic": ("kali-tools-sniffing-spoofing",
                "tcpdump, tshark, bettercap, responder, scapy"),
}


def kali_plan(phases: list[str] | None = None, is_root: bool = False
              ) -> list[tuple[str, str, list[str]]]:
    """Deduplicated metapackage install plan for Kali.

    Returns (metapackage, what_it_covers, argv). Information-gathering covers
    two phases, so dedupe or the operator sees it twice."""
    pre = [] if is_root or not shutil.which("sudo") else ["sudo"]
    seen, out = set(), []
    for phase, (pkg, covers) in KALI_METAPACKAGES.items():
        if phases and phase not in phases:
            continue
        if pkg in seen:
            continue
        seen.add(pkg)
        out.append((pkg, covers, pre + ["apt-get", "install", "-y", pkg]))
    return out


TOOLS: list[Tool] = [

    # ---------------- Discovery / Recon ----------------
    Tool("nmap", "nmap", Phase.DISCOVERY, "Port, service and OS discovery; NSE scripts",
         Need.CORE, apt="nmap", brew="nmap", version_flag="--version",
         notes="The backbone. Vision parses its XML directly."),
    Tool("masscan", "masscan", Phase.DISCOVERY, "Very fast SYN sweeps over large ranges",
         Need.STANDARD, apt="masscan", brew="masscan",
         notes="Feed results into nmap for service detection."),
    Tool("rustscan", "rustscan", Phase.DISCOVERY, "Fast port sweep that pipes into nmap",
         Need.OPTIONAL, cargo="rustscan", brew="rustscan",
         manual="cargo install rustscan (needs Rust: https://rustup.rs), "
                "or download a release from https://github.com/RustScan/RustScan/releases"),
    Tool("naabu", "naabu", Phase.DISCOVERY, "ProjectDiscovery port scanner",
         Need.OPTIONAL, go="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
    Tool("fping", "fping", Phase.DISCOVERY, "Fast ICMP host liveness sweeps",
         Need.STANDARD, apt="fping", brew="fping"),
    Tool("arp-scan", "arp-scan", Phase.DISCOVERY, "Layer-2 host discovery on the local segment",
         Need.STANDARD, apt="arp-scan",
         notes="Finds hosts that drop ICMP. Local segment only."),
    Tool("netdiscover", "netdiscover", Phase.DISCOVERY, "Passive/active ARP reconnaissance",
         Need.OPTIONAL, apt="netdiscover"),
    Tool("dnsx", "dnsx", Phase.DISCOVERY, "Fast DNS resolution and probing",
         Need.OPTIONAL, go="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
    Tool("subfinder", "subfinder", Phase.DISCOVERY, "Passive subdomain enumeration",
         Need.OPTIONAL, go="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    Tool("amass", "amass", Phase.DISCOVERY, "In-depth attack surface / DNS mapping",
         Need.OPTIONAL, apt="amass", go="github.com/owasp-amass/amass/v4/...@master"),

    # ---------------- Service Enumeration ----------------
    Tool("enum4linux-ng", "enum4linux-ng", Phase.ENUM, "SMB/AD enumeration (modern rewrite)",
         Need.STANDARD, pipx="enum4linux-ng", apt="enum4linux-ng",
         alt_binaries=["enum4linux"]),
    Tool("smbmap", "smbmap", Phase.ENUM, "SMB share enumeration and permissions",
         Need.STANDARD, apt="smbmap", pipx="smbmap"),
    Tool("smbclient", "smbclient", Phase.ENUM, "Interactive SMB share access",
         Need.STANDARD, apt="smbclient", version_argv=["--version"]),
    Tool("netexec", "nxc", Phase.ENUM, "AD/SMB swiss army knife (CrackMapExec successor)",
         Need.STANDARD, pipx="git+https://github.com/Pennyw0rth/NetExec",
         alt_binaries=["netexec", "crackmapexec", "cme"],
         notes="CrackMapExec is unmaintained; netexec is the active fork."),
    Tool("ldapsearch", "ldapsearch", Phase.ENUM, "Raw LDAP queries against directory services",
         Need.STANDARD, apt="ldap-utils", brew="openldap"),
    Tool("windapsearch", "windapsearch", Phase.ENUM, "Scripted LDAP enumeration of AD",
         Need.OPTIONAL, go="github.com/ropnop/go-windapsearch@latest",
         manual="https://github.com/ropnop/go-windapsearch/releases"),
    Tool("bloodhound-python", "bloodhound-python", Phase.ENUM, "AD graph collection for BloodHound",
         Need.STANDARD, pipx="bloodhound", pip="bloodhound"),
    Tool("snmpwalk", "snmpwalk", Phase.ENUM, "SNMP tree enumeration",
         Need.STANDARD, apt="snmp", brew="net-snmp"),
    Tool("onesixtyone", "onesixtyone", Phase.ENUM, "Fast SNMP community string scanner",
         Need.OPTIONAL, apt="onesixtyone"),
    Tool("rpcclient", "rpcclient", Phase.ENUM, "MS-RPC enumeration over SMB",
         Need.STANDARD, apt="smbclient"),
    Tool("showmount", "showmount", Phase.ENUM, "NFS export enumeration",
         Need.OPTIONAL, apt="nfs-common"),
    Tool("nbtscan", "nbtscan", Phase.ENUM, "NetBIOS name scanning",
         Need.OPTIONAL, apt="nbtscan"),
    Tool("ike-scan", "ike-scan", Phase.ENUM, "IPsec/IKE VPN endpoint fingerprinting",
         Need.OPTIONAL, apt="ike-scan"),

    # ---------------- Vulnerability Scanning ----------------
    Tool("nuclei", "nuclei", Phase.VULN, "Templated CVE and misconfiguration checks",
         Need.CORE, go="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
         apt="nuclei", brew="nuclei",
         notes="Run `nuclei -update-templates` after install."),
    Tool("testssl.sh", "testssl.sh", Phase.VULN, "Thorough TLS configuration audit",
         Need.STANDARD, apt="testssl.sh", brew="testssl", alt_binaries=["testssl"]),
    Tool("sslscan", "sslscan", Phase.VULN, "Fast TLS cipher and protocol enumeration",
         Need.STANDARD, apt="sslscan", brew="sslscan"),
    Tool("sslyze", "sslyze", Phase.VULN, "Scriptable TLS scanner with JSON output",
         Need.OPTIONAL, pipx="sslyze", pip="sslyze"),
    Tool("gvm-cli", "gvm-cli", Phase.VULN, "OpenVAS / Greenbone control interface",
         Need.OPTIONAL, pipx="gvm-tools", pip="gvm-tools",
         notes="Needs a running Greenbone server; not installed by vision."),
    Tool("nessuscli", "nessuscli", Phase.VULN, "Tenable Nessus command interface",
         Need.OPTIONAL, manual="https://www.tenable.com/downloads/nessus",
         notes="Commercial, licence required. Manual install only."),

    # ---------------- Exploitation ----------------
    Tool("metasploit", "msfconsole", Phase.EXPLOIT, "Exploit framework — vision indexes its modules",
         Need.CORE, apt="metasploit-framework", brew="metasploit",
         notes="Required for `vision check` and `vision exploit`."),
    Tool("msfvenom", "msfvenom", Phase.EXPLOIT, "Payload generation",
         Need.STANDARD, apt="metasploit-framework"),
    Tool("searchsploit", "searchsploit", Phase.EXPLOIT, "Offline Exploit-DB search",
         Need.STANDARD, apt="exploitdb", brew="exploitdb",
         version_argv=["-h"]),
    Tool("impacket", "impacket-psexec", Phase.EXPLOIT, "AD/SMB protocol toolkit (psexec, secretsdump, ...)",
         Need.CORE, pipx="impacket", pip="impacket", apt="impacket-scripts",
         alt_binaries=["psexec.py", "impacket-secretsdump"],
         notes="Provides ntlmrelayx, GetNPUsers, GetUserSPNs, secretsdump."),
    Tool("responder", "responder", Phase.EXPLOIT, "LLMNR/NBT-NS/MDNS poisoning",
         Need.STANDARD, apt="responder", alt_binaries=["Responder.py"],
         notes="Noisy and intrusive. Confirm it's in scope before running."),
    Tool("evil-winrm", "evil-winrm", Phase.EXPLOIT, "WinRM shell for authenticated Windows access",
         Need.STANDARD, gem="evil-winrm", apt="evil-winrm"),
    Tool("mssqlclient", "impacket-mssqlclient", Phase.EXPLOIT, "MSSQL authenticated client",
         Need.OPTIONAL, pipx="impacket", alt_binaries=["mssqlclient.py"]),

    # ---------------- Credential Attacks ----------------
    Tool("hydra", "hydra", Phase.CREDS, "Online password attacks across many protocols",
         Need.STANDARD, apt="hydra", brew="hydra",
         notes="Account lockout risk. Check the client's policy first."),
    Tool("medusa", "medusa", Phase.CREDS, "Parallel online brute forcer",
         Need.OPTIONAL, apt="medusa", brew="medusa"),
    Tool("ncrack", "ncrack", Phase.CREDS, "Network authentication cracker from the nmap project",
         Need.OPTIONAL, apt="ncrack"),
    Tool("hashcat", "hashcat", Phase.CREDS, "GPU-accelerated offline hash cracking",
         Need.STANDARD, apt="hashcat", brew="hashcat"),
    Tool("john", "john", Phase.CREDS, "Offline password cracking (John the Ripper)",
         Need.STANDARD, apt="john", brew="john",
         version_argv=[]),
    Tool("kerbrute", "kerbrute", Phase.CREDS, "Kerberos user enumeration and password spraying",
         Need.STANDARD, go="github.com/ropnop/kerbrute@latest",
         notes="Pre-auth enumeration does not increment lockout counters."),

    # ---------------- Post-Ex / Pivoting ----------------
    Tool("chisel", "chisel", Phase.POSTEX, "TCP/UDP tunnel over HTTP",
         Need.STANDARD, go="github.com/jpillora/chisel@latest", brew="chisel"),
    Tool("ligolo-ng", "ligolo-ng", Phase.POSTEX, "Tunnelling and pivoting via TUN interface",
         Need.OPTIONAL, go="github.com/nicocha30/ligolo-ng/cmd/proxy@latest",
         manual="https://github.com/nicocha30/ligolo-ng/releases",
         alt_binaries=["ligolo-proxy", "proxy"]),
    Tool("sshuttle", "sshuttle", Phase.POSTEX, "Transparent VPN-like proxy over SSH",
         Need.OPTIONAL, apt="sshuttle", pipx="sshuttle", brew="sshuttle"),
    Tool("proxychains", "proxychains4", Phase.POSTEX, "Force arbitrary tools through a proxy",
         Need.STANDARD, apt="proxychains4", brew="proxychains-ng",
         alt_binaries=["proxychains", "proxychains-ng"]),
    Tool("socat", "socat", Phase.POSTEX, "Bidirectional data relay",
         Need.STANDARD, apt="socat", brew="socat"),
    Tool("netcat", "ncat", Phase.POSTEX, "Raw TCP/UDP connections and listeners",
         Need.STANDARD, apt="ncat", brew="nmap", alt_binaries=["nc", "netcat"]),

    # ---------------- Traffic / Manual ----------------
    Tool("tcpdump", "tcpdump", Phase.TRAFFIC, "Packet capture",
         Need.STANDARD, apt="tcpdump", brew="tcpdump"),
    Tool("tshark", "tshark", Phase.TRAFFIC, "Wireshark CLI for capture and analysis",
         Need.STANDARD, apt="tshark", brew="wireshark"),
    Tool("bettercap", "bettercap", Phase.TRAFFIC, "Network attack and monitoring framework",
         Need.OPTIONAL, apt="bettercap", brew="bettercap",
         notes="MITM capability. Explicit authorisation required."),
    Tool("hping3", "hping3", Phase.TRAFFIC, "Packet crafting and firewall testing",
         Need.OPTIONAL, apt="hping3"),
    Tool("scapy", "scapy", Phase.TRAFFIC, "Python packet crafting library",
         Need.OPTIONAL, pipx="scapy", pip="scapy", apt="python3-scapy"),
    Tool("openssl", "openssl", Phase.TRAFFIC, "Manual TLS inspection via s_client",
         Need.STANDARD, apt="openssl", brew="openssl",
         version_argv=["version"]),
    Tool("curl", "curl", Phase.TRAFFIC, "HTTP client for manual probing",
         Need.CORE, apt="curl", brew="curl"),
]

BY_NAME = {t.name: t for t in TOOLS}


# ---------------------------------------------------------------------------
# Environment detection
# ---------------------------------------------------------------------------

@dataclass
class Environment:
    os_name: str
    distro: str
    is_kali: bool
    package_managers: list[str]
    go_bin_on_path: bool
    local_bin_on_path: bool
    is_root: bool

    @property
    def preferred_order(self) -> list[str]:
        if self.os_name == "Darwin":
            return ["brew", "pipx", "go", "gem", "cargo", "pip"]
        # apt first on Debian derivatives: signed, maintained packages.
        return ["apt", "pipx", "go", "gem", "cargo", "pip"]


def detect_environment() -> Environment:
    os_name = platform.system()
    distro = ""
    is_kali = False
    try:
        with open("/etc/os-release") as fh:
            data = dict(
                line.split("=", 1) for line in fh.read().splitlines() if "=" in line
            )
        distro = data.get("ID", "").strip('"')
        is_kali = distro == "kali" or "kali" in data.get("PRETTY_NAME", "").lower()
    except OSError:
        pass

    pms = [pm for pm, binary in (
        ("apt", "apt-get"), ("brew", "brew"), ("pipx", "pipx"),
        ("pip", "pip3"), ("go", "go"), ("gem", "gem"), ("cargo", "cargo"),
    ) if shutil.which(binary)]

    gobin = os.environ.get("GOBIN") or os.path.expanduser("~/go/bin")
    _path_dirs = os.environ.get("PATH", "").split(os.pathsep)
    on_path = gobin in _path_dirs
    # pipx and `pip install --user` place executables in ~/.local/bin. If it is
    # not on PATH, those tools install successfully but stay invisible to
    # shutil.which — which reads as "not installed" and is the most common
    # reason the tool count comes in low on a box where setup.sh actually ran.
    local_bin = os.path.expanduser("~/.local/bin")
    local_on_path = local_bin in _path_dirs

    return Environment(
        os_name=os_name, distro=distro, is_kali=is_kali,
        package_managers=pms, go_bin_on_path=on_path,
        local_bin_on_path=local_on_path,
        is_root=(hasattr(os, "geteuid") and os.geteuid() == 0),
    )


def audit(tools: list[Tool] | None = None,
          with_versions: bool = False) -> list[tuple[Tool, bool, Optional[str]]]:
    out = []
    for t in (tools or TOOLS):
        present = t.installed
        ver = t.version() if (present and with_versions) else None
        out.append((t, present, ver))
    return out


def missing(need: Need | None = None) -> list[Tool]:
    out = [t for t in TOOLS if not t.installed]
    if need:
        order = {Need.CORE: 0, Need.STANDARD: 1, Need.OPTIONAL: 2}
        out = [t for t in out if order[t.need] <= order[need]]
    return out


def choose_method(tool: Tool, env: Environment) -> Optional[str]:
    for pm in env.preferred_order:
        if pm in env.package_managers and tool.install_plan(pm):
            return pm
    return None


def resolve(name: str) -> "str | None":
    """Path to a tool's binary, or None if it is not installed.

    Every stage needs this, and it was copy-pasted into three separate stage
    modules. One definition means one place to fix when tool discovery changes.
    """
    tool = BY_NAME.get(name)
    return tool.which() if tool else None
