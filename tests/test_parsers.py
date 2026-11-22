"""Parser tests against realistic tool output.

These parsers are the project's largest exposure to reality: everything else is
logic I control, but these read text produced by other people's tools, which
reformat between releases. A parser that silently returns nothing after an
`apt upgrade` produces a clean report for a vulnerable network — the worst
possible failure for an assessment tool.

Fixtures below reproduce the output formats these tools actually emit,
including version variation, colour codes, and error paths.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vision.core.parsers import (
    strip_ansi, parse_smbmap_shares, smbmap_has_write, parse_rpcclient_users,
    parse_showmount_exports, export_is_world_readable, parse_sslscan_protocols,
    deprecated_enabled, parse_netexec_smb, signing_disabled, snmp_responded,
    ike_aggressive_mode, parse_searchsploit, searchsploit_cves,
    parse_ldap_contexts, ldap_bind_succeeded,
)

fails = []
def check(label, cond, detail=""):
    print(f"{'PASS' if cond else 'FAIL'}  {label}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond: fails.append(label)

print("--- ANSI handling (tools colour even when piped) ---")
check("colour stripped", strip_ansi("\x1b[32mgreen\x1b[0m") == "green")
check("plain text untouched", strip_ansi("plain") == "plain")
check("None safe", strip_ansi(None) == "")

print("\n--- smbmap: classic format ---")
SMBMAP_V1 = """[+] Finding open SMB ports....
[+] User SESSION       	IP: 10.0.0.5:445	Name: target
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	backups                                           	READ, WRITE	nightly dumps
	public                                            	READ ONLY	
"""
shares = parse_smbmap_shares(SMBMAP_V1)
names = {n for n, _ in shares}
check("readable shares found", {"backups", "public"} <= names, str(names))
check("NO ACCESS excluded", "ADMIN$" not in names and "C$" not in names)
check("IPC$ excluded", "IPC$" not in names)
check("write permission detected", smbmap_has_write(shares))
check("header rows excluded", "Disk" not in names and "----" not in names)
check("permission normalised",
      any(p == "READ WRITE" for n, p in shares if n == "backups"), str(shares))

print("\n--- smbmap: newer format with different spacing ---")
SMBMAP_V2 = """[+] IP: 10.0.0.5:445\tName: target.corp.local      Status: Authenticated
        Disk                                                      Permissions     Comment
        ----                                                      -----------     -------
        IPC$                                                      READ ONLY       Remote IPC
        netlogon                                                  READ ONLY       Logon server share
        sysvol                                                    READ, WRITE     Logon server share
"""
shares2 = parse_smbmap_shares(SMBMAP_V2)
n2 = {n for n, _ in shares2}
check("alternate spacing parsed", {"netlogon", "sysvol"} <= n2, str(n2))
check("write still detected", smbmap_has_write(shares2))

print("\n--- smbmap: punctuation variants ---")
for variant, label in [("READ,WRITE", "no space"), ("READ_ONLY", "underscore"),
                       ("READ WRITE", "space only")]:
    out = f"\tshare1                    \t{variant}\tcomment\n"
    parsed = parse_smbmap_shares(out)
    check(f"handles {label} ({variant})", len(parsed) == 1, str(parsed))

print("\n--- smbmap: colour and error paths ---")
check("coloured output parsed",
      len(parse_smbmap_shares("\t\x1b[32mdata\x1b[0m       \tREAD ONLY\t\n")) == 1)
check("no shares yields nothing", parse_smbmap_shares(
    "[!] Authentication error on 10.0.0.5\n") == [])
check("empty output safe", parse_smbmap_shares("") == [])
check("garbage safe", parse_smbmap_shares("random text\nwith no shares") == [])
check("write check on empty list", not smbmap_has_write([]))

print("\n--- rpcclient ---")
RPC = """user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[svc_sql] rid:[0x452]
"""
users = parse_rpcclient_users(RPC)
check("all users parsed", len(users) == 4, str(users))
check("names extracted", "svc_sql" in users)
check("order preserved", users[0] == "Administrator")
check("duplicates removed",
      len(parse_rpcclient_users(RPC + "user:[Guest] rid:[0x1f5]\n")) == 4)
check("access denied yields nothing",
      parse_rpcclient_users("result was NT_STATUS_ACCESS_DENIED\n") == [])
check("empty safe", parse_rpcclient_users("") == [])
check("names with spaces parsed",
      parse_rpcclient_users("user:[Domain Admin] rid:[0x1]") == ["Domain Admin"])

print("\n--- showmount ---")
NFS = """Export list for 10.0.0.5:
/srv/backup       *
/home             10.0.0.0/24
/opt/shared       host1.corp.local,host2.corp.local
"""
exports = parse_showmount_exports(NFS)
check("all exports parsed", len(exports) == 3, str(exports))
check("path extracted", exports[0][0] == "/srv/backup")
check("clients extracted", exports[1][1] == "10.0.0.0/24")
check("header line skipped", not any("Export list" in p for p, _ in exports))
check("wildcard is world-readable", export_is_world_readable("*"))
check("empty client list is world-readable", export_is_world_readable(""))
check("CIDR is not world-readable", not export_is_world_readable("10.0.0.0/24"))
check("hostnames are not world-readable",
      not export_is_world_readable("host1.corp.local,host2.corp.local"))
check("wildcard among others detected", export_is_world_readable("host1,*"))
check("rpc error yields nothing",
      parse_showmount_exports("clnt_create: RPC: Program not registered\n") == [])
check("no exports yields nothing",
      parse_showmount_exports("Export list for 10.0.0.5:\n") == [])

print("\n--- sslscan (the parser that was silently broken) ---")
SSLSCAN = """Version: 2.0.15
OpenSSL 3.0.2 15 Mar 2022

Connected to 10.0.0.5

Testing SSL server 10.0.0.5 on port 443 using SNI name 10.0.0.5

  SSL/TLS Protocols:
SSLv2     disabled
SSLv3     disabled
TLSv1.0   enabled
TLSv1.1   enabled
TLSv1.2   enabled
TLSv1.3   disabled
"""
protos = parse_sslscan_protocols(SSLSCAN)
check("all protocols parsed", len(protos) == 6, str(protos))
check("TLSv1.0 enabled detected", protos.get("TLSv1.0") is True)
check("TLSv1.1 enabled detected", protos.get("TLSv1.1") is True)
check("SSLv2 disabled detected", protos.get("SSLv2") is False)
check("TLSv1.3 disabled detected", protos.get("TLSv1.3") is False)

dep = dict(deprecated_enabled(protos))
check("deprecated protocols flagged", set(dep) == {"TLSv1.0", "TLSv1.1"}, str(dep))
check("TLSv1.2 not flagged", "TLSv1.2" not in dep)
check("severity assigned", dep.get("TLSv1.0") == "medium")

print("\n--- sslscan: spacing variation (the actual bug) ---")
for spacing, label in [(" ", "single space"), ("  ", "two spaces"),
                       ("     ", "five spaces"), ("\t", "tab")]:
    out = f"SSLv2{spacing}enabled\nSSLv3{spacing}enabled\n"
    p = parse_sslscan_protocols(out)
    check(f"SSLv2 enabled with {label}", p.get("SSLv2") is True, str(p))
sev = dict(deprecated_enabled(parse_sslscan_protocols("SSLv2 enabled\n")))
check("SSLv2 rated critical", sev.get("SSLv2") == "critical")

check("coloured sslscan parsed",
      parse_sslscan_protocols("\x1b[31mSSLv3\x1b[0m   enabled\n").get("SSLv3") is True)
check("legacy TLSv1 label handled",
      parse_sslscan_protocols("TLSv1     enabled\n").get("TLSv1") is True)
check("connection failure yields nothing",
      parse_sslscan_protocols("Connection refused\n") == {})
check("empty safe", parse_sslscan_protocols("") == {})
check("nothing deprecated when all modern",
      deprecated_enabled({"TLSv1.2": True, "TLSv1.3": True}) == [])

print("\n--- netexec / crackmapexec ---")
NXC = ("SMB         10.0.0.5    445    TARGET    [*] Windows 10.0 Build 17763 "
       "x64 (name:TARGET) (domain:corp.local) (signing:False) (SMBv1:True)")
fields = parse_netexec_smb(NXC)
check("signing parsed", fields.get("signing") == "False", str(fields))
check("domain parsed", fields.get("domain") == "corp.local")
check("name parsed", fields.get("name") == "TARGET")
check("SMBv1 parsed", fields.get("smbv1") == "True")
check("signing disabled detected", signing_disabled(fields) is True)

secure = parse_netexec_smb(NXC.replace("signing:False", "signing:True"))
check("signing enabled detected", signing_disabled(secure) is False)

check("absent signing returns None, not False",
      signing_disabled(parse_netexec_smb("SMB 10.0.0.5 445 TARGET [*] Windows")) is None)
check("None is distinguishable from False",
      signing_disabled({}) is None and signing_disabled({"signing": "True"}) is False)
check("coloured output parsed",
      parse_netexec_smb("\x1b[1;34mSMB\x1b[0m (signing:False)").get("signing") == "False")
check("empty safe", parse_netexec_smb("") == {})

print("\n--- snmpwalk ---")
check("real reply detected", snmp_responded(
    "SNMPv2-MIB::sysDescr.0 = STRING: Linux gw 5.4.0-90-generic", 0))
check("iso-form reply detected", snmp_responded(
    "iso.3.6.1.2.1.1.1.0 = STRING: \"Cisco IOS Software\"", 0))
check("timeout rejected", not snmp_responded(
    "Timeout: No Response from 10.0.0.5", 0))
check("no-such-object rejected", not snmp_responded(
    "SNMPv2-MIB::sysDescr.0 = No Such Object available on this agent", 0))
check("auth failure rejected", not snmp_responded("Authentication failure", 0))
check("non-zero exit rejected", not snmp_responded("SNMPv2-MIB::sysDescr.0 = STRING: x", 1))
check("empty rejected", not snmp_responded("", 0))
check("noise without an OID rejected", not snmp_responded("some random text", 0))

print("\n--- ike-scan ---")
AGG = ("10.0.0.5\tAggressive Mode Handshake returned "
       "HDR=(CKY-R=abc) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024)")
check("aggressive mode detected", ike_aggressive_mode(AGG))
MAIN = "10.0.0.5\tMain Mode Handshake returned HDR=(CKY-R=abc)"
check("main mode is not aggressive", not ike_aggressive_mode(MAIN))
check("no handshake detected", not ike_aggressive_mode(
    "0 returned handshake; 0 returned notify"))
check("empty safe", not ike_aggressive_mode(""))

print("\n--- searchsploit ---")
SS = ('{"SEARCH": "vsftpd 2.3", "RESULTS_EXPLOIT": ['
      '{"Title": "vsftpd 2.3.4 - Backdoor Command Execution", '
      '"Codes": "CVE-2011-2523", "Path": "/x/17491.rb"},'
      '{"Title": "vsftpd 2.3.2 - Denial of Service", "Codes": ""}]}')
hits = parse_searchsploit(SS)
check("hits parsed", len(hits) == 2)
check("title available", "Backdoor" in hits[0]["Title"])
check("CVEs extracted", searchsploit_cves(hits) == ["CVE-2011-2523"])
check("banner before JSON tolerated",
      len(parse_searchsploit("Exploit-DB search\n" + SS)) == 2)
check("no results yields nothing",
      parse_searchsploit('{"RESULTS_EXPLOIT": []}') == [])
check("malformed JSON yields nothing", parse_searchsploit("{not json") == [])
check("empty yields nothing", parse_searchsploit("") == [])
check("non-dict entries filtered",
      parse_searchsploit('{"RESULTS_EXPLOIT": ["str", {"Title":"ok"}]}') ==
      [{"Title": "ok"}])
check("no CVEs is empty list", searchsploit_cves([{"Title": "x", "Codes": ""}]) == [])
check("CVEs deduplicated and sorted",
      searchsploit_cves([{"Codes": "CVE-2020-2000, CVE-2020-1000"},
                         {"Codes": "CVE-2020-1000"}]) ==
      ["CVE-2020-1000", "CVE-2020-2000"])
# CVE IDs require at least four digits in the sequence portion, so a
# short-form string is not a CVE and must not be reported as one.
check("short-form pseudo-CVE rejected",
      searchsploit_cves([{"Codes": "CVE-2020-1"}]) == [])

print("\n--- ldapsearch ---")
LDAP = """# extended LDIF
#
dn:
namingContexts: DC=corp,DC=local
namingContexts: CN=Configuration,DC=corp,DC=local
namingContexts: CN=Schema,CN=Configuration,DC=corp,DC=local

# search result
search: 2
result: 0 Success
"""
ctx = parse_ldap_contexts(LDAP)
check("contexts parsed", len(ctx) == 3, str(ctx))
check("base DN extracted", ctx[0] == "DC=corp,DC=local")
check("anonymous bind confirmed", ldap_bind_succeeded(LDAP, 0))
check("bind failure rejected", not ldap_bind_succeeded(
    "ldap_bind: Invalid credentials (49)", 1))
check("operations error rejected", not ldap_bind_succeeded(
    "ldap_bind: Operations error (1)", 0))
check("non-zero exit rejected", not ldap_bind_succeeded(LDAP, 1))
check("empty rejected", not ldap_bind_succeeded("", 0))
check("no contexts is empty", parse_ldap_contexts("dn:\n") == [])

print("\n--- every parser survives hostile input ---")
HOSTILE = ["", "   ", "\x00\x00\x00", "\x1b[2J" * 100, "A" * 100_000,
           "\n" * 1000, "日本語 ☠", "</script><script>alert(1)</script>",
           "%s%s%s%n", "../../etc/passwd"]
parsers = [
    ("smbmap", parse_smbmap_shares), ("rpcclient", parse_rpcclient_users),
    ("showmount", parse_showmount_exports), ("sslscan", parse_sslscan_protocols),
    ("netexec", parse_netexec_smb), ("ike-scan", ike_aggressive_mode),
    ("searchsploit", parse_searchsploit), ("ldap", parse_ldap_contexts),
]
crashed = []
for name, fn in parsers:
    for payload in HOSTILE:
        try:
            fn(payload)
        except Exception as exc:
            crashed.append(f"{name}({payload[:12]!r}): {type(exc).__name__}")
check(f"all {len(parsers)} parsers survive {len(HOSTILE)} hostile inputs",
      not crashed, "; ".join(crashed[:3]))

for name, fn in parsers:
    try:
        fn(None)
    except (TypeError, AttributeError):
        crashed.append(f"{name}(None)")
check("all parsers handle None", not crashed, "; ".join(crashed[:3]))

print("\n--- no parser invents findings from noise ---")
NOISE = """Starting scan
Connection timed out
[!] Error: unable to connect
Host is down
"""
check("smbmap invents nothing", parse_smbmap_shares(NOISE) == [])
check("rpcclient invents nothing", parse_rpcclient_users(NOISE) == [])
check("showmount invents nothing", parse_showmount_exports(NOISE) == [])
check("sslscan invents nothing", parse_sslscan_protocols(NOISE) == {})
check("ike-scan invents nothing", not ike_aggressive_mode(NOISE))
check("searchsploit invents nothing", parse_searchsploit(NOISE) == [])
check("ldap invents nothing", parse_ldap_contexts(NOISE) == [])
check("snmp invents nothing", not snmp_responded(NOISE, 0))

print("\n" + "=" * 52)
print("ALL PASS" if not fails else f"FAILURES ({len(fails)}): " + ", ".join(fails))
sys.exit(1 if fails else 0)
