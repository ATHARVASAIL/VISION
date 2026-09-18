# Setting up a legal test target

## The rule

**Only scan and exploit systems you own or have written authorization to test.**

Unauthorized scanning is a criminal offence in most jurisdictions — the
Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), and Section 43
& 66 of the IT Act 2000 (India). "I was just testing my tool" is not a defence,
and port scanning alone has resulted in prosecutions.

Everything below is a target that is *yours* or is explicitly published for
testing. Don't point this tool anywhere else.

---

## Option A — Metasploitable 2 (recommended)

The best fit for vision specifically: it runs a dozen services with real MSF
modules, several of which implement `check`, so you can exercise the entire
verify-then-exploit path.

**Download:** SourceForge, `metasploitable-linux-2.0.0.zip` (~865 MB).
Search "Metasploitable 2 SourceForge" — it's a Rapid7 project.

**Setup (VirtualBox):**

```
1. Unzip, then File → Import Appliance → Metasploitable.vmx
   (or New VM → use the existing Metasploitable.vmdk as the disk)
2. Settings → Network → Adapter 1 → Host-only Adapter
   ⚠ NOT Bridged. NOT NAT. Host-only keeps it off your LAN and off the
     internet. This VM has a root shell hanging off port 1524; it will be
     compromised within minutes if exposed.
3. Boot. Login: msfadmin / msfadmin
4. `ip addr` → note the 192.168.56.x address
```

**Confirm isolation before you scan anything:**

```bash
# from the VM — both should FAIL
ping -c2 8.8.8.8
ping -c2 <your-router-ip>
```

**What vision will find on it:**

| Port | Service | CVE | MSF module | `check`? |
|---|---|---|---|---|
| 21 | vsftpd 2.3.4 | CVE-2011-2523 | `exploit/unix/ftp/vsftpd_234_backdoor` | yes |
| 139/445 | Samba 3.0.20 | CVE-2007-2447 | `exploit/multi/samba/usermap_script` | no |
| 1099 | Java RMI | CVE-2011-3556 | `exploit/multi/misc/java_rmi_server` | yes |
| 3632 | distccd | CVE-2004-2687 | `exploit/unix/misc/distcc_exec` | yes |
| 5432 | PostgreSQL 8.3 | weak creds | `exploit/linux/postgres/postgres_payload` | yes |
| 6667 | UnrealIRCd 3.2.8.1 | CVE-2010-2075 | `exploit/unix/irc/unreal_ircd_3281_backdoor` | no |
| 8180 | Tomcat 5.5 | weak creds | `exploit/multi/http/tomcat_mgr_deploy` | yes |
| 3306 | MySQL 5.0.51a | blank root | `auxiliary/scanner/mysql/mysql_login` | — |

Start with **distcc** or **Java RMI** — both have working `check` methods, so
you can validate the verify path before firing anything.

---

## Option B — Docker lab (fastest)

No VM, comes up in a minute. Included as `lab/docker-compose.yml`.

```bash
cd lab && docker compose up -d
docker compose ps          # note the mapped ports
```

Bound to `127.0.0.1` only — nothing is reachable from your LAN. Scan
`127.0.0.1` with `--rfc1918-only`.

Lighter on MSF-exploitable services than Metasploitable 2, but good for
smoke-testing the pipeline.

---

## Option C — Metasploitable 3 (Windows targets)

If you want to test the MS17-010 / EternalBlue path — i.e. the destructive-lock
behaviour — you need a Windows target. Metasploitable 3 builds a Windows Server
2008 VM via Packer + Vagrant.

```bash
git clone https://github.com/rapid7/metasploitable3
cd metasploitable3 && ./build.sh windows2008
vagrant up
```

Takes 45–90 minutes and needs ~30 GB. Worth it only if you specifically want
Windows coverage. Same rule: host-only networking.

---

## Option D — Hosted labs

| Platform | Notes |
|---|---|
| **TryHackMe** | Beginner-friendly, per-room targets. Free tier available. |
| **Hack The Box** | Retired machines are good practice targets. |
| **VulnHub** | Free downloadable VMs, huge catalogue. Run host-only. |
| **PortSwigger Web Academy** | Web only — not useful for network VAPT. |

For THM and HTB, scan **only** the IP assigned to your session, and only while
connected to their VPN. Their infrastructure IPs are off-limits and scanning
them will get your account banned.

---

## `scanme.nmap.org`

Nmap's project explicitly permits scanning this host. It is fine for testing
that your *scanner* works — but **do not run exploits against it**. Permission
covers scanning, not exploitation. Vision's `advise` on it is fine;
`exploit` is not.

---

## Recommended network layout

```
┌─────────────────────────────────────┐
│ Your host                           │
│                                     │
│  ┌───────────┐    ┌──────────────┐  │
│  │ Kali VM   │───▶│ Metasploit-  │  │
│  │ vision  │    │ able 2       │  │
│  └───────────┘    └──────────────┘  │
│        vboxnet0 (host-only)         │
│        192.168.56.0/24              │
└─────────────────────────────────────┘
              ✗ no route out
```

Run vision from a second VM rather than your host OS. Keeps the engagement
traffic, the audit log, and any shells contained.

---

## Full test run against Metasploitable 2

```bash
# 0. index (once)
vision index

# 1. scan
sudo nmap -sV -sC --script vuln -oX scan.xml 192.168.56.101

# 2. normalize
python3 tools/nmap2findings.py scan.xml > run.json

# 3. triage — read-only, touches nothing
vision advise --findings run.json --scope 192.168.56.0/24 --rfc1918-only

# 4. preview what would run, without MSF even installed
vision exploit --findings run.json --scope 192.168.56.0/24 \
  --rfc1918-only --dry-run

# 5. verify only — safe, no payloads delivered
vision exploit --findings run.json --scope 192.168.56.0/24 \
  --rfc1918-only --operator omkar --default-action check

# 6. exploit, one at a time, typing the IP to confirm each
vision exploit --findings run.json --scope 192.168.56.0/24 \
  --rfc1918-only --operator omkar --default-action exploit

# 7. review what you did
jq -c '{iso,event,module,target,verdict}' vision-audit.jsonl
```

**Test the guardrails too** — they should all refuse:

```bash
# out of scope
vision exploit --findings run.json --scope 10.0.0.0/24 --dry-run

# public address blocked by --rfc1918-only
echo '{"findings":[{"ip":"1.1.1.1","title":"x","cves":["CVE-2012-2122"]}]}' > /tmp/oos.json
vision advise --findings /tmp/oos.json --scope 0.0.0.0/0 --rfc1918-only

# destructive module locked
vision exploit --findings run.json --scope 192.168.56.0/24 --dry-run
# select an entry marked 🔒 → should refuse without --allow-destructive
```

If any of those *succeed*, that's a bug — tell me and I'll fix it.
