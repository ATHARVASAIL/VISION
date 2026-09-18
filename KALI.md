# Running Vision on Kali Linux

Kali is the recommended platform. It ships most of the 55 tools Vision
orchestrates, so `vision doctor` typically reports 40+ already present on a fresh
install, and `vision setup` fills the rest from Kali's curated metapackages.

Vision is not Kali-only — it runs on Ubuntu, Debian, Parrot, and macOS, and
`setup` picks the right package manager per platform. But on Kali the setup step
is one command instead of a scavenger hunt.

---

## 1. Get the VM

Download the **prebuilt virtual machine** image, not the installer ISO — it
saves an hour of installation.

Go to `kali.org/get-kali/` → **Virtual Machines** → pick VMware or VirtualBox
(7z archive, roughly 3 GB).

| | |
|---|---|
| Default credentials | `kali` / `kali` |
| Minimum RAM | 4 GB (8 GB if you'll run Metasploit + BloodHound) |
| Minimum disk | 40 GB — the metapackages are large |
| CPUs | 2+ |

Change the default password immediately: `passwd`.

---

## 2. Network configuration

This is the part that matters most.

**Two adapters is the right setup:**

| Adapter | Mode | Purpose |
|---|---|---|
| Adapter 1 | NAT | Internet, for updates and installs |
| Adapter 2 | Host-only | The isolated lab network you scan |

Your targets go on the host-only network. Nothing you scan can reach the
internet, and nothing on your home LAN can be hit by a stray scan.

**Do not use Bridged mode for the scanning interface.** Bridged puts Kali
directly on your home or office LAN, which means a mistyped CIDR scans your
router, your NAS, your housemate's laptop, or your employer's network. On a
corporate network that will trigger the SOC and can end your employment.

Confirm which interface is which before scanning:

```bash
ip -brief addr
# eth0  UP  10.0.2.15/24        <- NAT, internet
# eth1  UP  192.168.56.10/24    <- host-only, your lab
```

Then always scope to the host-only range:

```bash
vision run --scope 192.168.56.0/24 --rfc1918-only
```

`--rfc1918-only` is a second safety net: it hard-refuses any public address even
if your scope file has a typo.

---

## 3. Install Vision

```bash
sudo apt update && sudo apt -y full-upgrade
sudo apt install -y python3-pip python3-venv unzip

unzip vision.zip && cd vision
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

vision --version
```

Kali marks its Python as externally managed, so install inside a venv. If you
want `vision` available without activating the venv each time:

```bash
sudo ln -s "$(pwd)/.venv/bin/vision" /usr/local/bin/vision
```

---

## 4. Set up the toolchain

```bash
vision doctor              # see what Kali already gave you
vision setup --dry-run     # preview the metapackages
vision setup               # install them
vision index               # build the Metasploit module index
```

On Kali, `setup` uses metapackages rather than 40 individual apt calls:

| Metapackage | Covers |
|---|---|
| `kali-tools-information-gathering` | nmap, masscan, amass, dnsx, enum4linux, smbmap |
| `kali-tools-vulnerability` | nuclei, nikto, sslscan, testssl.sh |
| `kali-tools-exploitation` | metasploit-framework, exploitdb, impacket, evil-winrm |
| `kali-tools-passwords` | hydra, medusa, hashcat, john, wordlists |
| `kali-tools-post-exploitation` | chisel, proxychains, sshuttle, socat |
| `kali-tools-sniffing-spoofing` | tcpdump, tshark, bettercap, responder |

These pull several GB and take 10–30 minutes. For a lean install:

```bash
vision setup --no-metapackages --need core
```

A few tools aren't in any metapackage — `kerbrute` and `netexec` are go/pipx
installs. `setup` tells you which are left and how to get them.

If you install go tools, add the bin directory to your PATH or `doctor` won't
find them:

```bash
echo 'export PATH=$PATH:~/go/bin' >> ~/.zshrc && source ~/.zshrc
```

---

## 5. Metasploit first run

```bash
sudo msfdb init          # initialise the database
msfconsole -q -x "db_status; exit"
vision index              # ~10s, parses ~2800 modules
```

`vision index` must be re-run after every `msfupdate`, or the module index goes
stale.

---

## 6. Full run

```bash
vision doctor
vision run --scope 192.168.56.0/24 --rfc1918-only -o ~/engagements/lab
vision exploit --findings ~/engagements/lab/findings.json \
  --scope 192.168.56.0/24 --rfc1918-only --operator "$USER"
```

`run` scans and advises but never exploits. `exploit` starts in check-only mode
and requires you to type the target IP to confirm each action.

---

## Docker alternative

If you'd rather not run a full VM, the Kali container works — with one
important limitation.

```bash
docker run -it --rm \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v "$PWD:/opt/vision" \
  kalilinux/kali-rolling
```

`NET_RAW` and `NET_ADMIN` are required or nmap can't send SYN packets and
silently falls back to slow connect scans.

The limitation: containers share the host's network stack, so you lose the
isolation a host-only VM adapter gives you. A mistyped scope in a container can
reach your real LAN. Use the container for developing and testing Vision itself;
use the VM for anything that touches real targets.

---

## Snapshot before you scan

Take a VM snapshot once everything is installed and working. Engagement tooling
breaks in creative ways — a bad `apt upgrade`, a half-finished go install, a
Metasploit database that won't start — and rolling back to a known-good state
beats debugging at 2am mid-engagement.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `externally-managed-environment` on pip | Use the venv; don't `--break-system-packages` on Kali |
| `doctor` can't find go tools | Add `~/go/bin` to PATH |
| nmap needs root for `-sS` | Run `vision run` with `sudo -E` to keep the venv |
| `msfconsole` very slow on first run | Normal — it builds its cache once |
| No hosts found | Check you're scoping the host-only subnet, not the NAT one |
| Scan hits unexpected hosts | Wrong adapter. Verify with `ip -brief addr` before rescanning |
