"""Accuracy and performance tests: version logic, concurrency, false positives."""
import sys, tempfile, time, threading
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vision.core.version import Version, older_than, major_minor
from vision.core.concurrency import parallel_map, parallel_collect, worker_count, MAX_WORKERS
from vision.core.pipeline import Pipeline, RunState
from vision.core.scope import Scope

fails = []
def check(label, cond, detail=""):
    print(f"{'PASS' if cond else 'FAIL'}  {label}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond: fails.append(label)

print("--- version comparison (string compare got these wrong) ---")
check("2.3.10 > 2.3.4", Version("2.3.10") > Version("2.3.4"))
check("10.0 > 7.0", Version("10.0") > Version("7.0"))
check("1.20.1 > 1.9.9", Version("1.20.1") > Version("1.9.9"))
check("2.4.51 > 2.4.9", Version("2.4.51") > Version("2.4.9"))
check("equal versions", Version("1.2.3") == Version("1.2.3"))
check("padding: 1.2 == 1.2.0", Version("1.2") == Version("1.2.0"))
check("1.2 < 1.2.1", Version("1.2") < Version("1.2.1"))

print("\n--- real-world messy version strings ---")
for raw, ok in [("2.3.4-Debian", True), ("7.2p2", True), ("1.0.2k-fips", True),
                ("5.5.28-0ubuntu0.12.04.3", True), ("3.0.20-Debian", True),
                ("unknown", False), ("", False), (None, False)]:
    check(f"parses {raw!r}" if ok else f"rejects {raw!r}", bool(Version(raw)) == ok)
check("Debian suffix ignored in compare", Version("3.0.20-Debian") < Version("4.0"))
check("OpenSSH patch letter ordered", Version("7.2p2") > Version("7.2p1"))
check("fips suffix ignored", Version("1.0.2k-fips") < Version("1.1.0"))

print("\n--- pre-release ordering ---")
check("1.0-rc1 < 1.0", Version("1.0-rc1") < Version("1.0"))
check("2.0-beta < 2.0", Version("2.0-beta") < Version("2.0"))

print("\n--- older_than refuses to guess ---")
check("proven older -> True", older_than("2.3.4", "2.3.5"))
check("proven newer -> False", not older_than("2.3.6", "2.3.5"))
check("equal -> False", not older_than("2.3.5", "2.3.5"))
check("unparseable -> False (no false positive)", not older_than("unknown", "2.3.5"))
check("empty -> False", not older_than("", "2.3.5"))
check("None -> False", not older_than(None, "2.3.5"))
check("the old bug: 2.3.10 not called older than 2.3.4",
      not older_than("2.3.10", "2.3.4"))

print("\n--- helpers ---")
check("major_minor 5.5.28 -> 5.5", major_minor("5.5.28") == "5.5")
check("major_minor 2.3.4-Debian -> 2.3", major_minor("2.3.4-Debian") == "2.3")
check("major_minor junk -> empty", major_minor("unknown") == "")

print("\n--- concurrency correctness ---")
check("worker count never exceeds ceiling", worker_count(999, 999) <= MAX_WORKERS)
check("workers never exceed item count", worker_count(20, 3) == 3)
check("at least one worker", worker_count(0, 0) >= 1)

results = parallel_map(lambda x: x * 2, list(range(50)))
check("all items processed", sorted(results) == sorted(x * 2 for x in range(50)))

def flaky(x):
    if x % 3 == 0:
        raise RuntimeError("host refused")
    return x
ok = parallel_map(flaky, list(range(30)))
check("exceptions isolated per item", len(ok) == 20, str(len(ok)))
check("no exception escapes the pool", True)

check("None results dropped", parallel_map(lambda x: None, [1, 2, 3]) == [])
check("empty input safe", parallel_map(lambda x: x, []) == [])
check("single item bypasses pool", parallel_map(lambda x: x + 1, [5]) == [6])
check("single item exception handled", parallel_map(flaky, [3]) == [])

flat = parallel_collect(lambda x: [{"v": x}, {"v": x * 10}], [1, 2])
check("parallel_collect flattens", len(flat) == 4)
check("parallel_collect handles empty returns",
      parallel_collect(lambda x: [], [1, 2, 3]) == [])

print("\n--- concurrency actually parallel (the 3.9-hour fix) ---")
DELAY, N = 0.25, 12
t0 = time.time()
parallel_map(lambda x: time.sleep(DELAY) or x, list(range(N)))
elapsed = time.time() - t0
serial = DELAY * N
check(f"{N} x {DELAY}s ran concurrently ({elapsed:.2f}s vs {serial:.1f}s serial)",
      elapsed < serial / 3, f"{elapsed:.2f}s")

seen = set()
lock = threading.Lock()
def record(x):
    with lock:
        seen.add(threading.current_thread().name)
    time.sleep(0.05)
    return x
parallel_map(record, list(range(20)))
check("multiple threads used", len(seen) > 1, f"{len(seen)} thread(s)")

print("\n--- banner analysis: false-positive suppression ---")
scope = Scope.from_lists(["10.10.0.0/24"])
def analyse(services):
    wd = Path(tempfile.mkdtemp())
    st = RunState(scope="t", workdir=str(wd))
    st.services = services
    p = Pipeline(scope, wd, st)
    p.banner_analysis()
    return st.findings

def S(**kw):
    base = {"ip": "10.10.0.5", "proto": "tcp"}
    base.update(kw)
    return base

f = analyse([S(port=6379, name="redis", product="Redis")])
check("Redis on 6379 flagged", any("Redis" in x["title"] for x in f))
check("confirmed identity -> firm", all(x["confidence"] == "firm" for x in f))

f = analyse([S(port=6379, name="http", product="nginx")])
check("nginx on port 6379 NOT called Redis",
      not any("Redis" in x["title"] for x in f), str([x["title"] for x in f]))

f = analyse([S(port=6379)])
check("unidentified service on 6379 -> tentative",
      f and all(x["confidence"] == "tentative" for x in f))

f = analyse([S(port=80, name="http", tunnel="ssl")])
check("TLS-wrapped HTTP not flagged as cleartext",
      not any("without transport encryption" in x["title"] for x in f))

f = analyse([S(port=21, name="ftp", product="vsftpd", version="2.3.4")])
check("vsftpd 2.3.4 flagged as outdated",
      any("Outdated" in x["title"] for x in f))
f = analyse([S(port=21, name="ftp", product="vsftpd", version="3.0.5")])
check("vsftpd 3.0.5 NOT flagged as outdated",
      not any("Outdated" in x["title"] for x in f))
f = analyse([S(port=21, name="ftp", product="vsftpd", version="2.3.10")])
check("vsftpd 2.3.10 NOT flagged (old string-compare bug)",
      not any("Outdated" in x["title"] for x in f),
      str([x["title"] for x in f]))
f = analyse([S(port=21, name="ftp", product="vsftpd", version="unknown")])
check("unparseable version not flagged outdated",
      not any("Outdated" in x["title"] for x in f))

print("\n--- non-standard ports (the bug integration testing caught) ---")
f = analyse([S(port=2121, name="ftp", product="vsftpd", version="2.3.4")])
check("FTP on 2121 flagged", any("FTP exposed" in x["title"] for x in f),
      str([x["title"] for x in f]))
f = analyse([S(port=2323, name="telnet")])
check("Telnet on 2323 flagged", any("Telnet" in x["title"] for x in f))
f = analyse([S(port=8080, name="http", product="nginx")])
check("HTTP on 8080 flagged", any("HTTP exposed" in x["title"] for x in f))
f = analyse([S(port=54321, name="redis", product="Redis")])
check("Redis on an arbitrary high port flagged",
      any("Redis" in x["title"] for x in f))
f = analyse([S(port=2121, name="ftp")])
check("nmap-named service is firm even off-port",
      f and all(x["confidence"] == "firm" for x in f if "FTP" in x["title"]))
f = analyse([S(port=21)])
check("unnamed service on well-known port is tentative",
      f and all(x["confidence"] == "tentative" for x in f))
f = analyse([S(port=21, name="ssh", product="OpenSSH")])
check("nmap naming something else suppresses the port guess",
      not any("FTP" in x["title"] for x in f), str([x["title"] for x in f]))
f = analyse([S(port=99999 % 65535, name="unknown-service")])
check("unknown service on unknown port produces nothing",
      not any(x["source"] == "banner-analysis" for x in f))

f = analyse([S(ip="8.8.8.8", port=23, name="telnet")])
check("out-of-scope host produces nothing", len(f) == 0)

print("\n--- every finding is defensible ---")
f = analyse([S(port=23, name="telnet"), S(port=5900, name="vnc"),
             S(port=21, name="ftp", product="vsftpd", version="2.3.4")])
check("all findings carry remediation", all(x.get("remediation") for x in f))
check("all findings carry evidence", all(x.get("evidence") for x in f))
check("all findings carry confidence", all(x.get("confidence") for x in f))
check("all severities valid",
      all(x["severity"] in ("info", "low", "medium", "high", "critical") for x in f))

print("\n" + "=" * 50)
print("ALL PASS" if not fails else "FAILURES: " + ", ".join(fails))
sys.exit(1 if fails else 0)
