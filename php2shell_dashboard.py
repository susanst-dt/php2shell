#!/usr/bin/env python3
"""
PHP2Shell (CVE-2026-109618 / CVE-2026-109619) and Node.js Oct-2026 security release
exposure dashboard for Dynatrace Managed (also works on SaaS) -- creates a CLASSIC dashboard.

Pure Python 3.7+ standard library: runs unchanged on Windows, Linux and macOS.

What it does
  1. Reads every process (PROCESS_GROUP_INSTANCE) that OneAgent reports as running PHP
     and/or Node.js, through the Environment API v2 (/api/v2/entities).
  2. Classifies each one from the version OneAgent detected:
        VULNERABLE      supported branch, fix not applied
        VULNERABLE_EOL  end-of-life branch, no official fix
        PATCHED         fixed release or newer
        UNKNOWN         version not readable -> check manually
  3. Creates / updates a classic dashboard (Config API v1) with KPI tiles,
     breakdowns and lists showing exactly which hosts / workloads / processes
     are affected, with deep links into the Dynatrace UI.
  4. Optionally writes a CSV with every process.

Fixed versions (sources dated 21 Oct 2026)
  PHP      8.5.12, 8.4.27, 8.3.36, 8.2.35   https://www.php.net/archive/2026.php#2026-10-21-1
  Node.js  22.23.4, 24.22.1, 26.12.1        https://nodejs.org/en/blog/vulnerability/october-2026-security-releases

Caveats
  - Version-only check. Distro vendors (Red Hat, Ubuntu, SUSE) may backport a fix without
    bumping the upstream version string: verify with the OS package manager (rpm -q / dpkg -l)
    before closing a finding.
  - OneAgent reports the running process. A process upgraded on disk but not restarted still
    shows the old version, which is correct: it is still exposed.

The dashboard is a snapshot of the moment the script ran. Re-run it (same
dashboard name = updated in place) to refresh, e.g. from cron / Task Scheduler.

Authentication: API token (Authorization: Api-Token ...) with scopes
  entities.read      (Read entities)
  ReadConfig + WriteConfig  (only to create/update the dashboard)
Give it as --token, the DT_API_TOKEN (or DT_TOKEN) env var, or enter it at the hidden prompt.
URL: Managed https://<host>/e/<env-id>; through an Environment ActiveGate
https://<activegate>:9999/e/<env-id>; SaaS https://<id>.live.dynatrace.com
"""
import argparse
import csv
import getpass
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict

DASHBOARD_NAME = "PHP2Shell, Node2Shell with Python and .NET"

# Fixed releases (php.net / nodejs.org advisories of 21 Oct 2026, Microsoft .NET out-of-band update of 25 Oct 2026).
PHP_FIXED = {(8, 5): (8, 5, 12), (8, 4): (8, 4, 27), (8, 3): (8, 3, 36), (8, 2): (8, 2, 35)}
PHP_EOL_MAX = (8, 1)  # branches <= 8.1 are end of life, no fix
NODE_FIXED = {22: (22, 23, 4), 24: (24, 22, 1), 26: (26, 12, 1)}  # major -> first fixed
# Node.js October 2026 security releases (https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)
NODE_CVES = [
    ("CVE-2026-111497", "High", "Brotli decoder out-of-bounds write, remote code execution"),
    ("CVE-2026-105482", "High", "dns.resolve truncates names containing a NUL character"),
    ("CVE-2026-105483", "High", "TLS hostname check bypass with fullwidth-digit IP"),
    ("CVE-2026-106069", "High", "TLS hostname check bypass with loosely resolved IP"),
    ("CVE-2026-105481", "Medium", "keep-alive sockets process a response written before the request"),
    ("CVE-2026-106072", "Medium", "non-canonical IPv4 hostnames let DNS SANs authenticate IP endpoints"),
    ("CVE-2026-106074", "Medium", "randomUUID()/randomInt() entropy cache saved in snapshots and SEAs"),
    ("CVE-2026-106070", "Low", "ZipFile returns attacker-controlled bytes after failed validation (26.x)"),
    ("CVE-2026-106071", "Low", "Permission Model filesystem over-grant via wildcard lookup (26.x)"),
    ("CVE-2026-106073", "Low", "Permission Model bypass with fs.realpathSync"),
]
# .NET October 2026 out-of-band security updates (released 2026-10-25):
# https://devblogs.microsoft.com/dotnet/dotnet-october-2026-oob-security-updates/
# Supported lines are 8, 9 and 10; .NET 11 is a release candidate (RC3 required, not classifiable from the version),
# .NET Framework is not affected, anything older is out of support.
DOTNET_FIXED = {8: (8, 0, 33), 9: (9, 0, 22), 10: (10, 0, 14)}
DOTNET_CVES = [
    ("CVE-2026-111497", "Brotli decompression buffer overflow, process memory read/corruption. ALL platforms, only apps "
                        "that use Brotli (ASP.NET Core request decompression, HttpClient auto-decompression, "
                        "System.IO.Compression). .NET Framework is not affected"),
    ("CVE-2026-114148", "Unsafe ownership metadata in .NET tarballs, local privilege escalation. LINUX only: .NET 8/9 "
                        "tarballs (incl. ASP.NET Core), .NET 10/11 source-build tarballs"),
    ("CVE-2026-70197", "SocketAsyncEventArgs memory corruption (re-release)"),
    ("CVE-2026-102870", "Blazor WebAssembly debugger (re-release; .NET 10, 11)"),
]
PHP_CVES = ["CVE-2026-109618", "CVE-2026-109619"]
# Python: end-of-life check from the python.org lifecycle (https://devguide.python.org/versions/). The interpreter is not
# affected by CVE-2026-111497 (a Google Brotli library bug, NVD: Brotli 1.0.3 to 1.2.0; fixed 1.0.10 / 1.1.1 / 1.2.1;
# Python packages Brotli and brotlicffi < 1.2.1.0): OneAgent process data cannot see installed packages.
PYTHON_EOL_MAX = (3, 10)  # 3.10 and older (and 2.x) are end of life; 3.11 to 3.15 are supported
PYTHON_EOL_DATES = {"3.10": "2026-10-01", "3.9": "2025-10-31", "3.8": "2024-10-07", "3.7": "2023-06-27"}
PYTHON_CVES = ["CVE-2026-111497"]
TECHS = {"php": ("PHP", "PHP"), "node": ("NODE_JS", "Node.js"),
         "dotnet": ("DOTNET", ".NET"), "python": ("PYTHON", "Python")}  # option -> (Dynatrace type, label)
TECH_KEY = {"PHP": "PHP", "Node.js": "NODE", ".NET": "DOTNET", "Python": "PYTHON"}  # label -> classify() key
TECH_SUBTITLE = {"PHP": "PHP2Shell CVE-2026-109618 / CVE-2026-109619",
                 "Node.js": "Node.js October 2026 security releases",
                 ".NET": ".NET October 2026 out-of-band security updates",
                 "Python": "Python end-of-life check, plus the Brotli library CVE-2026-111497"}

# CISA Known Exploited Vulnerabilities catalog
KEV_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
KEV_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# Used when the machine running the script cannot reach cisa.gov (checked against catalog 2026.10.26).
KEV_FALLBACK = {c: {"cveID": c, "vendorProject": "PHP Group", "product": "PHP", "dateAdded": "2026-10-26",
                    "dueDate": "2026-10-29", "knownRansomwareCampaignUse": "Unknown"} for c in PHP_CVES}
KEV_FALLBACK["CVE-2026-111497"] = {"cveID": "CVE-2026-111497", "vendorProject": "Google", "product": "Brotli",
                                   "dateAdded": "2026-10-27", "dueDate": "2026-11-10",
                                   "knownRansomwareCampaignUse": "Unknown"}
KEV_FALLBACK_VERSION = "2026.10.28"

VULN, EOL, PATCHED, UNKNOWN = "VULNERABLE", "VULNERABLE_EOL", "PATCHED", "UNKNOWN"
SUPPORTED = "SUPPORTED"  # Python only: a supported branch (no CVE is checked against the interpreter)
ICON = {VULN: "\U0001F534", EOL: "\U0001F7E0", PATCHED: "\U0001F7E2", UNKNOWN: "\u26AA", SUPPORTED: "\U0001F7E2"}

REL_TYPES = ("HOST", "PROCESS_GROUP", "CLOUD_APPLICATION", "CLOUD_APPLICATION_NAMESPACE",
             "KUBERNETES_CLUSTER")


# --------------------------------------------------------------------------- #
# Version classification
# --------------------------------------------------------------------------- #
def parse_version(raw):
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", raw or "")
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


def classify(tech, raw):
    v = parse_version(raw)
    if v is None:
        return UNKNOWN
    if tech == "PHP":
        branch = v[:2]
        if branch <= PHP_EOL_MAX:
            return EOL
        fixed = PHP_FIXED.get(branch)
        if fixed is None:  # newer than the newest known branch
            return PATCHED if branch > max(PHP_FIXED) else EOL
        return PATCHED if v >= fixed else VULN
    if tech == "PYTHON":
        return EOL if (v[0] < 3 or v[:2] <= PYTHON_EOL_MAX) else SUPPORTED
    if tech == "DOTNET":
        fixed = DOTNET_FIXED.get(v[0])
        if fixed:
            return PATCHED if v >= fixed else VULN
        return UNKNOWN if v[0] == 11 else EOL  # 11 = release candidate (needs RC3); everything else is unsupported
    fixed = NODE_FIXED.get(v[0])  # Node.js
    if fixed:
        return PATCHED if v >= fixed else VULN
    return PATCHED if v[0] > max(NODE_FIXED) else EOL


# --------------------------------------------------------------------------- #
# Dynatrace API client
# --------------------------------------------------------------------------- #
class DT:
    def __init__(self, base, token, verify=True, ca_bundle=None, timeout=60):
        self.base = base.rstrip("/")
        self.token = token
        self.timeout = timeout
        if not verify:
            self.ctx = ssl._create_unverified_context()
        else:
            self.ctx = ssl.create_default_context(cafile=ca_bundle) if ca_bundle else None

    def call(self, method, path, params=None, body=None):
        url = self.base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Authorization": "Api-Token " + self.token, "Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json; charset=utf-8"
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        for attempt in range(4):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
                    raw = r.read()
                    return json.loads(raw) if raw else {}
            except urllib.error.HTTPError as e:
                detail = e.read().decode("utf-8", "replace")[:4000]
                if e.code in (429, 502, 503) and attempt < 3:
                    time.sleep(2 ** attempt * 2)
                    continue
                hint = {401: " (token invalid/expired)",
                        403: " (token is missing a required scope)",
                        404: " (check the URL; Managed needs https://<host>/e/<env-id>)"}.get(e.code, "")
                raise SystemExit("HTTP %s on %s %s%s\n%s" % (e.code, method, path, hint, detail))
            except urllib.error.URLError as e:
                raise SystemExit("Cannot reach %s: %s\n(self-signed Managed cert? try --insecure "
                                 "or --ca-bundle file.pem)" % (self.base, e.reason))

    def token_owner(self):
        """Owner (Dynatrace user) of the API token = whoever runs the script. None if it cannot be determined."""
        try:
            return self.call("POST", "/api/v2/apiTokens/lookup", body={"token": self.token}).get("owner") or None
        except SystemExit:
            return None

    def share_with_all_as_editors(self, dashboard_id):
        """Everyone in the environment can view AND edit the dashboard. Returns True on success."""
        try:
            self.call("PUT", "/api/config/v1/dashboards/%s/shareSettings" % dashboard_id,
                      body={"id": dashboard_id, "enabled": True, "permissions": [{"type": "ALL", "permission": "EDIT"}]})
            return True
        except SystemExit as e:
            print("Warning: could not share the dashboard with all users as editors: %s" % str(e).splitlines()[0])
            return False

    def entities(self, selector, fields, frm, page_size=500):
        params = {"entitySelector": selector, "fields": fields, "pageSize": page_size, "from": frm}
        out = []
        while True:
            r = self.call("GET", "/api/v2/entities", params)
            out.extend(r.get("entities", []))
            nxt = r.get("nextPageKey")
            if not nxt:
                return out
            params = {"nextPageKey": nxt}  # next pages accept only the key


def normalize_base(url):
    url = url.strip().rstrip("/")
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    return url


# --------------------------------------------------------------------------- #
# Data collection
# --------------------------------------------------------------------------- #
def collect(dt, frm, running_minutes, techs):
    wanted_types = {TECHS[t][0]: TECHS[t][1] for t in techs}
    print("Reading %s processes (%s) ..." % (" + ".join(wanted_types.values()), frm))
    selector = 'type("PROCESS_GROUP_INSTANCE"),softwareTechnologies(%s)' % ",".join('"%s"' % t for t in wanted_types)
    pgis = dt.entities(selector, "+properties,+fromRelationships,+toRelationships", frm)

    php = []  # (entity, technology label, version); one entry per process and technology
    for e in pgis:
        techs_found = (e.get("properties") or {}).get("softwareTechnologies") or []
        for dtype, label in wanted_types.items():
            hits = [t for t in techs_found if str(t.get("type", "")).upper() == dtype]
            if dtype == "DOTNET" and any("framework" in (t.get("edition") or "").lower() for t in hits):
                continue  # .NET Framework is not affected by the October 2026 updates
            if hits:
                php.append((e, label, next((t.get("version") for t in hits if t.get("version")), ""),
                            dtype, next((t.get("edition") for t in hits if t.get("edition")), "")))
    print("  %d matching processes" % len(php))

    # Kubernetes context (namespace / cluster / workload) hangs off the container group instance
    cgi_ids = sorted({r["id"] for e, _, _, _, _ in php for rels in (e.get("fromRelationships") or {}).values()
                      for r in rels if r.get("type") == "CONTAINER_GROUP_INSTANCE"})
    cgi_rels = {}
    for i in range(0, len(cgi_ids), 50):
        sel = 'type("CONTAINER_GROUP_INSTANCE"),entityId(%s)' % ",".join('"%s"' % c for c in cgi_ids[i:i + 50])
        for c in dt.entities(sel, "+fromRelationships", "now-30d"):
            cgi_rels[c["entityId"]] = c.get("fromRelationships") or {}

    def related(e):
        groups = [e.get("fromRelationships") or {}, e.get("toRelationships") or {}]
        for rels in (e.get("fromRelationships") or {}).values():
            groups += [cgi_rels[r["id"]] for r in rels if r.get("id") in cgi_rels]
        rel = defaultdict(list)
        for group in groups:
            for rels in group.values():
                for r in rels:
                    if r.get("type") in REL_TYPES and r["id"] not in rel[r["type"]]:
                        rel[r["type"]].append(r["id"])
        return rel

    # Resolve related entity names (host, workload, namespace, cluster, process group)
    wanted = defaultdict(set)
    for e, _, _, _, _ in php:
        for t, ids in related(e).items():
            wanted[t].update(ids)
    names, host_os = {}, {}
    for etype, idset in wanted.items():  # one type per query, mixed types are rejected
        ids = sorted(idset)
        for i in range(0, len(ids), 50):
            sel = 'type("%s"),entityId(%s)' % (etype, ",".join('"%s"' % c for c in ids[i:i + 50]))
            for ent in dt.entities(sel, "+properties.osType" if etype == "HOST" else "", "now-30d"):
                names[ent["entityId"]] = ent.get("displayName") or ent["entityId"]
                if etype == "HOST":
                    host_os[ent["entityId"]] = (ent.get("properties") or {}).get("osType") or ""

    now_ms = time.time() * 1000
    rows = []
    for e, tech, ver, dtype, edition in php:
        rel = related(e)

        def first(t):
            return names.get(rel[t][0], rel[t][0]) if rel.get(t) else ""

        ns, cluster, workload = first("CLOUD_APPLICATION_NAMESPACE"), first("KUBERNETES_CLUSTER"), first("CLOUD_APPLICATION")
        host_id = rel["HOST"][0] if rel.get("HOST") else ""
        pg_id = rel["PROCESS_GROUP"][0] if rel.get("PROCESS_GROUP") else ""
        props = e.get("properties") or {}
        scope = "Kubernetes" if ns else "Compute"
        last = e.get("lastSeenTms") or 0
        running = (now_ms - last) <= running_minutes * 60000 if last else True
        rows.append({
            "id": e["entityId"], "name": e.get("displayName", ""),
            "tech": tech, "tech_type": dtype, "edition": edition, "status": classify(TECH_KEY[tech], ver),
            "version": ver or "n/a", "scope": scope,
            "environment": ns if ns else first("HOST"),
            "cluster": cluster, "workload": workload or first("PROCESS_GROUP") or e.get("displayName", ""),
            "host": first("HOST"), "host_id": host_id, "pg_id": pg_id, "os": host_os.get(host_id, ""),
            "image": props.get("containerImageName", "") or "",
            "ports": ",".join(str(x) for x in props.get("listenPorts") or []),
            "state": "running" if running else "ended",
        })
    return len(pgis), rows


# --------------------------------------------------------------------------- #
# Dashboard rendering (classic dashboard JSON, markdown tiles)
# --------------------------------------------------------------------------- #
def esc(s):
    return str(s).replace("|", "/").replace("\n", " ").replace("\r", " ")


def bar(n, total, width=12):
    filled = 0 if not total else max(1 if n else 0, round(width * n / total))
    return "█" * filled + "░" * (width - filled)


def short_name(name, n=42):
    m = re.search(r"\(([^)]+)\)", name or "")
    return (m.group(1) if m else name or "")[:n]


def fix_for(tech, raw, status):
    """What to upgrade to, for the remediation lists."""
    v = parse_version(raw)
    if status in (PATCHED, SUPPORTED):
        return "ok"
    if status == UNKNOWN or v is None:
        return "check version"
    if tech == "PHP":
        fixed = PHP_FIXED.get(v[:2])
        return ".".join(map(str, fixed)) if fixed else "migrate to %s+" % ".".join(map(str, PHP_FIXED[max(PHP_FIXED)]))
    if tech == "Python":
        return "migrate to Python 3.11+ (3.13 or 3.14 recommended)"
    if tech == ".NET":
        if v[0] == 11:
            return "update to .NET 11 RC3"
        fixed = DOTNET_FIXED.get(v[0])
        return ".".join(map(str, fixed)) if fixed else "migrate to %s+" % ".".join(map(str, DOTNET_FIXED[min(DOTNET_FIXED)]))
    fixed = NODE_FIXED.get(v[0])
    return ".".join(map(str, fixed)) if fixed else "migrate to %s+" % ".".join(map(str, NODE_FIXED[min(NODE_FIXED)]))


def est_height(lines, col_width):
    """Rendered height: only link text counts, not the URL; ~7px per char, ~21px per line."""
    chars = max(30, int((col_width - 60) / 7.0))
    n = sum(-(-max(1, len(re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", l))) // chars) for l in lines)
    return max(76, 38 * -(-(40 + 21 * n) // 38))


def load_kev(offline=False, timeout=10):
    """CISA KEV entries (cveID -> entry), catalog version and whether it came live from cisa.gov.
    Falls back to the built-in snapshot when cisa.gov cannot be reached (for example an air-gapped Managed network)."""
    if not offline:
        try:
            req = urllib.request.Request(KEV_JSON_URL, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                d = json.loads(r.read().decode("utf-8"))
            return {v["cveID"]: v for v in d["vulnerabilities"]}, d.get("catalogVersion", "?"), True
        except Exception as e:  # network, TLS, proxy or format problems: use the snapshot
            print("Note: could not read the CISA KEV feed (%s); using the built-in snapshot." % e.__class__.__name__)
    return dict(KEV_FALLBACK), KEV_FALLBACK_VERSION, False


def cve_tile_specs(used, kev=None):
    """Rows of (name, markdown, relative width) tiles describing the CVEs evaluated, with their CISA KEV status."""
    kev_entries, kev_version, kev_live = kev if kev else ({}, "n/a", False)

    def kev_note(ids, what=""):
        hit = [c for c in ids if c in kev_entries]
        if not hit:
            return ""
        e = kev_entries[hit[0]]
        return "\U0001F6A8 **In CISA KEV%s**: %s, added %s, remediation due **%s**.\n\n" % (
            what, ", ".join(hit), e.get("dateAdded", "?"), e.get("dueDate", "?"))

    first, second = [], []
    if "PHP" in used:
        first.append(("PHP2Shell - CVE-2026-109618 / CVE-2026-109619",
                      "**PHP2Shell**\n\n**CVE-2026-109618**\n\n**CVE-2026-109619**\n\n"
                      "CVSS 4.0 **9.2 Critical**: unauthenticated remote code execution in the PHP core. "
                      "Disclosed 2026-10-21.\n\nFixed in **8.5.12 \u00B7 8.4.27 \u00B7 8.3.36 \u00B7 8.2.35**. "
                      "8.1 and older are EOL, no fix.\n\n" + kev_note(PHP_CVES) +
                      "[php.net advisory](https://www.php.net/archive/2026.php#2026-10-21-1)", 380))
    if "Node.js" in used:
        def cve_line(c):
            return "* **%s** %s: %s" % c
        half = (len(NODE_CVES) + 1) // 2
        head = ("**Node.js Oct-2026 security releases** (10 CVEs), fixed in **22.23.4 \u00B7 24.22.1 \u00B7 26.12.1**. "
                "[Advisory](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)\n\n"
                + kev_note([c[0] for c in NODE_CVES]))
        first.append(("Node.js CVEs (1/2)", head + "\n".join(cve_line(c) for c in NODE_CVES[:half]), 570))
        first.append(("Node.js CVEs (2/2)", "\n".join(cve_line(c) for c in NODE_CVES[half:]), 570))
    if ".NET" in used:
        second.append((".NET CVEs",
                       "**.NET October 2026 out-of-band updates** (2026-10-25), fixed in **8.0.33 \u00B7 9.0.22 \u00B7 10.0.14** "
                       "(.NET 11: RC3). [Advisory](https://devblogs.microsoft.com/dotnet/dotnet-october-2026-oob-security-updates/)\n\n"
                       + kev_note([c[0] for c in DOTNET_CVES])
                       + "\n".join("* **%s** %s" % c for c in DOTNET_CVES)
                       + "\n\nSelf-contained apps and containers must be rebuilt; a newer host runtime does not update them.",
                       760))
    if "Python" in used:
        second.append(("Python end-of-life and the Brotli library CVE",
                       "**Python** (end-of-life check, [python.org lifecycle](https://devguide.python.org/versions/))\n\n"
                       "3.10 and older are **end of life** (3.10 on 2026-10-01, 3.9 on 2025-10-31, 3.8 on 2024-10-07); "
                       "3.11 to 3.15 are supported.\n\n"
                       + kev_note(PYTHON_CVES, " (the Brotli library)") +
                       "**CVE-2026-111497 does not affect the interpreter.** It is a bug in the Google Brotli library "
                       "(1.0.3 to 1.2.0, fixed in 1.0.10 / 1.1.1 / 1.2.1, CVSS 3.1 9.8), which reaches Python through the "
                       "`Brotli` and `brotlicffi` (below 1.2.1.0) packages. OneAgent process data cannot see installed "
                       "packages, so check Runtime Vulnerability Analytics or your SCA findings "
                       "([NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-111497)).", 760))
    return [r for r in (first, second) if r]


def place_cve_tiles(rows_specs, W, top):
    """Lay the CVE tiles out row by row. Returns ([(name, text, top, left, width, height)], new_top)."""
    placed = []
    for row in rows_specs:
        scale = W / float(sum(w for _, _, w in row))
        widths = [int(round(w * scale / 38.0)) * 38 for _, _, w in row]
        widths[-1] = W - sum(widths[:-1])
        h = max(est_height(t.split("\n"), w) for (_, t, _), w in zip(row, widths))
        left = 0
        for (name, text, _), w in zip(row, widths):
            placed.append((name, text, top, left, w, h))
            left += w
        top += h
    return placed, top


def build_dashboard_markdown(base, rows, total_scanned, args):
    used = [TECHS[t][1] for t in args.techs]
    LIMIT = 1000  # Dynatrace markdown tiles hold at most 1000 characters
    W = 1520

    def link(kind, eid, label):
        return "[%s](%s/#%s;id=%s)" % (esc(label), base, kind, eid) if eid else esc(label)

    if args.running_only:
        rows = [r for r in rows if r["state"] == "running"]
    bad = [r for r in rows if r["status"] in (VULN, EOL)]
    eol = [r for r in bad if r["status"] == EOL]
    k8s = [r for r in bad if r["scope"] == "Kubernetes"]
    comp = [r for r in bad if r["scope"] == "Compute"]
    unknown = [r for r in rows if r["status"] == UNKNOWN]
    running_all = [r for r in rows if r["state"] == "running"]
    patched_running = [r for r in running_all if r["status"] in (PATCHED, SUPPORTED)]
    compliance = (100.0 * len(patched_running) / len(running_all)) if running_all else 100.0
    exposed_pct = (100.0 * len(bad) / len(rows)) if rows else 0.0
    stamp = time.strftime("%Y-%m-%d %H:%M %Z")

    # remediation targets: one per workload (Kubernetes) or host (Compute)
    targets = {}
    for r in bad:
        key = (r["tech"], r["scope"], r["cluster"], r["environment"],
               r["workload"] if r["scope"] == "Kubernetes" else r["host"])
        t = targets.setdefault(key, {"rows": [], "pg": r["pg_id"], "host": r["host_id"]})
        t["rows"].append(r)
    envs = {(r["scope"], r["environment"]) for r in bad}

    tiles = []

    def tile(kind, name, top, left, width, height, text=None):
        d = {"name": name, "tileType": kind, "configured": True,
             "bounds": {"top": top, "left": left, "width": width, "height": height}, "tileFilter": {}}
        if text is not None:
            d["markdown"] = text if len(text) <= LIMIT else text[:LIMIT - 4] + " ..."
        tiles.append(d)

    def md(name, text, top, left, width, height):
        tile("MARKDOWN", name, top, left, width, height, text)

    def header(text, top):
        tile("HEADER", text, top, 0, W, 38)
        return top + 38

    def cards(name, lines, top, cols=2, empty="_Nothing to show._"):
        """Bullet lines packed into <=1000 char tiles, laid out in `cols` columns."""
        chunks, cur = [], []
        for l in lines:
            if cur and len("\n".join(cur + [l])) > LIMIT - 40:
                chunks.append(cur)
                cur = []
            cur.append(l)
        if cur:
            chunks.append(cur)
        if not chunks:
            chunks = [[empty]]
        width = W // cols
        for i in range(0, len(chunks), cols):
            row = chunks[i:i + cols]
            h = max(est_height(c, width) for c in row)
            for j, c in enumerate(row):
                n = i + j
                title = name if len(chunks) == 1 else "%s (%d/%d)" % (name, n + 1, len(chunks))
                md(title, "\n".join(c), top, j * width, width, h)
            top += h
        return top

    # ------------------------------------------------------------------ executive
    top = header("CVES BEING CHECKED   |   a process is flagged when its runtime version is below the release that fixes them", 0)
    placed, top = place_cve_tiles(cve_tile_specs(used, args.kev), W, top)
    for name, text, t_top, t_left, t_w, t_h in placed:
        md(name, text, t_top, t_left, t_w, t_h)

    top = header("EXECUTIVE SUMMARY   |   %s   |   snapshot %s" % (" + ".join(used), stamp), top)

    md("Legend - how to read the colors",
       "**Status:** \U0001F534 **VULNERABLE** supported version without the fix \u00B7 "
       "\U0001F7E0 **VULNERABLE_EOL** end-of-life version, no patch exists, migrate \u00B7 "
       "\U0001F7E2 **PATCHED** at or above the fixed release \u00B7 \u26AA **UNKNOWN** version unreadable, check manually\n\n"
       "**Tiles:** \U0001F534 action needed \u00B7 \U0001F7E0 no fix available, migration needed \u00B7 "
       "\U0001F7E2 all clear \u00B7 \u26AA informational. **Bars** `\u2588\u2588\u2588\u2591\u2591` show the share "
       "of the total within each list.",
       top, 0, W, 114)
    top += 114

    if not rows:
        verdict = "# ⚪ No %s processes found\nNothing detected in timeframe `%s`." % (" / ".join(used), args.frm)
    elif not bad:
        verdict = "# \U0001F7E2 No exposed processes\nAll %d processes are on a fixed version." % len(rows)
    else:
        php_bad = [r for r in bad if r["tech"] == "PHP"]
        verdict = ("# \U0001F534 %d of %d processes exposed\n**%.1f%% need action** · %d patched\n\n"
                   "**%d** workloads / hosts to fix across **%d** environments "
                   "(%d Kubernetes · %d Compute processes)"
                   % (len(bad), len(rows), exposed_pct, len(rows) - len(bad) - len(unknown),
                      len(targets), len(envs), len(k8s), len(comp)))
        if php_bad:
            verdict += ("\n\n\U0001F6A8 **PHP2Shell (CVSS 9.2, unauthenticated RCE): %d process(es) - fix these first.**"
                        % len(php_bad))
        if eol:
            verdict += "\n\n⚠ **%d process(es) are end-of-life** - no patch exists, migration needed." % len(eol)
    md("Verdict", verdict, top, 0, 760, 266)

    by_tech = Counter(r["tech"] for r in rows)
    bad_tech = Counter(r["tech"] for r in bad)
    tech_lines = ["* **%s**  `%s`  %d of %d exposed (%.0f%%)" % (t, bar(bad_tech[t], n), bad_tech[t], n,
                                                              100.0 * bad_tech[t] / n)
                  for t, n in sorted(by_tech.items())] or ["_none_"]
    tech_lines.append("")
    by_scope = Counter(r["scope"] for r in bad)
    tech_lines += ["* **%s**  `%s`  %d exposed" % (sc, bar(by_scope[sc], len(bad)), by_scope[sc])
                   for sc in ("Kubernetes", "Compute") if bad]
    md("Exposure by technology and scope", "\n".join(tech_lines), top + 266, 0, 760, 190)

    def kpi(label, value, col, row, icon=""):
        md(label, "# %s%s\n%s" % (icon + " " if icon else "", value, label), top + row * 114, 760 + col * 380, 380, 114)

    red = "\U0001F534" if bad else "\U0001F7E2"
    kpi("vulnerable processes", len(bad), 0, 0, red)
    kpi("workloads / hosts to fix", len(targets), 1, 0, red)
    kpi("impacted environments", len(envs), 0, 1, red)
    kpi("compliance (patched / running)", "%.1f%%" % compliance, 1, 1, red if compliance < 100 else "\U0001F7E2")
    kpi("end-of-life, no fix", len(eol), 0, 2, "\U0001F7E0" if eol else "\U0001F7E2")
    kpi("unknown version", len(unknown), 1, 2, "⚪")
    kpi("Kubernetes exposed", len(k8s), 0, 3, red if k8s else "\U0001F7E2")
    kpi("Compute exposed", len(comp), 1, 3, red if comp else "\U0001F7E2")
    top += 456

    # ------------------------------------------------------------------ breakdown
    top = header("EXPOSURE BREAKDOWN", top)
    by_status = Counter(r["status"] for r in rows)
    md("By status",
       "\n".join("* %s **%s**  `%s`  %d" % (ICON[st], st, bar(by_status.get(st, 0), len(rows)), by_status.get(st, 0))
                 for st in (VULN, EOL, PATCHED, SUPPORTED, UNKNOWN) if st != SUPPORTED or by_status.get(st)), top, 0, 456, 266)
    by_ver = Counter((r["tech"], r["version"], r["status"]) for r in rows)
    top_ver = sorted(by_ver.items(), key=lambda x: (x[0][0] != "PHP", -x[1], x[0]))  # PHP2Shell first
    mx = max((n for _, n in top_ver), default=0)
    vlines = ["* %s **%s %s**  `%s`  %d" % (ICON[st], t, v, bar(n, mx), n) for (t, v, st), n in top_ver[:8]]
    if len(top_ver) > 8:
        vlines.append("_+%d more versions (see CSV)_" % (len(top_ver) - 8))
    md("Top versions in use", "\n".join(vlines) or "_none_", top, 456, 532, 266)
    by_env = Counter((r["scope"], r["environment"], r["cluster"]) for r in bad)
    top_env = by_env.most_common(7)
    mx = top_env[0][1] if top_env else 0
    elines = ["* **%s**%s  `%s`  %d" % (esc(e[:32]), " (%s)" % esc(c[:14]) if c else "", bar(n, mx, 8), n)
              for (sc, e, c), n in top_env]
    if len(by_env) > 7:
        elines.append("_+%d more environments (see CSV)_" % (len(by_env) - 7))
    md("Most exposed namespaces / hosts", "\n".join(elines) or "_none_", top, 988, 532, 266)
    row = tiles[-3:]
    h = max(est_height(t["markdown"].split("\n"), t["bounds"]["width"]) for t in row)
    for t in row:
        t["bounds"]["height"] = h
    top += h

    # ------------------------------------------------------------------ practitioner
    top = header("REMEDIATION PLAN   |   what to upgrade, and where (PHP first: critical RCE)", top)

    def target_line(key, t):
        tech, scope, cluster, env, loc = key
        rs = t["rows"]
        icon = ICON[VULN] if any(r["status"] == VULN for r in rs) else ICON[EOL]
        vers = ", ".join(sorted({r["version"] for r in rs}))
        fixes = " / ".join(sorted({fix_for(tech, r["version"], r["status"]) for r in rs}))
        if scope == "Kubernetes":
            name = link("processgroupdetails", t["pg"], loc[:40])
            where = "%s%s" % (esc(env[:30]), " · " + esc(cluster[:20]) if cluster else "")
        else:
            name = link("hostdetails", t["host"], loc[:45])
            where = "host"
        return "* %s **%s** · %s · %s %s → **%s** · %d proc" % (
            icon, name, where, tech, esc(vers[:30]), esc(fixes[:40]), len(rs))

    ordered = sorted(targets.items(), key=lambda x: (x[0][0] != "PHP", -len(x[1]["rows"])))
    for tech in [t for t in used if t in {k[0] for k in targets}]:
        mine = [(k, v) for k, v in ordered if k[0] == tech]
        lines = [target_line(k, v) for k, v in mine[:args.max_rows]]
        if len(mine) > args.max_rows:
            lines.append("_+%d more targets (see CSV)_" % (len(mine) - args.max_rows))
        label = "%s - %d workloads / hosts to fix" % (tech, len(mine))
        if tech == "PHP":
            label = "PRIORITY 1 · " + label + " (CVSS 9.2)"
        top = cards(label, lines, top)
    if not targets:
        top = cards("Nothing to fix", ["No exposed workloads or hosts."], top, cols=1)

    top = header("PROCESS DETAIL   |   sample of vulnerable processes (open in Dynatrace)", top)
    plines = ["* %s **%s %s** · %s · %s · %s" % (
        ICON[r["status"]], r["tech"], r["version"], esc(r["environment"][:28]),
        link("processdetails", r["id"], short_name(r["name"])), r["state"])
        for r in sorted(bad, key=lambda r: (r["tech"] != "PHP", r["status"], r["environment"], r["name"]))[:10]]
    if len(bad) > 10:
        plines.append("_Showing 10 of %d processes, PHP first. Full list: --csv export, or the targets above._" % len(bad))
    top = cards("Vulnerable processes", plines, top)

    if unknown:
        ulines = ["* ⚪ %s · %s · %s" % (r["tech"], esc(r["environment"][:28]),
                                                    link("processdetails", r["id"], short_name(r["name"])))
                  for r in unknown[:args.max_rows]]
        top = cards("Unreadable versions - check manually", ulines, top)

    top = header("ABOUT THIS DASHBOARD", top)
    md("Method and caveats",
       "**Status** comes from the version OneAgent detected: VULNERABLE (fix not applied), "
       "VULNERABLE_EOL (end-of-life line), PATCHED, UNKNOWN. **Version-only:** distro vendors may backport fixes "
       "without changing the version, verify with `rpm -q` / `dpkg -l`. Timeframe `%s`%s. "
       "Re-run the script to refresh this snapshot."
       % (args.frm, ", running only" if args.running_only else ""),
       top, 0, W, 190)

    return {"dashboardMetadata": {"name": args.name, "shared": args.shared, "owner": args.owner,
                                  "dashboardFilter": {"timeframe": "-2h"}, "hasConsistentColors": False},
            "tiles": tiles}


# --------------------------------------------------------------------------- #
# Native layout: live Data explorer tiles (single values, trend graphs, process tables)
# --------------------------------------------------------------------------- #
PGI_DIM = "dt.entity.process_group_instance"
VALUE_NAME = "Processes"        # series name shown for single values and tables; threshold rules refer to it
SERIES_NAMES = ["All processes", "Patched"]  # trend graph legend
MAX_VERSIONS_PER_PREDICATE = 50  # Dynatrace entity selector limit for softwareTechnologies.version
NODE_PATCH_RANGE = 6             # enumerate Node.js patch numbers 0..5 (plus every version actually seen)


def _chunks(items, n):
    for i in range(0, len(items), n):
        yield items[i:i + n]


def _dedupe(items):
    seen, out = set(), []
    for i in items:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


def version_buckets(tech, seen):
    """Version strings per status bucket. The entity selector matches exact versions, so each bucket is enumerated:
    every patch release in the range that matters, plus every version actually found by the scan."""
    b = {"vulnerable": [], "patched": [], "eol_backport": [], "eol_nofix": [], "eol_seen": []}
    if tech == "PHP":
        for (ma, mi), fx in PHP_FIXED.items():
            b["vulnerable"] += ["%d.%d.%d" % (ma, mi, p) for p in range(0, fx[2])]
            b["patched"] += ["%d.%d.%d" % (ma, mi, p) for p in range(fx[2], fx[2] + 31)]
        b["patched"] += ["%d.%d.%d" % (ma, mi, p) for ma, mi in ((8, 6), (8, 7), (9, 0), (9, 1)) for p in range(31)]
        b["eol_backport"] = ["8.%d.%d" % (mi, p) for mi in (1, 0) for p in range(41)]
        b["eol_nofix"] = ["%d.%d.%d" % (ma, mi, p) for ma, mis in ((7, range(5)), (5, range(7))) for mi in mis
                          for p in range(41)]
    elif tech == "Python":
        b["patched"] = ["3.%d.%d" % (mi, p) for mi in range(11, 16) for p in range(41)]  # supported: 3.11 to 3.15
        b["eol_nofix"] = ["%d.%d.%d" % (ma, mi, p) for ma, mi in ((3, 10), (3, 9), (3, 8), (3, 7), (3, 6), (2, 7))
                          for p in range(31)]
    elif tech == ".NET":
        for major, (ma, mi, pa) in DOTNET_FIXED.items():  # OneAgent reports e.g. 8.0.18.0
            b["vulnerable"] += ["%d.%d.%d.0" % (ma, mi, p) for p in range(0, pa)]
            b["patched"] += ["%d.%d.%d.0" % (ma, mi, p) for p in range(pa, pa + 31)]
        b["eol_nofix"] = ["%d.%d.%d.0" % (ma, mi, p) for ma, mi, top_p in
                          ((7, 0, 25), (6, 0, 45), (5, 0, 20), (3, 1, 40), (3, 0, 20), (2, 2, 10), (2, 1, 40))
                          for p in range(top_p + 1)]
    else:
        for major, (_, fmi, fpa) in NODE_FIXED.items():
            for mi in range(0, fmi + 1):
                for pa in range(NODE_PATCH_RANGE):
                    if (mi, pa) < (fmi, fpa):
                        b["vulnerable"].append("%d.%d.%d" % (major, mi, pa))
            for mi in range(fmi, fmi + 9):
                for pa in range(NODE_PATCH_RANGE):
                    if (mi, pa) >= (fmi, fpa):
                        b["patched"].append("%d.%d.%d" % (major, mi, pa))
    for r in seen:  # make sure every version present today lands in the right bucket
        v = parse_version(r["version"])
        if r["tech"] != tech or v is None:
            continue
        name = {VULN: "vulnerable", PATCHED: "patched", SUPPORTED: "patched"}.get(r["status"])
        if name is None and r["status"] == EOL:
            name = (("eol_backport" if v[:2] >= (8, 0) else "eol_nofix") if tech == "PHP"
                    else "eol_nofix" if tech in (".NET", "Python") else "eol_seen")
        if name:
            b[name].append(r["version"])
    return {k: _dedupe(v) for k, v in b.items()}


def _in(entity_selector):
    return 'in("%s",entitySelector("%s"))' % (PGI_DIM, entity_selector)


def _versions_in(dtype, versions):
    return [_in('type(process_group_instance),softwareTechnologies.version(%s)'
                % ",".join('~"%s:%s~"' % (dtype, v) for v in chunk))
            for chunk in _chunks(versions, MAX_VERSIONS_PER_PREDICATE)]


def _hosts_running(dtype, versions):
    """Metric-selector filters for the hosts that run at least one process with one of these versions."""
    return [('in("dt.entity.host",entitySelector("type(host),toRelationships.isProcessOf('
             'type(process_group_instance),softwareTechnologies.version(%s))"))')
            % ",".join('~"%s:%s~"' % (dtype, v) for v in chunk)
            for chunk in _chunks(versions, MAX_VERSIONS_PER_PREDICATE)]


def _or(parts):
    return parts[0] if len(parts) == 1 else "or(%s)" % ",".join(parts)


def _metric(filter_expr, kind):
    base = "builtin:pgi.availability.state:filter(%s)" % filter_expr
    if kind == "count":
        return base + ":splitBy():count"
    # Do not split by dt.host_group.id: series without a host group would silently drop out of the table.
    return base + ':last:splitBy("%s","dt.entity.host"):sort(value(auto,descending))' % PGI_DIM


def build_dashboard_native(base, rows, total_scanned, args):
    used = [TECHS[t][1] for t in args.techs]
    dtypes = {TECHS[t][1]: TECHS[t][0] for t in args.techs}
    W = 1520
    tiles = []

    def add(kind, name, top, left, width, height, **extra):
        d = {"name": name, "tileType": kind, "configured": True,
             "bounds": {"top": top, "left": left, "width": width, "height": height}, "tileFilter": {}}
        d.update(extra)
        tiles.append(d)

    def md(name, text, top, left, width, height):
        add("MARKDOWN", name, top, left, width, height, markdown=text)

    def header(text, top):
        add("HEADER", text, top, 0, W, 38, isAutoRefreshDisabled=False)
        return top + 38

    # Threshold colors. Dynatrace stores rules from the highest value down: a tile gets the color of the first rule
    # whose value is <= the count, and the last rule (no value) is the fallback.
    BLUE, GREEN, YELLOW, RED, ORANGE, FALLBACK = "#1496ff", "#2ab06f", "#f5d30f", "#c4233b", "#fd8232", "#dc172a"

    def alert(color):  # any process at all (>= 1) is bad, none (0) is good
        return [(1, color), (0, GREEN), (None, FALLBACK)]

    def solid(color):
        return [(0, color)]

    patched_rule = [(1, GREEN), (0, YELLOW), (None, FALLBACK)]  # nothing patched yet shows yellow

    def visual(kind, colors, thresholds=None, aliases=None):
        v = {"type": kind, "global": {},
                "rules": [dict(matcher="%s:" % "AB"[i], properties=dict(
                    color=c, **({"seriesType": "LINE"} if kind == "GRAPH_CHART" else {}),
                    **({} if aliases == [] else {"alias": (aliases or SERIES_NAMES)[i] if kind == "GRAPH_CHART" else VALUE_NAME})),
                    seriesOverrides=[]) for i, c in enumerate(colors)],
                "axes": {"xAxis": {"visible": True}, "yAxes": []}, "heatmapSettings": {"yAxis": "VALUE"},
                "thresholds": [], "tableSettings": {"isThresholdBackgroundAppliedToCell": False,
                                                    "hiddenColumns": []},
                "graphChartSettings": {"connectNulls": False},
                "honeycombSettings": {"showHive": True, "showLegend": True, "showLabels": False}}
        if thresholds:  # color the whole single-value tile, not just the sparkline
            v["thresholds"] = [{"axisTarget": "LEFT", "columnId": VALUE_NAME, "queryId": "A", "visible": True,
                                "rules": [{"value": val, "color": c} if val is not None else {"color": c}
                                          for val, c in thresholds]}]
            v["singleValueSettings"] = {"showTrend": False, "showSparkLine": False, "linkTileColorToThreshold": True}
        return v

    def explorer(name, selectors, kind, colors, top, left, width, height, thresholds=None, aliases=None):
        qs = [{"id": "AB"[i], "spaceAggregation": "AUTO", "timeAggregation": "DEFAULT", "metricSelector": sel,
               "rate": "NONE", "enabled": True, "histogram": False} for i, sel in enumerate(selectors)]
        if kind == "TABLE":
            exprs = ["resolution=null&(%s):names:fold(auto)" % selectors[0]]
        elif len(selectors) > 1 or kind == "GRAPH_CHART":
            exprs = ["resolution=null&" + ",".join("(%s):limit(100):names" % x for x in selectors)]
        else:
            exprs = ["resolution=Inf&(%s):limit(100):names" % selectors[0], "resolution=null&(%s)" % selectors[0]]
        add("DATA_EXPLORER", name, top, left, width, height, isAutoRefreshDisabled=False, customName=name,
            queries=qs, visualConfig=visual(kind, colors, thresholds, aliases), queriesSettings={"resolution": ""},
            **({} if args.slim else {"metricExpressions": exprs}))

    # ---- header
    top = header("%s exposure  |  live from OneAgent process technology data" % " & ".join(used), 0)

    # ---- per technology: KPI row + trend
    sels = {}
    exposed_versions = {}
    for tech in used:
        dtype = dtypes[tech]
        b = version_buckets(tech, rows)
        allp = _in("type(process_group_instance),softwareTechnologies(%s)" % dtype)
        vuln = _versions_in(dtype, b["vulnerable"])
        pat = _versions_in(dtype, b["patched"])
        f = {"all": allp, "vuln": _or(vuln) if vuln else None, "patched": _or(pat)}
        if tech == "PHP":
            f["eol_backport"] = _or(_versions_in(dtype, b["eol_backport"]))
            f["eol_nofix"] = _or(_versions_in(dtype, b["eol_nofix"]))
            f["eol"] = _or(_versions_in(dtype, b["eol_backport"] + b["eol_nofix"]))
        elif tech == "Python":  # no vulnerable status: 3.10 and older are end of life, 3.11+ supported
            eol_ins = _versions_in(dtype, b["eol_nofix"])
            f["eol"] = _or(eol_ins)
            f["unknown"] = "and(%s,not(%s))" % (allp, _or(pat + eol_ins))  # version not reported by OneAgent
        elif tech == ".NET":  # lines older than 8 are unsupported; .NET 11 (release candidate) is not classified
            f["eol"] = _or(_versions_in(dtype, b["eol_nofix"]))
            # OS matters: CVE-2026-114148 (tarball ownership) affects Linux only, CVE-2026-111497 all platforms
            linux = _in('type(process_group_instance),fromRelationships.isProcessOf(type(host),osType(~"LINUX~"))')
            f["vuln_linux"] = "and(%s,%s)" % (f["vuln"], linux)
        else:  # every other line (<= 21, 23, 25) is end of life: all Node.js that is in no fixed line
            f["eol"] = "and(%s,not(%s))" % (allp, _or(vuln + pat))
        sels[tech] = f
        # Host filter, kept short: PHP enumerates every vulnerable patch release; everything else uses the
        # exposed versions the scan actually found (a full enumeration would make the query too long).
        seen_exposed = _dedupe([r["version"] for r in rows
                                if r["tech"] == tech and r["status"] in (VULN, EOL) and parse_version(r["version"])])
        exposed_versions[tech] = (dtype, _dedupe((b["vulnerable"] if tech in ("PHP", ".NET") else []) + seen_exposed))

    # ---- summary: total, vulnerable, end-of-life and patched processes per technology
    top = header("SUMMARY  |  processes per technology: total, vulnerable, end-of-life, patched", top)
    order = [t for t in (("PHP", ".NET", "Node.js", "Python")) if t in used]
    for tech in order:
        f = sels[tech]
        if tech == "Python":  # no CVE is checked against the interpreter: end-of-life only
            cells = [("%s: total processes" % tech, f["all"], "BLUE", solid(BLUE)),
                     ("%s: version not reported" % tech, f["unknown"], "ORANGE", alert(YELLOW)),
                     ("%s: end-of-life (3.10 and older)" % tech, f["eol"], "RED", alert("#ef651f")),
                     ("%s: supported (3.11+)" % tech, f["patched"], "GREEN", solid(GREEN))]
        else:
            cells = [("%s: total processes" % tech, f["all"], "BLUE", solid(BLUE)),
                     ("%s: vulnerable, patch available" % tech, f["vuln"], "RED", alert(RED)),
                     ("%s: end-of-life / unsupported" % tech, f["eol"], "RED", alert("#ef651f")),
                     ("%s: patched" % tech, f["patched"], "GREEN", patched_rule)]
        for i, (name, flt, color, thr) in enumerate(cells):
            explorer(name, [_metric(flt, "count")], "SINGLE_VALUE", [color], top, i * (W // 4), W // 4, 114, thr)
        top += 114

    if args.detail:  # per-technology KPI rows (they repeat the summary and make the dashboard much taller)
        for tech in used:
            f = sels[tech]
            top = header("%s  |  %s" % (tech, TECH_SUBTITLE[tech]), top)
            if tech == "PHP":
                kpis = [("All PHP processes", f["all"], "BLUE", solid(BLUE)),
                        ("Patched (fixed release or newer)", f["patched"], "GREEN", patched_rule),
                        ("Vulnerable, patch available (8.2–8.5)", f["vuln"], "RED", alert(RED)),
                        ("EOL 8.0 / 8.1 (backport only)", f["eol_backport"], "RED", alert(ORANGE)),
                        ("EOL 7.x / 5.x (no fix)", f["eol_nofix"], "RED", alert(RED))]
            elif tech == "Python":
                kpis = [("All Python processes", f["all"], "BLUE", solid(BLUE)),
                        ("Version not reported by OneAgent", f["unknown"], "ORANGE", alert(YELLOW)),
                        ("End-of-life (3.10 and older)", f["eol"], "RED", alert("#ef651f")),
                        ("Supported (3.11 and newer)", f["patched"], "GREEN", solid(GREEN))]
            elif tech == ".NET":
                kpis = [("All .NET processes (.NET Framework is not affected)", f["all"], "BLUE", solid(BLUE)),
                        ("Patched (8.0.33 / 9.0.22 / 10.0.14 or newer)", f["patched"], "GREEN", patched_rule),
                        ("Vulnerable, patch available (8 / 9 / 10)", f["vuln"], "RED", alert(RED)),
                        ("EOL / unsupported (7 and older)", f["eol"], "RED", alert("#ef651f")),
                        ("Vulnerable on Linux: also check tarball installs (CVE-2026-114148)", f["vuln_linux"], "RED",
                         alert(RED))]
            else:
                kpis = [("All Node.js processes", f["all"], "BLUE", solid(BLUE)),
                        ("Patched (22.23.4 / 24.22.1 / 26.12.1 or newer)", f["patched"], "GREEN", patched_rule),
                        ("Vulnerable, patch available (22 / 24 / 26)", f["vuln"], "RED", alert(RED)),
                        ("EOL lines (no fix)", f["eol"], "RED", alert("#ef651f"))]
            kw = W // len(kpis)
            kw = kw - kw % 38
            for i, (name, flt, color, thr) in enumerate(kpis):
                explorer(name, [_metric(flt, "count")], "SINGLE_VALUE", [color], top, i * kw,
                         kw if i < len(kpis) - 1 else W - kw * (len(kpis) - 1), 152, thr)
            top += 152
            explorer("All %s vs patched over time" % tech, [_metric(f["all"], "count"), _metric(f["patched"], "count")],
                     "GRAPH_CHART", ["BLUE", "GREEN"], top, 0, W, 190)
            top += 190
    else:
        top = header("TRENDS  |  all processes vs patched over time", top)
        gw = W // 2 if len(used) > 1 else W
        for i, tech in enumerate(used):
            if i and i % 2 == 0:
                top += 190
            f = sels[tech]
            explorer("All %s vs patched over time" % tech, [_metric(f["all"], "count"), _metric(f["patched"], "count")],
                     "GRAPH_CHART", ["BLUE", "GREEN"], top, (i % 2) * gw, gw, 190)
        top += 190

    # ---- activity on exposed hosts: packets received, to spot traffic spikes
    host_parts = [x for t in used for x in _hosts_running(*exposed_versions[t]) if exposed_versions[t][1]]
    if host_parts:
        runtimes = " / ".join(used)
        top = header("ACTIVITY  |  traffic on hosts that run a vulnerable or end-of-life %s" % runtimes, top)
        packets = ('builtin:host.net.nic.packets.rx:filter(%s):splitBy("dt.entity.host"):sum'
                   ':sort(value(sum,descending)):limit(10)' % _or(host_parts))
        explorer("Packets received: top 10 hosts running vulnerable %s" % runtimes, [packets], "GRAPH_CHART",
                 ["BLUE"], top, 0, W, 266, aliases=[])
        top += 266

    # ---- process tables
    if args.process_tables:
        top = header("REMEDIATION  |  one row per process, click through to the process page", top)
        for tech in used:
            f = sels[tech]
            if tech == "PHP":
                left_t = ("PHP vulnerable, patch available: upgrade to 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35", f["vuln"])
                right_t = ("PHP EOL (8.1 and older): community backport or migrate", f["eol"])
            elif tech == "Python":
                left_t = ("Python end-of-life (3.10 and older): migrate to 3.11+", f["eol"])
                right_t = ("Python: version not reported by OneAgent (check the interpreter on the host)", f["unknown"])
            elif tech == ".NET":
                left_t = (".NET vulnerable, patch available: upgrade to 8.0.33 / 9.0.22 / 10.0.14", f["vuln"])
                right_t = (".NET EOL / unsupported (7 and older): migrate to .NET 8, 9 or 10", f["eol"])
            else:
                left_t = ("Node.js vulnerable, patch available: upgrade to 22.23.4 / 24.22.1 / 26.12.1", f["vuln"])
                right_t = ("Node.js EOL lines: migrate to a fixed line (22 / 24 / 26)", f["eol"])
            for i, (name, flt) in enumerate((left_t, right_t)):
                explorer(name, [_metric(flt, "table")], "TABLE", ["DEFAULT"], top, i * (W // 2), W // 2, 342)
            top += 342
            if tech == ".NET":
                explorer(".NET vulnerable on Linux hosts: also check tarball installs (CVE-2026-114148, Linux only)",
                         [_metric(f["vuln_linux"], "table")], "TABLE", ["DEFAULT"], top, 0, W, 266)
                top += 266

        top = header("REFERENCE  |  every process OneAgent identified, any version", top)
        rw = W // 2 if len(used) > 1 else W
        for i, tech in enumerate(used):
            if i and i % 2 == 0:
                top += 342
            explorer("All %s processes (reference)" % tech, [_metric(sels[tech]["all"], "table")], "TABLE", ["DEFAULT"],
                     top, (i % 2) * rw, rw, 342)
        top += 342

    # ---- reference material at the bottom: the terms used and the CVEs evaluated
    top = header("TERMS AND CVES EVALUATED", top)
    terms = ("**Total** = every process of that runtime OneAgent identified in the timeframe. **Vulnerable** = a supported "
             "release line below the fixed version. **End-of-life** = a line that no longer receives fixes: migrate "
             "(Python: 3.10 and older). **Patched** = at or above the fixed version (Python: **supported**, 3.11 and "
             "newer). **Version not reported** = OneAgent could not read the version. **KEV** = listed in CISA's "
             "[Known Exploited Vulnerabilities catalog](%s). **Colors:** \U0001F535 total \u00B7 \U0001F7E2 patched, or none "
             "left \u00B7 \U0001F7E1 nothing patched yet \u00B7 \U0001F534 vulnerable \u00B7 \U0001F7E0 end-of-life. "
             "**Version-only:** distro backports are not visible, and a process upgraded on disk but not restarted still "
             "shows the old version (it is still exposed)." % KEV_CATALOG_URL)
    th = est_height([terms], W)
    md("Terms used on this dashboard", terms, top, 0, W, th)
    top += th
    placed, top = place_cve_tiles(cve_tile_specs(used, args.kev), W, top)
    for name, text, t_top, t_left, t_w, t_h in placed:
        md(name, text, t_top, t_left, t_w, t_h)

    return {"dashboardMetadata": {"name": args.name, "shared": args.shared, "owner": args.owner,
                                  "dashboardFilter": {"timeframe": "-2h"}, "tags": ["security", "php2shell"],
                                  "dynamicFilters": {"filters": ["CUSTOM_DIMENSION:dt.host_group.id",
                                                                 "CUSTOM_DIMENSION:Host"], "genericTagFilters": []},
                                  "hasConsistentColors": False},
            "tiles": tiles}


# Dynatrace rejected imports of dashboards 5,244 units tall or more (400 "Constraints violated"); 4,750 imported fine.
MAX_IMPORT_HEIGHT = 4750


def build_dashboard(base, rows, total_scanned, args):
    builder = build_dashboard_markdown if args.layout == "markdown" else build_dashboard_native
    dash = builder(base, rows, total_scanned, args)
    for t in dash["tiles"]:  # Dynatrace requires every dimension to be a positive multiple of 38
        for k, v in t["bounds"].items():
            assert v % 38 == 0 and (v > 0 or k in ("top", "left")), "tile %r bound %s=%s" % (t["name"], k, v)
    height = max(t["bounds"]["top"] + t["bounds"]["height"] for t in dash["tiles"])
    if height > MAX_IMPORT_HEIGHT:
        print("Warning: the dashboard is %d units tall. Imports failed with 'Constraints violated' at 5,244 and worked "
              "at 4,750, so this one may be rejected. Leave out --detail or --process-tables, or use fewer technologies."
              % height)
    return dash



CSV_COLS = ["technology", "version", "status", "process", "host", "listen_ports", "pgi_id", "pg_id", "host_id", "edition", "os"]
CSV_STATUS = {EOL: "EOL-AFFECTED"}  # CSV uses EOL-AFFECTED where the dashboard says VULNERABLE_EOL


def write_csv(path, rows):
    """One row per process and technology: technology, version, status, process, host, listen_ports, ids, edition."""
    out = [{"technology": r["tech_type"], "version": "" if r["version"] == "n/a" else r["version"],
            "status": CSV_STATUS.get(r["status"], r["status"]), "process": r["name"], "host": r["host"],
            "listen_ports": r["ports"], "pgi_id": r["id"], "pg_id": r["pg_id"], "host_id": r["host_id"],
            "edition": r["edition"], "os": r["os"]} for r in rows]
    out.sort(key=lambda r: (r["technology"] != "PHP", r["technology"], r["status"], r["version"], r["host"]))  # PHP2Shell (critical) first
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_COLS)
        w.writeheader()
        w.writerows(out)


def main():
    p = argparse.ArgumentParser(description="Create a classic Dynatrace dashboard of processes exposed to the "
                                            "PHP2Shell and Node.js Oct-2026 vulnerabilities.")
    p.add_argument("--url", "--base-url", default=os.environ.get("DT_URL"),
                   help="Managed: https://<host>/e/<environment-id>  ActiveGate: https://<ag>:9999/e/<id>  "
                        "SaaS: https://<id>.live.dynatrace.com   (env DT_URL)")
    p.add_argument("--token", default=os.environ.get("DT_API_TOKEN") or os.environ.get("DT_TOKEN"),
                   help="API token (env DT_API_TOKEN or DT_TOKEN, or hidden prompt)")
    p.add_argument("--tech", default="php,node,dotnet,python",
                   help="technologies to check: any of php, node, dotnet, python, comma separated (default all four)")
    p.add_argument("--no-kev", action="store_true",
                   help="do not read the CISA KEV feed (use the built-in snapshot; for networks without internet access)")
    p.add_argument("--from", "--timeframe", dest="frm", default="now-24h",
                   help="entity timeframe, default now-24h (e.g. now-2h, now-7d)")
    p.add_argument("--running-only", action="store_true", help="only processes seen in the last --running-minutes")
    p.add_argument("--running-minutes", type=int, default=15)
    p.add_argument("--name", default=None, help="dashboard name (same name = updated in place)")
    p.add_argument("--owner", default=os.environ.get("DT_DASHBOARD_OWNER"),
                   help="Dynatrace user who owns (and can edit) the dashboard. Default: the owner of the API token, "
                        "i.e. whoever runs the script (env DT_DASHBOARD_OWNER)")
    p.add_argument("--editable-by-all", action="store_true",
                   help="also let every user edit the dashboard (needs WriteConfig; automatic if the token owner is unknown)")
    p.add_argument("--shared", action="store_true", help="share the dashboard with all users")
    p.add_argument("--layout", choices=("native", "markdown"), default="native",
                   help="native = live Data explorer tiles like a hand-built dashboard (default); "
                        "markdown = static snapshot tiles")
    p.add_argument("--detail", action="store_true",
                   help="native layout: add the per-technology KPI rows (taller; may exceed the height Dynatrace "
                        "accepts on import, see MAX_IMPORT_HEIGHT)")
    p.add_argument("--validate", action="store_true",
                   help="send the dashboard to Dynatrace's validator and print exactly which constraints fail "
                        "(needs WriteConfig; nothing is created)")
    p.add_argument("--with-expressions", action="store_true",
                   help="native layout: also write the generated metricExpressions copies of every query (about 2.2x "
                        "larger file). Off by default: Dynatrace rebuilds them when the dashboard is opened")
    p.add_argument("--slim", action="store_true", help=argparse.SUPPRESS)  # old name of the default, kept for scripts
    p.add_argument("--no-process-tables", action="store_true",
                   help="native layout: leave out the per-process tables (vulnerable, end-of-life, all)")
    p.add_argument("--max-rows", type=int, default=20, help="max entries per list (CSV always has everything)")
    p.add_argument("--csv", "--out", metavar="FILE", default="php2shell_exposure.csv",
                   help="CSV with every process (default php2shell_exposure.csv)")
    p.add_argument("--dry-run", metavar="FILE", help="do not touch the tenant's dashboards; write dashboard JSON to FILE")
    p.add_argument("--insecure", action="store_true", help="skip TLS verification (self-signed Managed certificate)")
    p.add_argument("--ca-bundle", help="PEM file with your Managed CA certificate")
    args = p.parse_args()
    args.slim = not args.with_expressions
    args.process_tables = not args.no_process_tables

    args.techs = [t.strip().lower() for t in args.tech.split(",") if t.strip()]
    if not args.techs or any(t not in TECHS for t in args.techs):
        sys.exit("--tech must be one or more of: php, node, dotnet, python")
    if not args.name:
        args.name = DASHBOARD_NAME if set(args.techs) == set(TECHS) else \
            ("PHP2Shell - CVE-2026-109618 / CVE-2026-109619 exposure" if args.techs == ["php"]
             else "%s Oct-2026 - exposure" % " & ".join(TECHS[t][1] for t in args.techs))
    if not args.url:
        args.url = input("Dynatrace URL (Managed: https://host/e/<env-id>): ").strip()
    if not args.token:
        args.token = getpass.getpass("API token (input hidden): ").strip()
    if not args.url or not args.token:
        sys.exit("URL and token are required.")
    base = normalize_base(args.url)
    dt = DT(base, args.token, verify=not args.insecure, ca_bundle=args.ca_bundle)

    # Who may edit the dashboard: the user running the script (owner of the API token). If that cannot be
    # determined, fall back to a dashboard that every user can view and edit.
    args.edit_all = args.editable_by_all
    if not args.owner:
        args.owner = dt.token_owner()
        if args.owner:
            print("Dashboard owner (editable by): %s" % args.owner)
        else:
            args.edit_all = True
            args.owner = "php2shell-script"
            print("Could not determine the token owner: the dashboard will be shared so that all users can edit it.")
    args.shared = args.shared or args.edit_all

    args.kev = load_kev(offline=args.no_kev)
    total, rows = collect(dt, args.frm, args.running_minutes, args.techs)
    write_csv(args.csv, rows)
    print("CSV written: " + args.csv)
    dash = build_dashboard(base, rows, total, args)

    print()
    print("%-8s %-10s %-16s %9s" % ("TECH", "VERSION", "STATUS", "PROCESSES"))
    for (t, v, st), n in sorted(Counter((r["tech"], r["version"], r["status"]) for r in rows).items(),
                                key=lambda kv: (-kv[1], kv[0]))[:25]:
        print("%-8s %-10s %-16s %9d" % (t, v, st, n))
    print()
    for t in sorted({r["tech"] for r in rows}):
        c = Counter(r["status"] for r in rows if r["tech"] == t)
        print("%s: %d processes | %s" % (t, sum(c.values()), " | ".join("%s %d" % kv for kv in sorted(c.items()))))
    print("Reminder: version-only check. Verify distro backports (rpm -q php / dpkg -l php*) before closing a finding.")

    if args.validate:
        try:
            dt.call("POST", "/api/config/v1/dashboards/validator", body=dash)
            print("Dynatrace accepts this dashboard (%d tiles, %d KB)." % (
                len(dash["tiles"]), len(json.dumps(dash, separators=(",", ":"))) // 1024))
        except SystemExit as e:
            print("Dynatrace rejects this dashboard (%d tiles, %d KB):\n%s" % (
                len(dash["tiles"]), len(json.dumps(dash, separators=(",", ":"))) // 1024, e))
            sys.exit(1)
        return

    if args.dry_run:
        with open(args.dry_run, "w", encoding="utf-8") as f:
            json.dump(dash, f, indent=2)
        print("Dry run - dashboard JSON written: " + args.dry_run)
        if args.edit_all:
            print("Note: edit access for all users cannot be set through a JSON import. After importing, open Share "
                  "on the dashboard and give everyone edit access, or run without --dry-run (needs WriteConfig).")
        return

    existing = [d for d in dt.call("GET", "/api/config/v1/dashboards").get("dashboards", []) if d.get("name") == args.name]
    if existing:
        did = existing[0]["id"]
        dash["id"] = did  # PUT requires the id in the body as well as in the URL
        dt.call("PUT", "/api/config/v1/dashboards/" + did, body=dash)
        print("Dashboard updated.")
    else:
        did = dt.call("POST", "/api/config/v1/dashboards", body=dash)["id"]
        print("Dashboard created.")
    if args.edit_all and dt.share_with_all_as_editors(did):
        print("Shared with all users as editors.")
    print("Open: %s/#dashboard;id=%s" % (base, did))


if __name__ == "__main__":
    main()
