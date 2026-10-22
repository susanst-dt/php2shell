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

DASHBOARD_NAME = "PHP2Shell & Node.js Oct-2026 - exposure"

# Fixed releases (php.net / nodejs.org advisories of 21 Oct 2026).
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
TECHS = {"php": ("PHP", "PHP"), "node": ("NODE_JS", "Node.js")}  # option -> (Dynatrace type, label)

VULN, EOL, PATCHED, UNKNOWN = "VULNERABLE", "VULNERABLE_EOL", "PATCHED", "UNKNOWN"
ICON = {VULN: "\U0001F534", EOL: "\U0001F7E0", PATCHED: "\U0001F7E2", UNKNOWN: "\u26AA"}

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
                detail = e.read().decode("utf-8", "replace")[:600]
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
            if hits:
                php.append((e, label, next((t.get("version") for t in hits if t.get("version")), "")))
    print("  %d matching processes" % len(php))

    # Kubernetes context (namespace / cluster / workload) hangs off the container group instance
    cgi_ids = sorted({r["id"] for e, _, _ in php for rels in (e.get("fromRelationships") or {}).values()
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
    for e, _, _ in php:
        for t, ids in related(e).items():
            wanted[t].update(ids)
    names = {}
    for etype, idset in wanted.items():  # one type per query, mixed types are rejected
        ids = sorted(idset)
        for i in range(0, len(ids), 50):
            sel = 'type("%s"),entityId(%s)' % (etype, ",".join('"%s"' % c for c in ids[i:i + 50]))
            for ent in dt.entities(sel, "", "now-30d"):
                names[ent["entityId"]] = ent.get("displayName") or ent["entityId"]

    now_ms = time.time() * 1000
    rows = []
    for e, tech, ver in php:
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
            "tech": tech, "status": classify("PHP" if tech == "PHP" else "NODE", ver),
            "version": ver or "n/a", "scope": scope,
            "environment": ns if ns else first("HOST"),
            "cluster": cluster, "workload": workload or first("PROCESS_GROUP") or e.get("displayName", ""),
            "host": first("HOST"), "host_id": host_id, "pg_id": pg_id,
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
    if status == PATCHED:
        return "ok"
    if status == UNKNOWN or v is None:
        return "check version"
    if tech == "PHP":
        fixed = PHP_FIXED.get(v[:2])
        return ".".join(map(str, fixed)) if fixed else "migrate to %s+" % ".".join(map(str, PHP_FIXED[max(PHP_FIXED)]))
    fixed = NODE_FIXED.get(v[0])
    return ".".join(map(str, fixed)) if fixed else "migrate to %s+" % ".".join(map(str, NODE_FIXED[min(NODE_FIXED)]))


def build_dashboard(base, rows, total_scanned, args):
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
    patched_running = [r for r in running_all if r["status"] == PATCHED]
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

    def est_height(lines, col_width):
        """Rendered height: only link text counts, not the URL; ~7px per char, ~21px per line."""
        chars = max(30, int((col_width - 60) / 7.0))
        n = sum(-(-max(1, len(re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", l))) // chars) for l in lines)
        return max(76, 38 * -(-(40 + 21 * n) // 38))

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
    cve_tiles = []
    if "PHP" in used:
        cve_tiles.append(("PHP2Shell - CVE-2026-109618 / CVE-2026-109619",
                          "**PHP2Shell**\n\n**CVE-2026-109618**\n\n**CVE-2026-109619**\n\n"
                          "CVSS 4.0 **9.2 Critical**: unauthenticated remote code execution in the PHP core. "
                          "Disclosed 2026-10-21.\n\nFixed in **8.5.12 \u00B7 8.4.27 \u00B7 8.3.36 \u00B7 8.2.35**. "
                          "8.1 and older are EOL, no fix.\n\n"
                          "[php.net advisory](https://www.php.net/archive/2026.php#2026-10-21-1)", 380))
    if "Node.js" in used:
        def cve_line(c):
            return "* **%s** %s: %s" % c
        half = (len(NODE_CVES) + 1) // 2
        head = ("**Node.js Oct-2026 security releases** (10 CVEs), fixed in **22.23.4 \u00B7 24.22.1 \u00B7 26.12.1**. "
                "[Advisory](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)\n\n")
        cve_tiles.append(("Node.js CVEs (1/2)", head + "\n".join(cve_line(c) for c in NODE_CVES[:half]), 570))
        cve_tiles.append(("Node.js CVEs (2/2)", "\n".join(cve_line(c) for c in NODE_CVES[half:]), 570))
    scale = W / float(sum(w for _, _, w in cve_tiles))
    widths = [int(round(w * scale / 38.0)) * 38 for _, _, w in cve_tiles]
    widths[-1] = W - sum(widths[:-1])
    ch = max(est_height(t.split("\n"), w) for (_, t, _), w in zip(cve_tiles, widths))
    top = header("CVES BEING CHECKED   |   a process is flagged when its runtime version is below the release that fixes them", 0)
    left = 0
    for (name, text, _), w in zip(cve_tiles, widths):
        md(name, text, top, left, w, ch)
        left += w
    top += ch

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
                 for st in (VULN, EOL, PATCHED, UNKNOWN)), top, 0, 456, 266)
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

    for t in tiles:  # Dynatrace requires every dimension to be a positive multiple of 38
        for k, v in t["bounds"].items():
            assert v % 38 == 0 and (v > 0 or k in ("top", "left")), "tile %r bound %s=%s" % (t["name"], k, v)
    return {"dashboardMetadata": {"name": args.name, "shared": args.shared, "owner": args.owner or "php2shell-script",
                                  "dashboardFilter": {"timeframe": "-2h"}, "hasConsistentColors": False},
            "tiles": tiles}


def write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        cols = ["tech", "status", "version", "ports", "scope", "environment", "cluster", "workload", "host", "name", "id",
                "pg_id", "host_id", "image", "state"]
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(sorted(rows, key=lambda r: (r["status"], r["environment"], r["name"])))


# --------------------------------------------------------------------------- #
def main():
    p = argparse.ArgumentParser(description="Create a classic Dynatrace dashboard of processes exposed to the "
                                            "PHP2Shell and Node.js Oct-2026 vulnerabilities.")
    p.add_argument("--url", "--base-url", default=os.environ.get("DT_URL"),
                   help="Managed: https://<host>/e/<environment-id>  ActiveGate: https://<ag>:9999/e/<id>  "
                        "SaaS: https://<id>.live.dynatrace.com   (env DT_URL)")
    p.add_argument("--token", default=os.environ.get("DT_API_TOKEN") or os.environ.get("DT_TOKEN"),
                   help="API token (env DT_API_TOKEN or DT_TOKEN, or hidden prompt)")
    p.add_argument("--tech", default="php,node", help="technologies to check: php, node or php,node (default both)")
    p.add_argument("--from", "--timeframe", dest="frm", default="now-24h",
                   help="entity timeframe, default now-24h (e.g. now-2h, now-7d)")
    p.add_argument("--running-only", action="store_true", help="only processes seen in the last --running-minutes")
    p.add_argument("--running-minutes", type=int, default=15)
    p.add_argument("--name", default=None, help="dashboard name (same name = updated in place)")
    p.add_argument("--owner", default=None, help="dashboard owner (default php2shell-script)")
    p.add_argument("--shared", action="store_true", help="share the dashboard with all users")
    p.add_argument("--max-rows", type=int, default=20, help="max entries per list (CSV always has everything)")
    p.add_argument("--csv", "--out", metavar="FILE", help="also write all processes to a CSV file")
    p.add_argument("--dry-run", metavar="FILE", help="do not touch the tenant's dashboards; write dashboard JSON to FILE")
    p.add_argument("--insecure", action="store_true", help="skip TLS verification (self-signed Managed certificate)")
    p.add_argument("--ca-bundle", help="PEM file with your Managed CA certificate")
    args = p.parse_args()

    args.techs = [t.strip().lower() for t in args.tech.split(",") if t.strip()]
    if not args.techs or any(t not in TECHS for t in args.techs):
        sys.exit("--tech must be php, node or php,node")
    if not args.name:
        args.name = DASHBOARD_NAME if set(args.techs) == set(TECHS) else \
            ("PHP2Shell - CVE-2026-109618 / CVE-2026-109619 exposure" if args.techs == ["php"]
             else "Node.js Oct-2026 - exposure")
    if not args.url:
        args.url = input("Dynatrace URL (Managed: https://host/e/<env-id>): ").strip()
    if not args.token:
        args.token = getpass.getpass("API token (input hidden): ").strip()
    if not args.url or not args.token:
        sys.exit("URL and token are required.")
    base = normalize_base(args.url)
    dt = DT(base, args.token, verify=not args.insecure, ca_bundle=args.ca_bundle)

    total, rows = collect(dt, args.frm, args.running_minutes, args.techs)
    if args.csv:
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

    if args.dry_run:
        with open(args.dry_run, "w", encoding="utf-8") as f:
            json.dump(dash, f, indent=2)
        print("Dry run - dashboard JSON written: " + args.dry_run)
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
    print("Open: %s/#dashboard;id=%s" % (base, did))


if __name__ == "__main__":
    main()
