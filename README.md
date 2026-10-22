# PHP2Shell + Node.js Oct-2026 exposure dashboard (Dynatrace Managed, classic dashboard)

Finds every PHP and Node.js process OneAgent monitors, classifies it against the fix releases of 21 Oct 2026
(PHP2Shell CVE-2026-109618 / CVE-2026-109619, and the Node.js security releases) and creates a
**classic dashboard** showing where the vulnerable runtimes are: hosts, Kubernetes namespaces/workloads and
individual processes, with links into Dynatrace.

| Technology | Fixed versions | Source |
|---|---|---|
| PHP | 8.5.12, 8.4.27, 8.3.36, 8.2.35 (8.1 and older: EOL, no fix) | https://www.php.net/archive/2026.php#2026-10-21-1 |
| Node.js | 22.23.4, 24.22.1, 26.12.1 (other lines: EOL) | https://nodejs.org/en/blog/vulnerability/october-2026-security-releases |

Works on Dynatrace Managed and on SaaS (via the classic API).

## CVEs this checks for

The same list is shown at the top of the generated dashboard.

**PHP ("PHP2Shell")**: CVSS 4.0 9.2 critical, unauthenticated remote code execution in the PHP core, disclosed 2026-10-21.

| CVE |
|---|
| CVE-2026-109618 |
| CVE-2026-109619 |

**Node.js October 2026 security releases** ([advisory](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)):

| CVE | Severity | Description | Lines affected |
|---|---|---|---|
| CVE-2026-111497 | High | Brotli decoder out-of-bounds write, remote code execution | 22, 24, 26 |
| CVE-2026-105482 | High | `dns.resolve` truncates names containing a NUL character | 22, 24, 26 |
| CVE-2026-105483 | High | TLS hostname check bypass with fullwidth-digit IP | 24, 26 |
| CVE-2026-106069 | High | TLS hostname check bypass with loosely resolved IP | 22, 24, 26 |
| CVE-2026-105481 | Medium | Keep-alive sockets process a response written before the request | 22, 24, 26 |
| CVE-2026-106072 | Medium | Non-canonical IPv4 hostnames let DNS SANs authenticate IP endpoints | 22, 24, 26 |
| CVE-2026-106074 | Medium | `randomUUID()` / `randomInt()` entropy cache saved in startup snapshots and SEAs | 22, 24, 26 |
| CVE-2026-106070 | Low | `ZipFile` returns attacker-controlled bytes after failed header validation | 26 |
| CVE-2026-106071 | Low | Permission Model filesystem over-grant via wildcard lookup | 26 |
| CVE-2026-106073 | Low | Permission Model bypass with `fs.realpathSync` | 22, 24, 26 |

The advisory lists affected lines per CVE; confirm details in the individual release notes.

The script does not test for individual CVEs. It flags any process whose runtime version is below the release that
fixes them (see the fixed-version table above), so one version check covers every CVE in that release.

---

## 1. Requirements

| Item | Requirement |
|---|---|
| Python | **3.7 or newer** (tested on 3.14). One of: `python3`, `python`, or on Windows `py -3` |
| Dependencies | **None.** Standard library only: no `pip install`, no virtualenv |
| OS | Windows, Linux, macOS (same single file) |
| Network | The machine running the script must reach the Dynatrace URL over HTTPS (port 443, or your Managed port). It can run on a laptop, it does not need to run on a monitored host. Proxy settings from `HTTPS_PROXY` / `HTTP_PROXY` are honored |
| Dynatrace | OneAgent monitoring the PHP hosts. Kubernetes namespace/workload names require Kubernetes monitoring |

Check Python:

```bash
python3 --version
```

Windows (PowerShell / cmd):

```
py -3 --version
```

Install Python if missing: https://www.python.org/downloads/ (Windows: tick "Add python.exe to PATH"),
or `brew install python` (macOS), or `apt install python3` / `dnf install python3` (Linux).

## 2. API token and scopes

Create the token in the Dynatrace UI: **Settings > Integration > Dynatrace API > Generate token**
(Managed: same path inside the environment; the user needs permission to create API tokens).

| Scope (UI name) | Scope ID | Needed for |
|---|---|---|
| Read entities | `entities.read` | Reading processes, hosts, namespaces, workloads (**always required**) |
| Read configuration | `ReadConfig` | Finding an existing dashboard to update in place |
| Write configuration | `WriteConfig` | Creating / updating the dashboard |

Minimum for read-only use (`--dry-run`, CSV, or manual import): **`entities.read` only**.
Full automatic dashboard creation: all three scopes.

The script never modifies monitored entities, settings or tags. It only writes one dashboard.
Treat the token as a secret: prefer the hidden prompt or an environment variable over typing it on the command line
(command lines end up in shell history and process lists), and delete the token when finished.

## 3. Environment URL

| Deployment | `--url` value (alias `--base-url`) |
|---|---|
| Managed | `https://<managed-host>/e/<environment-id>` (the URL you use in the browser, without the `#...` part) |
| Managed via an Environment ActiveGate | `https://<activegate-host>:9999/e/<environment-id>` |
| SaaS | `https://<tenant-id>.live.dynatrace.com` |

## 4. Run it

Download `php2shell_dashboard.py` and open a terminal in its folder.

### Interactive (recommended): the script prompts for URL and token (token input is hidden)

Linux / macOS:
```bash
python3 php2shell_dashboard.py
```

Windows:
```
py -3 php2shell_dashboard.py
```

### With environment variables

Linux / macOS:
```bash
export DT_URL='https://managed.example.com/e/<environment-id>'
export DT_API_TOKEN='dt0c01.XXXX'   # DT_TOKEN also works
python3 php2shell_dashboard.py
```

Windows PowerShell:
```powershell
$env:DT_URL = 'https://managed.example.com/e/<environment-id>'
$env:DT_API_TOKEN = 'dt0c01.XXXX'
py -3 php2shell_dashboard.py
```

Windows cmd:
```
set DT_URL=https://managed.example.com/e/<environment-id>
set DT_API_TOKEN=dt0c01.XXXX
py -3 php2shell_dashboard.py
```

### With arguments

```bash
python3 php2shell_dashboard.py --url https://managed.example.com/e/<environment-id> --token dt0c01.XXXX
```

On success the script prints the number of PHP processes found and a link to the dashboard:

```
PHP processes: 12 | vulnerable: 5 | unknown: 1
Dashboard created.
Open: https://managed.example.com/e/<environment-id>/#dashboard;id=...
```

Running it again with the same dashboard name **updates the dashboard in place**, so it can be scheduled
(cron, systemd timer, Windows Task Scheduler) to keep the snapshot fresh.

### Options

| Option | Purpose |
|---|---|
| `--no-process-tables` | Native layout: leave out the per-process tables |
| `--layout native` / `--layout markdown` | `native` (default): live Data explorer tiles like a hand-built dashboard. `markdown`: static snapshot tiles with bar graphics and remediation lists |
| `--tech php` / `--tech node` | Check only one technology (default `php,node`, both) |
| `--from now-7d` | Timeframe for processes (default `now-24h`; alias `--timeframe`). A process counts if it existed in that timeframe |
| `--running-only` | Only count processes seen in the last 15 minutes (`--running-minutes N` to change) |
| `--csv file.csv` | CSV with every process, all statuses (default `php2shell_exposure.csv`, alias `--out`). Written on every run, including `--dry-run` |
| `--dry-run out.json` | Do not create anything in Dynatrace; write the dashboard JSON to a file |
| `--name "My name"` | Dashboard name (also the key used for update-in-place) |
| `--owner user@company.com` | Dashboard owner (default: the owner of the API token, i.e. whoever runs the script) |
| `--editable-by-all` | Let every user edit the dashboard (needs `WriteConfig`; automatic when the token owner is unknown) |
| `--shared` | Share the dashboard with all users (view access) |
| `--max-rows N` | Entries per list (default 20); CSV always has everything |
| `--insecure` | Skip TLS verification (self-signed Managed certificate) |
| `--ca-bundle ca.pem` | Trust your own CA certificate instead of using `--insecure` |

### Who can edit the dashboard

By default the dashboard is owned by **whoever runs the script**: the script looks up the owner of the API token and
sets it as the dashboard owner, so the person who ran it can edit the dashboard (the same applies to a JSON exported
with `--dry-run` and imported by that person). The owner and environment admins can always edit.

- `--owner user@company.com` makes a different user the owner (env `DT_DASHBOARD_OWNER`).
- If the token owner cannot be determined, the script falls back to a dashboard that **every user can view and edit**
  (shared, with edit permission for all users).
- `--editable-by-all` does the same on demand. Setting the share permissions needs `WriteConfig`, so it works when the
  script creates or updates the dashboard, not with `--dry-run`: for a manual import use **Share** on the imported
  dashboard to give everyone edit access.

### If the token cannot create dashboards

Run with `--dry-run` (only `entities.read` needed), then import the JSON in the UI:
**Dashboards (classic) > Import dashboard** and select the file.

```bash
python3 php2shell_dashboard.py --dry-run php2shell-dashboard.json --csv php2shell.csv
```

### CSV output

Every run writes a CSV (default `php2shell_exposure.csv` in the current folder), one row per process and technology:

| Column | Content |
|---|---|
| `technology` | `PHP` or `NODE_JS` |
| `version` | Version OneAgent detected (empty if unreadable) |
| `status` | `VULNERABLE`, `EOL-AFFECTED` (end-of-life line, no fix), `PATCHED` or `UNKNOWN` |
| `process` | Process name |
| `host` | Host the process runs on |
| `listen_ports` | Listening ports |
| `pgi_id`, `pg_id`, `host_id` | Dynatrace entity IDs of the process instance, process group and host |
| `edition` | Software edition reported by OneAgent (for example `CLI` for PHP) |

Sorted with PHP first (the critical PHP2Shell findings), then by technology, status, version and host. The CSV always has every process; the dashboard lists are capped.
Note the CSV calls end-of-life findings `EOL-AFFECTED`, while the dashboard shows them as `VULNERABLE_EOL`.

## 5. Troubleshooting

| Message | Cause / fix |
|---|---|
| `HTTP 401` | Token invalid, expired or copied incorrectly |
| `HTTP 403 ... missing a required scope` | Add the scope named in the error (see table above) |
| `HTTP 404` | Wrong URL. Managed needs `https://<host>/e/<environment-id>` |
| `Cannot reach ...` / certificate error | Network/proxy problem, or self-signed cert: use `--ca-bundle` or `--insecure` |
| `0 matching processes` | No PHP / Node.js monitored in the timeframe: widen with `--from now-7d`; check OneAgent is deployed on those hosts |
| Everything shows as Compute | Kubernetes monitoring is not enabled, so processes have no namespace relationship |
| Import error `Could not map JSON` | A markdown tile exceeded 1000 characters; use the current script version |

## 6. How status is decided

From the version OneAgent detects on each process (a process running both technologies appears once per technology):

| Status | PHP | Node.js |
|---|---|---|
| VULNERABLE | 8.2 below 8.2.35, 8.3 below 8.3.36, 8.4 below 8.4.27, 8.5 below 8.5.12 | 22 below 22.23.4, 24 below 24.22.1, 26 below 26.12.1 |
| VULNERABLE_EOL | branch 8.1 or older (no fix, migrate) | any other line (20, 23, 25 and older): EOL, upgrade to a fixed line |
| PATCHED | at or above the fixed release (or a newer branch) | at or above the fixed release (or newer than 26) |
| UNKNOWN | version not readable, check manually | same |

The fixed versions are the `PHP_FIXED` / `NODE_FIXED` tables at the top of the script; edit them if advisories change.

Caveats: the check is version-only. Distro vendors (Red Hat, Ubuntu, SUSE, Debian) may backport a fix without
changing the version string; those processes show as VULNERABLE here, so confirm with `rpm -q` / `dpkg -l`
before closing a finding. A process that was upgraded on disk but not restarted still shows the old version,
which is correct: it is still exposed.

## 7. Dashboard contents

### Native layout (default): live tiles

Built like a hand-made Dynatrace dashboard: every tile is a metric query (`builtin:pgi.availability.state`) filtered by the
version OneAgent detected on each process (`softwareTechnologies.version`), so numbers and tables update with the
dashboard timeframe. The **Host group / Host** filters at the top narrow the view; leave them empty to see everything, including hosts without a host group.

- **CVE section** (top): the PHP2Shell CVEs and all ten Node.js CVEs with severity and fixed versions, plus a color guide
- **Per technology**: single-value tiles (all, patched in green, vulnerable in red, end-of-life in orange) and an
  "all vs patched over time" trend graph
- **Network**: packets received by the top 10 hosts that run a vulnerable or end-of-life runtime, to spot traffic spikes
- **Remediation tables**: one row per process (process link and host) for vulnerable and end-of-life processes,
  including hosts without a host group, plus every PHP / Node.js process. Leave the tables out with `--no-process-tables`
- **Gaps**: what the dashboard cannot see (no OneAgent, unfingerprinted runtimes)

The entity selector matches exact version strings (at most 50 per condition), so the script enumerates every patch
release in the range that matters, plus every version it actually found. A version it does not know (for example
Node.js newer than 26 or an unusual patch number) is counted in the "All" tile only: re-run the script to refresh the lists.

### Markdown layout (`--layout markdown`): static snapshot

Verdict and KPI tiles, bar breakdowns, a prioritized remediation list with the version to upgrade to, and a process
sample. Static: re-run to refresh.

## 8. Limits

- The native layout needs the viewing user to have access to process metrics; creating the dashboard needs only the
  token scopes above. It adds no data to the environment (no custom metrics).
- Version lists are enumerated (entity selector limit); re-run the script after new releases or new versions appear.
- The packets-received tile filters hosts by the exposed versions the script found when it ran (plus every vulnerable
  PHP patch release), to keep the query short: re-run the script to pick up hosts that start running a new exposed version.
- The markdown layout is a snapshot and does not render tables (markdown tiles hold at most 1000 characters).
- Kubernetes vs Compute is decided by whether the process belongs to a Kubernetes namespace (CSV and markdown layout).
