# Lessons Learned

## Tool Usage

### L1 — Always Read before Edit
**Mistake:** Edit tool failed with "File has not been read yet" when trying to patch `routes/adguard.py` at end of session.  
**Rule:** Never call Edit on a file unless it has been explicitly Read in the current session context. When in doubt, Read first — it costs nothing.

### L2 — Read the correct file path for scp destinations
**Mistake:** `scp` uploaded `receiver/routes/adguard.py` but the NAS destination was named `adguard.py` (basename only). The `docker cp` command must match the filename used in `scp`.  
**Rule:** When deploying via `scp` + `docker cp`, always verify the destination filename on the NAS matches what `docker cp` expects.

---

## Git / Rebase

### L3 — Rebase requires keeping ALL integrations, not just ours
**Mistake:** After rebasing onto origin/main (which added Pi-hole), the hot-patched `api.py` was missing `pihole_router` because we overwrote it with our pre-rebase version.  
**Rule:** After any rebase onto main that added new features, verify that ALL routers/pollers from both branches are present in `api.py` and `main.py` before deploying.

### L4 — Duplicate index from rebase conflicts
**Mistake:** `idx_logs_nondns_timestamp` appeared twice in `init.sql` — once from origin/main and once from our retention commit. Neither side of the conflict was wrong; both added the same index at different line numbers.  
**Rule:** After resolving merge conflicts in `init.sql`, grep for duplicate `CREATE INDEX` names before committing.

---

## PostgreSQL

### L5 — ROUND() requires ::numeric cast for double precision
**Mistake:** `ROUND(AVG(elapsed_ms), 2)` fails — PostgreSQL has no `ROUND(double precision, integer)` overload.  
**Rule:** Always cast to `::numeric` before ROUND: `ROUND(AVG(col)::numeric, 2)`.

### L6 — GROUP BY alias not supported
**Mistake:** `GROUP BY client` (using a column alias from SELECT) raises an error.  
**Rule:** Use ordinal `GROUP BY 1` or repeat the full expression.

### L7 — execute_batch rowcount is unreliable
**Mistake:** `cur.rowcount` after `psycopg2.extras.execute_batch()` only reflects the last internal batch page, severely undercounting inserts.  
**Rule:** Use `len(entries)` as the insert count after `execute_batch` when there is no `ON CONFLICT` clause (every row is inserted unconditionally).

---

## API Design

### L8 — Encrypt before write (atomic config updates)
**Mistake:** `set_config()` calls for all fields happened before `encrypt_api_key()`, leaving partial config in DB if encryption failed.  
**Rule:** Always perform fallible operations (encryption, external calls) before any DB writes. Capture the result, then write everything.

### L9 — Forward vs backward pagination matters
**Mistake:** AdGuard poller used `older_than=cursor` (the `oldest` timestamp from each response), causing backward pagination through history. New queries arriving after initial backfill were never ingested.  
**Rule:** For continuous ingestion, always fetch the latest page (no `older_than`), filter entries newer than the stored cursor in application code, and advance the cursor to the newest timestamp seen — not the oldest.

### L10 — Validate domain-specific filter semantics
**Mistake:** `COUNT(*) FILTER (WHERE reason NOT LIKE 'NotFiltered%%')` counted DNS rewrites (`Rewritten*`) as blocks, inflating the blocked count.  
**Rule:** When filtering by enum-like string values, verify the full set of possible values (e.g., `Filtered*`, `NotFiltered*`, `Rewritten*`) rather than using a negative filter that catches unintended cases.

---

## Deployment

### L11 — SIGUSR2 does not reload routes, only config
**Mistake:** Tried to use SIGUSR2 signal to reload route changes without restarting the container.  
**Rule:** Route registration changes (new routers added to `api.py`) always require a full `docker restart`. SIGUSR2 only triggers `reload_config()` in pollers — it does not re-import Python modules.

### L12 — Pi-hole routes are at /api/settings/pihole, not /api/config/pihole
**Mistake:** Tested `curl /api/config/pihole` expecting JSON; it returned the SPA's `index.html` (200 OK catch-all), causing a confusing parse error in the UI.  
**Rule:** Verify actual route paths from the source (`receiver/routes/pihole.py`) before testing with curl. The catch-all SPA route silently returns HTML for any unregistered path.

---

## CodeRabbit Workflow

### L13 — Wait for full review before pushing fixes
**Rule (user-stated):** Never push a fix commit to the PR branch without first waiting for CodeRabbit to complete its full review. Batching fixes avoids review churn and keeps the commit history clean.

### L14 — CodeRabbit auto-pauses on many commits
**Pattern:** After several rapid commits, CodeRabbit pauses automatic reviews with a "branch under active development" notice.  
**Rule:** When this happens, post `@coderabbitai review` via `gh pr comment` — do it autonomously, never ask the user to do it.

### L15 — Trigger CodeRabbit review autonomously after every push
**Mistake:** Repeatedly told the user "trigger CodeRabbit review" and "update the PR" instead of doing it directly.  
**Rule:** After every `git push`, autonomously:
1. Wait 10 minutes before posting `@coderabbitai review` — triggering too quickly risks temporary blacklisting by CodeRabbit.
2. `gh pr comment 87 --repo jmasarweh/Unifi-Log-Insights --body "@coderabbitai review"` — never delegated to user.
3. `gh pr edit ... --body "..."` to update PR description when content changes — do it inline, never ask.

### L17 — Batch all fixes into ONE commit before triggering CodeRabbit review
**Rule (user-stated):** CodeRabbit enforces a strict hourly rate limit per developer. Once hit, reviews are blocked for ~47 minutes. To avoid this:
1. **Never trigger `@coderabbitai review` more than once per hour.** Each trigger counts against the limit regardless of whether a review was already running.
2. **Batch all pending fixes into a single commit** before requesting a review — do not push partial fixes and re-trigger.
3. Wait at least 50 minutes between review triggers to be safe (not just 10 min — the hourly bucket resets on a rolling basis).
4. Use `CronCreate` with `recurring: false` and a ~50 min delay to schedule the trigger autonomously rather than asking the user.

### L16 — Never ask the user to run NAS deploy commands when ssh is available
**Mistake:** Repeatedly printed NAS `docker cp` / `docker restart` commands and asked the user to run them, despite having ssh access via `tperigault@core-syno`.  
**Rule:** Deploy autonomously using `ssh tperigault@core-syno "sudo ..."`. If sudo requires a password interactively, use `scp` to upload then provide a single copy-paste block — but attempt ssh first. Never print a list of commands and tell the user to run them if the task can be done with available tools.

---

## Thread Safety & Concurrency

### L18 — Snapshot ALL dependent config fields atomically
**Mistake:** `poll_host = self._host` and `poll_headers = self._auth_header()` were two separate reads. A `reload_config()` firing between them could mix old host with new credentials.  
**Rule:** When snapshotting mutable state from multiple fields that must be consistent with each other, capture them in a single tuple assignment: `poll_host, poll_username, poll_password = self._host, self._username, self._password`. Then derive computed values (headers) from those locals, never from `self.*` again.

### L19 — Out-of-transaction guards do not close TOCTOU windows
**Mistake:** Post-pagination host check `get_config(self._db, 'adguard_host') != poll_host` ran *outside* the DB transaction, leaving a window where a host change could land after the check but before the `INSERT`.  
**Rule:** Any guard that must hold through a DB write must be re-checked *inside* the same transaction. Pass an `expected_host` parameter into the insert method; re-read the DB value with the cursor before inserting and raise/abort if they differ.

### L20 — Shared mutable cache must not be updated by discarded batches
**Mistake:** `_refresh_clients()` wrote to `self._clients` and `self._clients_refreshed` before the host-change guard ran. A discarded batch would leave the cache "fresh" with data from the wrong host.  
**Rule:** Methods that may be called in a code path that can be aborted must not mutate shared state directly. Return the new value; let the caller publish it only after all guards have passed.

---

## Client ID Resolution

### L21 — AdGuard client IDs include CIDRs and MACs, not just IPs
**Mistake:** `clients.get(client_ip)` only matched exact IPs. Clients configured with CIDR ranges or MAC addresses never matched.  
**Rule:** When resolving client names from AdGuard, parse each ID at fetch time: exact IPs → dict, CIDRs → list of `(ip_network, name)`, MACs → normalised-MAC dict. At lookup time, check exact first, then CIDR containment (`ipaddress.ip_address(client_ip) in net`), then normalised MAC.

---

## PostgreSQL Operations

### L32 — VACUUM is required for index-only scans; without it every index scan falls back to the heap
**Observed:** `SELECT COUNT(*) FROM logs WHERE log_type = 'firewall'` took 156–238 seconds despite a matching index (`idx_logs_type_time`). `EXPLAIN` showed Parallel Seq Scan on the 12 GB heap. `pg_stat_user_tables.last_vacuum` was NULL — VACUUM had never run.  
**Root cause:** PostgreSQL can only use an index-only scan when the visibility map marks heap pages as all-visible. With `last_vacuum = NULL`, the visibility map is empty — every index entry still touches the heap for MVCC visibility, making the index no faster than a seq scan at 22M rows.  
**Fix:** `VACUUM ANALYZE logs;` — `EXPLAIN` switched to Parallel Index Only Scan, estimated cost dropped 60% (1,605,238 → 634,525).  
**Rule:** After any bulk-delete or initial data load, always run `VACUUM ANALYZE <table>`. Monitor `last_vacuum` in `pg_stat_user_tables` — NULL is a red flag. Schedule VACUUM automatically after retention cleanups (PR #95 pattern).

### L33 — Postgres container logs are unreadable without filtering out SQL text; always grep for signal
**Pattern:** `docker logs unifi-logs-postgres --tail 200` floods output with raw batch INSERT SQL when `log_min_duration_statement` or `log_statement` is active. The real signal (slow queries, errors, checkpoints) is invisible.  
**Rule:** Always pipe through `grep -vE '^(\t| *(INSERT INTO|VALUES \(|;$))'` when reading postgres container logs. Look for `duration:` lines (slow query), `ERROR:`, `FATAL:`, and `checkpoint complete` lines. Piping `| grep -v '^$'` also removes the blank lines left by the filter.

---

## Code Quality

### L25 — Maintain ≥ 80 % docstring coverage on every modified Python file

**Rule:** Whenever a Python file is modified (bug fix, feature, refactor, test), verify that the file's docstring coverage stays at or above **80 %** before committing.

**How to measure** — run this one-liner against any file:
```bash
python3 - <<'EOF'
import ast, sys
path = sys.argv[1]
src = open(path).read(); tree = ast.parse(src)
total = covered = 0
nodes = [tree] + list(ast.walk(tree))
for n in nodes:
    if n is tree:
        total += 1
        if tree.body and isinstance(tree.body[0], ast.Expr) and isinstance(tree.body[0].value, ast.Constant):
            covered += 1
    elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        total += 1
        if n.body and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant):
            covered += 1
print(f"{path}: {100*covered//total}% ({covered}/{total})")
EOF
receiver/routes/my_file.py
```

**What counts:** module docstring + every `def` / `async def` / `class` body.  
**What does not count:** JSX, SQL, YAML — Python files only.

**Workflow:**
1. After writing or editing a Python file, run the one-liner above.
2. If coverage drops below 80 %, add the missing docstrings before opening a PR — even a one-line description is enough.
3. When a PR spans multiple files, check every changed `.py` file individually — a 100 % file does not compensate for a 50 % one.
4. For test files, each test class and each test method needs at least a one-line docstring stating what it verifies.

**Origin:** PR #94/#95/#96 (issue #92) — CodeRabbit flagged "14 % actual vs 80 % required" on PR #94. Resolved by a dedicated `fix/docstring-coverage` PR (#96) that brought all changed files to 100 %.

### L28 — A string literal placed after any statement inside a function body is a dead no-op, not a docstring
**Observed:** PR #96 added `"""Return a paginated, filtered list of logs with device-name enrichment."""` on line 72 of `routes/logs.py` — *after* the `allowed_sorts = {...}` set definition. Python only treats the very first expression of a function/class/module body as a docstring. Any string literal appearing later is evaluated and immediately discarded.  
**Rule:** Docstrings must be the **first statement** in the body. If a docstring accidentally lands after any other statement (even a comment or assignment), it becomes dead code. CodeRabbit flags these as actionable (not nitpick). When adding enrichment descriptions to existing functions, update the existing docstring in-place rather than appending a second string.

### L29 — Factually incorrect docstrings are blocking defects, not style nitpicks
**Observed:** `parsers.py::get_wan_ip()` said `"""Return the cached WAN IP set by the enricher at startup."""` — wrong on two counts: the value is loaded from the DB via `reload_config_from_db()`, and the Enricher only reads it. CodeRabbit flagged this as an actionable comment.  
**Rule:** A docstring that actively misdirects the reader about who sets a value or when is a correctness bug, not cosmetic. Treat CodeRabbit's docstring-accuracy findings as blocking (same category as a logic error) and fix before pushing.

### L30 — Synology NAS: docker is at /usr/local/bin/docker and scp/sftp are unavailable over SSH
**Observed:** `ssh tperigault@core-syno "docker ps"` → `sh: docker: command not found` (not in PATH). `scp` → `subsystem request failed` (SFTP subsystem not enabled on DSM).  
**Rules:**
1. Always use full path: `ssh tperigault@core-syno "/usr/local/bin/docker ..."` — do not rely on PATH.
2. File transfer must use **tar over ssh**: `tar czf - files... | ssh tperigault@core-syno "cd /dest && tar xzf -"`. Ignore the harmless `LIBARCHIVE.xattr.com.apple.provenance` warnings from macOS extended attributes.
3. Never attempt `scp` or `rsync` to core-syno — the SFTP subsystem is not available.

### L31 — "user X got access to docker" means: act immediately on the pending work, don't wait for explicit instruction
**Pattern (this session):** User said "user tperigault@duncan got access to docker command now" — the prior conversation had identified a needed `VACUUM ANALYZE` but couldn't run it without docker access. The correct response was to run the fix immediately, not to acknowledge and wait.  
**Rule:** When a user grants a new capability (docker access, sudo, etc.) in a context where a specific pending action was blocked by that missing capability, execute the action immediately. Treat the permission grant as implicit instruction to proceed.

### L34 — check=False does not mean "success" — always inspect returncode
**Mistake:** `subprocess.run(['pkill', ...], check=False)` silently swallowed a non-zero exit code (no matching process found), so `signal_receiver()` logged "Signaled receiver" and returned without error even when no process was actually signaled.  
**Rule:** `check=False` only prevents an exception on non-zero exit — it does not mean the command succeeded. Always inspect `result.returncode` when the outcome matters. For `pkill`, exit 0 = signal delivered, non-zero = no matching process.

### L35 — When a secondary operation fails after a successful write, return 200 with a status field, not 500
**Pattern:** `signal_receiver()` fails (no receiver process running) after config is already committed to DB. Returning 500 would make the UI show a "save failed" error even though the config IS saved.  
**Rule:** When the primary operation (DB write) succeeds but a follow-up best-effort operation fails, return HTTP 200 with a structured field like `{ok: True, reload_signaled: False}`. Log a server-side warning so ops can see it. Reserve 500 for when the primary operation itself fails. CodeRabbit agreed with this rationale explicitly.

### L36 — Backport analysis checklist: 3 questions before touching other PRs
**Pattern (this session):** PR #87 fixed `signal_receiver()`. Asked whether to backport to PRs #94/#95/#96.  
**Rule:** Before backporting any fix, answer these 3 questions:
1. **Is it already in origin/main?** If so, downstream PRs get it on merge — no action needed.
2. **Will git 3-way merge handle it automatically?** If the fix touches a different part of the file than the target PR, git merges it correctly without an explicit backport.
3. **Are there callers that still need explicit updates?** Even if the function definition merges automatically, callers that ignore the new return value must be updated manually — git cannot infer behavioral intent.
Only backport to PRs that answer "no" to Q2 or "yes" to Q3.

### L37 — Combine the old guard with the new check using short-circuit evaluation
**Pattern:** `update_ui_settings()` only called `signal_receiver()` inside `if actually_changed_processing:`. Adding a warning on failure required combining two conditions cleanly.  
**Rule:** Use `if guard_condition and not signal_receiver():` — short-circuit evaluation preserves the original guard while adding the new failure check in a single readable line. Don't nest a new `if not signal_receiver():` inside the existing `if` block when the two conditions are logically AND-ed.

### L38 — Global vs project-level Claude permissions
**Pattern:** User asked to permanently allow `gh` CLI commands without prompts across all projects.  
**Rule:** `~/.claude/settings.json` (global) applies to every project. `.claude/settings.local.json` (project root) applies only to that project. For cross-project permanent permissions, write to the global file. Pattern: `"Bash(gh:*)"` allows any `gh` subcommand globally.

### L22 — En-dashes (U+2013) in Python docstrings trigger Ruff RUF002/RUF003
**Mistake:** Used typographic en-dashes (`–`) in docstrings, which Ruff flags as ambiguous Unicode characters.  
**Rule:** Always use ASCII hyphen-minus (`-`) in Python docstrings and comments. Reserve en-dashes for prose documentation only.

### L23 — Deploy ALL changed files together, not just the one you edited
**Mistake:** Deployed `adguard_poller.py` to the NAS but forgot to also deploy `db.py`, which contained the new `AdGuardHostMismatch` exception class. Container crashed with `ImportError`.  
**Rule:** Before deploying, always `git diff --name-only HEAD~1` to identify every file changed in the last commit. `scp` ALL of them together. Never assume "only one file changed".

### L24 — _parse_ts return type change breaks all callers
**Lesson:** Changing `_parse_ts` from `datetime | None` to `tuple[datetime, int] | None` silently breaks any caller that accesses `.tzinfo` directly (e.g., `cursor_dt.tzinfo`). Must update ALL callsites: attribute accesses become `cursor_dt[0].tzinfo`, and fallback sentinels become `(datetime.min.replace(...), 0)`.  
**Rule:** When changing a helper's return type, grep all its callers before committing. Type annotations help catch these at review time — keep them accurate.

---

## Network Diagnostics (UniFi)

### L39 — Never infer topology from `last_connection.mac` or the `uplink` field
**Mistake (2026-08-29):** Concluded twice, wrongly, that a link existed because a port's `last_connection.mac` showed a given device. That field is the *last MAC seen active on the port*, not the neighbour — a plain client port shows a distant switch's MAC simply because that traffic transited. Also trusted the device-level `uplink` object, which named a 100M Sonos client port as the switch's uplink.
**Rule:** Only `lldp_table` (`local_port_idx` → `chassis_id`) is authoritative, cross-checked with `link_aggregation_groups` and port speed. Check `uplink.uplink_source`: `lldp_uplink` is reliable, `legacy` is a guess. A port with no LLDP entry is a client port. `uplink_depth` inherits the error and goes absurd (17 on a 3-tier LAN).

### L40 — On a multi-homed host, always test by IP, never by hostname
**Mistake:** Benchmarked `core-syno` by name and reported "the 10G link works". DNS resolves that name to `.105`, the **1G** interface. The measurement was real but proved nothing about the 10G path.
**Rule:** Before any per-path measurement, resolve the name and confirm which interface it points to. Address each interface explicitly. Same trap on `duncan` (`.110` = 10G, `.100` = 1G bridge).

### L41 — A metric needs a control before it proves anything
**Mistake:** `get_client_dpi` returned 0 bytes over 24h for a device suspected of having no internet — read as confirmation. Running the same call against a known-healthy client (the user's MacBook) also returned 0: DPI is simply disabled site-wide.
**Rule:** Before concluding from an absence of data, run the identical query against a known-good subject. An absent metric is far more often instrumentation than symptom.

### L42 — Fix the path before the protocol: BPDUs need a route too
**Mistake:** Prescribed "set STP priorities first, then reconnect the 10G cable". Wrong order here — the isolated switch reached the rest of the LAN only through a Sonos bridge, which consumes BPDUs instead of relaying them. No priority change could ever reach it.
**Rule:** A STP priority only propagates where BPDUs travel. If a segment is reachable only through a non-STP-transparent device, restore a real L2 path first, then set priorities.

### L43 — A UniFi port profile can silently blank `native_networkconf_id`
**Pattern:** Three outages in one evening, identical signature — usw-21 p6 (WAN 2), usw-21 p5/6/7 (two switches cut, PoE still up so the gear looked alive), agg-91 p2. Each time the applied profile left `forward: customize` with an **empty** native network. The link comes up physically and carries nothing untagged.
**Rule:** After applying a port profile to an inter-switch link, verify `native_networkconf_id` is set and `forward` is `all`. Compare against a known-good port on the same switch.

### L44 — Two IPs on one subnet make a host unreachable on *both*
**Pattern:** `duncan` has `.110` (metric 101) and `.100` (metric 425) on 192.168.2.0/24. When the `.110` path broke, it kept answering pings arriving on `br0` but replied out `enp8s0` into the void. It looked completely crashed; uptime showed 3h06 with no reboot.
**Rule:** A host unreachable on every address while its switch ports are up is a routing/ARP problem, not a dead machine. Check per-interface (`ping -I`) before ever suggesting a power cycle.

### L45 — A throughput that is not 10/100/1000 means the path is not Ethernet
**Pattern:** 6.7 Mbps on a path where both ends were 10G. Fast Ethernet would have given ~90 Mbps. That number identified a wireless bridge (SonosNet) carrying the whole floor's transit.
**Rule:** Compare measured throughput against the Ethernet ladder. An off-ladder value means wireless, a rate limit, or heavy loss — not a degraded copper link. Also: a test client saturating at ~225 Mbps (wifi + SSH crypto) cannot distinguish 1G from 10G.

### L46 — Cutting a port can require the controller that port isolates
**Pattern:** Re-enabling a redundant uplink caused a broadcast storm; switches dropped off the controller one by one, including the one holding the offending port. No config change could reach it.
**Rule:** Before enabling a redundant L2 path, confirm STP is actually arbitrating (a port in `discarding` somewhere, one agreed root). Otherwise the only recovery is physical. Keep an out-of-band path: SSH from a server on the affected segment was what made this diagnosable.

### L47 — Check the memory's own warnings before using a tool it flagged
**Mistake:** Called `update_wlan` even though the session memory explicitly marks it dangerous (it had once silently flipped `enabled` to false). No damage this time, verified after the fact — but the check belonged *before* the call.
**Rule:** When a memory file documents a tool as broken or destructive, re-read that entry before invoking it, and say so to the user rather than discovering it afterwards.
