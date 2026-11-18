# SENTINEL SOC — Detection Engineering Catalog

All detection rules in SENTINEL SOC implement `DetectionRuleContract` (`backend/app/detection/base.py`) as pure functions of `(events: Sequence[NormalizedEvent], config: RuleConfig) -> list[Finding]`.

> **Important Note on Heuristic Detections:** Rules use configurable thresholds, sliding time windows, and pattern indicators. They are designed to surface suspicious activity for analyst triage—not to guarantee detection of every attack variant or to prove malicious intent without investigation.

---

## Window & Deduplication Semantics

- **Event-Time Sliding Windows:** Events are sorted by `event.timestamp` (the timestamp extracted from the log, not server ingestion time). A window `[first, last]` qualifies when `(last.timestamp - first.timestamp).total_seconds() <= time_window_seconds` (inclusive).
- **Idempotent Ingestion (`event_hash`):** Every event's `SHA-256(log_source + "\x1f" + raw_event)` is constrained `UNIQUE` in PostgreSQL. Re-uploading the same log file inserts zero duplicate rows and cannot artificially inflate rule counters.
- **Alert Deduplication (`dedup_key`):** PostgreSQL enforces a partial unique index on `alerts(dedup_key) WHERE status IN ('new', 'investigating')`. Repeated findings for the same rule and entity update the existing open alert (`event_count`, `last_seen`, escalated `severity`, and linked `alert_events`) instead of flooding the analyst queue.

---

## Rule Specifications

### 1. `SENT-AUTH-001` — SSH Brute Force Detection
- **Category:** `authentication`
- **Default Severity:** `high` (escalates to `critical` if followed by a successful SSH login from the same IP within the window)
- **Default Threshold / Window:** `>= 10` failed SSH login attempts from a single `source_ip` within `300s`
- **MITRE ATT&CK:** `T1110.001` (Brute Force: Password Guessing — Primary), `T1021.004` (Remote Services: SSH)
- **False-Positive Controls:** `allowlist_ips` CIDR list; ignores duplicate `ssh_invalid_user` lines emitted alongside `Failed password for invalid user`.

### 2. `SENT-AUTH-002` — Password Spraying Detection
- **Category:** `authentication`
- **Default Severity:** `high` (escalates to `critical` if any login succeeds from the same IP)
- **Default Threshold / Window:** `>= 5` distinct usernames failed from one `source_ip` within `1800s` with `<= 3.0` average attempts per user
- **MITRE ATT&CK:** `T1110.003` (Brute Force: Password Spraying)
- **False-Positive Controls:** Upper bound on `max_avg_attempts_per_user` separates wide-and-shallow spraying from single-account brute force; `allowlist_ips` excludes known NAT/VPN concentrators.

### 3. `SENT-AUTH-003` — Multiple Failed Logins (Single Account)
- **Category:** `authentication`
- **Default Severity:** `medium` (escalates to `high` when failures originate from `>= 3` distinct source IPs)
- **Default Threshold / Window:** `>= 5` failed authentication attempts targeting a single `username` within `900s`
- **MITRE ATT&CK:** `T1110.001` (Brute Force: Password Guessing)
- **SOC Purpose:** Catches distributed brute-force attacks against a single high-value account that per-source-IP rules miss.

### 4. `SENT-NET-001` — Port Scanning Detection
- **Category:** `network`
- **Default Severity:** `medium`
- **Default Threshold / Window:** Vertical scan: `>= 20` distinct destination ports from `(source_ip, destination_ip)` within `60s`; Horizontal sweep: `>= 15` distinct destination hosts on the same port within `60s`
- **MITRE ATT&CK:** `T1046` (Network Service Discovery — Primary), `T1595.001` (Active Scanning: Scanning IP Blocks)
- **False-Positive Controls:** `allowlist_ips` for authorised vulnerability scanners and monitoring hosts.

### 5. `SENT-DNS-001` — Suspicious DNS Activity
- **Category:** `dns`
- **Default Severity:** `medium` (escalates to `high` on high subdomain volume or repeated high-entropy queries)
- **Default Threshold / Window:** Per-query indicators (`query_length > 75`, `label_length > 50`, subdomain Shannon entropy `> 3.8` with length `>= 20`, or suspicious TLD) OR `>= 50` unique subdomains under the same `(source_ip, registered_domain)` within `600s`
- **MITRE ATT&CK:** `T1071.004` (Application Layer Protocol: DNS — Primary), `T1568.002` (Dynamic Resolution: DGA), `T1048` (Exfiltration Over Alternative Protocol)
- **False-Positive Controls:** Offline Public Suffix List extraction (`tldextract` with `suffix_list_urls=()`) and `domain_allowlist` for CDN/cloud telemetry domains (`cloudfront.net`, `amazonaws.com`, etc.).

### 6. `SENT-WEB-001` — Suspicious HTTP Activity
- **Category:** `web`
- **Default Severity:** `medium` (escalates to `high` on exploit/probe syntax and `critical` if a traversal, sensitive-file, or SQLi probe returns HTTP `2xx`)
- **Default Threshold / Window:** Any request matching directory traversal (after up to 3 passes of URL percent-decoding), sensitive file probe (`.env`, `.git/config`, `wp-config.php`), SQLi, XSS, or scanner user agent (`sqlmap`, `nikto`, `nuclei`, etc.), OR `>= 30` HTTP 404 responses from one `source_ip` within `300s`
- **MITRE ATT&CK:** `T1190` (Exploit Public-Facing Application — Primary), `T1595.002` (Vulnerability Scanning), `T1595.003` (Wordlist Scanning)

### 7. `SENT-PRIV-001` — Unusual Privileged Activity
- **Category:** `privilege`
- **Default Severity:** `high` (escalates to `critical` on remote script piping `curl|bash` or `/etc/shadow` access)
- **Default Threshold / Window:** Evaluates 6 conditions across `authentication` and `process_execution` events:
  1. `sudo` / `su` by a user not in `authorized_admins`
  2. Direct `root` SSH login (`allow_root_ssh=false`)
  3. Local account creation (`useradd` / `usermod -aG sudo`)
  4. Sensitive command patterns (`/etc/shadow`, `/etc/sudoers`, `history -c`, `curl ... | bash`, SUID bit changes)
  5. Repeated failed `sudo`/`su` attempts (`>= 3` within `3600s`)
  6. Optional off-hours privileged execution (`enforce_business_hours`)
- **MITRE ATT&CK:** `T1548.003` (Sudo and Sudo Caching — Primary), `T1078.003` (Local Accounts), `T1136.001` (Create Account: Local Account), `T1070.003` (Clear Command History), `T1105` (Ingress Tool Transfer)
