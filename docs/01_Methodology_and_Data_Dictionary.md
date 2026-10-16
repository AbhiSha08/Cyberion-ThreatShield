# CDL-DET-V2 — Module 4.1 Deliverable
# Methodology & Data Dictionary
## Detection Engineering & Threat Hunting Engagement

> **Engagement Code:** `PROJ-CYBE-260802` (internal baseline: `CDL-DET-V2`)
> **Deliverable:** Module 4.1 — Methodology & Data Dictionary
> **Classification:** INTERNAL — RESTRICTED
> **Prepared by:** Cyberion ThreatShield — Detection Engineering Team
> **Date:** August 2026

---

## Table of Contents

1. [Engagement Overview](#1-engagement-overview)
2. [Detection Engineering Methodology](#2-detection-engineering-methodology)
   - 2.1 [Dataset Provenance](#21-dataset-provenance)
   - 2.2 [Hypothesis-Driven Hunting Workflow](#22-hypothesis-driven-hunting-workflow)
   - 2.3 [Sigma Rule Engineering Lifecycle](#23-sigma-rule-engineering-lifecycle)
3. [Data Dictionary — Windows Security & Sysmon](#3-data-dictionary--windows-security--sysmon)
4. [Data Dictionary — Zeek Network Logs](#4-data-dictionary--zeek-network-logs)
5. [Data Dictionary — Linux Auth & Auditd](#5-data-dictionary--linux-auth--auditd)
6. [Network Topology](#6-network-topology)
7. [Attack Chain Summary](#7-attack-chain-summary)

---

## 1. Engagement Overview

**Cyberion ThreatShield** (Project Code: `PROJ-CYBE-260802`, internal baseline: `CDL-DET-V2`) is a structured, four-phase detection engineering and threat hunting platform developed by the Cyberion ThreatShield team. The objective is to build a production-grade, fully-validated detection content repository covering the complete MITRE ATT&CK kill chain for a targeted corporate enterprise environment.

**Phase 1 Scope (this document):**
- Repository scaffolding and tooling
- Generation of realistic, schema-conformant security telemetry datasets
- Data dictionary authoring
- Python-based Sigma rule validation engine

The engagement simulates an advanced adversary campaign targeting a financial-sector corporate network (`cyberion.local`). The adversary achieves initial access via brute-force credential attacks, establishes C2 over HTTPS and DNS tunneling, performs lateral movement via SMB/RDP, conducts Kerberoasting, dumps LSASS credentials, exfiltrates data over non-standard ports, and deploys persistence mechanisms.

---

## 2. Detection Engineering Methodology

### 2.1 Dataset Provenance

Synthetic telemetry datasets in this engagement are modelled on the following authoritative real-world schemas and reference corpora:

| Source | Description | Relevance |
|--------|-------------|-----------|
| **EVTX-ATTACK-SAMPLES** (github.com/sbousseaden/EVTX-ATTACK-SAMPLES) | Curated Windows EVTX samples mapped to ATT&CK techniques by @sbousseaden | Windows EventID field schema and attack event patterns |
| **Mordor / OTRF Security Datasets** (github.com/OTRF/Security-Datasets) | Open Threat Research Foundation attack simulation dataset repository | Full attack-chain correlation, field naming conventions |
| **Atomic Red Team** (github.com/redcanaryco/atomic-red-team) | Red Canary's library of atomic test procedures mapped to ATT&CK | Attack technique execution fidelity and command-line patterns |
| **Zeek Documentation** (docs.zeek.org) | Official Zeek Network Monitor log schema | Zeek conn/dns/http field definitions |
| **Linux audit.rules / auditd man pages** | Linux kernel audit subsystem documentation | auditd SYSCALL/EXECVE/PATH record schemas |
| **Sigma Rule Specification** (github.com/SigmaHQ/sigma) | Open standard for SIEM-agnostic detection rule authoring | Rule schema and modifier semantics |

All field names, data types, and example values in this repository are aligned to the above schemas to maximise portability across SIEMs (Splunk, Elastic SIEM, Microsoft Sentinel, Chronicle).

**Telemetry Construction Approach:**

- **Attack events** are constructed to faithfully represent documented adversary TTPs (tactics, techniques, and procedures) with realistic command-line arguments, process hierarchies, access masks, and network byte counts.
- **Benign baseline events** are interspersed to enable false-positive tuning and precision testing of detection rules.
- **Timestamps** are anchored to August 14, 2026 UTC, with the attack chain progressing in chronological order over a ~13-minute window, while benign events span ±4 hours around the attack window.

---

### 2.2 Hypothesis-Driven Hunting Workflow

CDL-DET-V2 adopts a **hypothesis-driven threat hunting methodology**, structured as follows:

```
┌─────────────────────────────────────────────────────────┐
│  1. HYPOTHESIS FORMATION                                 │
│     • Intelligence input (CTI feeds, OSINT, IR reports) │
│     • ATT&CK technique mapping                          │
│     • Prior hunt findings / detection gaps              │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│  2. DATA SCOPE DEFINITION                               │
│     • Identify relevant log sources                     │
│     • Define time window and host scope                 │
│     • Confirm data availability / coverage gaps         │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│  3. ANALYTICAL QUERY DEVELOPMENT                        │
│     • Author SPL / KQL / Lucene hunt queries            │
│     • Apply field normalisation (ECS / OSSEM)          │
│     • Iteratively tune against baseline noise           │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│  4. RESULT TRIAGE & INVESTIGATION                       │
│     • Cluster results by endpoint / user / time         │
│     • Correlate across log sources                      │
│     • Determine true positive / false positive ratio    │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│  5. DETECTION CONTENT AUTHORING                         │
│     • Convert validated hunt queries to Sigma rules     │
│     • Assign severity, MITRE tags, false positive list  │
│     • Peer review and LGTM gate                         │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│  6. VALIDATION & DEPLOYMENT                             │
│     • Run validate_rules.py against telemetry datasets  │
│     • Confirm expected match counts                     │
│     • Deploy to SIEM via CI/CD pipeline                 │
└─────────────────────────────────────────────────────────┘
```

**Hunt Hypothesis Template:**

> *"It is possible that [threat actor / TTP] is [performing action] against [target asset/user] using [technique] in order to [objective], which would be observable in [log source] via [indicator]."*

---

### 2.3 Sigma Rule Engineering Lifecycle

All detection content in CDL-DET-V2 follows the **Sigma Rule Engineering Lifecycle (SREL)**:

#### Phase A — Research & Scoping
1. Identify the target ATT&CK technique (e.g., T1003.001 LSASS Memory)
2. Review public Sigma rule repositories (SigmaHQ/sigma, Elastic Detection Rules)
3. Document known-good (baseline) process/network patterns to avoid
4. Review Atomic Red Team test procedures for the technique

#### Phase B — Rule Authoring
Rules **must** include all PRD Section 8 required fields:

| Field | Requirement | Notes |
|-------|-------------|-------|
| `title` | String | Human-readable rule name, ≤ 100 chars |
| `id` | UUID v4 | Globally unique rule identifier |
| `status` | Enum | `stable` / `test` / `experimental` / `deprecated` |
| `description` | String | Purpose, context, and expected adversary behaviour |
| `references` | List[URL] | ATT&CK URL + at least one technical reference |
| `tags` | List[String] | Must include `attack.tXXXX` and optionally `attack.gXXXX` / `attack.sXXXX` |
| `logsource` | Dict | `product`, `category`, `service` keys |
| `detection` | Dict | `selection` + optional `filter` + mandatory `condition` |
| `falsepositives` | List[String] | Known benign triggers |
| `level` | Enum | `critical` / `high` / `medium` / `low` / `informational` |

#### Phase C — Validation
```bash
# Validate all rules and print terminal report
python scripts/validate_rules.py

# Export JSON report for CI/CD integration
python scripts/validate_rules.py --json-report results/validation_report.json

# Fail pipeline on any rule error
python scripts/validate_rules.py --fail-on-errors
```

#### Phase D — Peer Review & Merge
- Minimum 1 peer LGTM from a senior detection engineer
- CI/CD gate: `validate_rules.py --fail-on-errors` must return exit code 0
- Semantic versioning tag applied on merge to `main`

#### Phase E — Tuning & Deprecation
- Rules with > 10% FP rate over a 30-day window enter tuning review
- Deprecated rules keep `status: deprecated` and are retained in git history

---

## 3. Data Dictionary — Windows Security & Sysmon

**File:** `datasets/windows_security_sysmon_sample.json`
**Schema basis:** EVTX-ATTACK-SAMPLES / Mordor / OTRF Security Datasets

This dataset contains Windows Security Event Log and Sysmon Operational events representing a realistic attack chain (initial access → execution → persistence → credential access → lateral movement → defence evasion) plus ~15 benign baseline events.

### Core Event Identification Fields

| Field | Type | Example Value | Detection Engineering Utility |
|-------|------|---------------|-------------------------------|
| `EventID` | Integer | `4624` | Primary event classifier; mapped to ATT&CK techniques |
| `Channel` | String | `"Security"` | Distinguishes Security log events from Sysmon events |
| `TimeCreated` | ISO-8601 String | `"2026-08-14T08:06:00.000Z"` | Temporal correlation, beacon interval analysis |
| `Computer` | String | `"WS-FIN-04.cyberion.local"` | Host scoping, lateral movement path reconstruction |
| `description` | String | `"brute_force_failed_logon_1"` | Dataset-internal label; not present in real telemetry |

### Authentication & Logon Fields (EventID 4624, 4625, 4634)

| Field | Type | Example Value | Detection Engineering Utility |
|-------|------|---------------|-------------------------------|
| `SubjectUserName` | String | `"SYSTEM"` | Who initiated the logon request |
| `SubjectDomainName` | String | `"NT AUTHORITY"` | Domain context of initiating account |
| `TargetUserName` | String | `"svc_backup"` | Account being authenticated; key for account targeting detection |
| `TargetDomainName` | String | `"CYBERION"` | Target domain; cross-domain anomalies indicate pass-the-hash |
| `LogonType` | Integer | `3` / `10` | 3=Network, 10=RemoteInteractive(RDP); critical for lateral movement classification |
| `LogonProcessName` | String | `"NtLmSsp"` | Authentication process; NtLmSsp over network = NTLM, User32 = interactive |
| `AuthenticationPackageName` | String | `"NTLM"` / `"Kerberos"` | NTLM over network from external IP is high-fidelity C2/lateral indicator |
| `WorkstationName` | String | `"WS-MON-01"` | Source workstation; `-` indicates unknown/remote |
| `IpAddress` | String | `"185.220.101.45"` | Source IP; external IPs on auth events = external brute force |
| `IpPort` | String | `"49100"` | Source port; sequential ports = automated tooling |
| `Status` | Hex String | `"0xC000006D"` | Logon failure reason code (4625 only) |
| `SubStatus` | Hex String | `"0xC000006A"` | Sub-reason (wrong password, expired, etc.) |
| `LogonGuid` | UUID String | `"550E8400-E29B-..."` | Correlates 4624 with 4769/4776 across DC and workstation |
| `ProcessId` | Hex String | `"0x0"` | Initiating process; 0x0 = no associated process (network logon) |

### Process Creation Fields (EventID 4688 / Sysmon EventID 1)

| Field | Type | Example Value | Detection Engineering Utility |
|-------|------|---------------|-------------------------------|
| `NewProcessName` | String | `"C:\\Windows\\System32\\certutil.exe"` | Process image path; LOLBin detection (certutil, bitsadmin, etc.) |
| `CommandLine` | String | `"certutil.exe -urlcache -split -f http://..."` | Full command line; primary field for pattern-matching attacks |
| `ProcessId` | Hex String | `"0x1f00"` | Process ID for correlation |
| `ParentProcessName` | String | `"C:\\Windows\\System32\\cmd.exe"` | Parent process; unexpected parents indicate injection/lateral |
| `SubjectUserName` | String | `"j.doe"` | Executing user context |
| `SubjectDomainName` | String | `"CYBERION"` | User's domain |
| `Image` | String | `"C:\\Windows\\System32\\vssadmin.exe"` | Sysmon: full image path (same as NewProcessName for 4688 parity) |
| `User` | String | `"CYBERION\\j.doe"` | Sysmon: `DOMAIN\\user` formatted user context |
| `ParentImage` | String | `"C:\\Windows\\System32\\cmd.exe"` | Sysmon: parent image path |
| `ProcessGuid` | UUID String | `"A1B2C3D4-..."` | Sysmon: unique process GUID for cross-event correlation |
| `ParentProcessGuid` | UUID String | `"E5F6A7B8-..."` | Sysmon: parent process GUID; enables process tree reconstruction |
| `ProcessId` | Integer | `7788` | Sysmon: decimal PID |
| `ParentProcessId` | Integer | `7200` | Sysmon: parent PID |
| `Hashes` | String | `"MD5=9b71d..."` | Sysmon: file hashes for IOC matching |

**Key Detection Patterns:**
- `CommandLine` contains `-EncodedCommand` or `-enc` → Obfuscated PowerShell (T1059.001)
- `NewProcessName` endswith `certutil.exe` AND `CommandLine` contains `-urlcache` → Download cradle (T1105)
- `NewProcessName` endswith `schtasks.exe` AND `CommandLine` contains `/create` → Scheduled task persistence (T1053.005)
- `CommandLine` contains `reg add` AND `CurrentVersion\Run` → Run key persistence (T1547.001)
- `CommandLine` contains `vssadmin delete shadows` → Shadow copy deletion (T1490)

### Account Management Fields (EventID 4720, 4732)

| Field | Type | Example Value | Detection Engineering Utility |
|-------|------|---------------|-------------------------------|
| `SubjectUserName` | String | `"j.doe"` | Account that created/modified the target account |
| `TargetUserName` | String | `"support_adm"` | Newly created or modified account |
| `TargetDomainName` | String | `"WS-FIN-04"` | Local domain = local account creation |
| `TargetSid` | String | `"S-1-5-21-..."` | SID of target account |
| `GroupName` | String | `"Administrators"` | (4732 only) Group receiving new member |
| `GroupDomain` | String | `"WS-FIN-04"` | Group's domain |
| `MemberSid` | String | `"S-1-5-21-..."` | (4732 only) SID of account added to group |

**Key Detection Pattern:** 4720 immediately followed by 4732 with `GroupName=Administrators` within 60 seconds is near-certain T1136 + T1078.

### Kerberos Fields (EventID 4769)

| Field | Type | Example Value | Detection Engineering Utility |
|-------|------|---------------|-------------------------------|
| `SubjectUserName` | String | `"j.doe"` | Requesting user account |
| `SubjectUserDomain` | String | `"CYBERION"` | Requesting user's domain |
| `ServiceName` | String | `"svc_mssql"` | Target service account; high-value = Kerberoasting target |
| `ServiceSid` | String | `"S-1-5-21-..."` | Service account SID |
| `TicketOptions` | Hex String | `"0x40810000"` | Kerberos ticket flags |
| `TicketEncryptionType` | Hex String | `"0x17"` | **`0x17` = RC4-HMAC = Kerberoasting indicator** |
| `IpAddress` | String | `"::ffff:10.20.1.15"` | Source IP (IPv4-mapped IPv6 common in domain events) |
| `IpPort` | String | `"55743"` | Source port |

**Key Detection Pattern:** `TicketEncryptionType = 0x17` for a service account by a non-service user account → T1558.003 Kerberoasting.

### LSASS Access Fields (Sysmon EventID 10)

| Field | Type | Example Value | Detection Engineering Utility |
|-------|------|---------------|-------------------------------|
| `SourceImage` | String | `"C:\\Windows\\Temp\\procdump64.exe"` | Process performing the memory access; non-standard paths are suspicious |
| `SourceProcessId` | Integer | `9100` | Source PID for correlation |
| `SourceUser` | String | `"CYBERION\\j.doe"` | User context of accessing process |
| `TargetImage` | String | `"C:\\Windows\\System32\\lsass.exe"` | Process being accessed; lsass = credential material |
| `TargetProcessId` | Integer | `640` | lsass PID |
| `TargetUser` | String | `"NT AUTHORITY\\SYSTEM"` | lsass always runs as SYSTEM |
| `GrantedAccess` | Hex String | `"0x1010"` / `"0x1fffff"` | Memory access rights granted; `0x1010` = read virtual memory, `0x1fffff` = full access |
| `CallTrace` | String | `"ntdll.dll+0x6cc04\|..."` | Stack trace; unusual modules in trace indicate injection/hooking |

**Key Detection Patterns:**
- `TargetImage` endswith `lsass.exe` AND `GrantedAccess` in (`0x1010`, `0x1fffff`, `0x1410`) → T1003.001
- `SourceImage` not in whitelist (Task Manager, WER, antivirus) → LSASS dump attempt

### SMB Share Access Fields (EventID 5140, 5145)

| Field | Type | Example Value | Detection Engineering Utility |
|-------|------|---------------|-------------------------------|
| `SubjectUserName` | String | `"support_adm"` | Account accessing the share |
| `SubjectDomainName` | String | `"WS-FIN-04"` | Domain; local-domain user accessing network share = pass-the-hash indicator |
| `ShareName` | String | `"\\\\*\\ADMIN$"` | Share being accessed; ADMIN$ / C$ = administrative share lateral movement |
| `ShareLocalPath` | String | `"C:\\"` | Local path mapped by share |
| `AccessMask` | Hex String | `"0x1"` | Access rights requested |
| `RelativeTargetName` | String | `"Windows\\System32\\config\\SAM"` | (5145 only) Specific path within share; SAM access = credential harvesting |
| `IpAddress` | String | `"10.20.1.15"` | Source IP; internal IP targeting DC/servers = lateral movement |
| `IpPort` | String | `"49812"` | Source ephemeral port |

---

## 4. Data Dictionary — Zeek Network Logs

**File:** `datasets/zeek_network_sample.json`
**Schema basis:** Zeek Network Monitor official documentation (docs.zeek.org)

This dataset contains `conn.log`, `dns.log`, and `http.log` records. A `log_type` field discriminates record types. Records represent C2 beaconing, DNS tunneling, large-data exfiltration, internal lateral movement, and benign web traffic.

### Common Fields (all log types)

| Field | Type | Example Value | Detection Engineering Utility |
|-------|------|---------------|-------------------------------|
| `log_type` | String | `"conn"` / `"dns"` / `"http"` | Dataset-internal discriminator |
| `ts` | ISO-8601 String | `"2026-08-14T08:07:00.000Z"` | Connection/query timestamp; beacon interval analysis |
| `uid` | String | `"CBeacon0001"` | Zeek unique connection/query ID; join across log types |
| `id.orig_h` | String | `"10.20.1.15"` | Source IP address |
| `id.orig_p` | Integer | `50100` | Source port |
| `id.resp_h` | String | `"185.220.101.45"` | Destination IP address |
| `id.resp_p` | Integer | `443` | Destination port |
| `proto` | String | `"tcp"` / `"udp"` | Transport protocol |

### Connection Log Fields (`log_type: "conn"`)

| Field | Type | Example Value | Detection Engineering Utility |
|-------|------|---------------|-------------------------------|
| `service` | String | `"ssl"` / `"smb"` / `null` | Application-layer protocol identified by Zeek DPI |
| `duration` | Float | `42.7` | Connection duration in seconds; long durations = interactive sessions |
| `orig_bytes` | Integer | `54321890` | Bytes sent by originator; very large values = exfiltration |
| `resp_bytes` | Integer | `1024` | Bytes sent by responder; tiny response + large orig = data exfil pattern |
| `conn_state` | String | `"SF"` | Connection state (SF=normal close, S0=no response, REJ=rejected) |
| `missed_bytes` | Integer | `0` | Bytes missed by Zeek; non-zero = possible evasion/capture gap |
| `history` | String | `"ShADadFf"` | Zeek connection state machine history string |
| `orig_pkts` | Integer | `39104` | Packets sent by originator |
| `resp_pkts` | Integer | `22` | Packets sent by responder; skewed ratio = exfiltration or DDoS |

**Key Detection Patterns:**
- `id.resp_h` = `185.220.101.45` AND `id.resp_p` = `443` with consistent ~60s `ts` intervals → C2 beaconing (T1071.001)
- `id.resp_p` = `8443` AND `orig_bytes` > `1000000` AND `id.resp_h` in known-bad → Data exfiltration (T1048)
- `id.resp_p` = `445` AND `id.orig_h` != `id.resp_h` (both internal) AND NOT in baseline → SMB lateral movement (T1021.002)
- `id.resp_p` = `3389` AND `id.orig_h` != `id.resp_h` (both internal) → RDP lateral movement (T1021.001)

### DNS Log Fields (`log_type: "dns"`)

| Field | Type | Example Value | Detection Engineering Utility |
|-------|------|---------------|-------------------------------|
| `trans_id` | Integer | `10037` | DNS transaction ID; sequential IDs from same host = automated querying |
| `rtt` | Float | `0.003` | Round-trip time in seconds |
| `query` | String | `"cmd-aHR0cHM6...tunnel.cdn-update-check.com"` | DNS query QNAME; **long/encoded subdomains = DNS tunneling** |
| `qclass` | Integer | `1` | Query class (1=IN/Internet) |
| `qclass_name` | String | `"C_INTERNET"` | Human-readable query class |
| `qtype` | Integer | `16` | Query type integer (1=A, 16=TXT, 28=AAAA, 15=MX) |
| `qtype_name` | String | `"TXT"` | **TXT queries to external hosts = DNS tunneling indicator** |
| `rcode` | Integer | `0` | Response code (0=NOERROR, 3=NXDOMAIN) |
| `rcode_name` | String | `"NOERROR"` | Human-readable response code |
| `AA` | Boolean | `false` | Authoritative Answer flag |
| `TC` | Boolean | `false` | Truncated flag |
| `RD` | Boolean | `true` | Recursion Desired |
| `RA` | Boolean | `true` | Recursion Available |
| `answers` | List[String] | `["data_chunk_0_base64encoded"]` | DNS answer records; base64-like content = tunneling payload |
| `TTLs` | List[Integer] | `[60]` | Answer TTLs; very low TTL = fast-flux / dynamic C2 |
| `rejected` | Boolean | `false` | Whether resolver rejected the query |

**Key Detection Patterns:**
- `qtype_name = "TXT"` AND `len(query) > 50` AND external resolver → DNS tunneling (T1572)
- Subdomain contains base64-like strings (`[A-Za-z0-9+/]{20,}`) → T1572
- High query frequency to single external domain from single internal host → DNS beaconing

### HTTP Log Fields (`log_type: "http"`)

| Field | Type | Example Value | Detection Engineering Utility |
|-------|------|---------------|-------------------------------|
| `trans_depth` | Integer | `1` | HTTP pipeline depth |
| `method` | String | `"GET"` / `"POST"` | HTTP method; alternating GET/POST to same host = implant check-in pattern |
| `host` | String | `"cdn-update-check.com"` | HTTP Host header; domain reputation lookup |
| `uri` | String | `"/api/v2/config/check"` | Request URI; API-style paths to non-CDN IPs = C2 |
| `referrer` | String | `"-"` | HTTP Referer header; absent on tool-generated requests |
| `version` | String | `"1.1"` | HTTP version |
| `user_agent` | String | `"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"` | User agent; impersonating browser UA from automated tools |
| `request_body_len` | Integer | `256` | Request body bytes; POSTs with fixed-size bodies = implant beacons |
| `response_body_len` | Integer | `512` | Response body bytes |
| `status_code` | Integer | `200` | HTTP response code |
| `status_msg` | String | `"OK"` | HTTP response message |
| `resp_mime_types` | List[String] | `["application/json"]` | Response MIME types |

**Key Detection Patterns:**
- `host` = `cdn-update-check.com` AND `id.resp_h` = `185.220.101.45` (IP mismatch to legitimate CDN) → Domain fronting
- Uniform `request_body_len` across multiple connections → Fixed-size beacon
- Absent `referrer` + browser-impersonating `user_agent` + POST to `/api/` path → C2 implant

---

## 5. Data Dictionary — Linux Auth & Auditd

**File:** `datasets/linux_auth_auditd_sample.json`
**Schema basis:** Linux PAM / sshd auth.log format + Linux Kernel Audit System (auditd)

This dataset contains `auth.log` and `auditd` records. A `log_type` field (`"auth"` or `"auditd"`) discriminates record types.

### Common Fields (all record types)

| Field | Type | Example Value | Detection Engineering Utility |
|-------|------|---------------|-------------------------------|
| `log_type` | String | `"auth"` / `"auditd"` | Dataset-internal discriminator |
| `ts` | ISO-8601 String | `"2026-08-14T08:01:00.000Z"` | Event timestamp |
| `hostname` | String | `"SRV-DB-01"` | Target host |
| `description` | String | `"ssh_spray_failed_root"` | Dataset-internal label |

### Auth Log Fields (`log_type: "auth"`)

| Field | Type | Example Value | Detection Engineering Utility |
|-------|------|---------------|-------------------------------|
| `program` | String | `"sshd"` / `"sudo"` / `"CRON"` / `"su"` | Subsystem generating the log record |
| `pid` | Integer | `4000` | Process ID of the logging program |
| `message` | String | `"Failed password for root from 91.214.124.88 port 40000 ssh2"` | **Full auth.log message; primary field for pattern matching** |
| `user` | String | `"root"` | Target username (for SSH: attempted login account) |
| `src_ip` | String | `"91.214.124.88"` | Source IP address (SSH events) |
| `auth_method` | String | `"password"` / `"publickey"` | SSH authentication method |

**Key Detection Patterns from `message` field:**

| Pattern | Technique | Indicator |
|---------|-----------|-----------|
| `"Failed password for"` repeated from same `src_ip` | T1110.003 Password Spray | ≥ 5 failures in 60s |
| `"Failed password for invalid user"` | T1110.003 | Non-existent account targeting |
| `"Accepted password for"` after failures from same src | T1078 Valid Accounts | Successful spray |
| `"sudo"` + `"COMMAND=/bin/bash"` | T1548.003 Sudo/Su Abuse | Root shell via sudo |
| `"crontab"` + `"BEGIN EDIT"` | T1053.003 Cron | Cron modification event |
| `"pam_unix(su-l:auth): authentication failure"` | T1548.003 | Failed su to root |

### Auditd Fields (`log_type: "auditd"`)

| Field | Type | Example Value | Detection Engineering Utility |
|-------|------|---------------|-------------------------------|
| `type` | String | `"SYSCALL"` / `"PATH"` / `"EXECVE"` | Auditd record type |
| `msg` | String | `"audit(1723622400.000:1001): arch=c000003e..."` | Full auditd raw message string; all fields also parsed separately |
| `syscall` | String | `"open"` | System call name |
| `success` | String | `"yes"` / `"no"` | Whether the syscall succeeded; `no` = access denied |
| `exit` | Integer | `-13` | Syscall exit code; `-13` = EACCES (Permission Denied) |
| `exe` | String | `"/bin/cat"` | Full path of executing binary |
| `comm` | String | `"cat"` | Command name (truncated comm field) |
| `pid` | Integer | `4300` | PID of the process |
| `ppid` | Integer | `4100` | Parent PID |
| `uid` | Integer | `0` | Effective UID at time of syscall |
| `auid` | Integer | `1005` | Audit UID (original login UID, persists across su/sudo) |
| `key` | String | `"shadow_access"` | Audit rule key that triggered this record |
| `file_path` | String | `"/etc/shadow"` | (Dataset-augmented) Relevant file path |
| `name` | String | `"/etc/shadow"` | (PATH records) File path from audit PATH record |
| `mode` | String | `"0100640"` | (PATH records) File permissions |
| `nametype` | String | `"NORMAL"` / `"CREATE"` | (PATH records) Whether file was created or accessed |

**Key Detection Patterns:**

| Field | Value | Technique | Notes |
|-------|-------|-----------|-------|
| `key` | `shadow_access` | T1003.008 /etc/passwd and /etc/shadow | Requires auditd rule `-w /etc/shadow -p r -k shadow_access` |
| `key` | `cron_write` AND `nametype=CREATE` | T1053.003 Cron | New cron file written |
| `exe` | `/bin/cat` AND `name` = `/etc/shadow` | T1003.008 | Shadow file read attempt |
| `auid` | non-0 AND `uid` = 0 | T1548 | Privilege escalation via sudo/su |
| `type` | `EXECVE` AND `exe` in (`/usr/bin/id`, `/usr/bin/uname`, `/usr/bin/whoami`) | T1033 System Owner/User Discovery | Post-exploitation enumeration |

**Auditd `auid` Field — Detection Engineering Note:**

The `auid` (audit UID) is the **original login user's UID** that persists even after `sudo` or `su` privilege escalation. A record with `uid=0` (root) but `auid=1005` (svc_backup) definitively identifies that the root-level action was performed by the `svc_backup` user who escalated privileges — making this field critical for attribution.

---

## 6. Network Topology

```
INTERNET (Adversary-Controlled Infrastructure)
  ├── 185.220.101.45   cdn-update-check.com  [C2 server / HTTPS beacon target]
  ├── 91.214.124.88                          [SSH password spray source]
  └── 45.133.1.92                            [Data exfiltration endpoint :8443]

CORPORATE NETWORK — cyberion.local (10.20.0.0/16)
  ├── 10.20.0.10   DC-PROD-01    Domain Controller
  ├── 10.20.0.2    DNS-01        Internal DNS resolver
  ├── 10.20.1.15   WS-FIN-04     Finance workstation [COMPROMISED — initial access]
  ├── 10.20.1.22   WS-DEV-02     Developer workstation [lateral movement target]
  ├── 10.20.2.50   SRV-DB-01     Database server [Linux — SSH spray target]
  ├── 10.20.3.10   SRV-MON-01    Monitoring server
  ├── 10.20.3.11   WS-MON-01     Monitoring workstation
  └── 10.20.4.5    HELPDESK-01   Helpdesk workstation
```

---

## 7. Attack Chain Summary

The following table maps the synthetic attack chain events to MITRE ATT&CK techniques and the corresponding telemetry indicators present in the datasets:

| Step | Technique | Tactic | Dataset | Key Indicator |
|------|-----------|--------|---------|---------------|
| 1 | T1110.003 Password Spray | Initial Access | Windows | EventID 4625 × 5+ from `185.220.101.45` to `svc_backup` |
| 2 | T1078 Valid Accounts | Initial Access | Windows | EventID 4624 LogonType 3 from external IP after failures |
| 3 | T1110 Brute Force RDP | Initial Access | Windows | EventID 4625 LogonType 10 × 3 then 4624 LogonType 10 for `j.doe` |
| 4 | T1059.001 PowerShell | Execution | Windows | Sysmon EID 1 / EID 4688 with `-EncodedCommand` |
| 5 | T1033 System Discovery | Discovery | Windows | EID 4688 `whoami /priv` spawned from PowerShell |
| 6 | T1105 Ingress Tool Transfer | Command & Control | Windows | EID 4688 `certutil.exe -urlcache -split -f http://...` |
| 7 | T1197 BITS Jobs | Defense Evasion | Windows | EID 4688 `bitsadmin /transfer` to external URL |
| 8 | T1053.005 Scheduled Task | Persistence | Windows | EID 4688 `schtasks /create /sc MINUTE` with external binary |
| 9 | T1547.001 Registry Run Keys | Persistence | Windows | EID 4688 / Sysmon `reg add ...CurrentVersion\Run` |
| 10 | T1136.001 Local Account | Persistence | Windows | EID 4720 `support_adm` created + EID 4732 added to Administrators |
| 11 | T1558.003 Kerberoasting | Credential Access | Windows | EID 4769 `TicketEncryptionType=0x17` for `svc_mssql` / `svc_backup` |
| 12 | T1003.001 LSASS Memory | Credential Access | Windows | Sysmon EID 10 `GrantedAccess=0x1010/0x1fffff` targeting `lsass.exe` |
| 13 | T1021.002 SMB Lateral | Lateral Movement | Windows + Zeek | EID 5140/5145 ADMIN$/C$ access + Zeek conn port 445 |
| 14 | T1071.001 HTTPS C2 | Command & Control | Zeek | Periodic conn to `185.220.101.45:443` every ~60s |
| 15 | T1572 DNS Tunneling | Command & Control | Zeek | DNS TXT queries with encoded long subdomains |
| 16 | T1048 Exfiltration Alt Protocol | Exfiltration | Zeek | Large conn to `45.133.1.92:8443` (54MB+ outbound) |
| 17 | T1490 VSS Delete | Impact | Windows | EID 4688 `vssadmin delete shadows /all /quiet` |
| 18 | T1110.003 SSH Spray | Initial Access | Linux | Multiple `Failed password` in auth.log from `91.214.124.88` |
| 19 | T1548.003 Sudo Abuse | Privilege Escalation | Linux | sudo to `/bin/bash` as root by `svc_backup` |
| 20 | T1003.008 /etc/shadow | Credential Access | Linux | auditd `key=shadow_access` on `/etc/shadow` read attempt |
| 21 | T1053.003 Cron | Persistence | Linux | auditd `nametype=CREATE` on `/etc/cron.d/svc_update` |

---

*Document ends. Proceed to Phase 2: Sigma Rule Authoring (`rules/**/`).*
