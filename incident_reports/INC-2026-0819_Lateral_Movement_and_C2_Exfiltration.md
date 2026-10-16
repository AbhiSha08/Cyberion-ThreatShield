# Incident Case Report: INC-2026-0819

**Incident Title:** Internal Domain Lateral Movement, Kerberoasting, and High-Volume Exfiltration  
**Project Code:** `PROJ-CYBE-260802` (internal baseline: `CDL-DET-V2`)  
**Incident ID:** `INC-2026-0819`  
**Date of Incident:** 2026-08-19  
**Severity Rating:** **CRITICAL** (P1)  
**Assigned Lead Analyst:** Abhijeet Amarnath Sharma - Senior Detection Engineer & IR Lead  
**Incident Status:** Closed - Remediated  
**Closure Classification:** **True Positive (Active Network Lateral Movement & Data Exfiltration)**  

---

## 1. Executive Summary & Impact Assessment

On August 19, 2026, the Cyberion ThreatShield SOC responded to a high-severity alert chain indicating enterprise-wide lateral movement and massive data exfiltration.

Following the initial beachhead established on finance workstation `WS-FIN-04` (see `INC-2026-0814`), the adversary expanded access across the internal network. Utilizing harvested credentials and Kerberos TGS tickets requested with legacy RC4-HMAC encryption (`T1558.003`), the adversary pivoted laterally across internal subnets to development workstation **`WS-DEV-02.cyberion.local`** (`10.20.1.22`) and primary domain controller **`DC-PROD-01.cyberion.local`** (`10.20.0.10`).

The threat actor accessed default Windows administrative shares (`ADMIN$`, `C$`) and extracted the Security Account Manager (`config\SAM`) registry hive. Staged corporate intellectual property and database exports totaling **75.7 Megabytes** were subsequently exfiltrated over non-standard TCP port `8443` to foreign IP address **`45.133.1.92`**, supplemented by covert DNS tunneling TXT query channels to `*.tunnel.cyberion-exfil.com`.

### Impact Summary
* **Affected Hosts:**
  * `WS-FIN-04.cyberion.local` (`10.20.1.15`) - Weaponized pivot origin.
  * `WS-DEV-02.cyberion.local` (`10.20.1.22`) - Compromised development workstation; source code repository staging host.
  * `DC-PROD-01.cyberion.local` (`10.20.0.10`) - Targeted domain controller; SAM database accessed.
* **Targeted Accounts:** `CYBERION\svc_mssql`, `CYBERION\svc_backup`, `support_adm` (rogue local admin).
* **Exfiltrated Data Volume:** **75,777,890 bytes (~75.8 MB)** over TCP 8443, plus 4 high-entropy Base64 DNS TXT chunks.
* **Data Classification:** Confidential financial models, database connection strings, and Active Directory password hashes.

---

## 2. Incident Timeline Reconstruction

All events reconstructed from `datasets/windows_security_sysmon_sample.json`, `datasets/zeek_network_sample.json`, and firewall logs:

```text
08:10:00 UTC ──> 08:12:00 UTC ──> 08:25:00 UTC ──> 08:26:00 UTC ──> 08:30:00 UTC ──> 08:31:00 UTC
  Kerberoasting      SMB Admin        Exfil Phase 1    Exfil Phase 2      SMB Lateral        RDP Lateral
   TGS Tickets      Share Access       (54.3 MB)        (21.4 MB)          Pivoting           Pivoting
    (RC4 0x17)      (EID 5140/5145)    (WS-FIN-04)      (WS-DEV-02)        (Port 445)        (Port 3389)
```

| Timestamp (UTC) | Source Host / IP | Destination Host / IP | Protocol / Event ID | Artifact / Command Line / Details | Significance |
| :--- | :--- | :--- | :---: | :--- | :--- |
| **08:10:00.000Z** | `10.20.1.15` | `DC-PROD-01` (`10.20.0.10`) | Security `4769` | `ServiceName: svc_mssql, TicketEncryptionType: 0x17 (RC4)` | Kerberoasting request against SQL service SPN |
| **08:10:18.000Z** | `10.20.1.15` | `DC-PROD-01` (`10.20.0.10`) | Security `4769` | `ServiceName: svc_backup, TicketEncryptionType: 0x17 (RC4)` | Kerberoasting request against backup service SPN |
| **08:12:00.000Z** | `10.20.1.15` | `WS-DEV-02` (`10.20.1.22`) | Security `5140` | `ShareName: \\*\ADMIN$, AccessMask: 0x1` | Remote staging access to development workstation |
| **08:12:12.000Z** | `10.20.1.15` | `DC-PROD-01` (`10.20.0.10`) | Security `5140` | `ShareName: \\*\C$, AccessMask: 0x1` | Remote file share mount onto Domain Controller |
| **08:12:24.000Z** | `10.20.1.15` | `DC-PROD-01` (`10.20.0.10`) | Security `5145` | `RelativeTargetName: Windows\System32\config\SAM` | Direct extraction of local SAM password database |
| **08:25:00.000Z** | `10.20.1.15` | `45.133.1.92:8443` | Zeek `conn.log` | `orig_bytes: 54321890 (54.3 MB), duration: 42.1s` | Bulk encrypted exfiltration stream 1 |
| **08:26:00.000Z** | `10.20.1.22` | `45.133.1.92:8443` | Zeek `conn.log` | `orig_bytes: 21456000 (21.4 MB), duration: 18.4s` | Source code repository exfiltration stream 2 |
| **08:28:00.000Z** | `10.20.1.15` | `10.20.0.2:53` | Zeek `dns.log` | `qtype: TXT, query: c2Nhbi1kYXRh-01.tunnel.cyberion-exfil.com` | Covert DNS tunneling payload chunk 1 |
| **08:28:15.000Z** | `10.20.1.15` | `10.20.0.2:53` | Zeek `dns.log` | `qtype: TXT, query: Y3JlZC1oYXNo-02.tunnel.cyberion-exfil.com` | Covert DNS tunneling payload chunk 2 |
| **08:30:00.000Z** | `10.20.1.15` | `WS-DEV-02` (`10.20.1.22`) | Zeek `conn.log` | `Port: 445 (smb), orig_bytes: 4096` | Lateral SMB command delivery |
| **08:30:18.000Z** | `10.20.1.15` | `DC-PROD-01` (`10.20.0.10`) | Zeek `conn.log` | `Port: 445 (smb), orig_bytes: 4608` | Lateral SMB RPC connection to DC |
| **08:31:00.000Z** | `10.20.1.15` | `WS-DEV-02` (`10.20.1.22`) | Zeek `conn.log` | `Port: 3389 (rdp), orig_bytes: 204800` | Interactive RDP session established on DEV-02 |
| **08:31:30.000Z** | `10.20.1.15` | `DC-PROD-01` (`10.20.0.10`) | Zeek `conn.log` | `Port: 3389 (rdp), orig_bytes: 256000` | Interactive RDP administrative pivot to DC |
| **08:32:00.000Z** | `DC-PROD-01` | Local Host | Security `4688` | `vssadmin.exe delete shadows /all /quiet` | Shadow copy inhibition to prevent system recovery |

---

## 3. Root Cause Analysis (RCA)

Using the "Five Whys" methodology:
1. **Why was 75.8 MB of corporate data successfully exfiltrated?**  
   Endpoints were allowed to initiate direct outbound TCP connections over non-standard port 8443 directly to untrusted external IP addresses.
2. **Why was the attacker able to access sensitive repositories and the DC SAM hive?**  
   The attacker pivoted to `WS-DEV-02` and `DC-PROD-01` using compromised domain service account credentials.
3. **Why were service account credentials compromised?**  
   Accounts `svc_mssql` and `svc_backup` had registered Service Principal Names (SPNs) configured with legacy RC4 encryption, allowing rapid offline cracking of requested TGS tickets (Kerberoasting).
4. **Why could a compromised workstation directly contact the Domain Controller over SMB and RDP?**  
   Lack of internal network micro-segmentation; user workstation VLAN (`10.20.1.0/24`) had unfiltered, direct Layer 4 routing to the core server/DC VLAN (`10.20.0.0/24`).
5. **Root Cause:** Flat internal network routing without workstation-to-datacenter micro-segmentation, combined with unhardened Kerberos encryption standards and unrestricted outbound egress filtering.

---

## 4. MITRE ATT&CK Framework Mapping

| Tactic | Technique ID | Technique Name | Exploited Artifact / Procedure |
| :--- | :--- | :--- | :--- |
| **Credential Access** | `T1558.003` | Steal or Forge Kerberos: Kerberoasting | Requested TGS ticket with encryption `0x17` for `svc_mssql` and `svc_backup` |
| **Lateral Movement** | `T1021.002` | SMB/Windows Admin Shares | Remote mount of `\\*\ADMIN$` and `\\*\C$` on DEV-02 and DC-PROD-01 |
| **Lateral Movement** | `T1021.001` | Remote Desktop Protocol | Direct workstation-to-workstation and workstation-to-DC RDP hops |
| **Command & Control** | `T1071.001` | Web Protocols (HTTPS) | Egress control channel to `185.220.101.45:443` |
| **Command & Control** | `T1572` | Protocol Tunneling | High-entropy DNS TXT queries tunneling data to `*.tunnel.cyberion-exfil.com` |
| **Exfiltration** | `T1048` | Exfiltration Over Alternative Protocol | Outbound 75.8 MB data stream over non-standard TCP 8443 to `45.133.1.92` |
| **Impact** | `T1490` | Inhibit System Recovery | Invocation of `vssadmin.exe delete shadows /all /quiet` |

---

## 5. Containment, Eradication & Remediation Actions Taken

### 5.1 Immediate Containment (Executed within 15 Minutes of Alert)
* **Firewall Egress Rule:** Implemented emergency drop rules for TCP port `8443` outbound and blackholed IP `45.133.1.92/32`.
* **DNS Sinkhole:** Configured internal DNS forwarders (`10.20.0.2`) to sinkhole all queries resolving `*.cyberion-exfil.com` to `0.0.0.0`.
* **Host Quarantine:** Isolated `WS-FIN-04` and `WS-DEV-02` via EDR; forced credential invalidation on `DC-PROD-01`.
* **Internal Segmentation:** Implemented temporary switch ACLs blocking cross-subnet TCP 3389 and TCP 445 between workstation VLANs and server VLANs.

### 5.2 Eradication & Active Directory Remediation
* **Kerberos Remediation:** Reset passwords for `svc_mssql` and `svc_backup` with 32-character complex passphrases. Enforced AES-256 (`0x12`) encryption exclusively for all Active Directory SPN accounts (`msDS-SupportedEncryptionTypes = 24`).
* **Active Directory Purge:** Identified and deleted unauthorized local administrator account `support_adm` created during the chain.
* **Backup Restoration Verification:** Verified offline, immutable volume shadow copies and system state backups on DC-PROD-01 following the `vssadmin` deletion attempt.

### 5.3 Long-Term Defensive Enhancements
1. **Enforce Strict Egress Filtering:** Mandate that all outbound web traffic traverse an inspecting Secure Web Gateway (SWG). Block all outbound traffic on non-standard ports (e.g., 8443, 8080) for all user subnets.
2. **Network Micro-segmentation:** Enforce Zero Trust workstation isolation: block workstation-to-workstation (peer-to-peer) traffic on ports 445, 139, 3389, and 5985 via host-based Windows Defender Firewall GPOs.
3. **Deploy Group Managed Service Accounts (gMSA):** Migrate `svc_mssql` and `svc_backup` to Active Directory gMSAs, which eliminate static passwords and automatically rotate 128-character keys, permanently neutralizing Kerberoasting attacks.
