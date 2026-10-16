# Threat Intelligence Briefing: IOC Research & Operationalization

**Project Code:** `CDL-DET-V2`  
**Document ID:** `DOC-03`  
**Classification:** TLP:AMBER - Cyberion Internal SOC & Threat Intelligence  
**Author:** Abhijeet Amarnath Sharma - Senior Detection Engineer & Threat Intel Lead  
**Date:** 2026-08-15  
**Version:** 2.0.0  
**Status:** Operationalized / Active Enforcement  

---

## 1. Executive Summary

During the `CDL-DET-V2` threat detection and response engagement, Cyberion Defense Labs extracted, verified, and operationalized indicators of compromise (IOCs) associated with an advanced persistent threat (APT) campaign targeting finance, database, and engineering assets.

This intelligence report compiles all technical indicators across network, host, and domain layers, details OSINT and pivot research, and outlines the automated operationalization workflow used to enforce multi-layer defense across firewalls, DNS resolvers, endpoint detection agents, and SIEM correlation watchlists.

---

## 2. Threat Actor Infrastructure & Indicator Inventory

### 2.1 Network Indicators (IPv4 Infrastructure)

| IP Address | Autonomous System (ASN) & Geo | Role in Campaign | Threat Classification | Operational Action |
| :--- | :--- | :--- | :--- | :--- |
| **`185.220.101.45`** | AS208294 (Zwiebelfreunde e.V.) / Germany | External RDP brute force, PowerShell reverse shell listener, payload download host | High-Confidence Malicious (Known Tor Exit Node) | Perimeter BGP Null-Route / Firewall Drop |
| **`91.214.124.88`** | AS44094 (Webhost1 LLC) / Russia | Linux SSH distributed password spraying source (`SRV-DB-01`) | High-Confidence Malicious (Bulletproof VPS) | Edge Perimeter Drop / SSH Port Lockdown |
| **`45.133.1.92`** | AS197695 (Reg.ru Hosting) / Netherlands | High-volume exfiltration staging server (Port 8443 receiver) | Critical Malicious (Adversary Drop Box) | Global Egress Block / Forensic Monitoring |

### 2.2 Domain & DNS Tunneling Infrastructure

| Domain / FQDN | Registrar / Nameserver | Role in Campaign | Threat Classification | Operational Action |
| :--- | :--- | :--- | :--- | :--- |
| **`cdn-update-check.com`** | NameCheap, Inc. / Cloudflare NS | Fast-flux C2 fallback domain and TLS SNI certificate masquerade | High-Confidence Malicious | Proxy Categorization Block / Domain Takedown Request |
| **`*.tunnel.cyberion-exfil.com`** | Epik Holdings / Off-shore NS | Base64-encoded high-entropy TXT query covert DNS exfiltration | Critical Malicious (DNS Tunneling) | Internal DNS Sinkhole to `0.0.0.0` |

### 2.3 Host Artifacts & Cryptographic File Hashes

| File Name | Staged Location | File Type | SHA256 / MD5 Hash | Campaign Context |
| :--- | :--- | :--- | :--- | :--- |
| **`payload.exe`** (`svchost32.exe`) | `C:\Users\j.doe\AppData\Local\Temp\` | PE32+ Executable | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`<br>MD5: `9b71d224bd62f3785d96d46ad3ea3d73` | Initial secondary payload retrieved via `certutil.exe` |
| **`update.dll`** | `C:\Windows\Temp\` | PE64 Dynamic Link Library | `a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890`<br>MD5: `d41d8cd98f00b204e9800998ecf8427e` | Cobalt Strike / reflective DLL staged via `bitsadmin` & loaded by SYSTEM task |
| **`procdump64.exe`** | `C:\Windows\Temp\` | Sysinternals Executable | `84c45a7071db8c1b9f67a6d71b7b752763f03b2909477e3c153725ee793318b8`<br>MD5: `7c6a9926db860ef8292850900f607567` | Dual-use binary used for unauthorized memory extraction of `lsass.exe` |

---

## 3. Threat Intelligence OSINT Analysis & Attribution Pivots

### 3.1 IP Pivot: `185.220.101.45`
* **Threat Group Correlation:** The IP address is an active Tor exit node documented in AlienVault OTX and Emerging Threats feeds. The adversary routed interactive RDP and HTTP download cradles through Tor to obscure true geographical origin.
* **Hosting Details:** The IP regularly rotates subnets. Reverse DNS resolves to `tor-exit-45.zwiebel.network`.

### 3.2 Infrastructure Pivot: `45.133.1.92`
* **Threat Group Correlation:** IP address identified as a staging point for data-theft campaigns. Port scans reveal listener on TCP port `8443` running a custom Go-based HTTP listener without valid TLS certificates (self-signed `CN=localhost`).
* **Targeting:** Observed receiving bulk data streams from internal development subnets (`WS-DEV-02`) and finance endpoints.

---

## 4. Multi-Layer Operationalization Architecture

To ensure immediate, proactive defense across the enterprise, IOCs were operationalized across four independent defensive tiers:

```text
               ┌────────────────────────────────────────────────────────┐
               │    Cyberion Threat Intelligence Engine (MISP/STIX)     │
               └───────────────────────────┬────────────────────────────┘
                                           │
         ┌───────────────────┬─────────────┴───────┬───────────────────┐
         ▼                   ▼                     ▼                   ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ Perimeter Edge  │ │ Enterprise DNS  │ │   Endpoint EDR  │ │  SIEM Real-Time │
│  Firewall Drop  │ │ Blackhole Sink  │ │  Blocklist Hash │ │ Watchlist Rules │
│ (185.220.101.45)│ │ (*.tunnel.exfil)│ │ (update.dll SHA)│ │  (EID 4624/conn)│
└─────────────────┘ └─────────────────┘ └─────────────────┘ └─────────────────┘
```

### 4.1 Tier 1: Perimeter Network Firewalls (BGP & Drop ACLs)
* **Palo Alto / Fortinet Dynamic Block Lists (DBLs):**
  * Subscribed edge perimeter firewalls to the Cyberion High-Risk Threat Feed containing `185.220.101.45`, `91.214.124.88`, and `45.133.1.92`.
  * Traffic matching these IPs is dropped unconditionally with TCP Reset (`RST`) packets discarded.

### 4.2 Tier 2: Protective DNS Resolver (DNS Sinkholing)
* **Response Policy Zone (RPZ) / BIND Sinkholing:**
  ```text
  ; Cyberion Protective DNS RPZ Zone File
  $TTL 60
  tunnel.cyberion-exfil.com    CNAME .
  *.tunnel.cyberion-exfil.com  A     0.0.0.0
  cdn-update-check.com         A     0.0.0.0
  ```
  * Resolving queries are immediately directed to `0.0.0.0` while generating a high-priority SOC telemetry event in Zeek `dns.log`.

### 4.3 Tier 3: Endpoint Detection & Response (EDR Blocklists)
* **Hash Blacklisting:**
  * Created global IOC block policies in Microsoft Defender for Endpoint / CrowdStrike Falcon for SHA256 hashes of `payload.exe` and `update.dll`.
  * Attempts to execute or write these files to disk trigger instant host quarantine and process termination.

### 4.4 Tier 4: SIEM Automated Lookup & Watchlist Correlation
* **Splunk / Elastic / Microsoft Sentinel Watchlist Table:**
  ```sql
  -- Automated SIEM Correlation Query
  SELECT 
      TimeCreated, Computer, SubjectUserName, IpAddress, 'Match: Known_C2_IP' AS Alert_Type
  FROM windows_security_sysmon
  WHERE IpAddress IN (SELECT ioc_value FROM threat_intel_watchlist WHERE ioc_type = 'ip')
  UNION ALL
  SELECT 
      ts, id_orig_h, id_resp_h, id_resp_p, 'Match: Exfil_Staging_Server' AS Alert_Type
  FROM zeek_network
  WHERE id_resp_h IN ('45.133.1.92', '185.220.101.45');
  ```

---

## 5. Threat Intelligence Lifecycle & De-provisioning (Aging Policy)

To avoid accumulation of stale indicators and unnecessary firewall rule bloat:
1. **Dynamic IP Indicators:** Maintained on active drop lists for **30 days**. Re-evaluated every 14 days against public Tor exit and bulletproof hosting registries.
2. **Domain Indicators:** Retained in DNS sinkhole policies for **90 days** or until domain registration expires.
3. **Cryptographic Hashes:** Retained permanently in the Cyberion Threat Repository as historical reference signatures.
