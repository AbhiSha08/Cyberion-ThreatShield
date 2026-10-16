# <div align="center">CYBERION THREATSHIELD</div>
<div align="center"><h3>Detection Engineering & Threat Hunting Platform</h3></div>
<div align="center">
  <p><strong>Project Code:</strong> <code>PROJ-CYBE-260802</code> (internal baseline: <code>CDL-DET-V2</code>) | <strong>Lead Analyst:</strong> Abhijeet Amarnath Sharma</p>
  <p><a href="https://github.com/AbhiSha08/Cyberion-ThreatShield">GitHub Repository Link</a></p>
</div>

---

## 📌 Executive Summary
**Cyberion ThreatShield (Project Code: `PROJ-CYBE-260802`, internal baseline: `CDL-DET-V2`)** is a cybersecurity detection engineering and threat hunting platform focused on strengthening SOC capabilities through proactive threat detection and incident investigation. It features a validated Sigma detection rule library mapped to MITRE ATT&CK, automated telemetry validation, hypothesis-driven threat hunts, forensic investigations, and repeatable incident response playbooks. Operating with zero heavy software or database overhead, this project delivers a production-grade library of Sigma rules, multi-source telemetry validation harnesses, proactive threat hunts, forensic case reports, and standard operating procedure (SOP) playbooks mapped strictly to the **MITRE ATT&CK Framework**.

---

## 🛠️ Architecture & Engagement Scope
The engagement avoids custom software development in favor of pure detection engineering and content validation, mirroring actual day-to-day SOC workflows:
* **Multi-Source Telemetry Pipeline (`datasets/`):** Generates realistic enterprise datasets spanning Windows Security/Sysmon auditing, Zeek network connections (`conn.log`/`dns.log`), and Linux auditd/auth records.
* **Production Sigma Rule Library (`rules/`):** 16 validated detection rules spanning 7 core MITRE tactics, incorporating advanced correlation logic for multi-event sequences and thresholds.
* **Automated Validation Engine (`scripts/validate_rules.py`):** Standalone Python harness leveraging `pyyaml`, `pandas`, and `rich` to enforce PRD Section 8 schema compliance and evaluate true-positive match counts.
* **Proactive Threat Hunting & Forensics:** Hypothesis-driven hunts (`TH-001`, `TH-002`), forensic case reports (`INC-0814`, `INC-0819`) with 5-Whys root cause analysis, and 3 incident response playbooks (`PB-001` to `PB-003`).

---

## 📋 Key Deliverables & Artifacts Summary

| Module | Deliverable Description | Location Path | Status |
| :--- | :--- | :--- | :---: |
| **Module 4.1** | Methodology Document & Data Dictionary | `docs/01_Methodology_and_Data_Dictionary.md` | ✅ **Complete** |
| **Module 4.2** | 16 Production Sigma Rules (3 Correlation) | `rules/**/*.yml` | ✅ **16/16 PASS** |
| **Module 4.3** | MITRE ATT&CK Coverage Matrix & Navigator JSON | `mitre_attack/` | ✅ **24 Assessed** |
| **Module 4.4** | 2 Structured Hypothesis Threat Hunt Reports | `threat_hunts/` | ✅ **Complete** |
| **Module 4.5** | IOC Research Briefing & Operationalization | `docs/03_IOC_Research_and_Operationalization.md` | ✅ **Complete** |
| **Module 4.6** | 2 Forensic Incident Case Reports | `incident_reports/` | ✅ **Complete** |
| **Module 4.7** | 3 Incident Response Playbooks (SOPs) | `playbooks/` | ✅ **Complete** |
| **Module 4.8** | Rule Tuning & False-Positive Analysis Guide | `docs/02_Rule_Tuning_and_FP_Analysis.md` | ✅ **Complete** |
| **Module 4.9** | Executive CISO Summary Report | `docs/04_Executive_Summary_Report.md` | ✅ **Complete** |
| **Testing** | Automated Pytest Regression Suite (57 Tests) | `tests/test_detections.py` | ✅ **57/57 PASSED** |

---

## 🔬 Execution & Verification Proof

The repository includes programmatic test scripts and validation harnesses to guarantee 100% reproducibility and zero false positives.

### 1. Sigma Rule Validation Harness (`validate_rules.py`)
> *The screenshots below display the Rich terminal output confirming all 16 production Sigma rules passed schema compliance checks and successfully matched 67 true-positive events across the multi-source telemetry datasets.*

![Validation Summary 1](assets/validation_top.png)
![Validation Summary 2](assets/validation_bottom.png)

### 2. Pytest Regression & False-Positive Suite (`test_detections.py`)
> *The screenshot below confirms all 57 automated unit, schema, true-positive match, and false-positive immunity tests passing cleanly with a 100% success rate.*

![Pytest Passing](assets/pytest_passing.png)

---

## 💡 Challenges Faced & Overcome
1. **Multi-Source Log Schema Normalization:** Reconciling disparate field nomenclature between Windows Security auditing, Sysmon event IDs, Zeek connection attributes, and Linux auditd records presented significant parsing hurdles. This was resolved by designing a dynamic logsource-to-dataset routing layer within `validate_rules.py` that normalizes field lookups and query conditions.
2. **Eliminating False Positives on Heuristics:** Initial rules targeting PowerShell encoded execution and LSASS memory access inadvertently triggered administrative noise. This was mitigated by introducing production filter blocks (tuning out authorized administrative deployment scripts and legitimate EDR/antivirus integrity checks) verified through automated pytest regression suites.
3. **Mathematical Modeling of C2 Beaconing:** Proving statistical confidence for intermittent C2 callbacks without deployed SIEM infrastructure was addressed by applying Inter-Arrival Time (IAT) statistical dispersion modeling—calculating standard deviation ($\sigma$), mean ($\mu$), and Coefficient of Variation ($\text{CV} = \sigma / \mu < 0.25$)—to mathematically prove the beaconing signature in `TH-002`.

---
<div align="center"><small><em>End of Report — Cyberion ThreatShield (`CDL-DET-V2`)</em></small></div>