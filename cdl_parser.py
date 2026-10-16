import Evtx.Evtx as evtx

def parse_telemetry(file_path):
    print(f"[*] Analyzing telemetry from: {file_path}")
    
    # Existing mapping logic for target Event IDs
    mitre_mapping = {
        "4625": "T1110 (Brute Force)",
        "4624": "T1078 (Valid Accounts)",
        "4688": "T1059 (Command and Scripting Interpreter)"
    }
    
    try:
        # Open the binary log file
        with evtx.Evtx(file_path) as log:
            for record in log.records():
                xml_data = record.xml()
                
                # Check for our target Event IDs
                for event_id, technique in mitre_mapping.items():
                    if f">{event_id}<" in xml_data:
                        print(f"\n[+] Match Found: Event ID {event_id} -> {technique}")
                        # Print the first 300 characters to verify extraction
                        print(xml_data[:300] + "...\n")
                        return  # Stopping after first match for a clean terminal output
    except Exception as e:
        print(f"Error parsing log: {e}")

# Targeting an isolated sample file containing 4624/4625 events
sample_file = "/datasets/EVTX-ATTACK-SAMPLES/Credential Access/CA_4624_4625_LogonType2_LogonProc_chrome.evtx"
parse_telemetry(sample_file)