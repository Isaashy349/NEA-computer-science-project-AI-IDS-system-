# alerts.py
import random
import time
from datetime import datetime

#Import from our other modules
from threat_log import (
    create_threat_record,
    add_threat,
    update_threat_status,
    mark_as_false_positive,
    SEVERITY_NORMAL,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    STATUS_OPEN,
    STATUS_INVESTIGATING,
    STATUS_RESOLVED,
    STATUS_FALSE_POS
)
from model import THRESHOLD
#ATTACK TYPE CLASSIFICATION
#Maps probability ranges and feature patterns to likely attack categories. Makes an educated guess at the attack type based on the confidence score and which features had high values in the triggering event.

def infer_attack_type(confidence, event_dict):
    # Extract key feature values from the event (default to 0 if missing)
    failed_logins = event_dict.get("failed_logins", 0)
    packet_count = event_dict.get("packet_count", 0)
    unusual_port = event_dict.get("unusual_port", 0)
    requests_ps = event_dict.get("requests_per_sec", 0)
    duration  = event_dict.get("duration", 0)
    #Rule-based type inference based on the most suspicious features
    if failed_logins > 3:
        #Many failed login attempts- brute force or credential stuffing
        return "Brute Force / Credential Attack"
    elif packet_count > 400 and requests_ps > 100:
        #Extremely high traffic volume- DoS attack
        return "DoS / DDoS Attack"
    elif unusual_port == 1:
        #Traffic on unusual or same source/dest port- port scan or reconnaissance
        return "Network Reconnaissance / Port Scan"
    elif duration < 2 and packet_count > 200:
        #Very short duration but high packet count- probe or sweep
        return "Probe / Network Sweep"
    elif confidence >= 0.85:
        #Very high confidence but no specific pattern- likely known attack signature
        return "Advanced Persistent Threat (APT)"
    else:
        #Can't determine specific type
        return "Anomalous Traffic (Unknown Type)"
    
#Generates a human-readable explanation of WHY the AI flagged this event. Builds a list of suspicious observations based on feature values
observations = []
def generate_explanation(event_dict, confidence, severity):
    failed_logins = event_dict.get("failed_logins", 0)
    packet_count = event_dict.get("packet_count", 0)
    unusual_port = event_dict.get("unusual_port", 0)
    requests_ps = event_dict.get("requests_per_sec", 0)
    duration = event_dict.get("duration", 0)
    data_volume = event_dict.get("data_volume", 0)
    avg_pkt_size = event_dict.get("avg_packet_size", 0)
    # Check each feature and add a plain-language note if it's suspicious
    if failed_logins > 0:
        observations.append(
            f"• {int(failed_logins)} failed login attempt(s) detected - "
            f"may indicate a brute force or credential attack."
        )
    if packet_count > 300:
        observations.append(
            f"• Unusually high packet count ({int(packet_count)}) - "
            f"consistent with flood or DDoS attack patterns."
        )
    if unusual_port== 1:
        observations.append(
            "• Connection uses an unusual or reserved port - "
            "may indicate reconnaissance or exploitation attempt."
        )
    if requests_ps > 50:
        observations.append(
            f"• High request rate ({requests_ps:.0f} req/sec) - "
            f"far above normal browsing behaviour."
        )
    if duration < 2 and packet_count > 100:
        observations.append(
            f"• Very short connection ({duration}s) with high traffic - "
            f"pattern is consistent with automated attack tools."
        )
    if data_volume > 10000:
        observations.append(
            f"• Large data transfer volume ({int(data_volume):,} bytes) - "
            f"potential data exfiltration."
        )
    if avg_pkt_size > 8000:
        observations.append(
            f"• Abnormally large average packet size ({int(avg_pkt_size):,} bytes) - "
            f"may indicate malformed or crafted packets."
        )
    #Generate the full explanation
    explanation = (
        f"AI Confidence Score: {confidence:.0%}\n"
        f"Severity Level: {severity}\n\n"
        f"The following features contributed to this alert:\n\n"
    )
    if observations:
        explanation += "\n".join(observations)
    else:
        explanation+= (
            "• The overall combination of network features matched patterns "
            "associated with malicious activity in the training data, even though "
            "no single feature was highly anomalous on its own.")
    return explanation


def generate_recommended_action(severity, attack_type):
    """
    Generates a recommended course of action for the admin based on the
    severity level and inferred attack type.

    Returns a string of recommended steps.
    """
    if severity == SEVERITY_HIGH:
        base_action = (
            "IMMEDIATE ACTION REQUIRED:\n"
            "1) Block the source IP address at the firewall immediately.\n"
            "2) Isolate any affected systems from the network.\n"
            "3) Notify the security team and escalate to incident response.\n"
            "4) Preserve all logs for forensic analysis.\n"
            "5) Document the incident and begin formal response procedures.\n"
        )
    elif severity == SEVERITY_MEDIUM:
        base_action = (
            "REVIEW REQUIRED:\n"
            "1) Investigate the source IP - check if it is a known device.\n"
            "2) Review recent activity from this IP in the logs.\n"
            "3) Monitor closely for repeated or escalating behaviour.\n"
            "4) Consider temporarily blocking the source IP as a precaution.\n"
            "5) Mark as False Positive if confirmed to be legitimate traffic.\n"
        )
    else:
        base_action = (
            "MONITOR:\n"
            "1) No immediate action required.\n"
            "2) Keep this event in the log for trend analysis.\n"
            "3) If similar events repeat from the same source, escalate.\n"
        )
    #Adds attack-type specific guidance
    if "Brute Force" in attack_type:
        base_action += (
            "\nBrute Force Specific:\n"
            "- Check if the targeted account has been compromised.\n"
            "- Consider enforcing account lockout policies.\n"
            "- Review authentication logs for successful logins after the attempts.\n"
        )
    elif "DoS" in attack_type:
        base_action += (
            "\nDoS/DDoS Specific:\n"
            "- Activate rate limiting on the affected service.\n"
            "- Engage ISP if attack is coming from many sources (DDoS).\n"
            "- Check service availability and performance impact.\n"
        )
    elif "Reconnaissance" in attack_type:
        base_action += (
            "\nReconnaissance Specific:\n"
            "- The attacker may be preparing a larger attack - caution advised.\n"
            "- Review firewall rules and ensure no unintended ports are open.\n"
            "- Check if any services responded with detailed error information.\n"
        )
    return base_action



#ALERT GENERATION
#The main alert generation function. Called by the UI whenever the AI model detects a suspicious event
#Returns a dictionary with all alert information, or None for normal traffic

def process_detection(source_ip, destination_ip, confidence, severity, event_dict, affected_system="Network"):
    #Normal traffic - no alert needed, return None
    if severity == SEVERITY_NORMAL:
        return None
    #Determine what kind of attack this likely is
    attack_type = infer_attack_type(confidence, event_dict)
    #Create the threat record
    threat= create_threat_record(
        source_ip       = source_ip,
        destination_ip  = destination_ip,
        confidence      = confidence,
        severity        = severity,
        attack_type     = attack_type,
        affected_system = affected_system
    )
    #Adds to the threat log
    success = add_threat(threat)
    if not success:
        print("[Alerts] WARNING: Failed to log threat record.")
        return None
    #Generate the explanation and recommended action for UI
    explanation = generate_explanation(event_dict, confidence, severity)
    action      = generate_recommended_action(severity, attack_type)

    #Return everything that UI needs to display this alert
    return {
        "threat": threat, #The full threat record dictionary
        "explanation": explanation, #Why the AI flagged it
        "action": action #What the admin should do
    }


# LIVE TRAFFIC SIMULATION
#simulates a stream of network events by generating random traffic that has a realistic mix of normal and attack patterns
#UI calls generate_next_event() on a timer to simulate live detection
SIMULATED_SOURCE_IPS = [
    "192.168.1.10", "192.168.1.45", "10.0.0.88", "172.16.0.5",
    "203.0.113.42", "198.51.100.7", "192.168.2.101", "10.10.10.50",
    "172.31.255.1",  "192.0.2.200"
]
SIMULATED_DEST_IPS = [
    "10.0.0.1", "10.0.0.2", "10.0.0.5", "172.16.1.1", "192.168.0.1"
]
SIMULATED_SYSTEMS = [
    "Web Server", "Database Server", "Authentication Server",
    "File Server", "Network Gateway", "Admin Workstation"
]
#Network protocols used in simulation
SIMULATED_PROTOCOLS = ["TCP", "TCP", "TCP", "UDP", "UDP", "ICMP"]
#Generates a single simulated network event as a raw feature dictionary
# The event is randomly either normal (60%) or an attack (40%)
#Attack events have feature values that match real attack patterns

#Returns a tuple: (event_dict, source_ip, destination_ip, system)
  
def generate_simulated_event():
    #Randomly decides event is an attack or normal traffic
    is_attack = random.random() < 0.40    # 40% chance of attack

    #Picks a random protocol- usually TCP
    protocol = random.choice(SIMULATED_PROTOCOLS)
    if is_attack:
        #Attack traffic: high packet counts, failed logins, short duration
        event = {
            "packet_count": random.randint(200, 512),
            "avg_packet_size": random.randint(5000, 50000),
            "duration": random.randint(0, 4),
            "failed_logins": random.randint(0, 9),
            "requests_per_sec": random.randint(50, 500),
            "unusual_port": random.randint(0, 1),
            "data_volume": random.randint(0, 500),
            "protocol": protocol,
            "packet_size_bytes": random.randint(5000, 50000)
        }
    else:
        #Normal traffic: low packet counts, no failed logins, longer duration
        event= {
            "packet_count":     random.randint(1, 50),
            "avg_packet_size":  random.randint(100, 4000),
            "duration":         random.randint(1, 200),
            "failed_logins":    0,
            "requests_per_sec": random.randint(1, 30),
            "unusual_port":     0,
            "data_volume":      random.randint(500, 8000),
            "protocol":         protocol,
            "packet_size_bytes": random.randint(100, 4000)
        }
    source_ip = random.choice(SIMULATED_SOURCE_IPS)
    dest_ip = random.choice(SIMULATED_DEST_IPS)
    system = random.choice(SIMULATED_SYSTEMS)
    return event, source_ip, dest_ip, system


#Self test
if __name__ == "__main__":
    print("  Alerts Module - Self Test")
    print("=" * 55)
    #Tests events that should trigger high severity alert
    print("\n[Test 1] High severity event (DoS pattern):")
    high_event = {
        "packet_count": 480, "avg_packet_size": 15000,
        "duration": 1, "failed_logins": 0,
        "requests_per_sec": 400, "unusual_port": 0, "data_volume": 200
    }
    alert= process_detection("203.0.113.42", "10.0.0.1", confidence=0.92, severity="High", event_dict=high_event, affected_system="Web Server")
    if alert:
        print(f"  Threat ID: {alert['threat']['threat_id']}")
        print(f"  Attack: {alert['threat']['attack_type']}")
        print(f"  Severity: {alert['threat']['severity']}")
        print(f"\n  Explanation:\n{alert['explanation']}")
        print(f"\n  Recommended Action:\n{alert['action']}")

    #Tests normal event
    print("\n[Test 2] Normal traffic (should NOT generate alert):")
    normal_event = {
        "packet_count":10, "avg_packet_size": 500,
        "duration": 30, "failed_logins": 0,
        "requests_per_sec": 2, "unusual_port": 0, "data_volume": 3000
    }
    result= process_detection("192.168.1.10", "10.0.0.1",
                                confidence=0.08, severity="Normal",
                                event_dict=normal_event)
    print(f"  Result: {'No alert generated (correct)' if result is None else 'Alert generated (unexpected)'}")

    #Tests simulated event generator
    print("\n[Test 3] Generating 3 simulated events:")
    for i in range(3):
        ev, src, dst, sys = generate_simulated_event()
        print(f"  Event {i+1}: src={src} dst={dst} "
              f"packets={ev['packet_count']} logins={ev['failed_logins']}")
    print("\n  Self-test complete.")