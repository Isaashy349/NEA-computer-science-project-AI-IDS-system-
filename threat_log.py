import csv
import os
from datetime import datetime

#This is where the theat log is stored
THREAT_LOG_PATH = "data/threat_log.csv"
#Valid values a threat can have
STATUS_OPEN = "Open"
STATUS_INVESTIGATING = "Investigating"
STATUS_RESOLVED = "Resolved"
STATUS_FALSE_POS = "False Positive"
#valid severity levels
SEVERITY_NORMAL ="Normal"
SEVERITY_MEDIUM = "Medium"
SEVERITY_HIGH = "High"
#Field names in a threat record
THREAT_FIELDS =["threat_id",
    "timestamp",
    "source_ip",
    "destination_ip",
    "attack_type",
    "detection_method",
    "confidence",
    "severity",
    "affected_system",
    "response_priority",
    "status"]

daily_counter = 0 #Increments with each new threat in a day
last_date = None #Tracks when the day changes

#Generates unique IDs in the TID-YYYYMMDD-NNNN format
def generate_threat_id():
    global daily_counter, last_date #tells python that we want module level variables
    current_date = datetime.now().strftime("%Y%m%d")
    #if day has changed since last ID generated then reset counter
    if current_date != last_date:
        daily_counter =0
        last_date = current_date
        
    daily_counter+= 1 #Increment counter for new threat
    counter_str = str(daily_counter).zfill(4) #formats counter into a 4 digit string
    threat_id = f"TID-{current_date} - {counter_str}"
    return threat_id

#This creates a new threat record as a dictionary, each key-value pairs stores a piece of information about the threat
def create_threat_record(source_ip, destination_ip, confidence, severity, attack_type="Unknown", detection_method="AI -Logistic Regression", affected_system="Network"):
    if severity == SEVERITY_HIGH:
        priority = "P1 - Immediate"
    elif severity == SEVERITY_MEDIUM:
        priority = "P2 - Review soon"
    else:
        priority = "P3 - Monitor"
    threat = {"threat_id": generate_threat_id(),
        "timestamp":datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip":source_ip,
        "destination_ip":destination_ip,
        "attack_type":attack_type,
        "detection_method":detection_method,
        "confidence":round(float(confidence), 4),
        "severity":severity,
        "affected_system":affected_system,
        "response_priority":priority,
        "status":STATUS_OPEN}
    return threat

#This validates each threat record before its added to the log, checks that all required fields are present and values are in range
def validate_threat_record(threat):
    for field in THREAT_FIELDS:
        if field not in threat:
            return False, f"Missing required field: {field}"
    #checks that confidence is between 0-1
    try:
        conf = float(threat["confidence"])
        if not (0.0 <= conf <= 1.0):
            return False, f"Confidence {conf} is out of range [0,1]"
    except (ValueError, TypeError):
        return False, f"Confidence value '{threat['confidence']}' is not a number"
    #Checks if severity is a valid value
    valid_severities = [SEVERITY_NORMAL,SEVERITY_MEDIUM, SEVERITY_HIGH]
    if threat ["severity"] not in valid_severities:
        return False, f"Invalid severity: {threat['severity']}"
    #Checks if status is a valid value
    valid_statuses = [STATUS_OPEN, STATUS_INVESTIGATING, STATUS_RESOLVED, STATUS_FALSE_POS]
    if threat ["status"] not in valid_statuses:
        return False, f"Invalid status: {threat['status']}"
    return True, None #All checks passed

#This is the main memory for threat logs, stored as a dictionary and is also saved to CSV
threat_log=[]

#This validated a threat record and appends it to threat_log[]
def add_threat(threat):
    is_valid, error_msg = validate_threat_record(threat)
    if not is_valid:
        print(f"[Threatlog] ERROR: Invalid threat record - {error_msg}")
        return False
    threat_log.append(threat)
    #Save to CSV
    save_threat_log()
    return True

#This updates the status of an existing threat by its ID when its either resolved or marked as false positive
def update_threat_status(threat_id, new_status):
    for threat in threat_log:
        if threat["threat_id"] == threat_id:
            threat["status"] = new_status
            save_threat_log()
            print(f"[ThreatLog] Updated {threat_id} status to '{new_status}'")
            return True
    print(f"[ThreatLog] Warning: threat_id '{threat_id}' not found for status update")
    return False

#This marks a specific threat as a false positive, also prints a note saying the record can be used for retraining
def mark_as_false_positive(threat_id):
    success = update_threat_status(threat_id, STATUS_FALSE_POS)
    if success:
        print(f"[ThreatLog] {threat_id} marked as false positive")
        print(f"[ThreatLog] This record can be used for model retraining")
    return success

#This returns the full threat log as a list of dictionaries which fills up the alerts table
def get_all_threats():
    return threat_log

#This returns only the threats that match a certain severity level, used to filter alerts table by severity
def get_threats_by_severity(severity):
    return [t for t in threat_log if t["severity"] == severity]

#This returns only the threats with a certain status
def get_threats_by_status(status):
    return [t for t in threat_log if t["status"] == status]

#This returns only the threats detected in last 24hrs, used in the dashboard's "detected in last 24hrs" section
def get_threats_last_24h():
    now = datetime.now()
    result=[]
    for threat in threat_log:
        try:
            threat_time = datetime.strptime(threat["timestamp"], "%Y-%m-%d %H:%M:%S") #parses stored timestamp string back into datetime object
            hours_ago = (now - threat_time).total_seconds()/3600
            if hours_ago <= 24:
                result.append(threat)
        except ValueError:
            pass #skips records with unparseable timestamps
    return result

#This returns threats by ID or Nonne if not found, used when admin clicks on an alert to view details about it
def get_threat_by_id(threat_id):
    for threat in threat_log:
        if threat["threat_id"] == threat_id:
            return threat
    return None

#This searches threats from all fields and returns threats where the query string appears in any field value
def search_threats(query):
    query_lower = query.strip().lower()
    if not query_lower:
        return threat_log #empty query returns everything
    results=[]
    for threat in threat_log:
        for value in threat.values(): #checks if query appears in any field value
            if query_lower in str(value).lower():
                results.append(threat)
                break #found in 1 field, no need to check the rest
    return results

#This returns the amount of false positives
def count_false_positives():
    return sum(1 for t in threat_log if t["status"] == STATUS_FALSE_POS)

#Returns a dictionary with a count of how many threats are at each severity level, used for dashboard summary stats
def count_by_severity():
    return {
        SEVERITY_HIGH: sum(1 for t in threat_log if t["severity"] == SEVERITY_HIGH),
        SEVERITY_MEDIUM: sum(1 for t in threat_log if t["severity"] == SEVERITY_MEDIUM),
        SEVERITY_NORMAL: sum(1 for t in threat_log if t["severity"] == SEVERITY_NORMAL)}


#This returns a dictionary of summary stats about the threat log, used by threat logs page fill up bottom panel
def get_log_stats():
    total= len(threat_log)
    alerts = sum(1 for t in threat_log if t["severity"] in [SEVERITY_HIGH, SEVERITY_MEDIUM])
    unresolved = sum(1 for t in threat_log if t["status"] == STATUS_OPEN)
    acknowledged = sum(1 for t in threat_log if t["status"] == STATUS_INVESTIGATING)
    resolved = sum(1 for t in threat_log if t["status"] == STATUS_RESOLVED)
    false_pos = sum(1 for t in threat_log if t["status"] == STATUS_FALSE_POS)
    return {
        "total": total,
        "alerts": alerts,
        "traffic_logs": 0, #placeholder - this would come from packet capture in real system
        "system_logs": 0, #placeholder - this would come from OS event logs in rea system
        "unresolved": unresolved,
        "acknowledged": acknowledged,
        "resolved": resolved,
        "false_positives": false_pos}

#Returns stats about current user session, used by logout page to display session info
def get_session_stats(session_start):
    from datetime import datetime
    now = datetime.now()
    duration = now - session_start
    hours, remainder = divmod(int(duration.total_seconds()),3600)
    minutes, _       = divmod(remainder, 60)
    # count actions in this session
    acknowledged = sum(1 for t in threat_log
                       if t["status"] != STATUS_OPEN)
    return {
        "start_time": session_start.strftime("%H:%M:%S"),
        "duration": f"{hours:02d}h {minutes:02d}m",
        "actions_taken": len(threat_log),
        "alerts_acknowledged": acknowledged,
        "last_activity": now.strftime("%H:%M:%S")}

#This saves the current memory threat_log to a CSV file
def save_threat_log():
    os.makedirs("data", exist_ok=True)
    try:
        with open(THREAT_LOG_PATH, "w", newline="", encoding="utf-8") as f:
            #DictWriter creates dictionaries as CSV rows using the field nameds as headers
            writer = csv.DictWriter(f, fieldnames=THREAT_FIELDS)
            writer.writeheader() #writes column header row
            writer.writerows(threat_log) #writes all threat records
    except IOError as e:
        print(f"[ThreatLog] ERROR: Could not save threat log - {e}")
        
#This loads a previously saved threat log from CSV back into memory, called once when program starts so past threats are recovered
def load_threat_log():
    global threat_log
    if not os.path.exists(THREAT_LOG_PATH):
        print("[ThreatLog] No existing threat log found. Starting from fresh")
        threat_log=[]
        return
    try:
        loaded=[]
        with open(THREAT_LOG_PATH,"r",encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                #converts confidence back into float
                row["confidence"] = float(row["confidence"])
                loaded.append(dict(row))
        threat_log = loaded
        print(f"[ThreatLog] Loaded {len(threat_log)} threats from {THREAT_LOG_PATH}")
    except (IOError, ValueError) as e:
        print(f"[ThreatLog] ERROR loading threat log: {e}. Starting from fresh")
        threat_log=[]

#This clears the memory of the threat log and deletes saved CSV file, used when admin wants to reset logs
def clear_threat_log():
    global threat_log
    threat_log=[]
    if os.path.exists(THREAT_LOG_PATH):
        os.remove(THREAT_LOG_PATH)
    print("[ThreatLog] Threat log cleared")
    
#This is the self test and runs when threat_log.py is executed directly
if __name__ == "__main__":
    print("Threat Log Module - Self Test")
    print("="*50)
    #test 1 generate IDs
    print()
    print("[Test 1] Generating threat IDs:")
    for i in range(5):
        print(f" {generate_threat_id()}")
    #test 2 creating threat records
    print()
    print("[Test 2] Creating threat records")
    t1 = create_threat_record("192.168.1.45", "10.0.0.1", 0.87, "High", attack_type="DoS", affected_system="Web Server")
    t2 = create_threat_record("172.16.0.99", "10.0.0.2", 0.52, "Medium", attack_type="Probe")
    t3 = create_threat_record("10.10.10.5", "10.0.0.3", 0.12, "Normal")
    #test 3 add to log and display
    print()
    print("[Test 3] Adding to threat log:")
    add_threat(t1)
    add_threat(t2)
    add_threat(t3)
    print(f" Threat log now has {len(threat_log)} entries")
    #test 4 Filter
    print()
    print("[Test 4] Filtering by severity:")
    high = get_threats_by_severity("High")
    print(f" High severity threats: {len(high)}")
    #test 5 Status update
    print()
    print("[Test 5] Updating status:")
    update_threat_status(t1["threat_id"], STATUS_INVESTIGATING)
    mark_as_false_positive(t2["threat_id"])
    #test 6 searching
    print()
    print("[Test 6] Searching for '192':")
    results = search_threats("192")
    print(f" Found {len(results)} threats matching '192'")
    #test 7 counts
    print()
    print("[Test 7] Summary counts:")
    print(f" By severity: {count_by_severity()}")
    print(f" False positives: {count_false_positives()}")
    #clean up test file
    clear_threat_log()
    print()
    print("Self Test Complete")
