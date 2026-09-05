import sqlite3
from datetime import timedelta

# ... [Keep your existing generate_incident_report and save_incident_report code above] ...

import sqlite3
from datetime import timedelta, datetime
import os

# ... [Keep your existing RECOMMENDED_ACTIONS and generate_incident_report code] ...

def generate_shift_summary(db_path, hours_back=24):
    """Generates a consolidated summary and timeline of all activity over a specific time window."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Calculate time window threshold
    time_threshold = (datetime.now() - timedelta(hours=hours_back)).strftime("%Y-%m-%d %H:%M:%S")
    
    # Query all intrusions within the window, ordered chronologically
    cursor.execute('''
        SELECT id, timestamp, event_type, threat_level, threat_score 
        FROM intrusions 
        WHERE timestamp >= ?
        ORDER BY timestamp ASC
    ''', (time_threshold,))
    
    rows = cursor.fetchall()
    conn.close()
    
    total_incidents = len(rows)
    if total_incidents == 0:
        return f"No security incidents recorded in the last {hours_back} hours."
        
    level_counts = {"LOW": 0, "ELEVATED": 0, "HIGH": 0, "CRITICAL": 0}
    highest_score = 0
    camouflaged_count = 0
    
    timeline_log = []
    
    for row in rows:
        inc_id, ts, event, level, score = row
        
        # Aggregate stats
        if level in level_counts:
            level_counts[level] += 1
        if score > highest_score:
            highest_score = score
        if "CAMOUFLAGE" in event.upper():
            camouflaged_count += 1
            
        # Build the chronological log
        timeline_log.append(f"  [{ts}] ID:{inc_id:04d} | {level:8s} | Score: {score:.1f} | {event}")
            
    summary = [
        "=" * 70,
        f"IBVAP SHIFT SUMMARY ({hours_back}-HOUR WINDOW)",
        "=" * 70,
        f"Time Generated    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Total Incidents   : {total_incidents}",
        f"Peak Threat Score : {highest_score:.1f} / 100",
        "-" * 70,
        "THREAT BREAKDOWN:",
        f"  CRITICAL : {level_counts['CRITICAL']}",
        f"  HIGH     : {level_counts['HIGH']}",
        f"  ELEVATED : {level_counts['ELEVATED']}",
        f"  LOW      : {level_counts['LOW']}",
        "-" * 70,
        "NOTABLE ANOMALIES:",
        f"  Camouflage/Stealth Attempts : {camouflaged_count}",
        "=" * 70,
        "INCIDENT TIMELINE (CHRONOLOGICAL):"
    ]
    
    # Append every single event that happened
    summary.extend(timeline_log)
    summary.append("=" * 70)
    
    return "\n".join(summary)
    
    return "\n".join(summary)
def save_incident_report(base_dir, incident_id, report_text):
    # Route to a dedicated text-only directory
    reports_dir = os.path.join(base_dir, "alert_texts")
    os.makedirs(reports_dir, exist_ok=True)
    
    path = os.path.join(reports_dir, f"incident_{incident_id}.txt")
    with open(path, "w") as f:
        f.write(report_text)
    return path

def save_shift_summary(base_dir, summary_text):
    # Route to a dedicated text-only directory
    reports_dir = os.path.join(base_dir, "alert_texts")
    os.makedirs(reports_dir, exist_ok=True)
    
    path = os.path.join(reports_dir, f"shift_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    with open(path, "w") as f:
        f.write(summary_text)
    return path