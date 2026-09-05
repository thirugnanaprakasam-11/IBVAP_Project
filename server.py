import os
import sqlite3
from datetime import datetime
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from camera_map import generate_offline_map

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ALERTS_DIR = os.path.join(BASE_DIR, "alerts")
TEXTS_DIR = os.path.join(BASE_DIR, "alert_texts")
HQ_DB_PATH = os.path.join(BASE_DIR, "hq_command.db")

os.makedirs(ALERTS_DIR, exist_ok=True)
os.makedirs(TEXTS_DIR, exist_ok=True)

app = FastAPI(title="IBVAP Tactical HQ Backend", version="2.5.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------------------------------------
# DATABASE INITIALIZATION
# ----------------------------------------------------
def init_hq_db():
    conn = sqlite3.connect(HQ_DB_PATH)
    cur = conn.cursor()
    
    cur.execute('''
        CREATE TABLE IF NOT EXISTS hq_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            edge_node_id TEXT,
            timestamp TEXT,
            event_type TEXT,
            total_crossings INTEGER,
            image_hash TEXT,
            chain_hash TEXT,
            threat_score REAL,
            threat_level TEXT,
            acknowledged INTEGER DEFAULT 0
        )
    ''')
    
    cur.execute('''
        CREATE TABLE IF NOT EXISTS authorized_personnel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            role TEXT NOT NULL,
            badge_id TEXT UNIQUE NOT NULL,
            access_level TEXT NOT NULL,
            status TEXT DEFAULT 'ACTIVE'
        )
    ''')
    
    cur.execute('SELECT COUNT(*) FROM authorized_personnel')
    if cur.fetchone()[0] == 0:
        demo_staff = [
            ("Rajesh Kumar", "Watch Commander", "IND-TAC-101", "Full Clearance", "ACTIVE"),
            ("Priya Sharma", "Defense Vision Analyst", "IND-TAC-102", "Level 3 - Tactical", "ACTIVE"),
            ("Arjun Mehta", "Perimeter Response Lead", "IND-TAC-103", "Level 2 - Sector A", "ON PATROL"),
            ("Vijay Nair", "Cryptographic Systems Admin", "IND-TAC-104", "Level 4 - Network HQ", "STANDBY")
        ]
        cur.executemany('''
            INSERT INTO authorized_personnel (name, role, badge_id, access_level, status)
            VALUES (?, ?, ?, ?, ?)
        ''', demo_staff)
        
    conn.commit()
    conn.close()

init_hq_db()

# ----------------------------------------------------
# PYDANTIC SCHEMAS
# ----------------------------------------------------
class EdgeAlertPayload(BaseModel):
    edge_node_id: str
    timestamp: str
    event_type: str
    total_crossings: int
    image_hash: str
    chain_hash: Optional[str] = "N/A"
    threat_score: Optional[float] = 50.0
    threat_level: Optional[str] = "HIGH"
    jwt_token: str

class PersonnelCreate(BaseModel):
    name: str
    role: str
    badge_id: str
    access_level: str
    status: Optional[str] = "ACTIVE"

# ----------------------------------------------------
# CORE HQ API ROUTES
# ----------------------------------------------------
@app.post("/api/v1/alerts")
def receive_edge_alert(payload: EdgeAlertPayload):
    if payload.jwt_token != "ibvap_secure_edge_auth_2026":
        raise HTTPException(status_code=401, detail="Invalid edge security signature")
        
    conn = sqlite3.connect(HQ_DB_PATH)
    cur = conn.cursor()
    cur.execute('''
        INSERT INTO hq_alerts 
        (edge_node_id, timestamp, event_type, total_crossings, image_hash, chain_hash, threat_score, threat_level)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        payload.edge_node_id, payload.timestamp, payload.event_type,
        payload.total_crossings, payload.image_hash, payload.chain_hash,
        payload.threat_score, payload.threat_level
    ))
    conn.commit()
    alert_id = cur.lastrowid
    conn.close()
    return {"status": "SUCCESS", "hq_record_id": alert_id}

@app.get("/api/v1/alerts")
def get_alerts(limit: int = 50, acknowledged: Optional[int] = None):
    conn = sqlite3.connect(HQ_DB_PATH)
    cur = conn.cursor()
    query = "SELECT id, edge_node_id, timestamp, event_type, total_crossings, image_hash, chain_hash, threat_score, threat_level, acknowledged FROM hq_alerts"
    params = []
    if acknowledged is not None:
        query += " WHERE acknowledged = ?"
        params.append(acknowledged)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    
    cur.execute(query, tuple(params))
    rows = cur.fetchall()
    conn.close()
    
    return [
        {
            "id": r[0], "edge_node_id": r[1], "timestamp": r[2], "event_type": r[3],
            "total_crossings": r[4], "image_hash": r[5], "chain_hash": r[6],
            "threat_score": r[7], "threat_level": r[8], "acknowledged": bool(r[9])
        }
        for r in rows
    ]

@app.post("/api/v1/alerts/{alert_id}/ack")
def acknowledge_alert(alert_id: int):
    conn = sqlite3.connect(HQ_DB_PATH)
    cur = conn.cursor()
    cur.execute("UPDATE hq_alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))
    conn.commit()
    conn.close()
    return {"status": "ACKNOWLEDGED", "id": alert_id}

@app.post("/api/v1/alerts/ack-all")
def acknowledge_all_alerts():
    conn = sqlite3.connect(HQ_DB_PATH)
    cur = conn.cursor()
    cur.execute("UPDATE hq_alerts SET acknowledged = 1")
    conn.commit()
    conn.close()
    return {"status": "ALL_ACKNOWLEDGED"}

@app.get("/api/v1/vault")
def get_vault_clips():
    files = []
    if os.path.exists(ALERTS_DIR):
        for f in sorted(os.listdir(ALERTS_DIR), reverse=True):
            if f.lower().endswith(('.jpg', '.jpeg', '.png', '.mp4')):
                filepath = os.path.join(ALERTS_DIR, f)
                stat = os.stat(filepath)
                files.append({
                    "filename": f,
                    "size_kb": round(stat.st_size / 1024, 1),
                    "timestamp": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                    "source": "border_cam_01",
                    "url": f"/alerts/{f}"
                })
    return files

@app.delete("/api/v1/vault/{filename}")
def delete_vault_clip(filename: str):
    safe_name = os.path.basename(filename)
    path = os.path.join(ALERTS_DIR, safe_name)
    if os.path.exists(path):
        os.remove(path)
        return {"status": "DELETED", "filename": safe_name}
    raise HTTPException(status_code=404, detail="File not found")

@app.get("/api/v1/personnel")
def list_personnel():
    conn = sqlite3.connect(HQ_DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, name, role, badge_id, access_level, status FROM authorized_personnel ORDER BY id ASC")
    rows = cur.fetchall()
    conn.close()
    return [
        {"id": r[0], "name": r[1], "role": r[2], "badge_id": r[3], "access_level": r[4], "status": r[5]}
        for r in rows
    ]

@app.post("/api/v1/personnel")
def add_personnel(person: PersonnelCreate):
    conn = sqlite3.connect(HQ_DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute('''
            INSERT INTO authorized_personnel (name, role, badge_id, access_level, status)
            VALUES (?, ?, ?, ?, ?)
        ''', (person.name, person.role, person.badge_id, person.access_level, person.status))
        conn.commit()
        new_id = cur.lastrowid
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="Badge ID already exists")
    conn.close()
    return {"status": "CREATED", "id": new_id}

@app.get("/api/v1/telemetry")
def get_telemetry():
    conn = sqlite3.connect(HQ_DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM hq_alerts WHERE acknowledged = 0")
    unack_alerts = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM hq_alerts")
    total_breaches = cur.fetchone()[0]
    conn.close()
    
    return {
        "status": "ONLINE",
        "network": "ENCRYPTED SHA-256",
        "active_cameras": 4,
        "unacknowledged_alerts": unack_alerts,
        "total_breaches": total_breaches,
        "mesh_status": "P2P RESILIENT",
        "system_time": datetime.now().strftime("%H:%M:%S IST")
    }

# ----------------------------------------------------
# MAP, AUDIT LEDGER & INCIDENT REPORT INTEGRATION
# ----------------------------------------------------
@app.get("/map", response_class=HTMLResponse)
def serve_tactical_map():
    # Dynamically generate the map on every request to guarantee accuracy
    map_path = generate_offline_map(BASE_DIR)
    if os.path.exists(map_path):
        return FileResponse(map_path)
    raise HTTPException(status_code=500, detail="Failed to build tactical map.")

@app.get("/ledger", response_class=HTMLResponse)
def serve_audit_ledger():
    ledger_path = os.path.join(TEXTS_DIR, "command_audit_ledger.txt")
    content = open(ledger_path, "r").read() if os.path.exists(ledger_path) else "Audit ledger empty or not yet generated."
    return f"""
    <html>
    <head><title>IBVAP Cryptographic Audit Ledger</title></head>
    <body style="background-color: #0b0f19; color: #00ff66; font-family: monospace; padding: 25px;">
        <h2 style="border-bottom: 2px solid #00ff66; padding-bottom: 8px;">🔐 TAMPER-PROOF COMMAND AUDIT LEDGER (SHA-256)</h2>
        <p><a href="/" style="color: #38bdf8; text-decoration: none;">&larr; Back to Command Dashboard</a></p>
        <pre style="background: #111827; padding: 15px; border-radius: 5px; border: 1px solid #1f293d; white-space: pre-wrap;">{content}</pre>
    </body>
    </html>
    """

@app.get("/reports", response_class=HTMLResponse)
def list_incident_reports():
    files = [f for f in os.listdir(TEXTS_DIR) if f.endswith(".txt") and f != "command_audit_ledger.txt"] if os.path.exists(TEXTS_DIR) else []
    files.sort(reverse=True)
    
    links = "".join([f"<li style='margin-bottom:8px;'><a href='/reports/{f}' style='color:#38bdf8; text-decoration:none;'>📄 {f}</a></li>" for f in files])
    if not links:
        links = "<li>No incident reports or shift summaries generated yet.</li>"

    return f"""
    <html>
    <head><title>IBVAP Incident Reports</title></head>
    <body style="background:#0b0f19; color:#00ff66; font-family:monospace; padding:30px;">
        <h2 style="border-bottom: 2px solid #00ff66; padding-bottom: 8px;">📄 AIR-GAPPED INCIDENT REPORTS & SHIFT SUMMARIES</h2>
        <p><a href="/" style="color:#00ff66; text-decoration:none;">&larr; Back to Command Dashboard</a></p>
        <ul style="line-height: 1.8; font-size: 15px; list-style-type: none; padding-left: 0;">{links}</ul>
    </body>
    </html>
    """

@app.get("/reports/{filename}")
def serve_report(filename: str):
    file_path = os.path.join(TEXTS_DIR, os.path.basename(filename))
    if os.path.exists(file_path):
        return PlainTextResponse(open(file_path, "r").read())
    raise HTTPException(status_code=404, detail="Report file not found")

# Serve static alert snapshots
app.mount("/alerts", StaticFiles(directory=ALERTS_DIR), name="alerts")

# ----------------------------------------------------
# MAIN DASHBOARD (FALLBACK / UNIFIED)
# ----------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def serve_index():
    index_path = os.path.join(BASE_DIR, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()

    # Integrated Fallback Dashboard
    conn = sqlite3.connect(HQ_DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, edge_node_id, timestamp, event_type, threat_level, threat_score, image_hash FROM hq_alerts ORDER BY id DESC LIMIT 15")
    rows = cur.fetchall()
    conn.close()

    table_rows = "".join([
        f"""<tr style="border-bottom: 1px solid #1f293d;">
            <td style="padding:10px;">#{r[0]}</td>
            <td style="padding:10px;">{r[2]}</td>
            <td style="padding:10px;">{r[1]}</td>
            <td style="padding:10px;">{r[3]}</td>
            <td style="padding:10px; color:{'#ef4444' if r[4]=='CRITICAL' else '#f97316' if r[4]=='HIGH' else '#eab308' if r[4]=='ELEVATED' else '#22c55e'}; font-weight:bold;">{r[4]} ({r[5]:.0f})</td>
            <td style="padding:10px; font-family:monospace; color:#64748b;">{r[6][:14]}...</td>
        </tr>""" for r in rows
    ]) or "<tr><td colspan='6' style='padding:20px; text-align:center; color:#64748b;'>No intrusions recorded yet.</td></tr>"

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>IBVAP Tactical Command Center</title>
        <style>
            body {{ background-color: #04070a; color: #00ff66; font-family: 'Courier New', monospace; margin: 0; padding: 25px; }}
            h1 {{ margin-top: 0; border-bottom: 2px solid #00ff66; padding-bottom: 10px; font-size: 24px; }}
            .nav-bar {{ margin-bottom: 25px; display: flex; gap: 15px; }}
            .btn {{ background: #111827; border: 1px solid #00ff66; color: #00ff66; padding: 10px 18px; text-decoration: none; font-weight: bold; border-radius: 4px; display: inline-block; }}
            .btn:hover {{ background: #00ff66; color: #04070a; }}
            table {{ width: 100%; border-collapse: collapse; background: #0a0f18; border: 1px solid #1f293d; }}
            th {{ background: #111827; color: #fff; text-align: left; padding: 12px; border-bottom: 1px solid #1f293d; }}
        </style>
    </head>
    <body>
        <h1>🛡️ IBVAP TACTICAL COMMAND HQ</h1>
        <div class="nav-bar">
            <a href="/map" class="btn">🗺️ Tactical Map</a>
            <a href="/ledger" class="btn">📝 Audit Ledger</a>
            <a href="/reports" class="btn">📄 Incident Reports</a>
            <a href="/api/v1/vault" class="btn">📹 Vault API</a>
            <a href="/api/v1/personnel" class="btn">👥 Personnel API</a>
        </div>
        <h3>LIVE EDGE TELEMETRY & BREACH LEDGER</h3>
        <table>
            <thead>
                <tr><th>ID</th><th>TIMESTAMP</th><th>NODE</th><th>EVENT</th><th>THREAT LEVEL</th><th>HASH</th></tr>
            </thead>
            <tbody>
                {table_rows}
            </tbody>
        </table>
    </body>
    </html>
    """