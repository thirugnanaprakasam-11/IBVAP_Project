import os
import sqlite3
from datetime import datetime
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ALERTS_DIR = os.path.join(BASE_DIR, "alerts")
HQ_DB_PATH = os.path.join(BASE_DIR, "hq_command.db")
os.makedirs(ALERTS_DIR, exist_ok=True)

app = FastAPI(title="IBVAP Tactical HQ Backend", version="2.0.0")

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
    
    # Alert telemetry table
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
    
    # Authorized Personnel table
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
    
    # Populate default demo personnel if table is empty
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
# API ROUTES
# ----------------------------------------------------

# Ingest from edge nodes (main.py)
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

# Fetch alerts with optional search & filter
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

# Acknowledge single alert
@app.post("/api/v1/alerts/{alert_id}/ack")
def acknowledge_alert(alert_id: int):
    conn = sqlite3.connect(HQ_DB_PATH)
    cur = conn.cursor()
    cur.execute("UPDATE hq_alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))
    conn.commit()
    conn.close()
    return {"status": "ACKNOWLEDGED", "id": alert_id}

# Acknowledge all alerts
@app.post("/api/v1/alerts/ack-all")
def acknowledge_all_alerts():
    conn = sqlite3.connect(HQ_DB_PATH)
    cur = conn.cursor()
    cur.execute("UPDATE hq_alerts SET acknowledged = 1")
    conn.commit()
    conn.close()
    return {"status": "ALL_ACKNOWLEDGED"}

# Saved Recordings / Vault list
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

# Delete clip from Vault
@app.delete("/api/v1/vault/{filename}")
def delete_vault_clip(filename: str):
    safe_name = os.path.basename(filename)
    path = os.path.join(ALERTS_DIR, safe_name)
    if os.path.exists(path):
        os.remove(path)
        return {"status": "DELETED", "filename": safe_name}
    raise HTTPException(status_code=404, detail="File not found")

# Authorized Personnel list
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

# Add new personnel
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

# System telemetry metrics
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

# Serve alert images and UI
app.mount("/alerts", StaticFiles(directory=ALERTS_DIR), name="alerts")

@app.get("/", response_class=HTMLResponse)
def serve_index():
    index_path = os.path.join(BASE_DIR, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>index.html not found. Place it in the project root.</h1>"