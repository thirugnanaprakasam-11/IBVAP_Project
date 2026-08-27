from fastapi import FastAPI, HTTPException, Security
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3
import os
from datetime import datetime

# ==========================================
# 1. API SETUP & CORS
# ==========================================
app = FastAPI(title="IBVAP Command API", version="1.0")

# Allow a frontend dashboard to fetch data without security blocks
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================
# 2. CENTRAL HQ DATABASE
# ==========================================
# This is a separate database representing the Central Command Server
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "hq_command.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS hq_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            edge_node_id TEXT,
            timestamp TEXT,
            event_type TEXT,
            total_crossings INTEGER,
            image_hash TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# ==========================================
# 3. DATA CONTRACTS (Pydantic Models)
# ==========================================
class SecurityAlert(BaseModel):
    edge_node_id: str
    timestamp: str
    event_type: str
    total_crossings: int
    image_hash: str
    jwt_token: str # Simulated security token

# ==========================================
# 4. REST API ENDPOINTS
# ==========================================
@app.post("/api/v1/alerts")
async def ingest_alert(alert: SecurityAlert):
    """Receives secure alerts from Edge Cameras"""
    
    # 1. Zero-Trust Check (Simulated)
    if alert.jwt_token != "ibvap_secure_edge_auth_2026":
        raise HTTPException(status_code=403, detail="Unauthorized Edge Device")

    # 2. Log to HQ Database
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO hq_alerts (edge_node_id, timestamp, event_type, total_crossings, image_hash)
        VALUES (?, ?, ?, ?, ?)
    ''', (alert.edge_node_id, alert.timestamp, alert.event_type, alert.total_crossings, alert.image_hash))
    conn.commit()
    conn.close()

    print(f"📡 [HQ RECEIVED] Alert from {alert.edge_node_id} | Hash: {alert.image_hash[:10]}...")
    
    return {"status": "success", "message": "Alert securely logged to HQ Immutable Ledger"}

@app.get("/api/v1/alerts/latest")
async def get_latest_alerts():
    """Feeds the Frontend Command Dashboard"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM hq_alerts ORDER BY id DESC LIMIT 10')
    rows = cursor.fetchall()
    conn.close()

    alerts = []
    for row in rows:
        alerts.append({
            "alert_id": row[0],
            "edge_node_id": row[1],
            "timestamp": row[2],
            "event_type": row[3],
            "total_crossings": row[4],
            "image_hash": row[5]
        })

    return {"active_threats": len(alerts), "data": alerts}