import cv2
import sqlite3
import time
import hashlib
import os
import requests 
from datetime import datetime
from collections import deque
from ultralytics import YOLO
import face_recognition
import numpy as np
from shapely.geometry import Point, Polygon, LineString
import threading
import queue
import math
import zmq
import json
import argparse
from audit_ledger import AuditLedger
from camera_map import generate_offline_map
import webbrowser

# IMPORT THE UPGRADED UNIVERSAL TEXT ENGINE
from anpr_engine import TextExtractionEngine 

# ==========================================
# 0. PARSE NODE ARGUMENTS & SWARM INIT
# ==========================================
parser = argparse.ArgumentParser(description="IBVAP Edge Node Swarm")
parser.add_argument("--node", type=str, default="ALPHA", help="Node Identifier")
parser.add_argument("--pub", type=int, default=5555, help="Broadcast port (PUB)")
parser.add_argument("--sub", type=int, default=5556, help="Neighbor listening port (SUB)")
args, _ = parser.parse_known_args()

ACTIVE_MODE = "tactical"  
camouflage_defeat_active = False

print(f"[+] INITIALIZING IBVAP SUITE | NODE: {args.node} | PUB: {args.pub} | SUB: {args.sub}")

# ==========================================
# 1. ZEROMQ DECENTRALIZED NODE SWARM
# ==========================================
class SwarmNode:
    def __init__(self, node_id, pub_port, sub_port):
        self.node_id = node_id
        self.pub_port = pub_port
        self.sub_port = sub_port
        self.context = zmq.Context()
        self.peers_status = {}
        self.msg_queue = queue.Queue()

        threading.Thread(target=self._pub_worker, daemon=True).start()
        threading.Thread(target=self._sub_worker, daemon=True).start()

    def _pub_worker(self):
        pub_socket = self.context.socket(zmq.PUB)
        pub_socket.bind(f"tcp://*:{self.pub_port}")
        last_hb = time.time()
        while True:
            try:
                msg = self.msg_queue.get(timeout=0.5)
                pub_socket.send_string(f"SWARM {json.dumps(msg)}")
            except queue.Empty:
                pass
            
            if time.time() - last_hb > 2.0:
                hb = {"node_id": self.node_id, "type": "HEARTBEAT", "mode": ACTIVE_MODE, "time": time.time()}
                pub_socket.send_string(f"SWARM {json.dumps(hb)}")
                last_hb = time.time()

    def _sub_worker(self):
        sub_socket = self.context.socket(zmq.SUB)
        sub_socket.connect(f"tcp://127.0.0.1:{self.sub_port}")
        sub_socket.setsockopt_string(zmq.SUBSCRIBE, "SWARM")
        while True:
            try:
                raw_msg = sub_socket.recv_string(flags=zmq.NOBLOCK)
                data = json.loads(raw_msg.replace("SWARM ", "", 1))
                peer_id = data.get("node_id")
                if data.get("type") == "HEARTBEAT":
                    self.peers_status[peer_id] = time.time()
                elif data.get("type") == "ALERT":
                    print(f"\n[SWARM INTEL] 🚨 Peer {peer_id} reported breach: {data.get('threat')} ({data.get('level')})")
            except zmq.Again:
                time.sleep(0.05)
            except Exception:
                time.sleep(0.05)

    def send_alert(self, threat, level):
        self.msg_queue.put({"node_id": self.node_id, "type": "ALERT", "threat": threat, "level": level})

swarm = SwarmNode(args.node, args.pub, args.sub)

# ==========================================
# 2. CORE SYSTEM & DIRECTORY SETUP
# ==========================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ALERTS_DIR = os.path.join(BASE_DIR, "alerts")
os.makedirs(ALERTS_DIR, exist_ok=True)

HQ_API_URL = "http://127.0.0.1:8000/api/v1/alerts"
JWT_AUTH_TOKEN = "ibvap_secure_edge_auth_2026"
PIXELS_PER_METER = 25.0

# --- AUDIT LEDGER INITIALIZATION ---
audit = AuditLedger(BASE_DIR)
current_operator = "Officer_On_Duty"
audit.record_event(current_operator, "COMMAND_CENTRE_LOGIN", f"Node {args.node} booted in {ACTIVE_MODE.upper()} mode")

# ==========================================
# 3. CYBERSECURITY HASHING & BLOCKCHAIN LEDGER
# ==========================================
def generate_image_hash(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256.update(byte_block)
    return sha256.hexdigest()

def generate_chain_hash(image_hash, previous_chain_hash):
    combined = f"{image_hash}{previous_chain_hash}".encode()
    return hashlib.sha256(combined).hexdigest()

def get_last_chain_hash(cursor):
    cursor.execute("SELECT chain_hash FROM intrusions ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    return row[0] if row and row[0] else "GENESIS_BLOCK"

def verify_ledger_integrity(cursor):
    cursor.execute("SELECT id, image_hash, chain_hash FROM intrusions ORDER BY id ASC")
    rows = cursor.fetchall()
    previous = "GENESIS_BLOCK"
    print("\n" + "=" * 50)
    print("🔎 LEDGER INTEGRITY CHECK")
    for row_id, image_hash, stored_chain_hash in rows:
        expected = generate_chain_hash(image_hash, previous)
        if expected != stored_chain_hash:
            print(f"❌ TAMPER DETECTED at record #{row_id} — chain broken.")
            print("=" * 50 + "\n")
            return False
        previous = stored_chain_hash
    print(f"✅ LEDGER VERIFIED — {len(rows)} records, chain intact.")
    print("=" * 50 + "\n")
    return True

# ==========================================
# 4. DATABASE SETUP 
# ==========================================
DB_PATH = os.path.join(BASE_DIR, "ibvap_secure.db")
conn = sqlite3.connect(DB_PATH, check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS intrusions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        event_type TEXT,
        total_crossings INTEGER,
        image_path TEXT,
        image_hash TEXT,
        sync_status INTEGER DEFAULT 0,
        chain_hash TEXT,
        threat_score REAL,
        threat_level TEXT
    )
''')
conn.commit()

for col, coltype in [("chain_hash", "TEXT"), ("threat_score", "REAL"), ("threat_level", "TEXT")]:
    try:
        cursor.execute(f"ALTER TABLE intrusions ADD COLUMN {col} {coltype}")
        conn.commit()
    except sqlite3.OperationalError: pass 

# ==========================================
# 5. THREAT ENGINE & VECTOR BIOMETRICS
# ==========================================
class ThreatEngine:
    NIGHT_START_HOUR, NIGHT_END_HOUR = 22, 5
    HASH_MEMORY_SIZE = 200

    def __init__(self):
        self.count = 0
        self.mean_interval, self.m2 = 0.0, 0.0
        self.last_alert_time = None
        self.recent_hashes = deque(maxlen=self.HASH_MEMORY_SIZE)

    def _stddev(self):
        return 0.0 if self.count < 2 else math.sqrt(self.m2 / (self.count - 1))

    def _update_interval(self, interval_seconds):
        self.count += 1
        delta = interval_seconds - self.mean_interval
        self.mean_interval += delta / self.count
        self.m2 += delta * (interval_seconds - self.mean_interval)

    def score(self, timestamp, total_crossings, image_hash):
        z_score = 0.0
        if self.last_alert_time:
            interval = max((timestamp - self.last_alert_time).total_seconds(), 0.01)
            if self.count >= 5 and self._stddev() > 0:
                z_score = (self.mean_interval - interval) / self._stddev()
            self._update_interval(interval)
        else:
            self._update_interval(60.0)
        self.last_alert_time = timestamp

        freq_signal = max(-2.0, min(z_score, 6.0)) / 6.0
        is_night = timestamp.hour >= self.NIGHT_START_HOUR or timestamp.hour < self.NIGHT_END_HOUR
        temporal_signal = 1.0 if is_night else 0.3
        magnitude_signal = min(total_crossings / 5.0, 1.0)
        
        is_repeat = image_hash in self.recent_hashes
        if image_hash != "pending": self.recent_hashes.append(image_hash)
        
        raw = (1.6 * freq_signal + 1.1 * temporal_signal + 1.3 * magnitude_signal + 2.4 * (1.0 if is_repeat else 0.0)) - 1.8
        threat_score = 100.0 / (1.0 + math.exp(-raw))
        if is_repeat: threat_score = max(threat_score, 90.0)

        level = "CRITICAL" if threat_score >= 85 else "HIGH" if threat_score >= 60 else "ELEVATED" if threat_score >= 35 else "LOW"
        return round(threat_score, 1), level, is_repeat

class VectorBiometricDB:
    def __init__(self):
        self.encodings_matrix = np.empty((0, 128))
        self.names = []

    def add_face(self, encoding, name):
        self.encodings_matrix = np.vstack([self.encodings_matrix, encoding])
        self.names.append(name)

    def search(self, face_encoding, tolerance=0.55):
        if len(self.names) == 0: return None
        distances = np.linalg.norm(self.encodings_matrix - face_encoding, axis=1)
        best_match_idx = np.argmin(distances)
        if distances[best_match_idx] <= tolerance:
            return self.names[best_match_idx]
        return None

vector_db = VectorBiometricDB()
AUTH_FACES_DIR = os.path.join(BASE_DIR, "authorized_faces")
os.makedirs(AUTH_FACES_DIR, exist_ok=True)
for filename in os.listdir(AUTH_FACES_DIR):
    if filename.lower().endswith(('.jpg', '.jpeg', '.png')):
        try:
            enc = face_recognition.face_encodings(face_recognition.load_image_file(os.path.join(AUTH_FACES_DIR, filename)))
            if enc: vector_db.add_face(enc[0], f"{os.path.splitext(filename)[0].upper()} - Authorized")
        except Exception: pass

threat_engine = ThreatEngine()

# ==========================================
# 6. VISION UTILITIES & HUD
# ==========================================
def eradicate_weather(frame):
    lab = cv2.cvtColor(frame, cv2.COLOR_BGR2LAB)
    l_channel, a_channel, b_channel = cv2.split(lab)
    enhanced_l = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8)).apply(l_channel)
    enhanced_bgr = cv2.cvtColor(cv2.merge((enhanced_l, a_channel, b_channel)), cv2.COLOR_LAB2BGR)
    return cv2.addWeighted(enhanced_bgr, 1.3, cv2.GaussianBlur(enhanced_bgr, (0, 0), 2.0), -0.3, 0)

def draw_dashed_line(img, pt1, pt2, color, thickness=2, dash_length=15):
    x1, y1 = pt1
    x2, y2 = pt2
    dist = math.hypot(x2 - x1, y2 - y1)
    if dist == 0: return
    dashes = max(1, int(dist / dash_length))
    for i in range(dashes):
        cv2.line(img, (int(x1 + (x2 - x1) * i / dashes), int(y1 + (y2 - y1) * i / dashes)),
                 (int(x1 + (x2 - x1) * (i + 0.5) / dashes), int(y1 + (y2 - y1) * (i + 0.5) / dashes)), color, thickness)

def draw_threat_hud(frame, threat_score, threat_level, w, h):
    colors = {"LOW": (80, 240, 60), "ELEVATED": (0, 190, 255), "HIGH": (0, 120, 255), "CRITICAL": (0, 0, 255)}
    color = colors.get(threat_level, (80, 240, 60))
    bar_x, bar_y, bar_w, bar_h = 20, h - 45, 260, 22
    fill_w = int(bar_w * (threat_score / 100.0))
    cv2.rectangle(frame, (bar_x, bar_y), (bar_x + bar_w, bar_y + bar_h), (60, 60, 60), -1)
    cv2.rectangle(frame, (bar_x, bar_y), (bar_x + fill_w, bar_y + bar_h), color, -1)
    cv2.rectangle(frame, (bar_x, bar_y), (bar_x + bar_w, bar_y + bar_h), (255, 255, 255), 1)
    cv2.putText(frame, f"THREAT: {threat_level} ({threat_score:.0f})", (bar_x, bar_y - 8), cv2.FONT_HERSHEY_SIMPLEX, 0.55, color, 2)

# ==========================================
# 7. ASYNC BACKGROUND WORKERS
# ==========================================
model = YOLO("yolov8n.pt") 
text_engine = TextExtractionEngine("license_plate_detector.pt")

text_cache = {}
person_id_cache = {} 
ocr_queue = queue.Queue()
face_queue = queue.Queue()

def async_ocr_worker():
    while True:
        track_id, v_crop, obj_class = ocr_queue.get()
        if v_crop is not None:
            try:
                plate = text_engine.read_plate(v_crop)
                if plate and track_id in text_cache:
                    text_cache[track_id]["plate"] = plate
                    print(f"[ANPR] ✅ Plate Found: {plate}")
                
                if obj_class in ['TRUCK', 'BUS']:
                    general_text = text_engine.read_general_text(v_crop)
                    if general_text and track_id in text_cache:
                        text_cache[track_id]["other_text"] = general_text
                        print(f"[TEXT INTEL] 🔎 Identified Text: {general_text}")
            except Exception as e:
                pass
        ocr_queue.task_done()

def async_face_worker():
    # Create a debug folder to see the faces the AI is trying to read
    debug_face_dir = os.path.join(BASE_DIR, "debug_crops", "faces")
    os.makedirs(debug_face_dir, exist_ok=True)
    
    while True:
        track_id, rgb_crop = face_queue.get()
        if rgb_crop is not None:
            try:
                # 1. Enhance lighting and contrast mathematically
                lab = cv2.cvtColor(rgb_crop, cv2.COLOR_RGB2LAB)
                l, a, b = cv2.split(lab)
                l = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8)).apply(l)
                enhanced_rgb = cv2.cvtColor(cv2.merge((l, a, b)), cv2.COLOR_LAB2RGB)

                # Save debug image to disk
                cv2.imwrite(os.path.join(debug_face_dir, f"face_{track_id}_{time.time()}.jpg"), cv2.cvtColor(enhanced_rgb, cv2.COLOR_RGB2BGR))

                # 2. Upsample=2 zooms in to catch smaller faces from distance
                f_locs = face_recognition.face_locations(enhanced_rgb, model="hog", number_of_times_to_upsample=2)
                if f_locs:
                    f_encs = face_recognition.face_encodings(enhanced_rgb, f_locs)
                    if f_encs:
                        # 3. Tighter tolerance (0.50 instead of 0.55) to prevent false positives
                        matched_name = vector_db.search(f_encs[0], tolerance=0.50)
                        
                        if matched_name and track_id in person_id_cache:
                            person_id_cache[track_id]["label"] = matched_name
                            print(f"\n[BIOMETRICS] ✅ Subject Identified: {matched_name}")
                        elif track_id in person_id_cache and person_id_cache[track_id]["label"] == "PERSON":
                            person_id_cache[track_id]["label"] = "UNKNOWN INTRUDER"
            except Exception as e: 
                pass
        face_queue.task_done()

threading.Thread(target=async_ocr_worker, daemon=True).start()
threading.Thread(target=async_face_worker, daemon=True).start()

# ==========================================
# 7.5 ADD-ON: STORE-AND-FORWARD & TAMPER ENGINES
# ==========================================
def offline_sync_daemon():
    """Offline-First & Store-and-Forward Engine"""
    while True:
        try:
            local_conn = sqlite3.connect(DB_PATH)
            local_cursor = local_conn.cursor()
            local_cursor.execute("SELECT id, timestamp, event_type, total_crossings, image_hash, chain_hash, threat_score, threat_level FROM intrusions WHERE sync_status = 0")
            unsynced_alerts = local_cursor.fetchall()
            
            if unsynced_alerts:
                requests.get("http://8.8.8.8", timeout=2) 
                for alert in unsynced_alerts:
                    payload = {
                        "edge_node_id": f"{args.node}_{ACTIVE_MODE}",
                        "timestamp": alert[1], "event_type": alert[2],
                        "total_crossings": alert[3], "image_hash": alert[4],
                        "chain_hash": alert[5], "threat_score": alert[6],
                        "threat_level": alert[7], "jwt_token": JWT_AUTH_TOKEN
                    }
                    try:
                        res = requests.post(HQ_API_URL, json=payload, timeout=2)
                        if res.status_code in [200, 201]:
                            local_cursor.execute("UPDATE intrusions SET sync_status = 1 WHERE id = ?", (alert[0],))
                            local_conn.commit()
                            print(f"\n[STORE-AND-FORWARD] ☁️ Synced Alert #{alert[0]} to Command Dashboard.")
                    except requests.exceptions.RequestException:
                        break
            local_conn.close()
        except Exception:
            pass
        time.sleep(15) 

def detect_camera_tamper(current_frame, previous_frame):
    if previous_frame is None: return False, "OK"
    gray_curr = cv2.cvtColor(current_frame, cv2.COLOR_BGR2GRAY)
    if cv2.mean(gray_curr)[0] < 5.0:
        return True, "CRITICAL: CAMERA OBSTRUCTED / BLINDED"
    gray_prev = cv2.cvtColor(previous_frame, cv2.COLOR_BGR2GRAY)
    diff = cv2.absdiff(gray_curr, gray_prev)
    if cv2.countNonZero(diff) < 500: 
        return True, "WARNING: CAMERA FEED FROZEN"
    return False, "OK"

def generate_incident_report(alert_id, timestamp, event_type, crossings, threat_score, threat_level):
    report = f"""====================================================
IBVAP AUTOMATED INCIDENT REPORT (AIR)
====================================================
INCIDENT ID   : {alert_id}
TIMESTAMP     : {timestamp}
THREAT LEVEL  : {threat_level} (Score: {threat_score:.1f}/100)

EXECUTIVE SUMMARY:
At exactly {timestamp}, the edge node detected a {threat_level} level security event classified as '{event_type}'. 
The system tracked {crossings} distinct zone crossing(s) during this window.

SYSTEM ACTIONS TAKEN:
1. Cryptographic chain-of-custody hash generated and ledger updated.
2. High-resolution evidence frame captured and secured in local vault.
3. Peer-to-peer decentralized swarm notified.
4. Alert queued in Store-and-Forward daemon for HQ sync.

RECOMMENDED SOP:
{"Immediate physical interception and verification required." if threat_level in ["CRITICAL", "HIGH"] else "Continue autonomous monitoring and cross-reference with authorized schedules."}
===================================================="""
    report_path = os.path.join(ALERTS_DIR, f"report_{alert_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    with open(report_path, "w") as f:
        f.write(report)
    print(f"[REPORT ENGINE] 📄 AI Incident Report saved: {report_path}")

threading.Thread(target=offline_sync_daemon, daemon=True).start()

# ==========================================
# 8. SURVEILLANCE LOOP SETUP
# ==========================================
secure_zone_pts = np.array([[100, 240], [540, 240], [600, 460], [40, 460]], np.int32)
secure_polygon = Polygon(secure_zone_pts)

cap = cv2.VideoCapture(0)
if not cap.isOpened(): cap = cv2.VideoCapture(os.path.join(BASE_DIR, "test_footage.mp4"))

backSub = cv2.createBackgroundSubtractorMOG2(history=300, varThreshold=25, detectShadows=False)
heatmap_buffer = np.zeros((480, 640), dtype=np.float32)

track_data = {} 
frame_count = 0
prev_time = time.time()
last_alert_time = 0
weather_disturbance = False
previous_tamper_frame = None

while True:
    success, original_frame = cap.read()
    if not success:
        cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
        continue

    curr_time = time.time()
    frame_count += 1
    orig_h, orig_w, _ = original_frame.shape
    scale_x, scale_y = orig_w / 640.0, orig_h / 480.0

    frame = cv2.resize(original_frame, (640, 480))
    
    if frame_count % 15 == 1:
        gray_check = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        weather_disturbance = (gray_check.std() < 45.0 or cv2.Laplacian(gray_check, cv2.CV_64F).var() < 100.0)

    if weather_disturbance: frame = eradicate_weather(frame)
    annotated_frame = frame.copy()

    is_tampered, tamper_msg = detect_camera_tamper(frame, previous_tamper_frame)
    if is_tampered:
        cv2.putText(annotated_frame, tamper_msg, (20, 100), cv2.FONT_HERSHEY_SIMPLEX, 0.8, (0, 0, 255), 3)
    previous_tamper_frame = frame.copy()

    breach_detected = False
    current_threat = f"VIRTUAL_FENCE_BREACH ({ACTIVE_MODE.upper()})"
    breach_count_this_frame = 0

    fgMask = backSub.apply(frame)
    if camouflage_defeat_active:
        fgMask = cv2.morphologyEx(fgMask, cv2.MORPH_OPEN, cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (5, 5)))
        heatmap_buffer = cv2.addWeighted(heatmap_buffer, 0.90, fgMask.astype(np.float32), 0.10, 0)
        heatmap_norm = cv2.normalize(heatmap_buffer, None, 0, 255, cv2.NORM_MINMAX, dtype=cv2.CV_8U)
        annotated_frame = cv2.addWeighted(annotated_frame, 0.6, cv2.applyColorMap(heatmap_norm, cv2.COLORMAP_INFERNO), 0.4, 0)

        contours, _ = cv2.findContours(fgMask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        for cnt in contours:
            if cv2.contourArea(cnt) > 900:
                cx, cy, cw, ch = cv2.boundingRect(cnt)
                draw_dashed_line(annotated_frame, (cx, cy), (cx + cw, cy), (0, 0, 255), 2)
                cv2.putText(annotated_frame, "CAMOUFLAGED ANOMALY", (cx, max(20, cy - 10)), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 255), 2)
                breach_detected = True
                current_threat = "CAMOUFLAGED ANOMALY DETECTED"
                breach_count_this_frame += 1

    results = model.track(frame, device="mps", persist=True, tracker="bytetrack.yaml", verbose=False)
    zone_color = (255, 0, 0)
    
    for result in results:
        boxes = result.boxes
        if boxes.id is None: continue 

        for i, box in enumerate(boxes):
            x1, y1, x2, y2 = box.xyxy[0].int().tolist()
            cls_id = int(box.cls[0])
            track_id = int(boxes.id[i]) 
            class_name = model.names[cls_id].upper()
            
            foot_x, foot_y = int((x1 + x2) / 2), int(y2)
            foot_point = Point(foot_x, foot_y)
            
            current_speed, vx, vy = 0.0, 0.0, 0.0
            if track_id in track_data:
                prev_cx, prev_cy, prev_ts, prev_speed, prev_vx, prev_vy = track_data[track_id]
                time_diff = curr_time - prev_ts
                if time_diff > 0.12:
                    dist = math.hypot(foot_x - prev_cx, foot_y - prev_cy)
                    if dist > 4:
                        vx, vy = (foot_x - prev_cx) / time_diff, (foot_y - prev_cy) / time_diff
                        current_speed = ((dist / PIXELS_PER_METER) / time_diff) * 3.6
                    else:
                        vx, vy, current_speed = prev_vx, prev_vy, prev_speed
                    track_data[track_id] = (foot_x, foot_y, curr_time, current_speed, vx, vy)
                else:
                    vx, vy, current_speed = prev_vx, prev_vy, prev_speed
            else:
                track_data[track_id] = (foot_x, foot_y, curr_time, 0.0, 0.0, 0.0)

            if ACTIVE_MODE == "drone" and (abs(vx) > 5 or abs(vy) > 5):
                future_x, future_y = int(foot_x + (vx * 2.5)), int(foot_y + (vy * 2.5))
                if LineString([(foot_x, foot_y), (future_x, future_y)]).intersects(secure_polygon) and not secure_polygon.contains(foot_point):
                    draw_dashed_line(annotated_frame, (foot_x, foot_y), (future_x, future_y), (0, 0, 255), 2)
                else:
                    draw_dashed_line(annotated_frame, (foot_x, foot_y), (future_x, future_y), (255, 0, 255), 2)

            person_label = None
            if class_name == 'PERSON' and ACTIVE_MODE in ["tactical", "home"]:
                if track_id not in person_id_cache:
                    person_id_cache[track_id] = {"label": "PERSON", "attempts": 0, "last_checked": 0}
                p_cache = person_id_cache[track_id]
                if "Authorized" not in p_cache["label"] and p_cache["attempts"] < 8 and (frame_count - p_cache["last_checked"]) > 10:
                    orig_y1, orig_y2 = max(0, int(y1 * scale_y)), min(orig_h, int(y2 * scale_y))
                    orig_x1, orig_x2 = max(0, int(x1 * scale_x)), min(orig_w, int(x2 * scale_x))
                    person_crop = original_frame[orig_y1:orig_y2, orig_x1:orig_x2]
                    if person_crop.size > 0:
                        p_cache["attempts"] += 1; p_cache["last_checked"] = frame_count
                        face_queue.put((track_id, cv2.cvtColor(person_crop, cv2.COLOR_BGR2RGB)))
                person_label = p_cache["label"]

            if secure_polygon.contains(foot_point):
                zone_color = (0, 0, 255)
                breach_detected = True   
                breach_count_this_frame += 1

                if class_name in ['CAR', 'TRUCK', 'BUS', 'MOTORCYCLE'] and ACTIVE_MODE in ["tactical", "traffic", "drone"]:
                    if track_id not in text_cache: 
                        text_cache[track_id] = {"plate": None, "other_text": None, "attempts": 0, "last_checked": 0}
                    cache_entry = text_cache[track_id]
                    
                    if cache_entry["attempts"] < 10 and (frame_count - cache_entry["last_checked"]) > 5:
                        orig_x1, orig_y1 = max(0, int(x1 * scale_x)), max(0, int(y1 * scale_y))
                        orig_x2, orig_y2 = min(orig_w, int(x2 * scale_x)), min(orig_h, int(y2 * scale_y))
                        v_crop = original_frame[orig_y1:orig_y2, orig_x1:orig_x2]
                        
                        cache_entry["attempts"] += 1
                        cache_entry["last_checked"] = frame_count
                        ocr_queue.put((track_id, v_crop.copy(), class_name))

                    ui_text = f"{class_name}"
                    if cache_entry["plate"]: ui_text += f" | PLT: {cache_entry['plate']}"
                    if cache_entry["other_text"]: ui_text += f" | TXT: {cache_entry['other_text']}"
                    
                    if cache_entry["plate"] or cache_entry["other_text"]:
                        current_threat = f"{ui_text} BREACH @ {int(current_speed)}km/h"
                        cv2.putText(annotated_frame, ui_text, (x1, max(25, y1 - 30)), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 255), 2)
                    else:
                        current_threat = f"{class_name} BREACH @ {int(current_speed)}km/h"
                
                elif person_label and "UNKNOWN" in person_label:
                    current_threat = "UNKNOWN INTRUDER DETECTED"

            box_color = (0, 255, 0) if (person_label and "Authorized" in person_label) else (0, 255, 255)
            cv2.rectangle(annotated_frame, (x1, y1), (x2, y2), box_color, 2)
            
            display_tag = person_label if person_label else f"ID:{track_id} {class_name}"
            if current_speed > 0 and ACTIVE_MODE in ["drone", "traffic", "tactical"]: 
                display_tag += f" {int(current_speed)}km/h"
                
            cv2.putText(annotated_frame, display_tag, (x1, y1 - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.5, box_color, 2)
            cv2.circle(annotated_frame, (int((x1+x2)/2), int(y2)), 5, zone_color, -1)

    cv2.polylines(annotated_frame, [secure_zone_pts], isClosed=True, color=zone_color, thickness=3)

    if breach_detected:
        temp_score, temp_level, _ = threat_engine.score(datetime.now(), breach_count_this_frame, "pending")
        draw_threat_hud(annotated_frame, temp_score, temp_level, 640, 480)

    fps = 1 / (curr_time - prev_time) if (curr_time - prev_time) > 0 else 0
    prev_time = curr_time

    active_peers = len([p for p, t in swarm.peers_status.items() if curr_time - t < 5.0])
    swarm_status = f"{active_peers} PEER(S) CONNECTED" if active_peers > 0 else "ISOLATED NODE"
    
    hud_line1 = f"NODE: {args.node} | {swarm_status} | FPS: {int(fps)}"
    hud_line2 = f"MODE: [{ACTIVE_MODE.upper()}]"
    if weather_disturbance: hud_line2 += " | WEATHER EQ: ACTIVE"
    if camouflage_defeat_active: hud_line2 += " | CAMO DEFEAT: ON"
    
    cv2.putText(annotated_frame, hud_line1, (20, 25), cv2.FONT_HERSHEY_SIMPLEX, 0.55, (0, 255, 255), 2)
    cv2.putText(annotated_frame, hud_line2, (20, 48), cv2.FONT_HERSHEY_SIMPLEX, 0.55, (0, 255, 0), 2)
    
    cv2.imshow("IBVAP Enterprise Suite", annotated_frame)

    if breach_detected and (curr_time - last_alert_time) > 5.0:
        now_dt = datetime.now()
        timestamp_formatted = now_dt.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
        file_timestamp = now_dt.strftime("%Y%m%d_%H%M%S")
        
        image_name = f"intrusion_{file_timestamp}.jpg"
        image_path = os.path.join(ALERTS_DIR, image_name)
        cv2.imwrite(image_path, annotated_frame)
        
        img_hash = generate_image_hash(image_path)
        chain_hash = generate_chain_hash(img_hash, get_last_chain_hash(cursor))
        threat_score, threat_level, is_repeat = threat_engine.score(now_dt, breach_count_this_frame, img_hash)
        
        cursor.execute('INSERT INTO intrusions (timestamp, event_type, total_crossings, image_path, image_hash, sync_status, chain_hash, threat_score, threat_level) VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)', 
                       (timestamp_formatted, current_threat, breach_count_this_frame, image_path, img_hash, chain_hash, threat_score, threat_level))
        alert_id = cursor.lastrowid
        conn.commit()
        
        generate_incident_report(alert_id, timestamp_formatted, current_threat, breach_count_this_frame, threat_score, threat_level)
        swarm.send_alert(current_threat, threat_level)

        dynamic_node_id = f"{args.node}_{ACTIVE_MODE}"
        payload = {"edge_node_id": dynamic_node_id, "timestamp": timestamp_formatted, "event_type": current_threat, "total_crossings": breach_count_this_frame, "image_hash": img_hash, "chain_hash": chain_hash, "threat_score": threat_score, "threat_level": threat_level, "jwt_token": JWT_AUTH_TOKEN}
        try:
            requests.post(HQ_API_URL, json=payload, timeout=1.5)
            cursor.execute('UPDATE intrusions SET sync_status = 1 WHERE id = ?', (alert_id,))
            conn.commit()
        except requests.exceptions.RequestException: pass

        print(f"\n🚨 BREACH ALERT [{ACTIVE_MODE.upper()}] | {current_threat} | Score: {threat_score} ({threat_level}) | BROADCASTED TO SWARM")
        last_alert_time = curr_time 

    key = cv2.waitKey(1) & 0xFF
    if key == ord('q'): 
        audit.record_event(current_operator, "SYSTEM_SHUTDOWN", "Command session closed by operator")
        break
    elif key == ord('1'): 
        ACTIVE_MODE = "tactical"
        audit.record_event(current_operator, "MODE_SWITCH", "TACTICAL")
        print("\n🛡️ MODE: TACTICAL")
    elif key == ord('2'): 
        ACTIVE_MODE = "traffic"
        audit.record_event(current_operator, "MODE_SWITCH", "TRAFFIC")
        print("\n🚦 MODE: TRAFFIC")
    elif key == ord('3'): 
        ACTIVE_MODE = "home"
        audit.record_event(current_operator, "MODE_SWITCH", "HOME")
        print("\n🏠 MODE: HOME")
    elif key == ord('4'): 
        ACTIVE_MODE = "drone"
        audit.record_event(current_operator, "MODE_SWITCH", "DRONE_VECTOR")
        print("\n🛸 MODE: DRONE")
    elif key == ord('a'): 
        camouflage_defeat_active = not camouflage_defeat_active
        audit.record_event(current_operator, "CONFIG_CHANGE", f"Camouflage Defeat set to {camouflage_defeat_active}")
    elif key == ord('v'): 
        verify_ledger_integrity(cursor)
        audit.verify_ledger()
    elif key == ord('m'): 
        # Generate the map file locally
        map_path = generate_offline_map(BASE_DIR)
        audit.record_event(current_operator, "VIEW_TACTICAL_MAP", "Opened Camera Network Map")
        print(f"\n🗺️ [MAP] Launching Tactical Map Interface...")
        
        # Route through local HQ server or direct file protocol without crashing Cocoa
        import webbrowser
        webbrowser.open("http://127.0.0.1:8000/map")

cap.release()
cv2.destroyAllWindows()
conn.close()