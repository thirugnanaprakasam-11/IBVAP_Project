import cv2
import sqlite3
import time
import hashlib
import os
import requests 
import json      
from datetime import datetime
from collections import deque
from ultralytics import YOLO
import face_recognition
import numpy as np
from shapely.geometry import Point, Polygon, LineString
import easyocr
import re
import math
import threading
import queue

# ==========================================
# 0. LIVE MODE STATE
# ==========================================
ACTIVE_MODE = "tactical"  

print("[+] INITIALIZING IBVAP ENGINE... READY FOR LIVE MODE SWITCHING")

# ==========================================
# 1. CORE SYSTEM & DIRECTORY SETUP
# ==========================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ALERTS_DIR = os.path.join(BASE_DIR, "alerts")
os.makedirs(ALERTS_DIR, exist_ok=True)

HQ_API_URL = "http://127.0.0.1:8000/api/v1/alerts"
JWT_AUTH_TOKEN = "ibvap_secure_edge_auth_2026"

# ==========================================
# 2. CYBERSECURITY HASHING & BLOCKCHAIN LEDGER
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
# 3. DATABASE SETUP 
# ==========================================
DB_PATH = os.path.join(BASE_DIR, "ibvap_secure.db")
conn = sqlite3.connect(DB_PATH)
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
# 3.5 ZERO-TRUST BIOMETRICS 
# ==========================================
known_face_encodings, known_face_names = [], []
print("Loading Secure Identity Signatures into Memory...")
AUTH_FACES_DIR = os.path.join(BASE_DIR, "authorized_faces")
os.makedirs(AUTH_FACES_DIR, exist_ok=True)
for filename in os.listdir(AUTH_FACES_DIR):
    if filename.lower().endswith(('.jpg', '.jpeg', '.png')):
        img_path = os.path.join(AUTH_FACES_DIR, filename)
        person_name = os.path.splitext(filename)[0].replace("_", " ").upper()
        try:
            enc = face_recognition.face_encodings(face_recognition.load_image_file(img_path))
            if enc:
                known_face_encodings.append(enc[0])
                known_face_names.append(f"{person_name} - Authorized")
                print(f"  -> Added signature for: {person_name}")
        except Exception: pass

# ==========================================
# 4. PREDICTIVE THREAT INTELLIGENCE ENGINE
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

# ==========================================
# 4.5 VISION, ANPR & HUD UTILS
# ==========================================
def eradicate_weather(frame):
    lab = cv2.cvtColor(frame, cv2.COLOR_BGR2LAB)
    l_channel, a_channel, b_channel = cv2.split(lab)
    clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8))
    enhanced_l = clahe.apply(l_channel)
    enhanced_bgr = cv2.cvtColor(cv2.merge((enhanced_l, a_channel, b_channel)), cv2.COLOR_LAB2BGR)
    gaussian = cv2.GaussianBlur(enhanced_bgr, (0, 0), 2.0)
    return cv2.addWeighted(enhanced_bgr, 1.3, gaussian, -0.3, 0)

def apply_night_vision(frame):
    lab = cv2.cvtColor(frame, cv2.COLOR_BGR2LAB)
    l, a, b = cv2.split(lab)
    cl = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8,8)).apply(l)
    return cv2.cvtColor(cv2.merge((cl,a,b)), cv2.COLOR_LAB2BGR)

def get_average_brightness(frame):
    return cv2.mean(cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY))[0]

def extract_license_plate(vehicle_crop, ocr_engine):
    if vehicle_crop is None or vehicle_crop.size == 0: return None
    vh, vw, _ = vehicle_crop.shape
    plate_roi = vehicle_crop[int(vh * 0.4):vh, :]
    if plate_roi.size == 0: plate_roi = vehicle_crop
    
    gray = cv2.cvtColor(plate_roi, cv2.COLOR_BGR2GRAY)
    detections = ocr_engine.readtext(gray, allowlist='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ', detail=1)
    
    candidates = []
    for _, text, score in detections:
        clean_text = re.sub(r'[^A-Z0-9]', '', text.upper())
        if len(clean_text) >= 4 and score >= 0.1:
            candidates.append((clean_text, score))
            
    if candidates:
        candidates.sort(key=lambda x: x[1], reverse=True)
        return candidates[0][0]
    return None

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
# 5. VIDEO & AI ENGINE SETUP
# ==========================================
secure_zone_pts = np.array([[100, 240], [540, 240], [600, 460], [40, 460]], np.int32)
secure_polygon = Polygon(secure_zone_pts)
PIXELS_PER_METER = 25.0  

LIVE_CAM_ID = 0
FALLBACK_VIDEO_PATH = os.path.join(BASE_DIR, "test_footage.mp4")
cap = cv2.VideoCapture(LIVE_CAM_ID)
using_fallback = False

model = YOLO("yolov8n.pt") 
ocr_reader = easyocr.Reader(['en'], gpu=False)
threat_engine = ThreatEngine()

# --- ASYNC BACKGROUND WORKERS ---
vehicle_plate_cache = {}
person_id_cache = {} 
ocr_queue = queue.Queue()
face_queue = queue.Queue()

def async_ocr_worker():
    while True:
        track_id, v_crop = ocr_queue.get()
        if v_crop is not None:
            try:
                plate = extract_license_plate(v_crop, ocr_reader)
                if plate and track_id in vehicle_plate_cache:
                    vehicle_plate_cache[track_id]["plate"] = plate
            except Exception: pass
        ocr_queue.task_done()

def async_face_worker():
    while True:
        track_id, rgb_crop = face_queue.get()
        if rgb_crop is not None:
            try:
                f_locs = face_recognition.face_locations(rgb_crop, model="hog", number_of_times_to_upsample=1)
                if f_locs:
                    f_encs = face_recognition.face_encodings(rgb_crop, f_locs)
                    if f_encs and known_face_encodings:
                        matches = face_recognition.compare_faces(known_face_encodings, f_encs[0], tolerance=0.6)
                        if True in matches and track_id in person_id_cache:
                            matched_name = known_face_names[matches.index(True)]
                            person_id_cache[track_id]["label"] = matched_name
                            print(f"\n[BIOMETRIC AUTH] ✅ Match Confirmed: {matched_name}")
                        elif track_id in person_id_cache and person_id_cache[track_id]["label"] == "PERSON":
                            person_id_cache[track_id]["label"] = "UNKNOWN INTRUDER"
                            print(f"\n[BIOMETRIC AUTH] ❌ Match Failed. Classified as Unknown.")
                else:
                    pass
            except Exception as e: 
                print(f"[BIOMETRIC DEBUG] Error processing face: {e}")
        face_queue.task_done()

threading.Thread(target=async_ocr_worker, daemon=True).start()
threading.Thread(target=async_face_worker, daemon=True).start()

# --- CAMOUFLAGE DEFEAT ENGINE ---
backSub = cv2.createBackgroundSubtractorMOG2(history=300, varThreshold=25, detectShadows=False)
heatmap_buffer = np.zeros((480, 640), dtype=np.float32)
camouflage_defeat_active = False

prev_time, last_alert_time = time.time(), 0
night_vision_active, night_vision_manual_override = False, False
weather_disturbance = False
BRIGHTNESS_THRESHOLD = 70  
frame_count = 0
vehicle_track_data = {}   

# ==========================================
# 6. HIGH-PERFORMANCE SURVEILLANCE LOOP
# ==========================================
while cap.isOpened():
    success, original_frame = cap.read()
    if not success:
        cap = cv2.VideoCapture(FALLBACK_VIDEO_PATH)
        using_fallback = True
        continue

    frame_count += 1
    orig_h, orig_w, _ = original_frame.shape
    scale_x, scale_y = orig_w / 640.0, orig_h / 480.0

    frame = cv2.resize(original_frame, (640, 480))
    
    if frame_count % 15 == 1 or frame_count == 1:
        gray_check = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        contrast_level = gray_check.std()
        sharpness_level = cv2.Laplacian(gray_check, cv2.CV_64F).var()
        weather_disturbance = (contrast_level < 45.0 or sharpness_level < 100.0)

    if weather_disturbance:
        frame = eradicate_weather(frame)
    
    annotated_frame = frame.copy()

    # --- CAMOUFLAGE ANOMALY DETECTION ---
    # Continuously update background model for instant readiness
    fgMask = backSub.apply(frame)

    if camouflage_defeat_active:
        kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (5, 5))
        fgMask = cv2.morphologyEx(fgMask, cv2.MORPH_OPEN, kernel)
        
        # Accumulate residual motion energy
        heatmap_buffer = cv2.addWeighted(heatmap_buffer, 0.90, fgMask.astype(np.float32), 0.10, 0)
        
        # Map to Predator-style Inferno visual
        heatmap_norm = cv2.normalize(heatmap_buffer, None, 0, 255, cv2.NORM_MINMAX, dtype=cv2.CV_8U)
        anomaly_color = cv2.applyColorMap(heatmap_norm, cv2.COLORMAP_INFERNO)
        
        # Overlay Anomaly Heatmap
        annotated_frame = cv2.addWeighted(annotated_frame, 0.6, anomaly_color, 0.4, 0)

        # Flag physical anomalies that YOLO neural net might miss
        contours, _ = cv2.findContours(fgMask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        for cnt in contours:
            if cv2.contourArea(cnt) > 900:
                cx, cy, cw, ch = cv2.boundingRect(cnt)
                draw_dashed_line(annotated_frame, (cx, cy), (cx + cw, cy), (0, 0, 255), 2)
                draw_dashed_line(annotated_frame, (cx, cy + ch), (cx + cw, cy + ch), (0, 0, 255), 2)
                cv2.putText(annotated_frame, "CAMOUFLAGED ANOMALY", (cx, max(20, cy - 10)), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 255), 2)

    curr_time = time.time()
    fps = 1 / (curr_time - prev_time) if (curr_time - prev_time) > 0 else 0
    prev_time = curr_time

    key = cv2.waitKey(1) & 0xFF
    if key == ord('q'): break
    elif key == ord('1'): 
        ACTIVE_MODE = "tactical"
        print("\n🛡️ SWITCHED TO: TACTICAL MODE")
    elif key == ord('2'): 
        ACTIVE_MODE = "traffic"
        print("\n🚦 SWITCHED TO: TRAFFIC MODE")
    elif key == ord('3'): 
        ACTIVE_MODE = "home"
        print("\n🏠 SWITCHED TO: HOME MODE")
    elif key == ord('a'): 
        camouflage_defeat_active = not camouflage_defeat_active
        if not camouflage_defeat_active: heatmap_buffer = np.zeros((480, 640), dtype=np.float32)
        print(f"\n🕵️ CAMOUFLAGE DEFEAT: {'ENABLED' if camouflage_defeat_active else 'DISABLED'}")
    elif key == ord('n'): 
        night_vision_manual_override = True
        night_vision_active = not night_vision_active
    elif key == ord('f') and not using_fallback:
        cap = cv2.VideoCapture(FALLBACK_VIDEO_PATH)
        using_fallback = True
    elif key == ord('c') and using_fallback:
        cap = cv2.VideoCapture(LIVE_CAM_ID)
        using_fallback = False
    elif key == ord('v'):
        verify_ledger_integrity(cursor)

    if not night_vision_manual_override:
        night_vision_active = get_average_brightness(frame) < BRIGHTNESS_THRESHOLD
    if night_vision_active: 
        frame = apply_night_vision(frame)

    results = model.track(frame, device="mps", persist=True, tracker="bytetrack.yaml", verbose=False)
    zone_color = (255, 0, 0)
    
    breach_detected = False
    current_threat = f"VIRTUAL_FENCE_BREACH ({ACTIVE_MODE.upper()})"
    breach_count_this_frame = 0

    for result in results:
        boxes = result.boxes
        if boxes.id is None: continue 

        for i, box in enumerate(boxes):
            x1, y1, x2, y2 = box.xyxy[0].int().tolist()
            cls_id, conf = int(box.cls[0]), float(box.conf[0])
            track_id = int(boxes.id[i]) 
            class_name = model.names[cls_id].upper()
            
            foot_x, foot_y = int((x1 + x2) / 2), int(y2)
            foot_point = Point(foot_x, foot_y)
            
            current_speed, vx, vy = 0.0, 0.0, 0.0
            if track_id in vehicle_track_data:
                prev_cx, prev_cy, prev_ts, prev_speed, prev_vx, prev_vy = vehicle_track_data[track_id]
                time_diff = curr_time - prev_ts
                if time_diff > 0.12:
                    dist = math.hypot(foot_x - prev_cx, foot_y - prev_cy)
                    if dist > 4:
                        vx, vy = (foot_x - prev_cx) / time_diff, (foot_y - prev_cy) / time_diff
                        current_speed = ((dist / PIXELS_PER_METER) / time_diff) * 3.6
                    else:
                        vx, vy, current_speed = prev_vx, prev_vy, prev_speed
                    vehicle_track_data[track_id] = (foot_x, foot_y, curr_time, current_speed, vx, vy)
                else:
                    vx, vy, current_speed = prev_vx, prev_vy, prev_speed
            else:
                vehicle_track_data[track_id] = (foot_x, foot_y, curr_time, 0.0, 0.0, 0.0)

            future_x, future_y = int(foot_x + (vx * 2.5)), int(foot_y + (vy * 2.5))
            if abs(vx) > 5 or abs(vy) > 5:
                if LineString([(foot_x, foot_y), (future_x, future_y)]).intersects(secure_polygon) and not secure_polygon.contains(foot_point):
                    draw_dashed_line(annotated_frame, (foot_x, foot_y), (future_x, future_y), (0, 0, 255), 2)
                else:
                    draw_dashed_line(annotated_frame, (foot_x, foot_y), (future_x, future_y), (0, 255, 0), 2)

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
                        rgb_crop = cv2.cvtColor(person_crop, cv2.COLOR_BGR2RGB)
                        p_cache["attempts"] += 1
                        p_cache["last_checked"] = frame_count
                        face_queue.put((track_id, rgb_crop.copy()))
                        
                person_label = p_cache["label"]

            if secure_polygon.contains(foot_point):
                zone_color = (0, 0, 255)
                breach_detected = True   
                breach_count_this_frame += 1

                if class_name in ['CAR', 'TRUCK', 'BUS', 'MOTORCYCLE'] and ACTIVE_MODE in ["tactical", "traffic"]:
                    if track_id not in vehicle_plate_cache: 
                        vehicle_plate_cache[track_id] = {"plate": None, "attempts": 0, "last_checked": 0}
                    cache_entry = vehicle_plate_cache[track_id]
                    
                    if cache_entry["plate"] is None and (cache_entry["attempts"] < 8 and (frame_count - cache_entry["last_checked"]) > 12):
                        orig_x1, orig_y1 = max(0, int(x1 * scale_x)), max(0, int(y1 * scale_y))
                        orig_x2, orig_y2 = min(orig_w, int(x2 * scale_x)), min(orig_h, int(y2 * scale_y))
                        v_crop = original_frame[orig_y1:orig_y2, orig_x1:orig_x2]
                        
                        cache_entry["attempts"] += 1
                        cache_entry["last_checked"] = frame_count
                        ocr_queue.put((track_id, v_crop.copy()))

                    if cache_entry["plate"]:
                        current_threat = f"{class_name} BREACH (PLATE: {cache_entry['plate']}) @ {int(current_speed)}km/h"
                        cv2.putText(annotated_frame, f"PLATE: {cache_entry['plate']}", (x1, max(25, y1 - 30)), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 255), 2)
                    else:
                        current_threat = f"{class_name} BREACH @ {int(current_speed)}km/h"
                elif person_label and "UNKNOWN" in person_label:
                    current_threat = "UNKNOWN INTRUDER DETECTED"

            box_color = (0, 255, 0) if (person_label and "Authorized" in person_label) else (0, 255, 255)
            cv2.rectangle(annotated_frame, (x1, y1), (x2, y2), box_color, 2)
            display_tag = person_label if person_label else f"ID:{track_id} {class_name}"
            if current_speed > 0: display_tag += f" {int(current_speed)}km/h"
            cv2.putText(annotated_frame, display_tag, (x1, y1 - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.5, box_color, 2)
            cv2.circle(annotated_frame, (foot_x, foot_y), 5, zone_color, -1)

    cv2.polylines(annotated_frame, [secure_zone_pts], isClosed=True, color=zone_color, thickness=3)

    if breach_detected:
        temp_score, temp_level, _ = threat_engine.score(datetime.now(), breach_count_this_frame, "pending")
        draw_threat_hud(annotated_frame, temp_score, temp_level, 640, 480)

    hud_text = f"IBVAP [{ACTIVE_MODE.upper()}] - FPS: {int(fps)}"
    if weather_disturbance:
        hud_text += " | WEATHER EQ: ACTIVE"
    if camouflage_defeat_active:
        hud_text += " | CAMO DEFEAT: ON"
    cv2.putText(annotated_frame, hud_text, (20, 40), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 2)
    
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

        dynamic_node_id = f"border_cam_{ACTIVE_MODE}_01"
        payload = {"edge_node_id": dynamic_node_id, "timestamp": timestamp_formatted, "event_type": current_threat, "total_crossings": breach_count_this_frame, "image_hash": img_hash, "chain_hash": chain_hash, "threat_score": threat_score, "threat_level": threat_level, "jwt_token": JWT_AUTH_TOKEN}
        try:
            requests.post(HQ_API_URL, json=payload, timeout=1.5)
            cursor.execute('UPDATE intrusions SET sync_status = 1 WHERE id = ?', (alert_id,))
            conn.commit()
        except requests.exceptions.RequestException: pass

        print(f"\n🚨 BREACH ALERT [{ACTIVE_MODE.upper()}] | {current_threat} | Score: {threat_score} ({threat_level})")
        last_alert_time = curr_time 

cap.release()
cv2.destroyAllWindows()
conn.close()