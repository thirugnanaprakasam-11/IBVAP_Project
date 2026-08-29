from builtins import print
import cv2
import sqlite3
import time
import hashlib
import os
import requests 
import json      
from datetime import datetime
from ultralytics import YOLO
import face_recognition
import numpy as np
from shapely.geometry import Point, Polygon
import easyocr

# ==========================================
# THREAT CLASSIFICATION & SEVERITY CONFIG
# ==========================================
SEVERITY_THRESHOLDS = {
    "CRITICAL": ["UNKNOWN INTRUDER", "UNAUTHORIZED DRONE"],
    "HIGH": ["CAR BREACH", "TRUCK BREACH", "BUS BREACH", "PERSON BREACH"],
    "MEDIUM": ["SUSPICIOUS ACTIVITY", "UNIDENTIFIED OBJECT", "VIRTUAL_FENCE_BREACH"],
    "LOW": ["AUTHORIZED PERSONNEL", "LOW CONFIDENCE MOTION"]
}

def determine_severity(threat_label: str, confidence: float) -> str:
    threat_upper = threat_label.upper()
    if any(crit in threat_upper for crit in SEVERITY_THRESHOLDS["CRITICAL"]):
        return "CRITICAL"
    if any(high in threat_upper for high in SEVERITY_THRESHOLDS["HIGH"]):
        return "CRITICAL" if confidence >= 0.85 else "HIGH"
    if any(med in threat_upper for med in SEVERITY_THRESHOLDS["MEDIUM"]):
        return "MEDIUM"
    return "LOW"

# ==========================================
# 0. ADVANCED GEOMETRY SETUP (640x480 Scale)
# ==========================================
secure_zone_pts = np.array([[100, 240], [540, 240], [600, 460], [40, 460]], np.int32)
secure_polygon = Polygon(secure_zone_pts)

# ==========================================
# 1. CORE SYSTEM & DIRECTORY SETUP
# ==========================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ALERTS_DIR = os.path.join(BASE_DIR, "alerts")
os.makedirs(ALERTS_DIR, exist_ok=True)

HQ_API_URL = "http://127.0.0.1:8000/api/v1/alerts"
EDGE_NODE_ID = "border_cam_01"
JWT_AUTH_TOKEN = "ibvap_secure_edge_auth_2026"

# ==========================================
# 2. CYBERSECURITY HASHING
# ==========================================
def generate_image_hash(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256.update(byte_block)
    return sha256.hexdigest()

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
        image_hash TEXT
    )
''')
conn.commit()

# ==========================================
# 3.5 ZERO-TRUST MULTI-ADMIN IDENTITY ENCODING
# ==========================================
print("Loading Secure Identity Signatures from folder...")
known_face_encodings = []
known_face_names = []

AUTH_FACES_DIR = os.path.join(BASE_DIR, "authorized_faces")
os.makedirs(AUTH_FACES_DIR, exist_ok=True)

admin_images_found = False
for filename in os.listdir(AUTH_FACES_DIR):
    if filename.lower().endswith(('.jpg', '.jpeg', '.png')):
        admin_images_found = True
        img_path = os.path.join(AUTH_FACES_DIR, filename)
        person_name = os.path.splitext(filename)[0].replace("_", " ").upper()
        
        try:
            admin_image = face_recognition.load_image_file(img_path)
            encodings = face_recognition.face_encodings(admin_image)
            
            if encodings:
                known_face_encodings.append(encodings[0])
                known_face_names.append(f"{person_name} - Authorized Admin")
                print(f"✅ Loaded security profile: {person_name}")
            else:
                print(f"⚠️ No clear face found in {filename}, skipping.")
        except Exception as e:
            print(f"❌ Error loading {filename}: {e}")

if not admin_images_found or not known_face_encodings:
    print("⚠️ authorized_faces folder is empty. System will flag all faces as UNKNOWN INTRUDERS.")

# ==========================================
# 4. ADVANCED VIDEO ANALYTICS MODULES
# ==========================================
def apply_night_vision(frame):
    lab = cv2.cvtColor(frame, cv2.COLOR_BGR2LAB)
    l, a, b = cv2.split(lab)
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8,8))
    cl = clahe.apply(l)
    enhanced_img = cv2.merge((cl,a,b))
    return cv2.cvtColor(enhanced_img, cv2.COLOR_LAB2BGR)

# ==========================================
# 5. VIDEO & AI SETUP
# ==========================================
LIVE_CAM_ID = 0
FALLBACK_VIDEO_PATH = os.path.join(BASE_DIR, "test_footage.mp4")

cap = cv2.VideoCapture(LIVE_CAM_ID)
using_fallback = False

model = YOLO("yolov8n.pt") 
print("Loading OCR Text Engine...")
ocr_reader = easyocr.Reader(['en'], gpu=False)

print("IBVAP Enterprise Suite Active.")
print("HOTKEYS: 'n'=Night Vision | 'f'=Fallback Video | 'c'=Live Cam | 'q'=Quit")

prev_time = time.time()
last_alert_time = 0
night_vision_active = False
human_in_frame_time = 0 
process_current_frame = True
face_locations = []

# ==========================================
# 6. MAIN SURVEILLANCE LOOP
# ==========================================
while cap.isOpened():
    success, frame = cap.read()
    
    if not success:
        if using_fallback:
            cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
            continue
        else:
            print("⚠️ Live camera lost! Auto-switching to Fallback Video...")
            cap = cv2.VideoCapture(FALLBACK_VIDEO_PATH)
            using_fallback = True
            continue

    frame = cv2.resize(frame, (640, 480))
    annotated_frame = frame.copy()

    curr_time = time.time()
    fps = 1 / (curr_time - prev_time) if (curr_time - prev_time) > 0 else 0
    prev_time = curr_time

    key = cv2.waitKey(1) & 0xFF
    if key == ord('q'):
        break
    elif key == ord('n'):
        night_vision_active = not night_vision_active
    elif key == ord('f') and not using_fallback:
        cap = cv2.VideoCapture(FALLBACK_VIDEO_PATH)
        using_fallback = True
    elif key == ord('c') and using_fallback:
        cap = cv2.VideoCapture(LIVE_CAM_ID)
        using_fallback = False

    if night_vision_active:
        frame = apply_night_vision(frame)

    results = model(frame, device="mps", verbose=False)
    zone_color = (255, 0, 0)
    
    breach_detected = False
    current_threat = "VIRTUAL_FENCE_BREACH"
    active_class_name = "Unidentified [Object]"
    active_confidence = 0.0
    active_identifying_attribute = "Unknown [Attribute]"

    # 1. RAW YOLO TRACKING & 2D POLYGON BREACH LOGIC
    for result in results:
        boxes = result.boxes
        for box in boxes:
            x1, y1, x2, y2 = box.xyxy[0].int().tolist()
            
            cls_id = int(box.cls[0])
            conf = float(box.conf[0])
            class_name = model.names[cls_id].upper()
            
            foot_x = int((x1 + x2) / 2)
            foot_y = int(y2)
            foot_point = Point(foot_x, foot_y)
            
            if secure_polygon.contains(foot_point):
                zone_color = (0, 0, 255)
                breach_detected = True   
                
                active_class_name = class_name
                active_confidence = conf
                current_threat = f"{class_name} BREACH"
                active_identifying_attribute = "No specific metadata extracted"
                
                if class_name in ['CAR', 'TRUCK', 'BUS', 'MOTORCYCLE', 'PERSON']:
                    h_frame, w_frame, _ = frame.shape
                    x1_safe, y1_safe = max(0, x1), max(0, y1)
                    x2_safe, y2_safe = min(w_frame, x2), min(h_frame, y2)
                    
                    vehicle_crop = frame[y1_safe:y2_safe, x1_safe:x2_safe]
                    
                    if vehicle_crop.size > 0:
                        extracted_text = ocr_reader.readtext(vehicle_crop, detail=0)
                        
                        if extracted_text:
                            plate_number = " ".join(extracted_text)
                            current_threat = f"{class_name} BREACH (PLATE: {plate_number})"
                            active_identifying_attribute = f"License Plate: {plate_number}"
                            cv2.putText(annotated_frame, f"PLATE: {plate_number}", (x1, y1 - 30), 
                                        cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 255), 2)
                        else:
                            active_identifying_attribute = "License Plate: [Unreadable / None]"

            cv2.rectangle(annotated_frame, (x1, y1), (x2, y2), (0, 255, 255), 2)
            cv2.putText(annotated_frame, f"{class_name} {conf:.2f}", (x1, y1 - 10), 
                        cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 255), 2)
            cv2.circle(annotated_frame, (foot_x, foot_y), 6, zone_color, -1)
            
    cv2.polylines(annotated_frame, [secure_zone_pts], isClosed=True, color=zone_color, thickness=3)

    # 2. BIOMETRIC FACE RECOGNITION
    if process_current_frame:
        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        face_locations = face_recognition.face_locations(rgb_frame, model="hog")
        face_encodings = face_recognition.face_encodings(rgb_frame, face_locations)

        for (top, right, bottom, left), face_encoding in zip(face_locations, face_encodings):
            matches = face_recognition.compare_faces(known_face_encodings, face_encoding, tolerance=0.5)
            name = "UNKNOWN INTRUDER"
            box_color = (0, 0, 255) 

            if True in matches:
                first_match_index = matches.index(True)
                name = known_face_names[first_match_index]
                box_color = (0, 255, 0) 
            else:
                # Trigger alert for unauthorized biometrics
                breach_detected = True
                active_class_name = "PERSON"
                current_threat = "UNKNOWN INTRUDER DETECTED"
                active_identifying_attribute = "Biometrics: Unregistered Signature"
                active_confidence = 0.99

            cv2.rectangle(annotated_frame, (left, top), (right, bottom), box_color, 2)
            cv2.putText(annotated_frame, name, (left, top - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.6, box_color, 2)

    process_current_frame = not process_current_frame

    # 3. LOITERING DETECTION
    if len(face_locations) > 0:
        human_in_frame_time += 1
        if human_in_frame_time > 20: 
            cv2.putText(annotated_frame, "⚠️ SUSPICIOUS ACTIVITY: LOITERING", (20, 100), 
                        cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 255), 2)
    else:
        human_in_frame_time = 0

    # 4. TACTICAL HUD
    mode_text = "NIGHT VISION ACTIVE" if night_vision_active else "DAY MODE"
    feed_text = "FALLBACK FEED" if using_fallback else "LIVE EDGE FEED"
    cv2.putText(annotated_frame, f"IBVAP - FPS: {int(fps)} | {mode_text} | {feed_text}", (20, 40), 
                cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 2)
                
    live_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cv2.putText(annotated_frame, live_timestamp, (420, 460), 
                cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 2)

    cv2.imshow("IBVAP Enterprise Suite", annotated_frame)

    # 5. INTRUSION DATABASE LOGGING (Cooldown Enabled & Refactored)
    if breach_detected:
        if (curr_time - last_alert_time) > 5.0:
            now_tz = datetime.now().astimezone()
            timestamp_formatted = now_tz.strftime("%Y-%m-%d %H:%M:%S %Z")
            file_timestamp = now_tz.strftime("%Y%m%d_%H%M%S")
            
            image_name = f"intrusion_{file_timestamp}.jpg"
            image_path = os.path.join(ALERTS_DIR, image_name)
            
            cv2.imwrite(image_path, annotated_frame)
            img_hash = generate_image_hash(image_path)
            severity = determine_severity(current_threat, active_confidence)

            cursor.execute('''
                INSERT INTO intrusions (timestamp, event_type, total_crossings, image_path, image_hash)
                VALUES (?, ?, ?, ?, ?)
            ''', (timestamp_formatted, current_threat, 1, image_path, img_hash))
            conn.commit()

            payload = {
                "edge_node_id": EDGE_NODE_ID,
                "timestamp": timestamp_formatted,
                "event_type": current_threat,
                "total_crossings": 1, 
                "image_hash": img_hash,
                "jwt_token": JWT_AUTH_TOKEN
            }
            
            try:
                requests.post(HQ_API_URL, json=payload, timeout=2)
            except requests.exceptions.RequestException:
                pass 

            print("\n" + "="*50)
            print(f"🚨 TACTICAL BREACH ALERT [{severity}]")
            print(f"Timestamp        : {timestamp_formatted}")
            print(f"Edge Node        : {EDGE_NODE_ID}")
            print(f"Target Category  : {active_class_name}")
            print(f"Threat Event     : {current_threat}")
            print(f"Identifiable Attr: {active_identifying_attribute}")
            print(f"AI Confidence    : {active_confidence:.2%}")
            print(f"Encrypted File   : {image_name}")
            print(f"SHA-256 Ledger   : {img_hash}")
            print("="*50 + "\n")
            
            last_alert_time = curr_time 

cap.release()
cv2.destroyAllWindows()
conn.close()