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
# 0. ADVANCED GEOMETRY SETUP (640x480 Scale)
# ==========================================
# Shape: Top-Left, Top-Right, Bottom-Right, Bottom-Left
secure_zone_pts = np.array([[100, 240], [540, 240], [600, 460], [40, 460]], np.int32)
secure_polygon = Polygon(secure_zone_pts)

# ==========================================
# 1. CORE SYSTEM & DIRECTORY SETUP
# ==========================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ALERTS_DIR = os.path.join(BASE_DIR, "alerts")
os.makedirs(ALERTS_DIR, exist_ok=True)

# 🌐 FASTAPI CENTRAL COMMAND SETTINGS
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
# ==========================================
# 3.5 ZERO-TRUST MULTI-ADMIN IDENTITY ENCODING
# ==========================================
print("Loading Secure Identity Signatures from folder...")
known_face_encodings = []
known_face_names = []

AUTH_FACES_DIR = os.path.join(BASE_DIR, "authorized_faces")
os.makedirs(AUTH_FACES_DIR, exist_ok=True)

# Scan the folder for all authorized personnel images
admin_images_found = False
for filename in os.listdir(AUTH_FACES_DIR):
    if filename.lower().endswith(('.jpg', '.jpeg', '.png')):
        admin_images_found = True
        img_path = os.path.join(AUTH_FACES_DIR, filename)
        
        # Clean up filename for display (e.g., "thiru.jpg" -> "THIRU")
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

# Load Raw YOLO Model (Replaces ObjectCounter)
model = YOLO("yolov8n.pt") 
# Initialize Software-Defined ANPR (English)
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

    # LAG FIX: Resize frame to reduce AI calculation payload
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

    # 1. RAW YOLO TRACKING & 2D POLYGON BREACH LOGIC
    results = model(frame, device="mps", verbose=False) # Force Apple Silicon Metal Acceleration
    zone_color = (255, 0, 0) # Default Blue Secure Zone
    breach_detected = False
    
    # Initialize default threat for the current frame
    current_threat = "VIRTUAL_FENCE_BREACH"

    for result in results:
        boxes = result.boxes
        for box in boxes:
            x1, y1, x2, y2 = box.xyxy[0].int().tolist()
            
            # Extract AI Classification & Confidence
            cls_id = int(box.cls[0])
            conf = float(box.conf[0])
            class_name = model.names[cls_id].upper()
            
            # Extract feet coordinates
            foot_x = int((x1 + x2) / 2)
            foot_y = int(y2)
            foot_point = Point(foot_x, foot_y)
            
            # Check Polygon Breach
            if secure_polygon.contains(foot_point):
                zone_color = (0, 0, 255) # Red Breach
                breach_detected = Test_Trigger = True   
                
                # SOFTWARE-DEFINED ANPR: Read plates only during an active breach
                # SOFTWARE-DEFINED ANPR: Read plates only during an active breach
                if class_name in ['CAR', 'TRUCK', 'BUS', 'PERSON']:
                    # 1. Ensure coordinates are valid and within frame boundaries
                    h_frame, w_frame, _ = frame.shape
                    x1_safe = max(0, x1)
                    y1_safe = max(0, y1)
                    x2_safe = min(w_frame, x2)
                    y2_safe = min(h_frame, y2)
                    
                    # 2. Crop just the vehicle/object safely
                    vehicle_crop = frame[y1_safe:y2_safe, x1_safe:x2_safe]
                    
                    # 3. Proceed only if the crop is not empty
                    if vehicle_crop.size > 0:
                        extracted_text = ocr_reader.readtext(vehicle_crop, detail=0)
                        
                        current_event_time = datetime.now().strftime("%Y%m%d_%H%M%S")
                        
                        if extracted_text:
                            plate_number = " ".join(extracted_text)
                            current_threat = f"{class_name} BREACH (PLATE: {plate_number})"
                            
                            cv2.putText(annotated_frame, f"PLATE: {plate_number}", (x1, y1 - 30), 
                                        cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 255), 2)
                            
                            print(f"🚗 [EVENT ID: EVT-{current_event_time}] TARGET IDENTIFIED | Type: {class_name} | Number Plate: {plate_number} | Confidence: {conf:.2f}")
                        else:
                            print(f"⚠️ [EVENT ID: EVT-{current_event_time}] ZONE BREACH | Type: {class_name} | Number Plate: [UNREADABLE / NONE]")

            
            # Draw targeting UI with Class Labels
            cv2.rectangle(annotated_frame, (x1, y1), (x2, y2), (0, 255, 255), 2)
            
            # Print the class name (e.g., PERSON, CAR) above the box
            label_text = f"{class_name} {conf:.2f}"
            cv2.putText(annotated_frame, label_text, (x1, y1 - 10), 
                        cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 255), 2)
                        
            cv2.circle(annotated_frame, (foot_x, foot_y), 6, zone_color, -1)
            
    # Draw the Secure Zone
    cv2.polylines(annotated_frame, [secure_zone_pts], isClosed=True, color=zone_color, thickness=3)

    # 2. BIOMETRIC FACE RECOGNITION (Alternating Frames)
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
                
    # Permanent Corner Timestamp
    live_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cv2.putText(annotated_frame, live_timestamp, (420, 460), 
                cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 2)

    cv2.imshow("IBVAP Enterprise Suite", annotated_frame)

    # 5. INTRUSION DATABASE LOGGING (Cooldown Enabled)
    if breach_detected:
        if (curr_time - last_alert_time) > 5.0:
            file_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            image_name = f"intrusion_{file_timestamp}.jpg"
            image_path = os.path.join(ALERTS_DIR, image_name)
            
            cv2.imwrite(image_path, annotated_frame)
            img_hash = generate_image_hash(image_path)
            current_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # This saves the full event description (including ANPR and vehicle type) into your existing event_type column
            cursor.execute('''
                INSERT INTO intrusions (timestamp, event_type, total_crossings, image_path, image_hash)
                VALUES (?, ?, ?, ?, ?)
            ''', (current_time_str, current_threat, 1, image_path, img_hash))
            conn.commit()

            # 🌐 TRANSMIT TO FASTAPI
            payload = {
                "edge_node_id": "border_cam_01",
                "timestamp": current_time_str,
                "event_type": current_threat,
                "total_crossings": 1, 
                "image_hash": img_hash,
                "jwt_token": JWT_AUTH_TOKEN
            }
            try:
                requests.post(HQ_API_URL, json=payload, timeout=2)
                print("✅ [NETWORK] Alert successfully transmitted to HQ Database")
            except requests.exceptions.RequestException:
                pass 

            last_alert_time = curr_time
            try:
                requests.post(HQ_API_URL, json=payload, timeout=2)
                print("✅ [NETWORK] Alert successfully transmitted to HQ Database")
            except requests.exceptions.RequestException:
                pass # Silently fail if HQ server is not running during local testing

            print("\n" + "="*50)
            print(f"🚨 TACTICAL ALERT: Intrusion at {current_time_str}")
            print(f"🚨 THREAT IDENTIFIED: {current_threat}")
            print(f"📸 Encrypted Image: {image_name}")
            print(f"🔒 SHA-256 Ledger Hash: {img_hash}")
            print("="*50 + "\n")
            
            last_alert_time = curr_time 

cap.release()
cv2.destroyAllWindows()
conn.close()