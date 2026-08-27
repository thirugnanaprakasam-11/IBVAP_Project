import cv2
import sqlite3
import time
import hashlib
import os
import requests  # <--- Add this!
import json      # <--- Add this!
from datetime import datetime
from ultralytics import solutions
import face_recognition

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

# 🛡️ FAILSAFE: Prevent Apple Silicon from crashing the script
try:
    if hasattr(cv2, 'data'):
        face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
    else:
        face_cascade = cv2.CascadeClassifier('haarcascade_frontalface_default.xml')
except AttributeError:
    print("⚠️ OpenCV Face Detection missing in this environment.")
    print("⚠️ Running in YOLO-Only Failsafe Mode to ensure stability.")
    face_cascade = None

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
# 3.5 ZERO-TRUST IDENTITY ENCODING
# ==========================================
print("Loading Secure Identity Signatures...")
try:
    admin_image = face_recognition.load_image_file(os.path.join(BASE_DIR, "thiru.jpg"))
    thiru_encoding = face_recognition.face_encodings(admin_image)[0]
    known_face_encodings = [thiru_encoding]
    known_face_names = ["Thiru - Authorized Admin"]
except FileNotFoundError:
    print("⚠️ thiru.jpg not found. System will flag all faces as INTRUDERS.")
    known_face_encodings = []
    known_face_names = []

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
# 5. VIDEO, AI SETUP & "DEMO GOD" FALLBACK
# ==========================================
LIVE_CAM_ID = 0
FALLBACK_VIDEO_PATH = os.path.join(BASE_DIR, "test_footage.mp4")

cap = cv2.VideoCapture(LIVE_CAM_ID)
using_fallback = False

w, h = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH)), int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
line_points = [(0, int(h/2)), (w, int(h/2))] 

# EXPANDED AI CLASSES: 
tracking_classes = [0, 2, 3, 5, 7, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23]

counter = solutions.ObjectCounter(
    model="yolov8n.pt", 
    show=False,           
    region=line_points,
    classes=tracking_classes        
)

print("IBVAP Enterprise Suite Active.")
print("HOTKEYS: 'n'=Night Vision | 'f'=Fallback Video | 'c'=Live Cam | 'q'=Quit")

previous_total = 0
prev_time = time.time()
last_alert_time=0
night_vision_active = False
human_in_frame_time = 0 

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

    curr_time = time.time()
    fps = 1 / (curr_time - prev_time) if (curr_time - prev_time) > 0 else 0
    prev_time = curr_time

    key = cv2.waitKey(1) & 0xFF
    if key == ord('q'):
        break
    elif key == ord('n'):
        night_vision_active = not night_vision_active
    elif key == ord('f') and not using_fallback:
        print("Switching to Simulated Drone/CCTV Footage...")
        cap = cv2.VideoCapture(FALLBACK_VIDEO_PATH)
        using_fallback = True
    elif key == ord('c') and using_fallback:
        print("Returning to Live Edge Camera...")
        cap = cv2.VideoCapture(LIVE_CAM_ID)
        using_fallback = False

    if night_vision_active:
        frame = apply_night_vision(frame)

    # 1. AI Tracking
    results = counter.process(frame)
    annotated_frame = results.plot_im 

    # 2. BIOMETRIC FACE RECOGNITION
        # Convert BGR (OpenCV format) to RGB (face_recognition format)
    rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        
    # Find faces and encode them
    face_locations = face_recognition.face_locations(rgb_frame, model="hog")
    face_encodings = face_recognition.face_encodings(rgb_frame, face_locations)

    for (top, right, bottom, left), face_encoding in zip(face_locations, face_encodings):
        matches = face_recognition.compare_faces(known_face_encodings, face_encoding, tolerance=0.5)
        name = "UNKNOWN INTRUDER"
        box_color = (0, 0, 255) # Red for intruders

        if True in matches:
            first_match_index = matches.index(True)
            name = known_face_names[first_match_index]
            box_color = (0, 255, 0) # Green for authorized admins

        # Draw the biometric targeting box
        cv2.rectangle(annotated_frame, (left, top), (right, bottom), box_color, 2)
        cv2.putText(annotated_frame, name, (left, top - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.6, box_color, 2)

    # 3. Tactical HUD
    cv2.rectangle(annotated_frame, (10, 10), (w-10, h-10), (0, 255, 0), 2)
    mode_text = "NIGHT VISION ACTIVE" if night_vision_active else "DAY MODE"
    feed_text = "FALLBACK FEED" if using_fallback else "LIVE EDGE FEED"
    
    cv2.putText(annotated_frame, f"IBVAP - FPS: {int(fps)} | {mode_text} | {feed_text}", (20, 40), 
                cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 2)
    cv2.imshow("IBVAP Enterprise Suite", annotated_frame)

    # 4. Loitering Detection
    if len(face_locations) > 0:
        human_in_frame_time += 1
        if human_in_frame_time > 20: 
            cv2.putText(annotated_frame, "⚠️ SUSPICIOUS ACTIVITY: LOITERING", (20, 100), 
                        cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 255), 2)
    else:
        human_in_frame_time = 0

    # 5. INTRUSION LOGIC
        current_total = results.in_count + results.out_count 
        if current_total > previous_total:
            
            # COOLDOWN LOCK: Only process if 5 seconds have passed since the last alert
            if (curr_time - last_alert_time) > 5.0:
                file_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                image_name = f"intrusion_{file_timestamp}.jpg"
                image_path = os.path.join(ALERTS_DIR, image_name)
                
                cv2.imwrite(image_path, annotated_frame)
                img_hash = generate_image_hash(image_path)
                current_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                cursor.execute('''
                    INSERT INTO intrusions (timestamp, event_type, total_crossings, image_path, image_hash)
                    VALUES (?, ?, ?, ?, ?)
                ''', (current_time_str, "VIRTUAL_FENCE_BREACH", current_total, image_path, img_hash))
                conn.commit()

                # 🌐 TRANSMIT TO FASTAPI HEADQUARTERS
                payload = {
                    "edge_node_id": "border_cam_01",
                    "timestamp": current_time_str,
                    "event_type": "VIRTUAL_FENCE_BREACH",
                    "total_crossings": current_total,
                    "image_hash": img_hash,
                    "jwt_token": "ibvap_secure_edge_auth_2026"
                }
                
                try:
                    response = requests.post(HQ_API_URL, json=payload, timeout=2)
                    if response.status_code == 200:
                        print("✅ [NETWORK] Alert successfully transmitted to HQ Database")
                except requests.exceptions.RequestException:
                    print("⚠️ [NETWORK] HQ Server offline. Alert saved locally in Edge Database.")

                print("\n" + "="*50)
                print(f"🚨 TACTICAL ALERT: Intrusion at {current_time_str}")
                print(f"📸 Encrypted Image: {image_name}")
                print(f"🔒 SHA-256 Ledger Hash: {img_hash}")
                print("="*50 + "\n")
                
                # Reset the cooldown timer
                last_alert_time = curr_time 
                
            # Always update previous_total so the counter doesn't get permanently stuck
            previous_total = current_total

cap.release()
cv2.destroyAllWindows()
conn.close()