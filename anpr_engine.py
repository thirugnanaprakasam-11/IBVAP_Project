import cv2
import numpy as np
import easyocr
import re
from ultralytics import YOLO
import os
import time

class TextExtractionEngine:
    def __init__(self, plate_model_path="license_plate_detector.pt"):
        print("[+] INITIALIZING DIAGNOSTIC TEXT ENGINE (DEBUG MODE ON)...")
        
        # Create a folder to see what the AI is actually looking at
        self.debug_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "debug_crops")
        os.makedirs(self.debug_dir, exist_ok=True)
        
        try:
            self.plate_model = YOLO(plate_model_path)
            self.plate_model.to("cpu") 
        except Exception as e:
            print(f"[!] WARNING: {plate_model_path} not found. Using geometric fallback.")
            self.plate_model = None
            
        # Initialize EasyOCR
        self.reader = easyocr.Reader(['en'], gpu=False)

    def _save_debug_crop(self, img, prefix):
        """Saves the image to disk so you can verify if it's actually readable by a human"""
        if img is not None and img.size > 0:
            timestamp = int(time.time() * 1000)
            filepath = os.path.join(self.debug_dir, f"{prefix}_{timestamp}.jpg")
            cv2.imwrite(filepath, img)

    def preprocess_image(self, crop, is_plate=True):
        """Stripped down preprocessing - let EasyOCR do the heavy lifting"""
        gray = cv2.cvtColor(crop, cv2.COLOR_BGR2GRAY)
        
        if is_plate:
            # Just upscale for plates, no aggressive thresholding
            return cv2.resize(gray, None, fx=2.5, fy=2.5, interpolation=cv2.INTER_CUBIC)
        else:
            # Just upscale for general text
            return cv2.resize(gray, None, fx=1.5, fy=1.5, interpolation=cv2.INTER_LINEAR)

    def read_plate(self, vehicle_crop):
        if vehicle_crop is None or vehicle_crop.size == 0: return None
        plate_crop = None
        
        # 1. YOLO Plate Extraction (Lowered confidence threshold to force detections)
        if self.plate_model is not None:
            results = self.plate_model(vehicle_crop, device="cpu", conf=0.1, verbose=False)
            for r in results:
                if len(r.boxes) > 0:
                    x1, y1, x2, y2 = r.boxes[0].xyxy[0].int().tolist()
                    plate_crop = vehicle_crop[y1:y2, x1:x2]
                    break
        
        # 2. FAILSAFE: Bottom 40% crop
        if plate_crop is None or plate_crop.size == 0:
            h, w = vehicle_crop.shape[:2]
            plate_crop = vehicle_crop[int(h * 0.6):h, :]
            
        if plate_crop is None or plate_crop.size == 0: return None
        
        clean_plate = self.preprocess_image(plate_crop, is_plate=True)
        self._save_debug_crop(clean_plate, "plate_debug") # <--- SAVES IMAGE TO FOLDER
        
        # Lowered OCR score threshold to catch weak readings
        detections = self.reader.readtext(clean_plate, allowlist='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ')
        
        for bbox, text, score in detections:
            clean_text = re.sub(r'[^A-Z0-9]', '', text.upper())
            if len(clean_text) >= 3:  # Lowered from 4 to 3
                return clean_text
        return None

    def read_general_text(self, vehicle_crop):
        if vehicle_crop is None or vehicle_crop.size == 0: return None
        
        clean_img = self.preprocess_image(vehicle_crop, is_plate=False)
        self._save_debug_crop(clean_img, "general_text_debug") # <--- SAVES IMAGE TO FOLDER
        
        detections = self.reader.readtext(clean_img)
        
        found_texts = []
        for bbox, text, score in detections:
            if score > 0.15 and len(text) > 2: # Lowered thresholds
                found_texts.append(text.upper())
                
        return " | ".join(found_texts) if found_texts else None