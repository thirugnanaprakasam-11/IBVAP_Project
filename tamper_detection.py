"""
tamper_detection.py — Camera Tamper Detection Engine

WHY A SEPARATE MODULE
This has nothing to do with YOLO tracking or the intrusion/threat logic, so
it's kept isolated: main.py imports one class and calls one method per
frame. If this module has a bug, it can't break tracking/alerts, and it
can be unit-tested on its own (see the __main__ block at the bottom).

WHAT IT DETECTS (three independent, cheap-to-compute signals)
1. FROZEN FEED   — if consecutive frames are nearly identical for too many
                     frames in a row, the "camera" is probably a static
                     image (spoofed feed) or the capture has hung.
2. OBSTRUCTION    — if the frame has almost no contrast (very low standard
                     deviation of pixel intensity), something is very
                     likely covering the lens (hand, tape, spray).
3. BLACKOUT/FLASH — a sudden, large jump in average brightness between
                     consecutive frames (lens covered suddenly, or a light
                     shone directly at the camera to blind it).

All three run on the grayscale frame only — cheap enough to check every
single frame without hurting FPS.
"""
import cv2
import numpy as np
from collections import deque


class TamperDetector:
    def __init__(
        self,
        freeze_window=15,          # frames considered for the freeze check
        freeze_diff_threshold=1.5,  # avg pixel diff below this = "identical"
        freeze_min_frozen=12,       # how many of the last N frames must be frozen
        obstruction_std_threshold=8.0,   # contrast below this = obstruction
        blackout_delta_threshold=45.0,   # brightness jump above this = blackout/flash
    ):
        self.freeze_window = freeze_window
        self.freeze_diff_threshold = freeze_diff_threshold
        self.freeze_min_frozen = freeze_min_frozen
        self.obstruction_std_threshold = obstruction_std_threshold
        self.blackout_delta_threshold = blackout_delta_threshold

        self._prev_gray = None
        self._prev_brightness = None
        self._recent_diffs = deque(maxlen=freeze_window)

    def check(self, frame):
        """
        Call once per frame. Returns (is_tampered: bool, reason: str or None).
        """
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        brightness = float(np.mean(gray))
        contrast = float(np.std(gray))

        reason = None

        # --- 1. Obstruction: near-zero contrast ---
        if contrast < self.obstruction_std_threshold:
            reason = "LENS OBSTRUCTION (near-zero contrast — object covering camera)"

        # --- 2. Blackout / flash: sudden brightness jump ---
        elif self._prev_brightness is not None and abs(brightness - self._prev_brightness) > self.blackout_delta_threshold:
            reason = "SUDDEN BLACKOUT/FLASH (abrupt brightness change)"

        # --- 3. Frozen feed: near-identical consecutive frames ---
        if self._prev_gray is not None:
            diff = float(np.mean(cv2.absdiff(gray, self._prev_gray)))
            self._recent_diffs.append(diff)
            frozen_count = sum(1 for d in self._recent_diffs if d < self.freeze_diff_threshold)
            if reason is None and len(self._recent_diffs) == self.freeze_window and frozen_count >= self.freeze_min_frozen:
                reason = "FROZEN FEED (no meaningful change across recent frames)"

        self._prev_gray = gray
        self._prev_brightness = brightness

        return (reason is not None), reason


def draw_tamper_warning(frame, reason, w, h):
    """Overlay a hard-to-miss warning banner when tamper is detected."""
    cv2.rectangle(frame, (0, 0), (w, 50), (0, 0, 200), -1)
    cv2.putText(frame, f"!! CAMERA TAMPER: {reason} !!", (15, 33),
                cv2.FONT_HERSHEY_SIMPLEX, 0.65, (255, 255, 255), 2)


if __name__ == "__main__":
    # Quick standalone sanity check using your webcam, independent of main.py.
    # Cover the lens with your hand while this runs to see it trigger.
    detector = TamperDetector()
    cap = cv2.VideoCapture(0)
    print("Tamper-detection self-test running — press 'q' to quit, cover the lens to test.")
    while True:
        ok, frame = cap.read()
        if not ok:
            break
        tampered, reason = detector.check(frame)
        if tampered:
            draw_tamper_warning(frame, reason, frame.shape[1], frame.shape[0])
            print("TAMPER:", reason)
        cv2.imshow("Tamper Detection Self-Test", frame)
        if cv2.waitKey(1) & 0xFF == ord('q'):
            break
    cap.release()
    cv2.destroyAllWindows()