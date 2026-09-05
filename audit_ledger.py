import os
import hashlib
from datetime import datetime

class AuditLedger:
    def __init__(self, base_dir, ledger_filename="command_audit_ledger.txt"):
        self.log_dir = os.path.join(base_dir, "alert_texts")
        os.makedirs(self.log_dir, exist_ok=True)
        self.ledger_path = os.path.join(self.log_dir, ledger_filename)
        self.last_hash = self._get_tail_hash()

    def _get_tail_hash(self):
        if not os.path.exists(self.ledger_path):
            return "GENESIS_AUDIT_BLOCK"
        last_line = ""
        with open(self.ledger_path, "r") as f:
            for line in f:
                if line.strip():
                    last_line = line.strip()
        if "CHAIN_HASH:" in last_line:
            return last_line.split("CHAIN_HASH:")[-1].strip()
        return "GENESIS_AUDIT_BLOCK"

    def record_event(self, actor, action, details=""):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry_data = f"{timestamp} | OPERATOR:{actor} | ACTION:{action} | DETAILS:{details}"
        
        # Cryptographic chain link
        new_chain_hash = hashlib.sha256(f"{entry_data}{self.last_hash}".encode()).hexdigest()
        log_line = f"{entry_data} | PREV_HASH:{self.last_hash[:12]} | CHAIN_HASH:{new_chain_hash}\n"
        
        with open(self.ledger_path, "a") as f:
            f.write(log_line)
            
        self.last_hash = new_chain_hash
        print(f"[AUDIT LOG] 📝 {action} by {actor}")

    def verify_ledger(self):
        if not os.path.exists(self.ledger_path):
            print("[AUDIT LEDGER] No audit log file exists yet.")
            return True

        expected_prev = "GENESIS_AUDIT_BLOCK"
        line_num = 0
        with open(self.ledger_path, "r") as f:
            for line in f:
                line_num += 1
                parts = line.strip().split(" | ")
                if len(parts) < 5:
                    continue
                entry_data = f"{parts[0]} | {parts[1]} | {parts[2]} | {parts[3]}"
                prev_stored = parts[3].split("PREV_HASH:")[-1].strip()
                curr_hash = parts[4].split("CHAIN_HASH:")[-1].strip()

                recomputed = hashlib.sha256(f"{entry_data}{expected_prev}".encode()).hexdigest()
                if recomputed != curr_hash:
                    print(f"❌ TAMPER DETECTED in Audit Ledger at line {line_num}!")
                    return False
                expected_prev = curr_hash

        print(f"✅ AUDIT LEDGER INTACT — Verified {line_num} system entries.")
        return True