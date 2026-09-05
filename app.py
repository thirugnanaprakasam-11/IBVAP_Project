import webview
import threading
import uvicorn
import time
import os
from server import app
from audit_ledger import AuditLedger

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def start_api_server():
    """Runs the FastAPI backend silently in a background thread."""
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="error")

if __name__ == '__main__':
    # 1. Cryptographically log Command Centre login
    try:
        audit = AuditLedger(BASE_DIR)
        audit.record_event("Officer_On_Duty", "COMMAND_CENTRE_APP_LAUNCH", "Desktop interface opened locally")
    except Exception:
        pass

    # 2. Boot FastAPI backend on background thread
    server_thread = threading.Thread(target=start_api_server, daemon=True)
    server_thread.start()
    time.sleep(1)

    # 3. Launch the native desktop window
    window = webview.create_window(
        title='IBVAP Tactical Command Center', 
        url='http://127.0.0.1:8000',
        width=1366, 
        height=768,
        background_color='#04070a',
        min_size=(1024, 600),
        frameless=False
    )
    
    webview.start(private_mode=False)

    # 4. Log session shutdown upon window close
    try:
        audit.record_event("Officer_On_Duty", "COMMAND_CENTRE_APP_CLOSE", "Desktop interface terminated by operator")
    except Exception:
        pass