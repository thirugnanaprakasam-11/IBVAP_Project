import webview
import threading
import uvicorn
import time
from server import app  # This imports your existing FastAPI server.py

def start_api_server():
    """Runs the FastAPI backend silently in a background thread."""
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="error")

if __name__ == '__main__':
    # 1. Boot up the HQ server in the background
    server_thread = threading.Thread(target=start_api_server)
    server_thread.daemon = True
    server_thread.start()

    # Give the server 1 second to bind to the port
    time.sleep(1)

    # 2. Launch the Native macOS Desktop Window
    webview.create_window(
        title='IBVAP Tactical Command Center', 
        url='http://127.0.0.1:8000',
        width=1366, 
        height=768,
        background_color='#04070a',  # Matches your dark-mode UI perfectly
        min_size=(1024, 600),
        frameless=False  # Set to True if you want a borderless military look
    )
    
    # Start the native app loop
    webview.start(private_mode=False)