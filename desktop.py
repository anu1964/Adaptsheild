import os
import sys
import time
import socket
import threading
from pathlib import Path

# Folder of the .exe when frozen, or of this file when run normally
APP_DIR = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent

# Read the Hugging Face token from hf_token.txt next to the app if the env var is not set
token_file = APP_DIR / "hf_token.txt"
if not os.environ.get("HF_TOKEN") and token_file.exists():
    os.environ["HF_TOKEN"] = token_file.read_text(encoding="utf-8").strip()

import uvicorn
import webview
from server import app, APP_PORT


def run_server():
    # log_config=None stops uvicorn crashing when the .exe has no console
    uvicorn.run(app, host="127.0.0.1", port=APP_PORT, log_config=None)


def wait_for_server(timeout=180):
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection(("127.0.0.1", APP_PORT), timeout=1):
                return True
        except OSError:
            time.sleep(0.5)
    return False


if __name__ == "__main__":
    threading.Thread(target=run_server, daemon=True).start()
    if not wait_for_server():
        print("Server did not start.")
        sys.exit(1)
    webview.create_window("AdaptShield", f"http://127.0.0.1:{APP_PORT}", width=1280, height=800)
    webview.start()