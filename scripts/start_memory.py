"""Offline local debugger. Never label it the live AGNTCY judging mode."""
import os
from pathlib import Path
import subprocess
import sys
import time

os.chdir(Path(__file__).resolve().parents[1])
fixture = subprocess.Popen([sys.executable, "-m", "uvicorn", "lab_target.app:app", "--host", "127.0.0.1", "--port", "8001"])
try:
    time.sleep(1)
    subprocess.run([sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000"], env={**os.environ, "AGNTCY_TRANSPORT": "memory"}, check=True)
finally:
    fixture.terminate()
    fixture.wait()

