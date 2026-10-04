"""
FastAPI Backend Entrypoint for TrustXCloud.
Exposes the complete TrustXCloud backend application from backend.main.

Usage:
    uvicorn api:app --host 0.0.0.0 --port 8000 --reload
"""

import os
import sys

# Ensure root directory is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.main import app

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
