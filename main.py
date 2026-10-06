"""
Cyber Threat Detector - Server Launcher
Launches the production-grade FastAPI and SOC Dashboard server on http://localhost:8000.
To run Streamlit legacy UI, run: streamlit run app.py
"""

import sys
import os
import uvicorn

if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

    print("=" * 65)
    print(" [*] CYBER THREAT DETECTOR - PRODUCTION SOC DASHBOARD")
    print("     AI-Powered Network Security & Threat Intelligence Platform")
    print("=" * 65)
    print("\n[+] Initializing Hybrid ML & Heuristic Threat Detection Engines...")
    print("[+] Database: SQLite (cyber_threat_detector.db)")
    print("[+] Starting Web Server at: http://localhost:8000")
    print("[+] API Documentation at  : http://localhost:8000/docs")
    print("\nPress Ctrl+C to stop the server.\n")

    uvicorn.run(
        "backend.app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info"
    )