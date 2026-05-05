"""Flask dashboard entrypoint for registry monitoring visualization."""

from __future__ import annotations

import os
import sys
import threading
import webbrowser
from pathlib import Path

from flask import Flask

# Ensure project root takes precedence when launched as a script:
#   python app/web/app.py
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.web.routes import register_routes


def create_app() -> Flask:
    """Create and configure Flask application."""
    app = Flask(__name__)
    register_routes(app)
    return app


def _is_streamlit_runtime() -> bool:
    """Return True when this module is executed by Streamlit."""
    if any(key.startswith("STREAMLIT_") for key in os.environ):
        return True
    return "streamlit.runtime.scriptrunner.script_runner" in sys.modules


if __name__ == "__main__":
    if _is_streamlit_runtime():
        # Streamlit Cloud runs this file as a script; avoid starting a nested Flask server.
        print("Detected Streamlit runtime; skipping Flask dev server startup.")
    else:
        # Prevent duplicate auto-open in reloader contexts.
        if os.environ.get("WERKZEUG_RUN_MAIN") != "true":
            threading.Timer(1.0, lambda: webbrowser.open("http://127.0.0.1:5000")).start()
        web_app = create_app()
        web_app.run(host="127.0.0.1", port=5000, debug=False)

