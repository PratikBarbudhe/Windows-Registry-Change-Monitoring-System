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


def create_app() -> Flask:
    """Create and configure Flask application."""
    from app.web.routes import register_routes

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
        host = os.environ.get("HOST", "127.0.0.1")
        port = int(os.environ.get("PORT", "5000"))
        # Render and similar PaaS environments require binding to all interfaces.
        if "RENDER" in os.environ:
            host = "0.0.0.0"

        # Prevent duplicate auto-open in reloader contexts.
        if (
            os.environ.get("WERKZEUG_RUN_MAIN") != "true"
            and host == "127.0.0.1"
            and port == 5000
        ):
            threading.Timer(1.0, lambda: webbrowser.open("http://127.0.0.1:5000")).start()
        web_app = create_app()
        web_app.run(host=host, port=port, debug=False)

