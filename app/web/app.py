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


if __name__ == "__main__":
    # Prevent duplicate auto-open in reloader contexts.
    if os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        threading.Timer(1.0, lambda: webbrowser.open("http://127.0.0.1:5000")).start()
    web_app = create_app()
    web_app.run(host="127.0.0.1", port=5000, debug=False)

