"""
AI-Defender — runnable demo.

This script starts a Flask app with the full honeypot installed. It is
the canonical way to reproduce the screenshots / behaviours described
in the README. For library usage in your own project, see
`examples/flask_demo.py`.

    python app.py
    # http://127.0.0.1:5000/
    # http://127.0.0.1:5000/_defender/dashboard
"""
from flask import Flask

from ai_defender import FlaskHoneypot


def create_app():
    app = Flask(__name__)
    FlaskHoneypot(app, log_path="logs/captures.jsonl")
    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)
