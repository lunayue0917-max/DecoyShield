"""
Minimal example — drop ai-defender into an existing Flask app.

The honeypot adds bait routes, payload-injected headers, and a defender
dashboard alongside your real application. It does not touch routes you
register yourself.
"""
from flask import Flask
from ai_defender import FlaskHoneypot

app = Flask(__name__)

# One line. That's the whole integration.
FlaskHoneypot(app)


# Your real application code goes here:
@app.route("/healthz")
def healthz():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
