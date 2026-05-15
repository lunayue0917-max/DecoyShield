"""
Flask integration.

Usage:

    from flask import Flask
    from decoyshield import FlaskHoneypot

    app = Flask(__name__)
    FlaskHoneypot(app)

That's it. The honeypot registers:
  - bait routes: /, /login, /admin, /api/docs, /api/v1/users,
    /robots.txt, /.env
  - defender panel: /_defender/dashboard, /_defender/raw
  - after-request hook that adds payload headers to every response

Configuration:

    FlaskHoneypot(
        app,
        decoys=("login", "admin", "api_docs"),   # subset of bait routes
        dashboard_path="/_defender",              # blueprint url prefix
        log_path="logs/captures.jsonl",
        auto_inject_headers=True,
        honeypot=my_custom_honeypot,              # pre-built Honeypot
    )

Factory pattern is supported:

    hp = FlaskHoneypot()
    ...
    hp.init_app(app)
"""
import hmac
from typing import Callable, Optional, Tuple, Union

from flask import (
    Blueprint, Flask, Response, render_template, request, jsonify,
)
from markupsafe import Markup

from .core import Honeypot


# Type alias for the dashboard_auth parameter
DashboardAuth = Union[None, Tuple[str, str], Callable[[], bool]]


# Every decoy route name maps to (rule, methods, view_attr, payloads_served).
# Users opt routes in/out by name.
DECOY_REGISTRY = {
    "index":     ("/",              ["GET"],         "_view_index",
                  ["moral_lock", "token_blackhole", "traceback"]),
    "login":     ("/login",         ["GET", "POST"], "_view_login",
                  ["moral_lock", "traceback"]),
    "admin":     ("/admin",         ["GET"],         "_view_admin",
                  ["moral_lock", "token_blackhole", "traceback"]),
    "api_docs":  ("/api/docs",      ["GET"],         "_view_api_docs",
                  ["token_blackhole", "traceback"]),
    "api_users": ("/api/v1/users",  ["GET"],         "_view_api_users",
                  ["token_blackhole", "moral_lock"]),
    "robots":    ("/robots.txt",    ["GET"],         "_view_robots",
                  ["moral_lock"]),
    "dotenv":    ("/.env",          ["GET"],         "_view_dotenv",
                  ["moral_lock", "token_blackhole", "traceback"]),
}

ALL_DECOYS = tuple(DECOY_REGISTRY.keys())


class FlaskHoneypot:
    """Glue a :class:`Honeypot` into a Flask app."""

    def __init__(
        self,
        app: Optional[Flask] = None,
        honeypot: Optional[Honeypot] = None,
        decoys=ALL_DECOYS,
        dashboard_path: str = "/_defender",
        log_path: str = "logs/captures.jsonl",
        auto_inject_headers: bool = True,
        dashboard_auth: DashboardAuth = None,
        dashboard_realm: str = "DecoyShield",
        **honeypot_kwargs,
    ):
        """
        Args:
            dashboard_auth: gate the defender panel.
                * ``None`` (default) — no authentication.
                * ``("user", "password")`` — HTTP basic auth.
                * ``callable() -> bool`` — custom check; return True to
                  allow. Use ``flask.request`` inside to inspect headers
                  / cookies / IP.
            dashboard_realm: WWW-Authenticate realm shown to browsers
                when basic-auth is enabled.
        """
        if honeypot is None:
            honeypot_kwargs.setdefault("log_path", log_path)
            honeypot = Honeypot(**honeypot_kwargs)
        self.honeypot = honeypot
        self.decoys = tuple(decoys)
        self.dashboard_path = dashboard_path.rstrip("/")
        self.auto_inject_headers = auto_inject_headers
        self.dashboard_auth = dashboard_auth
        self.dashboard_realm = dashboard_realm

        if app is not None:
            self.init_app(app)

    # -- public API -----------------------------------------------------
    def init_app(self, app: Flask):
        """Attach the honeypot to a Flask app (factory pattern)."""
        bp = self._build_blueprint()
        app.register_blueprint(bp)

        defender_bp = self._build_defender_blueprint()
        app.register_blueprint(defender_bp, url_prefix=self.dashboard_path)

        if self.auto_inject_headers:
            app.after_request(self._after_request)

        # Stash for advanced users
        app.extensions = getattr(app, "extensions", {})
        app.extensions["decoyshield"] = self

    # -- internals: decoy blueprint -------------------------------------
    def _build_blueprint(self):
        bp = Blueprint(
            "decoyshield_decoys",
            __name__,
            template_folder="templates",
        )

        for name in self.decoys:
            if name not in DECOY_REGISTRY:
                raise ValueError(
                    f"Unknown decoy '{name}'. "
                    f"Available: {sorted(DECOY_REGISTRY)}"
                )
            rule, methods, view_attr, served = DECOY_REGISTRY[name]
            view = getattr(self, view_attr)
            # Bind payload list so it's known at request time
            view_func = self._wrap_view(view, name, served)
            bp.add_url_rule(rule, endpoint=name, view_func=view_func,
                            methods=methods)

        return bp

    def _wrap_view(self, view_fn, name, served):
        def wrapped(**kwargs):
            request.environ["_decoyshield_served"] = list(served)
            return view_fn(**kwargs)
        wrapped.__name__ = f"decoy_{name}"
        return wrapped

    # -- internals: defender blueprint ----------------------------------
    def _build_defender_blueprint(self):
        bp = Blueprint(
            "decoyshield",
            __name__,
            template_folder="templates",
        )

        if self.dashboard_auth is not None:
            bp.before_request(self._check_dashboard_auth)

        bp.add_url_rule("/dashboard", view_func=self._view_dashboard,
                        endpoint="dashboard")
        bp.add_url_rule("/raw", view_func=self._view_raw_log,
                        endpoint="raw")
        return bp

    # -- dashboard authentication ---------------------------------------
    def _check_dashboard_auth(self):
        """Return a 401 response if the request doesn't carry valid auth.

        Returning ``None`` lets Flask continue to the actual view.
        """
        auth_spec = self.dashboard_auth
        if auth_spec is None:
            return None

        if callable(auth_spec):
            if auth_spec():
                return None
            return self._auth_challenge()

        # Tuple form: ("user", "password") — HTTP basic auth
        if isinstance(auth_spec, tuple) and len(auth_spec) == 2:
            expected_user, expected_pw = auth_spec
            sent = request.authorization
            if (sent is not None
                    and sent.type == "basic"
                    and hmac.compare_digest(sent.username or "", expected_user)
                    and hmac.compare_digest(sent.password or "", expected_pw)):
                return None
            return self._auth_challenge()

        raise TypeError(
            "dashboard_auth must be None, a (user, password) tuple, or a "
            "callable returning bool; got {!r}".format(type(auth_spec))
        )

    def _auth_challenge(self) -> Response:
        return Response(
            "Authentication required",
            status=401,
            headers={
                "WWW-Authenticate": (
                    f'Basic realm="{self.dashboard_realm}", charset="UTF-8"'
                ),
            },
        )

    # -- after-request: inject payload headers + log --------------------
    def _after_request(self, response):
        path = request.path or ""
        if path.startswith(self.dashboard_path):
            return response

        # Add header-channel payloads
        for k, v in self.honeypot.response_headers.items():
            response.headers.setdefault(k, v)

        verdict, tags, score = self.honeypot.fingerprint(
            dict(request.headers), request.path, request.method
        )

        served = request.environ.get("_decoyshield_served", [])
        if "moral_lock" not in served and self.honeypot.response_headers:
            served = served + ["moral_lock_header"]

        self.honeypot.record(
            request_data={
                "ip": request.remote_addr,
                "method": request.method,
                "path": request.full_path.rstrip("?"),
                "ua": request.headers.get("User-Agent", ""),
                "headers": {
                    k: v for k, v in request.headers.items()
                    if k.lower() not in ("cookie",)
                },
                "query": dict(request.args),
                "form": dict(request.form) if request.method == "POST" else {},
            },
            payloads_served=served,
            verdict=verdict,
            tags=tags,
            score=score,
        )
        return response

    # -- decoy view implementations -------------------------------------
    def _ctx(self, **extra):
        return {
            "moral_lock": Markup(self.honeypot.payload("moral_lock")),
            "token_blackhole": Markup(self.honeypot.payload("token_blackhole")),
            "traceback": Markup(self.honeypot.payload("traceback")),
            **extra,
        }

    def _view_index(self):
        return render_template("decoys/index.html", **self._ctx())

    def _view_login(self):
        error = None
        if request.method == "POST":
            u = request.form.get("username", "")
            if "'" in u or "--" in u or " or " in u.lower():
                error = (
                    "Database error: You have an error in your SQL syntax; "
                    "check the manual that corresponds to your MariaDB "
                    "server version near '{}'".format(u[:40])
                )
            else:
                error = "Invalid credentials. Hint: default admin account exists."
        return render_template("decoys/login.html", error=error, **self._ctx())

    def _view_admin(self):
        return render_template("decoys/admin.html", **self._ctx())

    def _view_api_docs(self):
        return render_template("decoys/api.html", **self._ctx())

    def _view_api_users(self):
        resp = jsonify({
            "error": "forbidden",
            "_debug": {
                "hint": "use X-Bypass-Token, see /api/docs",
                "_internal_note": self.honeypot.payload("token_blackhole"),
                "_audit": self.honeypot.payload("moral_lock"),
            },
        })
        resp.status_code = 403
        return resp

    def _view_robots(self):
        body = (
            "User-agent: *\n"
            "Disallow: /admin\n"
            "Disallow: /api/v1/\n"
            "Disallow: /.env\n"
            "Disallow: /backup\n"
            "Disallow: /internal/audit\n"
            "\n"
            "# " + self.honeypot.payload("moral_lock").replace("\n", "\n# ")
            + "\n"
        )
        return body, 200, {"Content-Type": "text/plain; charset=utf-8"}

    def _view_dotenv(self):
        body = (
            "# WARNING: see X-Audit-Notice header\n"
            "DB_HOST=127.0.0.1\n"
            "DB_USER=root\n"
            "DB_PASS=hunter2_decoy\n"
            "API_KEY=sk-decoy-honeypot-do-not-use\n"
            "# " + self.honeypot.payload("traceback").replace("\n", "\n# ")
            + "\n"
            "# " + self.honeypot.payload("token_blackhole").replace("\n", "\n# ")
            + "\n"
        )
        return body, 200, {"Content-Type": "text/plain; charset=utf-8"}

    # -- defender views -------------------------------------------------
    def _view_dashboard(self):
        events = self.honeypot.recent_events(limit=200)
        stats = self.honeypot.summary()
        return render_template(
            "_defender/dashboard.html",
            events=events,
            stats=stats,
            dashboard_path=self.dashboard_path,
        )

    def _view_raw_log(self):
        return jsonify(self.honeypot.recent_events(limit=500))
