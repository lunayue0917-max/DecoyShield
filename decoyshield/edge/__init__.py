"""
Edge-platform deployment templates — drop DecoyShield in front of any
upstream without installing Python.

Each platform module exports ``render() -> str`` which returns a
ready-to-paste config (or Worker script). Call programmatically:

    from decoyshield.edge import nginx, caddy, cloudflare
    open("/etc/nginx/conf.d/decoyshield.conf", "w").write(nginx.render())

Or via the CLI:

    decoyshield edge nginx > /etc/nginx/conf.d/decoyshield.conf
    decoyshield edge caddy > /etc/caddy/decoyshield.caddyfile
    decoyshield edge cloudflare > worker.js
"""
from . import caddy, cloudflare, nginx

SUPPORTED = ("nginx", "caddy", "cloudflare")

__all__ = ["SUPPORTED", "nginx", "caddy", "cloudflare"]
