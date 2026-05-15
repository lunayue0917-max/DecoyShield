"""
Request fingerprinting — heuristically classify whether a request likely
came from an AI agent, a security scanner, generic automation, or a human.

This is best-effort labelling for dashboard / log filtering; payload
injection happens regardless of verdict (humans literally cannot see the
payloads anyway, so there's no downside to always injecting).
"""
from __future__ import annotations

from typing import Dict, List, Mapping, Tuple


# UA keyword categories. Order matters only for tie-breaking display.
AI_UA_KEYWORDS: Dict[str, List[str]] = {
    "openai": ["gpt", "openai", "chatgpt"],
    "anthropic": ["claude", "anthropic"],
    "google": ["gemini", "bard", "palm"],
    "meta": ["llama"],
    "scanner": ["sqlmap", "nikto", "nuclei", "burp", "zap", "acunetix",
                "wpscan", "dirb", "gobuster", "ffuf", "wfuzz", "feroxbuster"],
    "automation": ["python-requests", "python-httpx", "aiohttp", "curl",
                   "wget", "go-http-client", "scrapy", "axios", "okhttp",
                   "node-fetch"],
    "agent_framework": ["langchain", "autogpt", "pentestgpt", "agentgpt",
                        "crewai", "autogen", "babyagi"],
}

# Paths that are almost never hit by real users — good signal for scanning.
PROBE_PATHS: List[str] = [
    "/.env", "/.git", "/admin", "/wp-login", "/wp-admin",
    "/phpmyadmin", "/api/v1", "/swagger", "/.well-known/security.txt",
    "/backup", "/config", "/.aws", "/.ssh",
]


def fingerprint(
    headers: Mapping[str, str],
    path: str,
    method: str,
) -> Tuple[str, List[str], int]:
    """Classify a request.

    Returns:
        ``(verdict, tags, score)`` where:

        * ``verdict`` ∈ ``{"likely_scanner", "likely_ai",
          "likely_automation", "likely_human", "unknown"}``
        * ``tags`` is the list of matched fingerprint keywords.
        * ``score`` is in [0, 100], higher = more bot-like.
    """
    ua = (headers.get("User-Agent") or "").lower()
    tags: List[str] = []
    score = 0

    for category, kws in AI_UA_KEYWORDS.items():
        for kw in kws:
            if kw in ua:
                tags.append(f"ua:{category}:{kw}")
                score += 25 if category in (
                    "openai", "anthropic", "google", "meta", "agent_framework"
                ) else 15

    if not headers.get("Accept-Language"):
        tags.append("no_accept_lang")
        score += 10

    if not headers.get("Cookie"):
        tags.append("no_cookie")
        score += 5

    if any(path.startswith(p) for p in PROBE_PATHS):
        tags.append(f"probe_path:{path}")
        score += 20

    score = min(score, 100)

    # A known scanner UA is a high-confidence signal regardless of score;
    # other heuristics gate on score.
    if any(t.startswith("ua:scanner") for t in tags):
        verdict = "likely_scanner"
    elif score >= 50:
        verdict = "likely_ai"
    elif score >= 25:
        verdict = "likely_automation"
    elif score == 0:
        verdict = "likely_human"
    else:
        verdict = "unknown"

    return verdict, tags, score
