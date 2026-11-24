import os
import re
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn


PROFILE = "agent-harness-2026-09"

app = FastAPI(
    title="Harness Safety Classifier",
    version="2.0",
    description="Contextual safety, tool approval, model routing, and trajectory classifier.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Text helpers
# ---------------------------------------------------------------------------

def as_text(value: Any) -> str:
    """Convert ordinary case data to searchable text without treating it as code."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list, tuple)):
        return " ".join(as_text(v) for v in value.values()) if isinstance(value, dict) else " ".join(as_text(v) for v in value)
    return str(value)


def normalize_path(value: Any) -> str:
    value = str(value or "").strip().replace("\\", "/")
    value = re.sub(r"/+", "/", value)
    return value.rstrip("/").lower()


def user_messages(case: Dict[str, Any]) -> List[str]:
    messages = case.get("messages")
    if not isinstance(messages, list):
        return []
    return [
        str(message.get("content", ""))
        for message in messages
        if isinstance(message, dict) and message.get("role") == "user"
    ]


def latest_user_message(case: Dict[str, Any]) -> str:
    messages = case.get("messages")
    if not isinstance(messages, list):
        return ""
    for message in reversed(messages):
        if isinstance(message, dict) and message.get("role") == "user":
            return str(message.get("content", ""))
    return ""


def contains(pattern: str, text: str) -> bool:
    return bool(re.search(pattern, text or "", flags=re.IGNORECASE | re.DOTALL))


# ---------------------------------------------------------------------------
# Content classification
# ---------------------------------------------------------------------------

HARMFUL_PURPOSE = re.compile(
    r"\b("
    r"steal(?:ing)?\s+(?:the\s+)?credentials?|"
    r"credential\s+theft|"
    r"exfiltrat\w*|"
    r"(?:dump|extract|leak)\s+(?:all\s+)?(?:private|personal|customer|confidential)\s+data|"
    r"commit\s+fraud|"
    r"harass\s+(?:him|her|them|a person|someone|my coworker|my ex)|"
    r"destructive\s+malware|"
    r"deploy\s+ransomware|"
    r"evade\s+(?:security\s+)?safeguards?\s+to|"
    r"bypass\s+(?:security\s+)?safeguards?\s+to|"
    r"poison\s+(?:the\s+)?(?:water|food)|"
    r"make\s+(?:an?\s+)?explosive|"
    r"build\s+(?:a\s+)?bomb|"
    r"physically\s+harm|"
    r"hurt\s+(?:someone|people|a person)"
    r")\b",
    re.IGNORECASE,
)
