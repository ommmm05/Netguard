"""
NetGuard — Project-wide configuration.

All tunables live here.  Env-var overrides follow the NETGUARD_ prefix.
Import as:  from config import settings
"""

from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)

# --- Paths ------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
MODEL_DIR = DATA_DIR / "models"
DB_PATH = DATA_DIR / "netguard.db"

# Ensure dirs exist on import
for _d in (DATA_DIR, UPLOAD_DIR, MODEL_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# --- Database ---------------------------------------------------------------
DATABASE_URL: str = os.environ.get(
    "NETGUARD_DATABASE_URL",
    f"sqlite:///{DB_PATH}",
)

# --- TShark / Capture Tunables -----------------------------------------------
def find_tshark_executable() -> tuple[str | None, str]:
    """
    Locate tshark.exe on the system dynamically.
    Returns (executable_path_or_none, status_detail).
    """
    env_path = os.environ.get("NETGUARD_TSHARK_PATH") or os.environ.get("TSHARK_PATH")
    if env_path and os.path.isfile(env_path):
        return env_path, f"Environment variable path: {env_path}"

    which_path = shutil.which("tshark") or shutil.which("tshark.exe")
    if which_path and os.path.isfile(which_path):
        return which_path, f"Found in PATH: {which_path}"

    candidates = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        r"C:\Wireshark\tshark.exe",
        r"D:\wireshark\tshark.exe",
        r"D:\Program Files\Wireshark\tshark.exe",
        os.path.expanduser(r"~\AppData\Local\Programs\Wireshark\tshark.exe"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path, f"Found at standard location: {path}"

    return None, (
        "TShark executable not found. Please install Wireshark from https://www.wireshark.org "
        "or set NETGUARD_TSHARK_PATH environment variable."
    )


TSHARK_PATH, TSHARK_STATUS_DETAIL = find_tshark_executable()

# Flow tracker tunables (configurable via env vars)
FLOW_TIMEOUT_SECONDS: float = float(os.environ.get("NETGUARD_FLOW_TIMEOUT", "30.0"))
FLOW_MAX_PACKETS: int = int(os.environ.get("NETGUARD_FLOW_MAX_PACKETS", "10000"))
FLOW_MAX_FLOWS: int = int(os.environ.get("NETGUARD_FLOW_MAX_FLOWS", "100000"))
MAX_PAYLOAD_BYTES: int = int(os.environ.get("NETGUARD_MAX_PAYLOAD_BYTES", "128"))

# --- ML / Detection ---------------------------------------------------------
MIN_DETECTION_CONFIDENCE: float = float(os.environ.get("NETGUARD_MIN_CONF", "0.45"))
CICIDS_FEATURE_DIM: int = 20  # compact subset used by models

# --- LLM / OpenAI -----------------------------------------------------------
OPENAI_API_KEY: str = os.environ.get("NETGUARD_OPENAI_KEY", "")
OPENAI_MODEL: str = os.environ.get("NETGUARD_OPENAI_MODEL", "gpt-4o-mini")

# --- Server -----------------------------------------------------------------
API_HOST: str = os.environ.get("NETGUARD_HOST", "127.0.0.1")
API_PORT: int = int(os.environ.get("NETGUARD_PORT", "8000"))

# --- CORS / Auth ------------------------------------------------------------
_DEFAULT_ORIGINS = "http://localhost:5173,http://127.0.0.1:5173"
ALLOWED_ORIGINS: list[str] = [
    o.strip()
    for o in os.environ.get("NETGUARD_ALLOWED_ORIGINS", _DEFAULT_ORIGINS).split(",")
    if o.strip()
]
API_TOKEN: str = os.environ.get("NETGUARD_API_TOKEN", "").strip()


def warn_if_unauthenticated() -> None:
    if not API_TOKEN:
        logger.warning(
            "NETGUARD_API_TOKEN is unset — /api routes are unauthenticated "
            "(OK for local development). Set NETGUARD_API_TOKEN for deployment."
        )


# --- Convenience bundle -----------------------------------------------------
class _Settings:
    """Dot-access wrapper so modules can do ``settings.MODEL_DIR``."""

    PROJECT_ROOT = PROJECT_ROOT
    DATA_DIR = DATA_DIR
    UPLOAD_DIR = UPLOAD_DIR
    MODEL_DIR = MODEL_DIR
    DB_PATH = DB_PATH
    DATABASE_URL = DATABASE_URL
    TSHARK_PATH = TSHARK_PATH
    TSHARK_STATUS_DETAIL = TSHARK_STATUS_DETAIL
    FLOW_TIMEOUT_SECONDS = FLOW_TIMEOUT_SECONDS
    FLOW_MAX_PACKETS = FLOW_MAX_PACKETS
    FLOW_MAX_FLOWS = FLOW_MAX_FLOWS
    MAX_PAYLOAD_BYTES = MAX_PAYLOAD_BYTES
    MIN_DETECTION_CONFIDENCE = MIN_DETECTION_CONFIDENCE
    CICIDS_FEATURE_DIM = CICIDS_FEATURE_DIM
    OPENAI_API_KEY = OPENAI_API_KEY
    OPENAI_MODEL = OPENAI_MODEL
    API_HOST = API_HOST
    API_PORT = API_PORT
    ALLOWED_ORIGINS = ALLOWED_ORIGINS
    API_TOKEN = API_TOKEN


settings = _Settings()

