import csv
import hashlib
import hmac
import html
import io
import json
import os
import re
import secrets
import smtplib
import threading
import time
import unicodedata
import uuid
import warnings
from collections import Counter
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Any, Callable, Optional, Tuple, TypeVar
from urllib.parse import quote
from zoneinfo import ZoneInfo

import gspread
import openpyxl
import pandas as pd
import streamlit as st
from google import genai
from google.genai import errors as genai_errors
from google.genai import types
from gspread.exceptions import APIError as GSpreadAPIError
from gspread.utils import rowcol_to_a1
from PIL import Image, ImageOps
from pydantic import BaseModel, Field

from crm_module import format_inr, get_crm_due_summary, render_crm_section

# ---------------------------------------------------------------------------
# Configuration & Security Constants
# ---------------------------------------------------------------------------
SCHEMA_VERSION = "v13_crm_and_multi_email"

MODEL_CHAIN = [
    "gemini-3.5-flash-lite",
    "gemini-3.1-flash-lite",
    "gemini-3.6-flash",
    "gemini-3.8-flash",
]

PER_REQUEST_TIMEOUT_MS = 22_000
TOTAL_SCAN_BUDGET_SEC = 45.0
MAX_IMAGE_SIDE_PX = 1400
JPEG_QUALITY = 82
MAX_DECODED_IMAGE_PIXELS = 25_000_000

Image.MAX_IMAGE_PIXELS = MAX_DECODED_IMAGE_PIXELS

MAX_CARD_IMAGES = 2
MAX_IMAGE_FILE_BYTES = 5 * 1024 * 1024
MAX_EXCEL_FILE_BYTES = 2 * 1024 * 1024
MAX_EXCEL_IMPORT_ROWS = 500
MAX_PHYSICAL_ROWS_SCANNED = 2000
MAX_EXCEL_IMPORT_COLS = 40
MAX_FIELD_LEN = 250
MAX_LONG_FIELD_LEN = 800
MAX_DIRECT_BCC_EMAILS = 45

MIN_SESSION_SECRET_LEN = 32
MIN_PASSWORD_LENGTH = 8
PBKDF2_ITERATIONS = 260_000
DEFAULT_DAILY_SCAN_LIMIT = 40
SESSION_TTL_SECONDS = 7 * 24 * 60 * 60
OTP_TTL_SECONDS = 10 * 60
MAX_OTP_GUESS_ATTEMPTS = 5
OTP_RESEND_COOLDOWN_SEC = 60
MAX_OTP_SENDS_PER_EMAIL_HOUR = 4
MAX_OTP_SENDS_PER_SESSION = 6
MAX_OTP_SENDS_GLOBAL_HOUR = 40
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 15 * 60

CARDS_WORKSHEET = "visiting_cards"
USERS_WORKSHEET = "users"
USAGE_WORKSHEET = "scan_usage"
RESETS_WORKSHEET = "password_resets"
REGISTER_OTPS_WORKSHEET = "register_otps"
SESSIONS_WORKSHEET = "sessions"
RATE_LIMITS_WORKSHEET = "auth_rate_limits"
AUDIT_LOGS_WORKSHEET = "audit_logs"

_WRITE_LOCK = threading.Lock()
_T = TypeVar("_T")

CARD_HEADERS = [
    "record_id",
    "user_id",
    "company_name",
    "contact_person",
    "call_phone",
    "whatsapp_phone",
    "email",
    "products_services",
    "address",
    "city",
    "notes",
    "created_at",
    "extra_data",
    "deleted_at",
]

DEFAULT_TABLE_COLUMNS = [
    "Company Name",
    "Contact Person",
    "Contact No.",
    "WhatsApp No.",
    "Email",
    "Product / Services",
    "Address",
    "City",
    "Notes",
    "Saved On",
]

ALL_RECORD_COLUMNS = [
    "Record ID",
    *DEFAULT_TABLE_COLUMNS,
    "Extra Details",
    "Extra Data JSON",
    "Deleted At",
]

STANDARD_FIELD_LABELS_LOWER = {
    "company name",
    "company",
    "contact person",
    "contact no",
    "contact no.",
    "call phone",
    "phone",
    "whatsapp no",
    "whatsapp no.",
    "whatsapp",
    "email",
    "product / services",
    "products / services",
    "products",
    "services",
    "address",
    "city",
    "notes",
    "saved on",
    "record id",
    "user id",
    "deleted at",
}

USER_HEADERS = ["user_id", "username", "email", "password_hash", "role", "created_at"]
USAGE_HEADERS = ["user_id", "quota_date", "scan_count", "updated_at"]
OTP_HEADERS = ["email", "code_hash", "expires_at", "used", "attempts", "created_at"]
SESSION_HEADERS = ["session_id", "user_id", "token_hash", "expires_at", "revoked", "created_at"]
RATE_LIMIT_HEADERS = ["limit_key", "attempt_count", "window_start", "locked_until"]
AUDIT_HEADERS = ["log_id", "user_id", "action", "record_id", "details", "created_at"]

EXCEL_COLUMN_ALIASES: dict[str, list[str]] = {
    "company_name": [
        "company name", "company", "business name", "business", "firm name", "firm",
        "organization", "org", "party name", "party", "shop name", "shop", "client",
    ],
    "contact_person": [
        "contact person", "person", "name", "full name", "contact name", "owner",
        "owner name", "director", "manager", "representative",
    ],
    "call_phone": [
        "contact no", "contact no.", "contact number", "call no", "call number", "call",
        "phone", "phone no", "phone number", "mobile", "mobile no", "mobile number",
        "telephone", "tel", "landline", "office no", "contact",
    ],
    "whatsapp_phone": [
        "whatsapp no", "whatsapp no.", "whatsapp number", "whatsapp", "wp no",
        "wp number", "wp", "wa no", "wa number", "wa",
    ],
    "email": ["email", "email id", "email address", "e-mail", "mail", "mail id"],
    "products_services": [
        "product / services", "products / services", "product/services", "products/services",
        "products", "product", "services", "service", "business type", "category", "items", "dealing in",
    ],
    "address": ["address", "full address", "office address", "shop address", "factory address", "location"],
    "city": ["city", "town", "district", "place"],
    "notes": ["notes", "note", "remarks", "remark", "comments", "comment"],
}

FIELD_PLACEHOLDERS = {
    "company_name": "e.g., Apex Industrial Solutions",
    "contact_person": "e.g., Rajesh Patel (Sales Manager)",
    "call_phone": "e.g., 9876543210 / 07926300000",
    "whatsapp_phone": "e.g., 9876543210 / 9123456789",
    "email": "e.g., sales@example.com / info@example.com",
    "products_services": "e.g., Industrial Valves, Pumps, Automation",
    "address": "e.g., Plot 12, GIDC Estate, Main Road",
    "city": "e.g., Ahmedabad",
    "notes": "e.g., Met at trade fair, wholesale supplier",
    "extra_details": "Website: www.example.com\nGSTIN: 24ABCDE1234F1Z5",
}

st.set_page_config(
    page_title="Company Visiting Card Scanner & CRM",
    page_icon="📇",
    layout="wide",
    initial_sidebar_state="auto",
)


# ---------------------------------------------------------------------------
# Clean Responsive UI Styling (Phone + Laptop) & Compact Image Previews
# ---------------------------------------------------------------------------
def inject_clean_ui_css() -> None:
    st.markdown(
        """
        <style>
            [data-testid="stToolbarActions"],
            [data-testid="stActionButtonIcon"],
            [data-testid="stAppDeployButton"],
            .stAppDeployButton,
            a[href*="github.com"],
            button[title*="GitHub"],
            button[title*="Fork"],
            #MainMenu,
            footer,
            .viewerBadge_container__1QSob,
            .styles_viewerBadge__1yB5_ {
                display: none !important;
                visibility: hidden !important;
            }
            .block-container { padding-top: 1.4rem; padding-bottom: 2.5rem; max-width: 1200px; }
            .stButton > button, .stDownloadButton > button, .stFormSubmitButton > button {
                min-height: 2.65rem; border-radius: 8px; font-weight: 500;
            }
            [data-testid="stImage"] img {
                max-height: 240px !important;
                max-width: min(300px, 100%) !important;
                width: auto !important; height: auto !important;
                object-fit: contain; border-radius: 8px;
                border: 1px solid rgba(128, 128, 128, 0.25);
            }
            [data-testid="stCameraInput"] { max-width: 420px; }
            .vcard-stat-strip { display: flex; flex-wrap: wrap; gap: 0.65rem; margin: 0.35rem 0 1rem 0; }
            .vcard-stat-pill {
                flex: 1 1 150px; padding: 0.65rem 0.95rem; border-radius: 10px;
                border: 1px solid rgba(128, 128, 128, 0.22); background: rgba(128, 128, 128, 0.06);
            }
            .vcard-stat-label { font-size: 0.78rem; opacity: 0.72; margin-bottom: 0.15rem; }
            .vcard-stat-value { font-size: 1.15rem; font-weight: 600; }
            .vcard-outreach-card {
                padding: 0.85rem 1rem; border-radius: 10px;
                border: 1px solid rgba(128, 128, 128, 0.22);
                background: rgba(128, 128, 128, 0.04); margin-bottom: 0.55rem;
            }
            .vcard-outreach-card-sent { border-left: 4px solid #16a34a; opacity: 0.82; }
            .vcard-action-link {
                display: inline-block; padding: 0.4rem 0.85rem; border-radius: 6px;
                text-decoration: none !important; font-size: 0.86rem; font-weight: 600;
                margin-right: 0.5rem; margin-top: 0.45rem;
            }
            .vcard-wa-btn { background: #16a34a; color: #ffffff !important; }
            .vcard-gmail-btn { background: #dc2626; color: #ffffff !important; }
            .vcard-mail-btn { background: #2563eb; color: #ffffff !important; }
            .vcard-sent-badge {
                display: inline-block; padding: 0.12rem 0.5rem; border-radius: 999px;
                font-size: 0.75rem; font-weight: 600;
                background: rgba(22, 163, 74, 0.18); color: #16a34a; margin-left: 0.4rem;
            }
            @keyframes vcardSlideDown {
                from { opacity: 0; transform: translateY(-10px); }
                to { opacity: 1; transform: translateY(0); }
            }
            .vcard-form-anchor { scroll-margin-top: 1rem; animation: vcardSlideDown 0.3s ease-out; }
            @media (max-width: 768px) {
                .block-container { padding-top: 0.9rem; padding-left: 0.85rem; padding-right: 0.85rem; }
                h1 { font-size: 1.65rem !important; }
                h2, h3 { font-size: 1.2rem !important; }
            }
        </style>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Browser Bridges: localStorage Session + Mobile Sidebar Close & Smooth Scroll
# ---------------------------------------------------------------------------
_SESSION_BRIDGE_JS = """
export default function(component) {
    const { data, setStateValue } = component;
    const STORAGE_KEY = "vcard_scanner_auth_token_v2";
    const action = (data && data.action) || "read";
    const desiredToken = (data && data.token) || "";

    if (action === "set" && desiredToken) {
        try { localStorage.setItem(STORAGE_KEY, desiredToken); } catch (e) {}
        if (window.__vcardReportedToken !== desiredToken) {
            window.__vcardReportedToken = desiredToken;
            setTimeout(() => setStateValue("token", desiredToken), 0);
        }
        return;
    }
    if (action === "clear") {
        try { localStorage.removeItem(STORAGE_KEY); } catch (e) {}
        if (window.__vcardReportedToken !== "__none__") {
            window.__vcardReportedToken = "__none__";
            setTimeout(() => setStateValue("token", "__none__"), 0);
        }
        return;
    }
    let existing = "__none__";
    try {
        const val = localStorage.getItem(STORAGE_KEY);
        if (val && val.trim()) existing = val.trim();
    } catch (e) {}
    if (window.__vcardReportedToken !== existing) {
        window.__vcardReportedToken = existing;
        setTimeout(() => setStateValue("token", existing), 0);
    }
}
"""

_UI_BRIDGE_JS = """
export default function(component) {
    const { data } = component;
    const closeSeq = Number((data && data.closeSidebarSeq) || 0);
    const scrollSeq = Number((data && data.scrollToFormSeq) || 0);

    if (closeSeq > 0 && window.__vcardLastCloseSeq !== closeSeq) {
        window.__vcardLastCloseSeq = closeSeq;
        const tryCloseMobileSidebar = () => {
            if (window.innerWidth > 900) return;
            const sidebar = document.querySelector('[data-testid="stSidebar"]');
            if (!sidebar || sidebar.getAttribute("aria-expanded") === "false") return;
            const btn =
                document.querySelector('[data-testid="stSidebarCollapseButton"] button') ||
                sidebar.querySelector('[data-testid="stSidebarHeader"] button') ||
                sidebar.querySelector('button[aria-label*="Close"], button[aria-label*="Collapse"], button[kind="headerNoPadding"]');
            if (btn) btn.click();
        };
        setTimeout(tryCloseMobileSidebar, 60);
        setTimeout(tryCloseMobileSidebar, 240);
    }
    if (scrollSeq > 0 && window.__vcardLastScrollSeq !== scrollSeq) {
        window.__vcardLastScrollSeq = scrollSeq;
        const tryScrollToForm = () => {
            const el = document.getElementById("card-entry-form-anchor");
            if (el) { el.scrollIntoView({ behavior: "smooth", block: "start" }); return true; }
            return false;
        };
        setTimeout(() => { if (!tryScrollToForm()) setTimeout(tryScrollToForm, 250); }, 120);
    }
}
"""

_HAS_COMPONENTS_V2 = hasattr(st, "components") and hasattr(st.components, "v2")
_SESSION_BRIDGE = (
    st.components.v2.component(
        "vcard_session_bridge",
        html="<div style='display:none'></div>",
        css=":host { display: none !important; height: 0 !important; }",
        js=_SESSION_BRIDGE_JS,
    )
    if _HAS_COMPONENTS_V2
    else None
)
_UI_BRIDGE = (
    st.components.v2.component(
        "vcard_ui_bridge",
        html="<div style='display:none'></div>",
        css=":host { display: none !important; height: 0 !important; }",
        js=_UI_BRIDGE_JS,
    )
    if _HAS_COMPONENTS_V2
    else None
)


def trigger_ui_bridge() -> None:
    if _UI_BRIDGE is None:
        return
    _UI_BRIDGE(
        data={
            "closeSidebarSeq": int(st.session_state.get("close_sidebar_seq", 0)),
            "scrollToFormSeq": int(st.session_state.get("scroll_to_form_seq", 0)),
        },
        key="vcard_ui_bridge_instance",
    )


# ---------------------------------------------------------------------------
# Google Sheets Rate-Limit (429) Retry Helper
# ---------------------------------------------------------------------------
def _is_transient_sheets_error(exc: Exception) -> bool:
    if isinstance(exc, GSpreadAPIError):
        status = getattr(getattr(exc, "response", None), "status_code", None)
        if status in (429, 500, 502, 503, 504):
            return True
    msg = str(exc).lower()
    return any(
        t in msg
        for t in ("429", "quota exceeded", "rate limit", "too many requests", "503", "502", "500", "timed out", "connection reset")
    )


def _sheets_call_with_retry(fn: Callable[[], _T], attempts: int = 3) -> _T:
    last_exc: Optional[Exception] = None
    for idx in range(attempts):
        try:
            return fn()
        except Exception as exc:
            last_exc = exc
            if idx < attempts - 1 and _is_transient_sheets_error(exc):
                time.sleep(0.8 * (idx + 1))
                continue
            raise
    assert last_exc is not None
    raise last_exc


# ---------------------------------------------------------------------------
# Secret, Session Signing, Password Policy & Multi-Phone / Multi-Email Helpers
# ---------------------------------------------------------------------------
def get_secret(key: str, default: Any = None) -> Any:
    try:
        if key in st.secrets:
            return st.secrets[key]
    except Exception:
        pass
    return os.getenv(key, default)


def get_daily_scan_limit() -> int:
    raw = get_secret("DAILY_SCAN_LIMIT", DEFAULT_DAILY_SCAN_LIMIT)
    try:
        return max(1, int(raw))
    except Exception:
        return DEFAULT_DAILY_SCAN_LIMIT


def get_quota_date_str() -> str:
    try:
        tz = ZoneInfo("America/Los_Angeles")
    except Exception:
        tz = timezone(timedelta(hours=-8))
    return datetime.now(tz).strftime("%Y-%m-%d")


def get_required_session_signing_key() -> bytes:
    raw_secret = str(get_secret("SESSION_SECRET", "") or "").strip()
    if len(raw_secret) < MIN_SESSION_SECRET_LEN:
        raise ValueError(
            f"`SESSION_SECRET` is missing or shorter than {MIN_SESSION_SECRET_LEN} characters."
        )
    return hashlib.sha256(f"vcard-session-v3:{raw_secret}".encode("utf-8")).digest()


def _hash_session_secret(raw_token_secret: str) -> str:
    return hmac.new(
        get_required_session_signing_key(),
        raw_token_secret.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), PBKDF2_ITERATIONS
    )
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt}${dk.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algo, iter_str, salt, expected_hex = stored_hash.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt.encode("utf-8"), int(iter_str)
        )
        return hmac.compare_digest(dk.hex(), expected_hex)
    except Exception:
        return False


def validate_password_strength(password: str) -> Tuple[bool, str]:
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must include at least one uppercase letter (A–Z)."
    if not re.search(r"[a-z]", password):
        return False, "Password must include at least one lowercase letter (a–z)."
    if not re.search(r"\d", password):
        return False, "Password must include at least one number (0–9)."
    return True, ""


def is_valid_email(email: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email))


def is_valid_username(username: str) -> bool:
    return bool(re.match(r"^[A-Za-z0-9_.-]{3,30}$", username))


def sanitize_text_field(val: Any, max_len: int = MAX_FIELD_LEN) -> str:
    if val is None:
        return ""
    cleaned = normalize_digits(str(val)).replace("\x00", "").strip()
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len].strip()
    return cleaned


def has_at_least_one_field(*values: str) -> bool:
    for val in values:
        cleaned = str(val or "").strip()
        if cleaned and cleaned.upper() != "N/A":
            return True
    return False


def normalize_digits(text: str) -> str:
    return "".join(
        str(unicodedata.digit(ch)) if ch.isdecimal() and not ch.isascii() else ch
        for ch in text
    )


def format_phone_numbers(raw: str) -> str:
    if not raw or str(raw).strip().upper() in ("N/A", "NAN", "NONE"):
        return "N/A"
    text = normalize_digits(str(raw)).strip()
    parts = re.split(r"[,/;\|\n&]+", text)
    formatted: list[str] = []
    seen: set[str] = set()

    for part in parts:
        part = re.sub(r"\.0$", "", part.strip())
        if not part:
            continue
        compact = re.sub(r"[\s\-\(\)\.]+", "", part)
        if compact.startswith("+91") and len(re.sub(r"\D", "", compact[3:])) == 10:
            digits = re.sub(r"\D", "", compact[3:])
        else:
            digits = re.sub(r"\D", "", compact)
            if len(digits) == 12 and digits.startswith("91") and digits[2] in "6789":
                digits = digits[2:]
        if not digits:
            continue
        if digits not in seen:
            seen.add(digits)
            formatted.append(digits)

    return " / ".join(formatted) if formatted else "N/A"


def extract_normalized_phones(phone_str: str) -> set[str]:
    formatted = format_phone_numbers(phone_str)
    if formatted == "N/A":
        return set()
    phones: set[str] = set()
    for part in formatted.split(" / "):
        digits = re.sub(r"\D", "", part)
        if len(digits) >= 7:
            phones.add(digits[-10:] if len(digits) >= 10 else digits)
    return phones


def extract_all_wa_dial_numbers(
    wp_str: str, fallback_call_str: str = ""
) -> list[Tuple[str, str]]:
    results: list[Tuple[str, str]] = []
    seen_dial: set[str] = set()
    formatted_wp = format_phone_numbers(wp_str)
    sources = (
        [formatted_wp]
        if formatted_wp != "N/A"
        else [format_phone_numbers(fallback_call_str)]
    )
    for candidate in sources:
        if not candidate or candidate == "N/A":
            continue
        for part in candidate.split(" / "):
            clean_disp = part.strip()
            digits = re.sub(r"\D", "", clean_disp)
            if not digits:
                continue
            if len(digits) == 10 and digits[0] in "6789":
                dial = f"91{digits}"
            elif len(digits) >= 10:
                dial = digits
            else:
                continue
            if dial not in seen_dial:
                seen_dial.add(dial)
                results.append((clean_disp, dial))
    return results


def parse_email_list(raw: str) -> list[str]:
    """Extract all valid, deduplicated lowercase email addresses from a string."""
    if not raw or str(raw).strip().upper() in ("N/A", "NAN", "NONE"):
        return []
    parts = re.split(r"[,/;\|\n\s]+", str(raw).strip())
    emails: list[str] = []
    seen: set[str] = set()
    for part in parts:
        cleaned = part.strip().strip("<>()[]\"'").lower()
        if not cleaned or cleaned in ("n/a", "nan", "none"):
            continue
        if is_valid_email(cleaned) and cleaned not in seen:
            seen.add(cleaned)
            emails.append(cleaned)
    return emails


def format_emails(raw: str) -> str:
    """Format one or multiple emails into a single column string separated by ' / '."""
    emails = parse_email_list(raw)
    return " / ".join(emails) if emails else "N/A"


def are_all_emails_valid(raw: str) -> bool:
    """Return True if blank/N/A or every delimited token is a valid email address."""
    if not raw or str(raw).strip().upper() in ("", "N/A", "NAN", "NONE"):
        return True
    tokens = [
        t.strip()
        for t in re.split(r"[,/;\|\n]+", str(raw).strip())
        if t.strip()
    ]
    if not tokens:
        return True
    return all(is_valid_email(t.lower()) for t in tokens)


def extract_normalized_emails(email_str: str) -> set[str]:
    return set(parse_email_list(email_str))


# ---------------------------------------------------------------------------
# Extra Data Helpers (Lossless JSON Validation & Auto-Expanded Columns)
# ---------------------------------------------------------------------------
def parse_extra_data(raw_json: str) -> dict[str, str]:
    if not raw_json or not str(raw_json).strip():
        return {}
    try:
        parsed = json.loads(str(raw_json))
        if not isinstance(parsed, dict):
            return {}
        cleaned: dict[str, str] = {}
        for k, v in parsed.items():
            ck = sanitize_text_field(k, 80)
            cv = sanitize_text_field(v, MAX_FIELD_LEN)
            if ck and cv and cv.upper() != "N/A":
                cleaned[ck] = cv
        return cleaned
    except Exception:
        return {}


def validate_and_serialize_extra_data(
    extra: dict[str, str], strict: bool = True
) -> Tuple[str, list[str]]:
    cleaned: dict[str, str] = {}
    for k, v in extra.items():
        ck = sanitize_text_field(k, 80)
        cv = sanitize_text_field(v, MAX_FIELD_LEN)
        if ck and cv and cv.upper() != "N/A":
            cleaned[ck] = cv

    if not cleaned:
        return "", []

    full_json = json.dumps(cleaned, ensure_ascii=False)
    if len(full_json) <= MAX_LONG_FIELD_LEN:
        return full_json, []

    if strict:
        raise ValueError(
            f"Extra Details are too long ({len(full_json)} / {MAX_LONG_FIELD_LEN} characters). "
            "Please shorten or remove some extra lines before saving."
        )

    kept: dict[str, str] = {}
    dropped: list[str] = []
    for k, v in cleaned.items():
        candidate = {**kept, k: v}
        if len(json.dumps(candidate, ensure_ascii=False)) <= MAX_LONG_FIELD_LEN:
            kept[k] = v
        else:
            dropped.append(k)

    serialized = json.dumps(kept, ensure_ascii=False) if kept else ""
    return serialized, dropped


def format_extra_data_for_input(extra: dict[str, str]) -> str:
    if not extra:
        return ""
    return "\n".join(f"{k}: {v}" for k, v in extra.items())


def parse_extra_data_from_input(text: str) -> dict[str, str]:
    if not text or not text.strip():
        return {}
    result: dict[str, str] = {}
    other_lines: list[str] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.upper() == "N/A":
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            ck = sanitize_text_field(k, 80)
            cv = sanitize_text_field(v, MAX_FIELD_LEN)
            if ck and cv and cv.upper() != "N/A":
                result[ck] = cv
        elif "=" in line:
            k, v = line.split("=", 1)
            ck = sanitize_text_field(k, 80)
            cv = sanitize_text_field(v, MAX_FIELD_LEN)
            if ck and cv and cv.upper() != "N/A":
                result[ck] = cv
        else:
            other_lines.append(sanitize_text_field(line, MAX_FIELD_LEN))

    if other_lines:
        existing_other = result.get("Other Info", "")
        combined = " | ".join([x for x in [existing_other, *other_lines] if x])
        result["Other Info"] = sanitize_text_field(combined, MAX_FIELD_LEN)

    return result


def format_extra_data_summary(extra: dict[str, str]) -> str:
    if not extra:
        return ""
    return " | ".join(f"{k}: {v}" for k, v in extra.items())


def collect_extra_column_names(df: pd.DataFrame) -> list[str]:
    if df.empty or "Extra Data JSON" not in df.columns:
        return []
    standard_lower = {c.lower() for c in DEFAULT_TABLE_COLUMNS}
    seen_lower: dict[str, str] = {}
    for raw in df["Extra Data JSON"].tolist():
        for key in parse_extra_data(str(raw)).keys():
            kl = key.lower()
            if kl in standard_lower:
                continue
            if kl not in seen_lower:
                seen_lower[kl] = key
    return list(seen_lower.values())


def build_expanded_dataframe(
    df: pd.DataFrame, include_extra_columns: bool = True
) -> pd.DataFrame:
    base_df = df[DEFAULT_TABLE_COLUMNS].copy()
    if not include_extra_columns or df.empty or "Extra Data JSON" not in df.columns:
        return base_df

    extra_cols = collect_extra_column_names(df)
    if not extra_cols:
        return base_df

    parsed_rows = [parse_extra_data(str(raw)) for raw in df["Extra Data JSON"].tolist()]
    for col_name in extra_cols:
        col_lower = col_name.lower()
        values = []
        for row_dict in parsed_rows:
            matched_val = "N/A"
            for k, v in row_dict.items():
                if k.lower() == col_lower:
                    matched_val = v
                    break
            values.append(matched_val)
        base_df[col_name] = values

    return base_df


def optimize_card_image(raw_bytes: bytes, fallback_mime: str) -> Tuple[bytes, str]:
    if not raw_bytes or len(raw_bytes) > MAX_IMAGE_FILE_BYTES:
        raise ValueError("Image is empty or exceeds the 5 MB upload limit.")

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(raw_bytes)) as img:
                width, height = img.size
                if width <= 0 or height <= 0 or (width * height) > MAX_DECODED_IMAGE_PIXELS:
                    raise ValueError(
                        "Image resolution is too large (exceeds 25 megapixels). Please upload a standard photo."
                    )
                img.verify()

            with Image.open(io.BytesIO(raw_bytes)) as img:
                width, height = img.size
                if width <= 0 or height <= 0 or (width * height) > MAX_DECODED_IMAGE_PIXELS:
                    raise ValueError(
                        "Image resolution is too large (exceeds 25 megapixels). Please upload a standard photo."
                    )
                img = ImageOps.exif_transpose(img)
                if img.mode in ("RGBA", "LA", "P"):
                    background = Image.new("RGB", img.size, (255, 255, 255))
                    converted = img.convert("RGBA")
                    background.paste(converted, mask=converted.split()[-1])
                    img = background
                elif img.mode != "RGB":
                    img = img.convert("RGB")

                if max(img.size) > MAX_IMAGE_SIDE_PX:
                    img.thumbnail(
                        (MAX_IMAGE_SIDE_PX, MAX_IMAGE_SIDE_PX),
                        Image.Resampling.LANCZOS,
                    )

                out = io.BytesIO()
                img.save(out, format="JPEG", quality=JPEG_QUALITY, optimize=True)
                return out.getvalue(), "image/jpeg"
    except ValueError:
        raise
    except (Image.DecompressionBombError, Image.DecompressionBombWarning) as bomb_err:
        raise ValueError(
            "Image resolution is too large (exceeds 25 megapixels). Please upload a standard photo."
        ) from bomb_err
    except Exception as img_err:
        raise ValueError(
            "Could not process this image file (it may be corrupted or unsupported). "
            "Please upload a valid JPG or PNG photo."
        ) from img_err


def clear_uploaded_inputs() -> None:
    st.session_state["uploader_reset_counter"] = (
        st.session_state.get("uploader_reset_counter", 0) + 1
    )


def clear_account_specific_state(preserve_flash: bool = False) -> None:
    st.session_state["bound_user_id"] = None
    st.session_state["active_view"] = "home"
    st.session_state["extracted_card"] = None
    st.session_state["is_manual_entry"] = False
    st.session_state["pending_duplicate_save"] = None
    st.session_state["scan_notice"] = None
    st.session_state["audit_warning"] = None
    st.session_state["ai_growth_output"] = None
    st.session_state["ai_pitch_output"] = None
    st.session_state["campaign_sent_keys"] = set()
    st.session_state["edit_counter"] = st.session_state.get("edit_counter", 0) + 1
    clear_uploaded_inputs()
    if not preserve_flash:
        st.session_state["flash_success"] = None
        st.session_state["flash_info"] = None


# ---------------------------------------------------------------------------
# Pydantic Schema for Gemini Structured Outputs
# ---------------------------------------------------------------------------
class ExtraDetail(BaseModel):
    label: str = Field(
        description=(
            "Short clean English Title Case label for an extra detail on the card "
            "(e.g., 'Website', 'GSTIN', 'PAN', 'Instagram', 'LinkedIn', 'Fax', 'Branch', 'Timings')."
        )
    )
    value: str = Field(
        description="Value of this extra detail in English with standard 0-9 digits."
    )


class VisitingCard(BaseModel):
    company_name: str = Field(
        description=(
            "Name of the company or business in English (Latin script). "
            "Transliterate non-English business names cleanly into readable English. Return 'N/A' if missing."
        )
    )
    contact_person: str = Field(
        description=(
            "Full name of the contact person in English (Latin script), including designation if printed. "
            "Transliterate non-English names into readable English. Return 'N/A' if missing."
        )
    )
    call_phone: str = Field(
        description=(
            "Normal call / office / landline number(s) formatted as plain ASCII digits separated by ' / ' "
            "(example: '9876543210 / 07926300000'), removing '+91' and spaces. "
            "ONLY populate this when the card explicitly distinguishes a call/phone/landline number using a phone/call "
            "icon or text label ('Call', 'Ph', 'Tel', 'Office', 'Landline', 'Contact') separately from WhatsApp. "
            "If there is only 1 unspecified number, or 2+ unspecified numbers, return 'N/A' here."
        )
    )
    whatsapp_phone: str = Field(
        description=(
            "WhatsApp number(s) formatted as plain ASCII digits separated by ' / ' "
            "(example: '9876543210 / 9123456789'), removing '+91' and spaces. "
            "Rules: (1) If WhatsApp icon/logo or text ('WP', 'WA', 'WhatsApp') marks specific number(s), put those here. "
            "(2) If only 1 number is on the card without a call-only/landline distinction, put it here by default. "
            "(3) If 2 or more numbers are on the card with NO icon or text distinguishing WhatsApp from Call, "
            "put ALL of them here separated by ' / '. Return 'N/A' only if no number applies."
        )
    )
    email: str = Field(
        description=(
            "All email address(es) printed on the card in English (Latin script, lowercase), "
            "separated by ' / ' if there are 2 or more (example: 'sales@company.com / info@company.com'). "
            "Keep every email printed on the card in this single field — do NOT put a second email in extra_details. "
            "Return 'N/A' if missing."
        )
    )
    products_services: str = Field(
        description=(
            "Products or services offered by the company in English (Latin script). "
            "Translate regional terms into natural English (keep well-known Indian item names in standard English "
            "spelling like Bhajiya, Jalebi, Boondi Laddu, Mohanthal). If not explicitly listed, infer from the "
            "company name, title, or tagline. Return 'N/A' only if completely impossible to determine."
        )
    )
    address: str = Field(
        description=(
            "Complete physical shop, office, or factory address translated and transliterated into clear English "
            "with standard 0-9 digits (translate directional words like 'near' or 'next to'; transliterate street "
            "and city names). Return 'N/A' if missing."
        )
    )
    city: str = Field(
        description=(
            "Only the City or Town name in standard English Title Case (e.g., 'Ahmedabad', 'Mumbai', "
            "'Kapadvanj', 'Dakor', 'Surat', 'Vadodara'). Do NOT include street, state, or PIN code here. "
            "Infer from the address or PIN code if clear; return 'N/A' if completely absent."
        )
    )
    extra_details: list[ExtraDetail] = Field(
        default_factory=list,
        description=(
            "Any additional useful details printed on the card that do NOT belong in the standard fields "
            "(such as Website, GSTIN, PAN, Fax, Instagram, LinkedIn, Facebook, Branch, Office Timings, ISO Certification). "
            "Do NOT repeat company name, contact person, phone, email, products, address, or city here. "
            "Return an empty list [] if none are printed."
        ),
    )


def _clean_card_output(card: VisitingCard) -> Tuple[VisitingCard, dict[str, str]]:
    raw_city = sanitize_text_field(card.city, 100)
    clean_city = raw_city if raw_city and raw_city.upper() != "N/A" else "N/A"

    collected_emails = parse_email_list(card.email)
    extra_dict: dict[str, str] = {}
    for item in card.extra_details or []:
        lbl = sanitize_text_field(item.label, 80)
        val = sanitize_text_field(item.value, MAX_FIELD_LEN)
        if not lbl or not val or val.upper() == "N/A":
            continue
        if "email" in lbl.lower() or "mail" in lbl.lower():
            for extra_em in parse_email_list(val):
                if extra_em not in collected_emails:
                    collected_emails.append(extra_em)
            continue
        if lbl.lower() not in STANDARD_FIELD_LABELS_LOWER:
            extra_dict[lbl] = val

    cleaned = card.model_copy(
        update={
            "company_name": sanitize_text_field(card.company_name, MAX_FIELD_LEN) or "N/A",
            "contact_person": sanitize_text_field(card.contact_person, MAX_FIELD_LEN) or "N/A",
            "call_phone": format_phone_numbers(card.call_phone),
            "whatsapp_phone": format_phone_numbers(card.whatsapp_phone),
            "email": " / ".join(collected_emails) if collected_emails else "N/A",
            "products_services": sanitize_text_field(card.products_services, MAX_FIELD_LEN) or "N/A",
            "address": sanitize_text_field(card.address, MAX_LONG_FIELD_LEN) or "N/A",
            "city": clean_city,
        }
    )
    return cleaned, extra_dict


# ---------------------------------------------------------------------------
# Google Sheets Storage Layer (Strict Header Validation & Migration)
# ---------------------------------------------------------------------------
@st.cache_resource(show_spinner=False)
def get_spreadsheet(_schema_version: str = SCHEMA_VERSION) -> gspread.Spreadsheet:
    get_required_session_signing_key()
    creds_section = get_secret("gcp_service_account")
    sheet_url = get_secret("GSHEET_URL")
    if not creds_section or not sheet_url:
        raise ValueError(
            "Google Sheets is not configured. Add `GSHEET_URL` and `[gcp_service_account]` to Streamlit Secrets."
        )
    client = gspread.service_account_from_dict(dict(creds_section))
    spreadsheet = _sheets_call_with_retry(
        lambda: client.open_by_url(str(sheet_url).strip())
    )
    ensure_worksheets(spreadsheet)
    return spreadsheet


def _migrate_cards_worksheet_if_needed(cards_ws: gspread.Worksheet) -> None:
    all_rows = _sheets_call_with_retry(cards_ws.get_all_values)
    if not all_rows:
        cards_ws.append_row(CARD_HEADERS, value_input_option="RAW")
        return

    current_headers = all_rows[0]
    if cards_ws.col_count < len(CARD_HEADERS):
        cards_ws.resize(cols=len(CARD_HEADERS))

    if "record_id" not in current_headers and "user_id" not in current_headers:
        cards_ws.insert_row(CARD_HEADERS, index=1, value_input_option="RAW")
        return

    normalized_headers = [
        "extra_data" if col == "Extra Details" else col for col in current_headers
    ]
    if normalized_headers == CARD_HEADERS:
        if normalized_headers != current_headers:
            cards_ws.update(values=[CARD_HEADERS], range_name="A1", value_input_option="RAW")
        return

    allowed_card_cols = set(CARD_HEADERS) | {"phone"}
    non_empty_headers = [h for h in normalized_headers if h.strip()]
    unknown = [h for h in non_empty_headers if h not in allowed_card_cols]
    if unknown:
        raise ValueError(
            f"Schema mismatch in worksheet '{CARDS_WORKSHEET}': unexpected column(s) {unknown}."
        )

    migrated_rows = [CARD_HEADERS]
    for row in all_rows[1:]:
        if not any(cell.strip() for cell in row):
            continue
        padded = row + [""] * (len(normalized_headers) - len(row))
        old_rec = dict(zip(normalized_headers, padded))
        new_rec = {
            "record_id": old_rec.get("record_id") or str(uuid.uuid4()),
            "user_id": old_rec.get("user_id", "default_user"),
            "company_name": old_rec.get("company_name", "N/A"),
            "contact_person": old_rec.get("contact_person", "N/A"),
            "call_phone": format_phone_numbers(old_rec.get("call_phone") or "N/A"),
            "whatsapp_phone": format_phone_numbers(
                old_rec.get("whatsapp_phone") or old_rec.get("phone") or "N/A"
            ),
            "email": format_emails(old_rec.get("email", "N/A")),
            "products_services": old_rec.get("products_services", "N/A"),
            "address": old_rec.get("address", "N/A"),
            "city": old_rec.get("city", "N/A") or "N/A",
            "notes": old_rec.get("notes", ""),
            "created_at": old_rec.get("created_at", ""),
            "extra_data": old_rec.get("extra_data", ""),
            "deleted_at": old_rec.get("deleted_at", ""),
        }
        migrated_rows.append([new_rec[col] for col in CARD_HEADERS])

    cards_ws.update(values=migrated_rows, range_name="A1", value_input_option="RAW")


def _migrate_or_validate_worksheet(
    ws: gspread.Worksheet,
    expected_headers: list[str],
    sheet_label: str,
    defaults: Optional[dict[str, str]] = None,
) -> None:
    all_rows = _sheets_call_with_retry(ws.get_all_values)
    if not all_rows:
        if ws.col_count < len(expected_headers):
            ws.resize(cols=len(expected_headers))
        ws.append_row(expected_headers, value_input_option="RAW")
        return

    raw_headers = all_rows[0]
    if raw_headers == expected_headers:
        return

    trimmed_headers = list(raw_headers)
    while trimmed_headers and not trimmed_headers[-1].strip():
        trimmed_headers.pop()

    if not trimmed_headers:
        if ws.col_count < len(expected_headers):
            ws.resize(cols=len(expected_headers))
        ws.update(values=[expected_headers], range_name="A1", value_input_option="RAW")
        return

    unknown_cols = [h for h in trimmed_headers if h not in expected_headers]
    if unknown_cols or len(set(trimmed_headers)) != len(trimmed_headers):
        raise ValueError(
            f"Schema mismatch in worksheet '{sheet_label}': expected {expected_headers}, found {trimmed_headers}."
        )

    if ws.col_count < len(expected_headers):
        ws.resize(cols=len(expected_headers))

    default_map = defaults or {}
    migrated_rows = [expected_headers]
    for row in all_rows[1:]:
        if not any(cell.strip() for cell in row):
            continue
        padded = row + [""] * (len(trimmed_headers) - len(row))
        rec = dict(zip(trimmed_headers, padded))
        migrated_rows.append(
            [rec.get(col, default_map.get(col, "")) for col in expected_headers]
        )

    ws.update(values=migrated_rows, range_name="A1", value_input_option="RAW")


def ensure_worksheets(spreadsheet: gspread.Spreadsheet) -> None:
    existing_ws = _sheets_call_with_retry(spreadsheet.worksheets)
    existing_titles = {ws.title for ws in existing_ws}

    if CARDS_WORKSHEET not in existing_titles:
        cards_ws = spreadsheet.add_worksheet(
            title=CARDS_WORKSHEET, rows=1000, cols=len(CARD_HEADERS)
        )
        cards_ws.append_row(CARD_HEADERS, value_input_option="RAW")
    else:
        _migrate_cards_worksheet_if_needed(spreadsheet.worksheet(CARDS_WORKSHEET))

    worksheet_specs: list[Tuple[str, list[str], dict[str, str]]] = [
        (USERS_WORKSHEET, USER_HEADERS, {"role": "user"}),
        (USAGE_WORKSHEET, USAGE_HEADERS, {"scan_count": "0"}),
        (RESETS_WORKSHEET, OTP_HEADERS, {"used": "yes", "attempts": "0"}),
        (REGISTER_OTPS_WORKSHEET, OTP_HEADERS, {"used": "yes", "attempts": "0"}),
        (SESSIONS_WORKSHEET, SESSION_HEADERS, {"revoked": "no"}),
        (
            RATE_LIMITS_WORKSHEET,
            RATE_LIMIT_HEADERS,
            {"attempt_count": "0", "window_start": "0", "locked_until": "0"},
        ),
        (AUDIT_LOGS_WORKSHEET, AUDIT_HEADERS, {}),
    ]

    for ws_name, headers, defaults in worksheet_specs:
        if ws_name not in existing_titles:
            ws = spreadsheet.add_worksheet(title=ws_name, rows=500, cols=len(headers))
            ws.append_row(headers, value_input_option="RAW")
        else:
            _migrate_or_validate_worksheet(
                spreadsheet.worksheet(ws_name), headers, ws_name, defaults
            )


def _get_or_create_worksheet(title: str, headers: list[str]) -> gspread.Worksheet:
    spreadsheet = get_spreadsheet(SCHEMA_VERSION)
    try:
        return spreadsheet.worksheet(title)
    except gspread.WorksheetNotFound:
        ws = spreadsheet.add_worksheet(title=title, rows=500, cols=len(headers))
        ws.append_row(headers, value_input_option="RAW")
        return ws


def get_cards_worksheet() -> gspread.Worksheet:
    return get_spreadsheet(SCHEMA_VERSION).worksheet(CARDS_WORKSHEET)


def get_users_worksheet() -> gspread.Worksheet:
    return _get_or_create_worksheet(USERS_WORKSHEET, USER_HEADERS)


def get_usage_worksheet() -> gspread.Worksheet:
    return _get_or_create_worksheet(USAGE_WORKSHEET, USAGE_HEADERS)


def get_resets_worksheet() -> gspread.Worksheet:
    return _get_or_create_worksheet(RESETS_WORKSHEET, OTP_HEADERS)


def get_register_otps_worksheet() -> gspread.Worksheet:
    return _get_or_create_worksheet(REGISTER_OTPS_WORKSHEET, OTP_HEADERS)


def get_sessions_worksheet() -> gspread.Worksheet:
    return _get_or_create_worksheet(SESSIONS_WORKSHEET, SESSION_HEADERS)


def get_rate_limits_worksheet() -> gspread.Worksheet:
    return _get_or_create_worksheet(RATE_LIMITS_WORKSHEET, RATE_LIMIT_HEADERS)


def get_audit_logs_worksheet() -> gspread.Worksheet:
    return _get_or_create_worksheet(AUDIT_LOGS_WORKSHEET, AUDIT_HEADERS)


# ---------------------------------------------------------------------------
# Audit History Logger
# ---------------------------------------------------------------------------
def append_audit_log(
    user_id: str, action: str, record_id: str, details: str
) -> bool:
    try:
        ws = get_audit_logs_worksheet()
        log_id = f"log_{uuid.uuid4().hex}"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        _sheets_call_with_retry(
            lambda: ws.append_row(
                [
                    log_id,
                    user_id,
                    action,
                    record_id,
                    sanitize_text_field(details, 300),
                    timestamp,
                ],
                value_input_option="RAW",
                table_range="A1",
            )
        )
        return True
    except Exception:
        st.session_state["audit_warning"] = (
            "Notice: An audit log entry could not be recorded due to a temporary storage error."
        )
        return False


def fetch_user_audit_logs(
    user_id: str, limit: Optional[int] = None
) -> pd.DataFrame:
    ws = get_audit_logs_worksheet()
    rows = _sheets_call_with_retry(ws.get_all_values)
    if len(rows) <= 1:
        return pd.DataFrame(columns=["Timestamp", "Action", "Record ID", "Details"])

    out = []
    for row in rows[1:]:
        if len(row) >= 6 and row[1] == user_id:
            out.append(
                {
                    "Timestamp": row[5],
                    "Action": row[2],
                    "Record ID": row[3],
                    "Details": row[4],
                }
            )
    if not out:
        return pd.DataFrame(columns=["Timestamp", "Action", "Record ID", "Details"])
    ordered = out[::-1]
    return pd.DataFrame(ordered[:limit] if limit is not None else ordered)


# ---------------------------------------------------------------------------
# Rate Limiting & Lockout Protection
# ---------------------------------------------------------------------------
@st.cache_data(ttl=15, show_spinner=False)
def _fetch_rate_limit_rows() -> list[list[str]]:
    ws = get_rate_limits_worksheet()
    return _sheets_call_with_retry(ws.get_all_values)


def _check_rate_limit(
    limit_key: str,
    max_attempts: int,
    window_seconds: int,
    cooldown_seconds: int = 0,
) -> Tuple[bool, str]:
    rows = _fetch_rate_limit_rows()
    now = int(time.time())

    for row in rows[1:]:
        if len(row) >= 4 and row[0] == limit_key:
            try:
                attempts = int(row[1])
                window_start = int(row[2])
                locked_until = int(row[3])
            except ValueError:
                return True, ""

            if locked_until > now:
                wait_sec = locked_until - now
                mins, secs = divmod(wait_sec, 60)
                wait_str = f"{mins}m {secs}s" if mins else f"{secs}s"
                return False, f"Too many attempts. Please wait {wait_str} before trying again."

            if now - window_start <= window_seconds:
                if cooldown_seconds > 0 and (now - window_start) < cooldown_seconds:
                    wait_cd = cooldown_seconds - (now - window_start)
                    return False, f"Please wait {wait_cd}s before requesting another code."
                if attempts >= max_attempts:
                    return False, "Rate limit reached. Please try again later."
            return True, ""

    return True, ""


def _record_rate_limit_event(
    limit_key: str,
    max_attempts: int,
    window_seconds: int,
    lockout_seconds: int,
    reset_window_on_each_event: bool = False,
) -> None:
    with _WRITE_LOCK:
        ws = get_rate_limits_worksheet()
        rows = _sheets_call_with_retry(ws.get_all_values)
        now = int(time.time())

        for row_idx, row in enumerate(rows[1:], start=2):
            if len(row) >= 4 and row[0] == limit_key:
                try:
                    attempts = int(row[1])
                    window_start = int(row[2])
                except ValueError:
                    attempts, window_start = 0, now

                if now - window_start > window_seconds:
                    new_attempts = 1
                    new_window_start = now
                else:
                    new_attempts = attempts + 1
                    new_window_start = now if reset_window_on_each_event else window_start

                locked_until = (
                    now + lockout_seconds if new_attempts >= max_attempts else 0
                )
                ws.update(
                    values=[
                        [
                            limit_key,
                            str(new_attempts),
                            str(new_window_start),
                            str(locked_until),
                        ]
                    ],
                    range_name=f"A{row_idx}:D{row_idx}",
                    value_input_option="RAW",
                )
                _fetch_rate_limit_rows.clear()
                return

        locked_until = now + lockout_seconds if 1 >= max_attempts else 0
        ws.append_row(
            [limit_key, "1", str(now), str(locked_until)],
            value_input_option="RAW",
            table_range="A1",
        )
        _fetch_rate_limit_rows.clear()


def _clear_rate_limit(limit_key: str) -> None:
    with _WRITE_LOCK:
        ws = get_rate_limits_worksheet()
        rows = _sheets_call_with_retry(ws.get_all_values)
        for row_idx, row in enumerate(rows[1:], start=2):
            if len(row) >= 1 and row[0] == limit_key:
                ws.update(
                    values=[[limit_key, "0", "0", "0"]],
                    range_name=f"A{row_idx}:D{row_idx}",
                    value_input_option="RAW",
                )
                _fetch_rate_limit_rows.clear()
                return


# ---------------------------------------------------------------------------
# Server-Backed Revocable Sessions (Resilient to Transient Sheets 429s)
# ---------------------------------------------------------------------------
class _TransientStorageError(Exception):
    pass


def create_server_session(user_id: str) -> str:
    session_id = f"sess_{uuid.uuid4().hex}"
    raw_secret = secrets.token_urlsafe(32)
    token_hash = _hash_session_secret(raw_secret)
    expires_at = str(int(time.time()) + SESSION_TTL_SECONDS)
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with _WRITE_LOCK:
        ws = get_sessions_worksheet()
        _sheets_call_with_retry(
            lambda: ws.append_row(
                [session_id, user_id, token_hash, expires_at, "no", created_at],
                value_input_option="RAW",
                table_range="A1",
            )
        )
    _check_session_in_sheets.clear()
    return f"{session_id}.{raw_secret}"


@st.cache_data(ttl=60, show_spinner=False)
def _check_session_in_sheets(composite_token: str) -> Tuple[str, Optional[str]]:
    if "." not in composite_token:
        return "invalid", None
    session_id, raw_secret = composite_token.split(".", 1)
    if not session_id.startswith("sess_") or not raw_secret:
        return "invalid", None

    try:
        expected_hash = _hash_session_secret(raw_secret)
        ws = get_sessions_worksheet()
        rows = _sheets_call_with_retry(ws.get_all_values)
    except Exception as exc:
        raise _TransientStorageError("Temporary storage read error") from exc

    now = int(time.time())
    for row in rows[1:]:
        if len(row) >= 5 and row[0] == session_id:
            user_id, stored_hash, exp_str, revoked = (
                row[1],
                row[2],
                row[3],
                row[4],
            )
            if revoked.strip().lower() == "yes":
                return "invalid", None
            try:
                if int(exp_str) < now:
                    return "invalid", None
            except ValueError:
                return "invalid", None
            if hmac.compare_digest(stored_hash, expected_hash):
                return "valid", user_id
            return "invalid", None

    return "invalid", None


def verify_server_session(composite_token: str) -> Tuple[str, Optional[str]]:
    try:
        return _check_session_in_sheets(composite_token)
    except _TransientStorageError:
        return "transient_error", None
    except Exception:
        return "invalid", None


def revoke_server_session(composite_token: Optional[str]) -> None:
    if not composite_token or "." not in composite_token:
        return
    session_id = composite_token.split(".", 1)[0]
    try:
        with _WRITE_LOCK:
            ws = get_sessions_worksheet()
            rows = _sheets_call_with_retry(ws.get_all_values)
            for row_idx, row in enumerate(rows[1:], start=2):
                if len(row) >= 5 and row[0] == session_id:
                    ws.update(
                        values=[["yes"]],
                        range_name=f"E{row_idx}",
                        value_input_option="RAW",
                    )
                    break
        _check_session_in_sheets.clear()
    except Exception:
        pass


def revoke_all_user_sessions(user_id: str) -> int:
    revoked_count = 0
    with _WRITE_LOCK:
        ws = get_sessions_worksheet()
        rows = _sheets_call_with_retry(ws.get_all_values)
        for row_idx, row in enumerate(rows[1:], start=2):
            if (
                len(row) >= 5
                and row[1] == user_id
                and row[4].strip().lower() != "yes"
            ):
                ws.update(
                    values=[["yes"]],
                    range_name=f"E{row_idx}",
                    value_input_option="RAW",
                )
                revoked_count += 1
    _check_session_in_sheets.clear()
    return revoked_count


def login_user_session(user: dict[str, str]) -> None:
    clear_account_specific_state(preserve_flash=False)
    composite_token = create_server_session(user["user_id"])
    st.session_state["auth_user"] = user
    st.session_state["bound_user_id"] = user["user_id"]
    st.session_state["session_token"] = composite_token
    st.session_state["session_action"] = "set"


def logout_user_session() -> None:
    revoke_server_session(st.session_state.get("session_token"))
    st.session_state["auth_user"] = None
    st.session_state["session_token"] = None
    st.session_state["session_action"] = "clear"
    clear_account_specific_state(preserve_flash=False)


def sync_and_restore_session() -> Tuple[Optional[dict[str, str]], bool]:
    try:
        if "session" in st.query_params:
            st.query_params.pop("session", None)
    except Exception:
        pass

    current_auth = st.session_state.get("auth_user")
    current_token = st.session_state.get("session_token") or ""

    if current_auth is not None:
        status, verified_uid = (
            verify_server_session(current_token)
            if current_token
            else ("invalid", None)
        )
        if status == "transient_error":
            st.session_state["flash_info"] = (
                "Google Sheets is momentarily busy — your session is still active."
            )
        elif status != "valid" or verified_uid != current_auth.get("user_id"):
            st.session_state["auth_user"] = None
            st.session_state["session_token"] = None
            st.session_state["session_action"] = "clear"
            clear_account_specific_state(preserve_flash=False)
            st.session_state["flash_info"] = (
                "Your session expired or was signed out. Please log in again."
            )
            current_auth = None
            current_token = ""

    if _SESSION_BRIDGE is None:
        return current_auth, False

    action = st.session_state.get("session_action", "read")

    if action == "set" and current_auth and current_token:
        _SESSION_BRIDGE(
            data={"action": "set", "token": current_token},
            default={"token": current_token},
            key="session_bridge",
            on_token_change=lambda: None,
        )
        return current_auth, False

    if action == "clear":
        res = _SESSION_BRIDGE(
            data={"action": "clear"},
            default={"token": "__clearing__"},
            key="session_bridge",
            on_token_change=lambda: None,
        )
        if res and res.get("token") == "__none__":
            st.session_state["session_action"] = "read"
        return None, False

    if current_auth is not None:
        return current_auth, False

    res = _SESSION_BRIDGE(
        data={"action": "read"},
        default={"token": "__loading__"},
        key="session_bridge",
        on_token_change=lambda: None,
    )
    stored_token = res.get("token", "__loading__") if res else "__loading__"

    if stored_token == "__loading__":
        return None, True

    if stored_token and stored_token not in ("__none__", "__clearing__"):
        status, user_id = verify_server_session(stored_token)
        if status == "transient_error":
            st.warning(
                "Google Sheets is momentarily busy restoring your session. Please click Refresh in a few seconds."
            )
            return None, True
        if status == "valid" and user_id:
            try:
                users = fetch_all_users()
            except Exception:
                st.warning(
                    "Google Sheets is momentarily busy. Please click Refresh in a few seconds."
                )
                return None, True
            for user in users:
                if user.get("user_id") == user_id:
                    clear_account_specific_state(preserve_flash=False)
                    restored = {
                        "user_id": user.get("user_id", ""),
                        "username": user.get("username", ""),
                        "email": user.get("email", ""),
                        "role": user.get("role", "user"),
                    }
                    st.session_state["auth_user"] = restored
                    st.session_state["bound_user_id"] = user_id
                    st.session_state["session_token"] = stored_token
                    st.session_state["session_action"] = "set"
                    return restored, False
        st.session_state["session_action"] = "clear"

    return None, False


# ---------------------------------------------------------------------------
# Cached Quota Reads + Optimistic Quota Reservation & Release
# ---------------------------------------------------------------------------
class QuotaExceededError(Exception):
    pass


@st.cache_data(ttl=60, show_spinner=False)
def get_user_scans_today(user_id: str) -> int:
    today = get_quota_date_str()
    ws = get_usage_worksheet()
    rows = _sheets_call_with_retry(ws.get_all_values)
    if len(rows) <= 1:
        return 0
    total = 0
    for row in rows[1:]:
        if len(row) >= 3 and row[0] == user_id and row[1] == today:
            total = max(total, int(row[2]))
    return total


def reserve_user_scan_slot(user_id: str, daily_limit: int) -> int:
    if daily_limit < 1:
        raise QuotaExceededError("Daily AI scan limit reached.")

    today = get_quota_date_str()
    with _WRITE_LOCK:
        ws = get_usage_worksheet()
        for _attempt in range(4):
            rows = _sheets_call_with_retry(ws.get_all_values)
            if not rows:
                ws.append_row(USAGE_HEADERS, value_input_option="RAW")
                rows = [USAGE_HEADERS]

            matching_indices = [
                (idx, row)
                for idx, row in enumerate(rows[1:], start=2)
                if len(row) >= 3 and row[0] == user_id and row[1] == today
            ]

            if matching_indices:
                row_idx, row = matching_indices[0]
                current = int(row[2])
                if current >= daily_limit:
                    raise QuotaExceededError(
                        f"Daily AI scan limit ({daily_limit}) reached."
                    )
                new_count = current + 1
                claim_stamp = (
                    f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}#{uuid.uuid4().hex[:8]}"
                )
                ws.update(
                    values=[[str(new_count), claim_stamp]],
                    range_name=f"C{row_idx}:D{row_idx}",
                    value_input_option="RAW",
                )
                verify_vals = ws.get(f"C{row_idx}:D{row_idx}")
                if (
                    verify_vals
                    and len(verify_vals[0]) >= 2
                    and verify_vals[0][1] == claim_stamp
                ):
                    get_user_scans_today.clear()
                    return new_count
                time.sleep(0.15)
                continue

            claim_stamp = (
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}#{uuid.uuid4().hex[:8]}"
            )
            ws.append_row(
                [user_id, today, "1", claim_stamp],
                value_input_option="RAW",
                table_range="A1",
            )
            post_rows = _sheets_call_with_retry(ws.get_all_values)
            dups = [
                (idx, r)
                for idx, r in enumerate(post_rows[1:], start=2)
                if len(r) >= 4 and r[0] == user_id and r[1] == today
            ]
            if len(dups) == 1:
                get_user_scans_today.clear()
                return 1
            for idx, r in reversed(dups):
                if r[3] == claim_stamp:
                    ws.delete_rows(idx)
                    break
            time.sleep(0.15)

    raise RuntimeError("Could not reserve a scan slot due to concurrent traffic.")


def release_user_scan_slot(user_id: str) -> None:
    try:
        with _WRITE_LOCK:
            ws = get_usage_worksheet()
            today = get_quota_date_str()
            for _attempt in range(3):
                rows = _sheets_call_with_retry(ws.get_all_values)
                for row_idx, row in enumerate(rows[1:], start=2):
                    if len(row) >= 3 and row[0] == user_id and row[1] == today:
                        current = int(row[2])
                        if current <= 0:
                            return
                        claim_stamp = (
                            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}#{uuid.uuid4().hex[:8]}"
                        )
                        ws.update(
                            values=[[str(current - 1), claim_stamp]],
                            range_name=f"C{row_idx}:D{row_idx}",
                            value_input_option="RAW",
                        )
                        verify_vals = ws.get(f"C{row_idx}:D{row_idx}")
                        if (
                            verify_vals
                            and len(verify_vals[0]) >= 2
                            and verify_vals[0][1] == claim_stamp
                        ):
                            get_user_scans_today.clear()
                            return
                        break
                time.sleep(0.1)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Email OTP Delivery & Verification
# ---------------------------------------------------------------------------
def _send_otp_email(
    recipient_email: str, username: str, code: str, subject: str, purpose_line: str
) -> None:
    smtp_email = str(get_secret("SMTP_EMAIL", "") or "").strip()
    smtp_password = str(get_secret("SMTP_APP_PASSWORD", "") or "").strip()
    smtp_host = str(get_secret("SMTP_HOST", "smtp.gmail.com") or "smtp.gmail.com").strip()
    smtp_port = int(get_secret("SMTP_PORT", 465) or 465)

    if not smtp_email or not smtp_password:
        raise ValueError(
            "Email OTP is not configured yet. Add `SMTP_EMAIL` and "
            "`SMTP_APP_PASSWORD` to Streamlit Secrets."
        )

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = smtp_email
    msg["To"] = recipient_email
    msg.set_content(
        f"Hello {username},\n\n"
        f"{purpose_line}: {code}\n\n"
        f"This code is valid for 10 minutes (maximum {MAX_OTP_GUESS_ATTEMPTS} verification attempts). "
        f"If you did not request this code, please ignore this email.\n"
    )

    with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=15) as server:
        server.login(smtp_email, smtp_password)
        server.send_message(msg)


def _check_otp_send_throttles(purpose_key: str, clean_email: str) -> Tuple[bool, str]:
    session_sends = int(st.session_state.get("otp_sends_this_session", 0))
    if session_sends >= MAX_OTP_SENDS_PER_SESSION:
        return (
            False,
            "You have requested too many verification codes in this browser session. Please try again later.",
        )

    global_ok, _ = _check_rate_limit(
        limit_key="otp_send:global",
        max_attempts=MAX_OTP_SENDS_GLOBAL_HOUR,
        window_seconds=3600,
    )
    if not global_ok:
        return (
            False,
            "Verification email service is temporarily busy. Please try again in a few minutes.",
        )

    return _check_rate_limit(
        limit_key=f"otp_send:{purpose_key}:{clean_email}",
        max_attempts=MAX_OTP_SENDS_PER_EMAIL_HOUR,
        window_seconds=3600,
        cooldown_seconds=OTP_RESEND_COOLDOWN_SEC,
    )


def _record_otp_send_throttles(purpose_key: str, clean_email: str) -> None:
    st.session_state["otp_sends_this_session"] = (
        int(st.session_state.get("otp_sends_this_session", 0)) + 1
    )
    _record_rate_limit_event(
        limit_key="otp_send:global",
        max_attempts=MAX_OTP_SENDS_GLOBAL_HOUR,
        window_seconds=3600,
        lockout_seconds=900,
        reset_window_on_each_event=False,
    )
    _record_rate_limit_event(
        limit_key=f"otp_send:{purpose_key}:{clean_email}",
        max_attempts=MAX_OTP_SENDS_PER_EMAIL_HOUR,
        window_seconds=3600,
        lockout_seconds=3600,
        reset_window_on_each_event=True,
    )


def _issue_otp(
    ws: gspread.Worksheet,
    purpose_key: str,
    email: str,
    username: str,
    subject: str,
    purpose_line: str,
) -> Tuple[bool, str]:
    allowed, rate_msg = _check_otp_send_throttles(purpose_key, email)
    if not allowed:
        return False, rate_msg

    code = f"{secrets.randbelow(900000) + 100000}"
    expires_at = str(int(time.time()) + OTP_TTL_SECONDS)
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    code_hash = hash_password(code)

    try:
        _send_otp_email(email, username, code, subject, purpose_line)
    except ValueError as cfg_err:
        return False, str(cfg_err)
    except Exception:
        return (
            False,
            "Could not send the verification email. Please check your SMTP settings and try again.",
        )

    with _WRITE_LOCK:
        _sheets_call_with_retry(
            lambda: ws.append_row(
                [email, code_hash, expires_at, "no", "0", created_at],
                value_input_option="RAW",
                table_range="A1",
            )
        )

    _record_otp_send_throttles(purpose_key, email)
    return True, f"A 6-digit verification code has been sent to {email} (valid for 10 minutes)."


def _verify_and_consume_otp(
    ws: gspread.Worksheet, email: str, code: str
) -> Tuple[bool, str]:
    clean_email = email.strip().lower()
    clean_code = re.sub(r"\s+", "", code.strip())

    if not re.match(r"^\d{6}$", clean_code):
        return False, "Please enter the 6-digit verification code from your email."

    with _WRITE_LOCK:
        otp_rows = _sheets_call_with_retry(ws.get_all_values)
        if len(otp_rows) <= 1:
            return False, "Invalid or expired verification code."

        matched_row_idx: Optional[int] = None
        matched_data: Optional[list[str]] = None
        for idx in range(len(otp_rows) - 1, 0, -1):
            row = otp_rows[idx]
            if (
                len(row) >= 4
                and row[0].strip().lower() == clean_email
                and row[3].strip().lower() == "no"
            ):
                matched_row_idx = idx + 1
                matched_data = row
                break

        if matched_row_idx is None or matched_data is None:
            return False, "Invalid or expired verification code."

        try:
            expires_at = int(matched_data[2])
            attempts = (
                int(matched_data[4])
                if len(matched_data) >= 5 and matched_data[4].isdigit()
                else 0
            )
        except ValueError:
            return False, "Invalid or expired verification code."

        if attempts >= MAX_OTP_GUESS_ATTEMPTS:
            ws.update(
                values=[["locked"]],
                range_name=f"D{matched_row_idx}",
                value_input_option="RAW",
            )
            return False, "Too many wrong attempts. This code is locked — please request a new code."

        if int(time.time()) > expires_at:
            ws.update(
                values=[["expired"]],
                range_name=f"D{matched_row_idx}",
                value_input_option="RAW",
            )
            return False, "This verification code has expired. Please request a new code."

        if not verify_password(clean_code, matched_data[1]):
            new_attempts = attempts + 1
            new_status = "locked" if new_attempts >= MAX_OTP_GUESS_ATTEMPTS else "no"
            ws.update(
                values=[[new_status, str(new_attempts)]],
                range_name=f"D{matched_row_idx}:E{matched_row_idx}",
                value_input_option="RAW",
            )
            remaining = MAX_OTP_GUESS_ATTEMPTS - new_attempts
            if remaining <= 0:
                return False, "Too many wrong attempts. This code is locked — please request a new code."
            return False, f"Incorrect verification code ({remaining} attempt(s) remaining)."

        claim_token = f"yes:{uuid.uuid4().hex[:10]}"
        ws.update(
            values=[[claim_token, str(attempts + 1)]],
            range_name=f"D{matched_row_idx}:E{matched_row_idx}",
            value_input_option="RAW",
        )
        verify_vals = ws.get(f"D{matched_row_idx}")
        if not verify_vals or not verify_vals[0] or verify_vals[0][0] != claim_token:
            return False, "This verification code was already used or locked. Please request a new code."

        return True, "Verified."


# ---------------------------------------------------------------------------
# User Authentication, OTP Registration & Generic Password Recovery
# ---------------------------------------------------------------------------
@st.cache_data(ttl=60, show_spinner=False)
def fetch_all_users() -> list[dict[str, str]]:
    ws = get_users_worksheet()
    all_rows = _sheets_call_with_retry(ws.get_all_values)
    if len(all_rows) <= 1:
        return []

    headers = all_rows[0]
    users = []
    for row in all_rows[1:]:
        if not any(cell.strip() for cell in row):
            continue
        padded = row + [""] * (len(headers) - len(row))
        users.append(dict(zip(headers, padded)))
    return users


def start_registration_otp(
    username: str, email: str, password: str
) -> Tuple[bool, str, Optional[dict[str, str]]]:
    clean_username = username.strip()
    clean_email = email.strip().lower()

    if not is_valid_username(clean_username):
        return (
            False,
            "Username must be 3–30 characters using only letters, numbers, `_`, `.`, or `-`.",
            None,
        )
    if not is_valid_email(clean_email):
        return False, "Please enter a valid email address.", None

    pw_ok, pw_msg = validate_password_strength(password)
    if not pw_ok:
        return False, pw_msg, None

    fetch_all_users.clear()
    for user in fetch_all_users():
        if user.get("username", "").strip().lower() == clean_username.lower():
            return False, "That username is already taken. Try another one.", None
        if user.get("email", "").strip().lower() == clean_email:
            return False, "An account with this email already exists. Please log in.", None

    ok, msg = _issue_otp(
        ws=get_register_otps_worksheet(),
        purpose_key="register",
        email=clean_email,
        username=clean_username,
        subject="Verify Your Email — Visiting Card Scanner",
        purpose_line="Your registration verification code is",
    )
    if not ok:
        return False, msg, None

    pending_data = {
        "username": clean_username,
        "email": clean_email,
        "password_hash": hash_password(password),
    }
    return True, msg, pending_data


def resend_registration_otp(pending_data: dict[str, str]) -> Tuple[bool, str]:
    return _issue_otp(
        ws=get_register_otps_worksheet(),
        purpose_key="register",
        email=pending_data["email"],
        username=pending_data["username"],
        subject="Verify Your Email — Visiting Card Scanner",
        purpose_line="Your new registration verification code is",
    )


def complete_registration_with_otp(
    pending_data: dict[str, str], otp_code: str
) -> Tuple[bool, str, Optional[dict[str, str]]]:
    clean_username = pending_data["username"]
    clean_email = pending_data["email"]
    pw_hash = pending_data["password_hash"]

    ok, msg = _verify_and_consume_otp(
        ws=get_register_otps_worksheet(),
        email=clean_email,
        code=otp_code,
    )
    if not ok:
        return False, msg, None

    with _WRITE_LOCK:
        fetch_all_users.clear()
        for user in fetch_all_users():
            if user.get("username", "").strip().lower() == clean_username.lower():
                return False, "That username was just taken. Please pick another one.", None
            if user.get("email", "").strip().lower() == clean_email:
                return False, "An account with this email already exists. Please log in.", None

        user_id = f"usr_{uuid.uuid4().hex}"
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        ws = get_users_worksheet()
        ws.append_row(
            [user_id, clean_username, clean_email, pw_hash, "user", created_at],
            value_input_option="RAW",
            table_range="A1",
        )
        fetch_all_users.clear()

    new_user = {
        "user_id": user_id,
        "username": clean_username,
        "email": clean_email,
        "role": "user",
    }
    return True, "Email verified and account created! Welcome.", new_user


def authenticate_user(
    identifier: str, password: str
) -> Tuple[bool, str, Optional[dict[str, str]]]:
    clean_id = identifier.strip().lower()
    if not clean_id or not password:
        return False, "Please enter both username/email and password.", None

    rate_key = f"login:{clean_id}"
    allowed, lock_msg = _check_rate_limit(
        limit_key=rate_key,
        max_attempts=MAX_LOGIN_ATTEMPTS,
        window_seconds=LOGIN_LOCKOUT_SECONDS,
    )
    if not allowed:
        return False, lock_msg, None

    users = fetch_all_users()
    matched_users = [
        u
        for u in users
        if clean_id
        in (
            u.get("username", "").strip().lower(),
            u.get("email", "").strip().lower(),
        )
    ]
    if not matched_users:
        fetch_all_users.clear()
        users = fetch_all_users()
        matched_users = [
            u
            for u in users
            if clean_id
            in (
                u.get("username", "").strip().lower(),
                u.get("email", "").strip().lower(),
            )
        ]

    for user in matched_users:
        if verify_password(password, user.get("password_hash", "")):
            _clear_rate_limit(rate_key)
            return (
                True,
                "Logged in successfully.",
                {
                    "user_id": user.get("user_id", ""),
                    "username": user.get("username", ""),
                    "email": user.get("email", ""),
                    "role": user.get("role", "user"),
                },
            )
        _record_rate_limit_event(
            limit_key=rate_key,
            max_attempts=MAX_LOGIN_ATTEMPTS,
            window_seconds=LOGIN_LOCKOUT_SECONDS,
            lockout_seconds=LOGIN_LOCKOUT_SECONDS,
        )
        return False, "Invalid username/email or password.", None

    _record_rate_limit_event(
        limit_key=rate_key,
        max_attempts=MAX_LOGIN_ATTEMPTS,
        window_seconds=LOGIN_LOCKOUT_SECONDS,
        lockout_seconds=LOGIN_LOCKOUT_SECONDS,
    )
    return False, "Invalid username/email or password.", None


def request_password_reset(email: str) -> Tuple[bool, str]:
    clean_email = email.strip().lower()
    if not is_valid_email(clean_email):
        return False, "Please enter a valid email address."

    allowed, rate_msg = _check_otp_send_throttles("reset", clean_email)
    if not allowed:
        return False, rate_msg

    generic_msg = (
        "If an account is registered with that email address, "
        "a 6-digit reset code has been sent (valid for 10 minutes)."
    )

    users = fetch_all_users()
    matched_user = next(
        (u for u in users if u.get("email", "").strip().lower() == clean_email),
        None,
    )
    if matched_user is None:
        fetch_all_users.clear()
        users = fetch_all_users()
        matched_user = next(
            (u for u in users if u.get("email", "").strip().lower() == clean_email),
            None,
        )

    if not matched_user:
        _record_otp_send_throttles("reset", clean_email)
        return True, generic_msg

    ok, err_msg = _issue_otp(
        ws=get_resets_worksheet(),
        purpose_key="reset",
        email=clean_email,
        username=matched_user.get("username", "User"),
        subject="Your Visiting Card Scanner Password Reset Code",
        purpose_line="Your password reset verification code is",
    )
    if not ok:
        return False, err_msg

    return True, generic_msg


def confirm_password_reset(
    email: str, code: str, new_password: str
) -> Tuple[bool, str]:
    clean_email = email.strip().lower()

    if not is_valid_email(clean_email):
        return False, "Please enter a valid email address."

    pw_ok, pw_msg = validate_password_strength(new_password)
    if not pw_ok:
        return False, pw_msg

    ok, msg = _verify_and_consume_otp(
        ws=get_resets_worksheet(),
        email=clean_email,
        code=code,
    )
    if not ok:
        return False, msg

    target_user_id = ""
    with _WRITE_LOCK:
        users_ws = get_users_worksheet()
        user_rows = _sheets_call_with_retry(users_ws.get_all_values)
        updated_user = False
        for row_idx, row in enumerate(user_rows[1:], start=2):
            if len(row) >= 4 and row[2].strip().lower() == clean_email:
                target_user_id = row[0]
                new_hash = hash_password(new_password)
                users_ws.update(
                    values=[[new_hash]],
                    range_name=f"D{row_idx}",
                    value_input_option="RAW",
                )
                updated_user = True
                break

        if not updated_user:
            return False, "Invalid or expired verification code."

        fetch_all_users.clear()

    if target_user_id:
        revoke_all_user_sessions(target_user_id)
        _clear_rate_limit(f"login:{clean_email}")

    return True, "Password updated and all active sessions signed out. Please log in with your new password."


# ---------------------------------------------------------------------------
# Visiting Card CRUD, Atomic Duplicate-Safe Saves, Soft-Delete & Audit
# ---------------------------------------------------------------------------
@st.cache_data(ttl=60, show_spinner=False)
def _fetch_all_card_rows() -> list[list[str]]:
    ws = get_cards_worksheet()
    all_rows = _sheets_call_with_retry(ws.get_all_values)
    if not all_rows:
        ws.append_row(CARD_HEADERS, value_input_option="RAW")
        return [CARD_HEADERS]

    first_row = all_rows[0]
    if "record_id" not in first_row and "user_id" not in first_row:
        ws.insert_row(CARD_HEADERS, index=1, value_input_option="RAW")
        return [CARD_HEADERS, *all_rows]

    if "Extra Details" in first_row and "extra_data" not in first_row:
        fixed_headers = [
            "extra_data" if col == "Extra Details" else col for col in first_row
        ]
        ws.update(values=[fixed_headers], range_name="A1", value_input_option="RAW")
        all_rows[0] = fixed_headers

    return all_rows


def _rows_to_user_df(
    all_rows: list[list[str]], user_id: str, include_deleted: bool = False
) -> pd.DataFrame:
    if len(all_rows) <= 1:
        return pd.DataFrame(columns=ALL_RECORD_COLUMNS)

    headers = all_rows[0]
    data_rows = []
    for row in all_rows[1:]:
        if not any(cell.strip() for cell in row):
            continue
        padded = row + [""] * (len(headers) - len(row))
        record = dict(zip(headers, padded))
        if record.get("user_id") == user_id:
            deleted_at = str(record.get("deleted_at", "")).strip()
            if not include_deleted and deleted_at:
                continue
            raw_extra = record.get("extra_data") or record.get("Extra Details") or ""
            extra_dict = parse_extra_data(raw_extra)
            extra_json_clean, _ = validate_and_serialize_extra_data(
                extra_dict, strict=False
            )
            data_rows.append(
                {
                    "Record ID": record.get("record_id", ""),
                    "Company Name": record.get("company_name", "N/A") or "N/A",
                    "Contact Person": record.get("contact_person", "N/A") or "N/A",
                    "Contact No.": format_phone_numbers(record.get("call_phone", "N/A")),
                    "WhatsApp No.": format_phone_numbers(
                        record.get("whatsapp_phone", "N/A")
                    ),
                    "Email": format_emails(record.get("email", "N/A")),
                    "Product / Services": record.get("products_services", "N/A") or "N/A",
                    "Address": record.get("address", "N/A") or "N/A",
                    "City": record.get("city", "N/A") or "N/A",
                    "Notes": record.get("notes", "") or "N/A",
                    "Saved On": record.get("created_at", ""),
                    "Extra Details": format_extra_data_summary(extra_dict),
                    "Extra Data JSON": extra_json_clean,
                    "Deleted At": deleted_at,
                }
            )

    if not data_rows:
        return pd.DataFrame(columns=ALL_RECORD_COLUMNS)

    return pd.DataFrame(data_rows[::-1], columns=ALL_RECORD_COLUMNS)


def fetch_user_records(user_id: str, include_deleted: bool = False) -> pd.DataFrame:
    return _rows_to_user_df(_fetch_all_card_rows(), user_id, include_deleted)


def search_records_df(df: pd.DataFrame, query: str) -> pd.DataFrame:
    q = query.strip()
    if not q or df.empty:
        return df.iloc[0:0]

    mask = (
        df["Company Name"].str.contains(q, case=False, na=False, regex=False)
        | df["Contact Person"].str.contains(q, case=False, na=False, regex=False)
        | df["Contact No."].str.contains(q, case=False, na=False, regex=False)
        | df["WhatsApp No."].str.contains(q, case=False, na=False, regex=False)
        | df["Email"].str.contains(q, case=False, na=False, regex=False)
        | df["Product / Services"].str.contains(q, case=False, na=False, regex=False)
        | df["Address"].str.contains(q, case=False, na=False, regex=False)
        | df["City"].str.contains(q, case=False, na=False, regex=False)
        | df["Notes"].str.contains(q, case=False, na=False, regex=False)
        | df["Extra Details"].str.contains(q, case=False, na=False, regex=False)
    )
    return df[mask]


def _find_duplicates_in_df(
    existing_df: pd.DataFrame,
    call_phone: str,
    whatsapp_phone: str,
    email: str,
) -> list[dict[str, Any]]:
    new_phones = extract_normalized_phones(call_phone) | extract_normalized_phones(
        whatsapp_phone
    )
    new_emails = extract_normalized_emails(email)

    if existing_df.empty or (not new_phones and not new_emails):
        return []

    matches: list[dict[str, Any]] = []
    for _, row in existing_df.iterrows():
        existing_phones = extract_normalized_phones(
            str(row.get("Contact No.", ""))
        ) | extract_normalized_phones(str(row.get("WhatsApp No.", "")))
        existing_emails = extract_normalized_emails(str(row.get("Email", "")))

        matched_phones = sorted(new_phones & existing_phones)
        matched_emails = sorted(new_emails & existing_emails)

        if matched_phones or matched_emails:
            reasons = []
            if matched_phones:
                reasons.append(f"Phone: {' / '.join(matched_phones)}")
            if matched_emails:
                reasons.append(f"Email: {', '.join(matched_emails)}")
            matches.append(
                {
                    "Company Name": row["Company Name"],
                    "Contact Person": row["Contact Person"],
                    "Contact No.": row["Contact No."],
                    "WhatsApp No.": row["WhatsApp No."],
                    "Email": row["Email"],
                    "City": row["City"],
                    "Saved On": row["Saved On"],
                    "Matched By": " | ".join(reasons),
                }
            )

    return matches


def _ensure_cards_header(ws: gspread.Worksheet) -> None:
    first_row = ws.row_values(1)
    if not first_row:
        ws.append_row(CARD_HEADERS, value_input_option="RAW", table_range="A1")
    elif "record_id" not in first_row and "user_id" not in first_row:
        ws.insert_row(CARD_HEADERS, index=1, value_input_option="RAW")


def save_record_atomic(
    user_id: str,
    company_name: str,
    contact_person: str,
    call_phone: str,
    whatsapp_phone: str,
    email: str,
    products_services: str,
    address: str,
    city: str,
    notes: str,
    extra_data: Optional[dict[str, str]] = None,
    allow_duplicate: bool = False,
) -> Tuple[Optional[str], list[dict[str, Any]]]:
    extra_json, _ = validate_and_serialize_extra_data(extra_data or {}, strict=True)

    with _WRITE_LOCK:
        ws = get_cards_worksheet()
        _ensure_cards_header(ws)

        if not allow_duplicate:
            fresh_rows = _sheets_call_with_retry(ws.get_all_values)
            fresh_df = _rows_to_user_df(fresh_rows, user_id, include_deleted=False)
            matches = _find_duplicates_in_df(
                fresh_df, call_phone, whatsapp_phone, email
            )
            if matches:
                return None, matches

        record_id = str(uuid.uuid4())
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        clean_company = sanitize_text_field(company_name, MAX_FIELD_LEN) or "N/A"

        row = [
            record_id,
            user_id,
            clean_company,
            sanitize_text_field(contact_person, MAX_FIELD_LEN) or "N/A",
            format_phone_numbers(call_phone),
            format_phone_numbers(whatsapp_phone),
            format_emails(email),
            sanitize_text_field(products_services, MAX_FIELD_LEN) or "N/A",
            sanitize_text_field(address, MAX_LONG_FIELD_LEN) or "N/A",
            sanitize_text_field(city, 100) or "N/A",
            sanitize_text_field(notes, MAX_LONG_FIELD_LEN) or "N/A",
            timestamp,
            extra_json,
            "",
        ]

        _sheets_call_with_retry(
            lambda: ws.append_row(row, value_input_option="RAW", table_range="A1")
        )
        _fetch_all_card_rows.clear()

    append_audit_log(user_id, "CREATE", record_id, f"Saved card: {clean_company}")
    return record_id, []


def merge_excel_records_atomic(
    raw_df: pd.DataFrame,
    col_mapping: dict[str, str],
    unmapped_extra_cols: list[str],
    user_id: str,
    skip_duplicates: bool,
    source_name: str,
) -> Tuple[int, int, int, list[str]]:
    with _WRITE_LOCK:
        ws = get_cards_worksheet()
        _ensure_cards_header(ws)

        existing_phones: set[str] = set()
        existing_emails: set[str] = set()
        if skip_duplicates:
            fresh_df = _rows_to_user_df(
                _sheets_call_with_retry(ws.get_all_values),
                user_id,
                include_deleted=False,
            )
            for _, ex_row in fresh_df.iterrows():
                existing_phones |= extract_normalized_phones(
                    str(ex_row.get("Contact No.", ""))
                )
                existing_phones |= extract_normalized_phones(
                    str(ex_row.get("WhatsApp No.", ""))
                )
                existing_emails |= extract_normalized_emails(str(ex_row.get("Email", "")))

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        rows_to_append: list[list[str]] = []
        skipped_dups = 0
        skipped_empty = 0
        dropped_extra_keys: set[str] = set()

        for _, row in raw_df.iterrows():
            raw_vals: dict[str, str] = {}
            for field_key in EXCEL_COLUMN_ALIASES:
                src_col = col_mapping.get(field_key, "")
                raw_vals[field_key] = (
                    _clean_excel_cell(row[src_col])
                    if src_col and src_col in raw_df.columns
                    else ""
                )

            extra_dict: dict[str, str] = {}
            for extra_col in unmapped_extra_cols:
                if extra_col in raw_df.columns:
                    val = _clean_excel_cell(row[extra_col])
                    if val and val.upper() != "N/A":
                        extra_dict[sanitize_text_field(extra_col, 80)] = (
                            sanitize_text_field(val, MAX_FIELD_LEN)
                        )

            if not has_at_least_one_field(*raw_vals.values(), *extra_dict.values()):
                skipped_empty += 1
                continue

            formatted_call = format_phone_numbers(raw_vals["call_phone"])
            formatted_wp = format_phone_numbers(raw_vals["whatsapp_phone"])
            clean_email = format_emails(raw_vals["email"])

            row_phones = extract_normalized_phones(
                formatted_call
            ) | extract_normalized_phones(formatted_wp)
            row_emails = extract_normalized_emails(clean_email)

            if skip_duplicates and (
                (row_phones and (row_phones & existing_phones))
                or (row_emails and (row_emails & existing_emails))
            ):
                skipped_dups += 1
                continue

            existing_phones |= row_phones
            existing_emails |= row_emails

            extra_json, dropped_for_row = validate_and_serialize_extra_data(
                extra_dict, strict=False
            )
            dropped_extra_keys.update(dropped_for_row)

            rows_to_append.append(
                [
                    str(uuid.uuid4()),
                    user_id,
                    sanitize_text_field(raw_vals["company_name"], MAX_FIELD_LEN) or "N/A",
                    sanitize_text_field(raw_vals["contact_person"], MAX_FIELD_LEN) or "N/A",
                    formatted_call,
                    formatted_wp,
                    clean_email,
                    sanitize_text_field(raw_vals["products_services"], MAX_FIELD_LEN) or "N/A",
                    sanitize_text_field(raw_vals["address"], MAX_LONG_FIELD_LEN) or "N/A",
                    sanitize_text_field(raw_vals["city"], 100) or "N/A",
                    sanitize_text_field(raw_vals["notes"], MAX_LONG_FIELD_LEN) or "N/A",
                    timestamp,
                    extra_json,
                    "",
                ]
            )

        if rows_to_append:
            _sheets_call_with_retry(
                lambda: ws.append_rows(
                    rows_to_append, value_input_option="RAW", table_range="A1"
                )
            )
            _fetch_all_card_rows.clear()

    if rows_to_append:
        append_audit_log(
            user_id,
            "BATCH_MERGE",
            f"batch_{len(rows_to_append)}",
            f"Merged {len(rows_to_append)} records from {source_name}",
        )

    return len(rows_to_append), skipped_dups, skipped_empty, sorted(dropped_extra_keys)


def update_record(
    record_id: str,
    user_id: str,
    company_name: str,
    contact_person: str,
    call_phone: str,
    whatsapp_phone: str,
    email: str,
    products_services: str,
    address: str,
    city: str,
    notes: str,
    extra_data: Optional[dict[str, str]] = None,
) -> bool:
    extra_json, _ = validate_and_serialize_extra_data(extra_data or {}, strict=True)

    with _WRITE_LOCK:
        ws = get_cards_worksheet()
        all_rows = _sheets_call_with_retry(ws.get_all_values)
        if len(all_rows) <= 1:
            return False

        headers = all_rows[0]
        for sheet_row_idx, row in enumerate(all_rows[1:], start=2):
            padded = row + [""] * (len(headers) - len(row))
            existing = dict(zip(headers, padded))

            if (
                existing.get("record_id") == record_id
                and existing.get("user_id") == user_id
                and not str(existing.get("deleted_at", "")).strip()
            ):
                original_created_at = existing.get(
                    "created_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                )
                clean_company = sanitize_text_field(company_name, MAX_FIELD_LEN) or "N/A"
                updated_row = [
                    record_id,
                    user_id,
                    clean_company,
                    sanitize_text_field(contact_person, MAX_FIELD_LEN) or "N/A",
                    format_phone_numbers(call_phone),
                    format_phone_numbers(whatsapp_phone),
                    format_emails(email),
                    sanitize_text_field(products_services, MAX_FIELD_LEN) or "N/A",
                    sanitize_text_field(address, MAX_LONG_FIELD_LEN) or "N/A",
                    sanitize_text_field(city, 100) or "N/A",
                    sanitize_text_field(notes, MAX_LONG_FIELD_LEN) or "N/A",
                    original_created_at,
                    extra_json,
                    "",
                ]
                end_cell = rowcol_to_a1(sheet_row_idx, len(CARD_HEADERS))
                ws.update(
                    values=[updated_row],
                    range_name=f"A{sheet_row_idx}:{end_cell}",
                    value_input_option="RAW",
                )
                _fetch_all_card_rows.clear()
                append_audit_log(
                    user_id, "UPDATE", record_id, f"Updated card: {clean_company}"
                )
                return True

    return False


def soft_delete_record(record_id: str, user_id: str) -> bool:
    with _WRITE_LOCK:
        ws = get_cards_worksheet()
        all_rows = _sheets_call_with_retry(ws.get_all_values)
        if len(all_rows) <= 1:
            return False

        headers = all_rows[0]
        del_col_idx = (
            headers.index("deleted_at") + 1
            if "deleted_at" in headers
            else len(CARD_HEADERS)
        )
        del_cell_col = rowcol_to_a1(1, del_col_idx)[0]
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        for sheet_row_idx, row in enumerate(all_rows[1:], start=2):
            row_record_id = row[0] if len(row) > 0 else ""
            row_user_id = row[1] if len(row) > 1 else ""
            company_label = row[2] if len(row) > 2 else ""
            if row_record_id == record_id and row_user_id == user_id:
                ws.update(
                    values=[[now_str]],
                    range_name=f"{del_cell_col}{sheet_row_idx}",
                    value_input_option="RAW",
                )
                _fetch_all_card_rows.clear()
                append_audit_log(
                    user_id,
                    "SOFT_DELETE",
                    record_id,
                    f"Moved to Trash: {company_label}",
                )
                return True

    return False


def restore_deleted_record(record_id: str, user_id: str) -> bool:
    with _WRITE_LOCK:
        ws = get_cards_worksheet()
        all_rows = _sheets_call_with_retry(ws.get_all_values)
        if len(all_rows) <= 1:
            return False

        headers = all_rows[0]
        del_col_idx = (
            headers.index("deleted_at") + 1
            if "deleted_at" in headers
            else len(CARD_HEADERS)
        )
        del_cell_col = rowcol_to_a1(1, del_col_idx)[0]

        for sheet_row_idx, row in enumerate(all_rows[1:], start=2):
            row_record_id = row[0] if len(row) > 0 else ""
            row_user_id = row[1] if len(row) > 1 else ""
            company_label = row[2] if len(row) > 2 else ""
            if row_record_id == record_id and row_user_id == user_id:
                ws.update(
                    values=[[""]],
                    range_name=f"{del_cell_col}{sheet_row_idx}",
                    value_input_option="RAW",
                )
                _fetch_all_card_rows.clear()
                append_audit_log(
                    user_id,
                    "RESTORE",
                    record_id,
                    f"Restored from Trash: {company_label}",
                )
                return True

    return False


# ---------------------------------------------------------------------------
# Formula-Safe Excel Export (Headers + Cells) & Bounded Spreadsheet Streaming
# ---------------------------------------------------------------------------
_FORMULA_TRIGGER_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def sanitize_excel_cell(val: Any) -> Any:
    if not isinstance(val, str):
        return val
    stripped = val.lstrip()
    if stripped and stripped[0] in _FORMULA_TRIGGER_PREFIXES:
        return f"'{val}"
    return val


def sanitize_df_for_excel(df: pd.DataFrame) -> pd.DataFrame:
    safe_df = df.copy()
    safe_headers: list[str] = []
    seen_headers: set[str] = set()
    for raw_col in safe_df.columns:
        clean_hdr = str(sanitize_excel_cell(str(raw_col).strip())) or "Column"
        candidate = clean_hdr
        counter = 2
        while candidate.lower() in seen_headers:
            candidate = f"{clean_hdr}_{counter}"
            counter += 1
        seen_headers.add(candidate.lower())
        safe_headers.append(candidate)

    safe_df.columns = safe_headers
    for col in safe_df.columns:
        safe_df[col] = safe_df[col].map(sanitize_excel_cell)
    return safe_df


def build_excel_bytes(df: pd.DataFrame, sheet_name: str = "Visiting Cards") -> bytes:
    safe_df = sanitize_df_for_excel(df)
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        safe_df.to_excel(writer, index=False, sheet_name=sheet_name[:31])
        worksheet = writer.sheets[sheet_name[:31]]

        for col_idx, col_name in enumerate(safe_df.columns, start=1):
            max_cell_len = (
                safe_df[col_name].astype(str).map(len).max() if not safe_df.empty else 0
            )
            col_width = min(max(len(str(col_name)), max_cell_len) + 4, 50)
            col_letter = worksheet.cell(row=1, column=col_idx).column_letter
            worksheet.column_dimensions[col_letter].width = col_width

    return output.getvalue()


def build_multi_sheet_excel_bytes(sheets: dict[str, pd.DataFrame]) -> bytes:
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        for raw_name, df in sheets.items():
            safe_df = sanitize_df_for_excel(df)
            safe_name = raw_name[:31]
            safe_df.to_excel(writer, index=False, sheet_name=safe_name)
            worksheet = writer.sheets[safe_name]
            for col_idx, col_name in enumerate(safe_df.columns, start=1):
                max_cell_len = (
                    safe_df[col_name].astype(str).map(len).max()
                    if not safe_df.empty
                    else 0
                )
                col_width = min(max(len(str(col_name)), max_cell_len) + 4, 52)
                col_letter = worksheet.cell(row=1, column=col_idx).column_letter
                worksheet.column_dimensions[col_letter].width = col_width
    return output.getvalue()


def _dedupe_import_headers(raw_header_row: list[Any]) -> list[str]:
    headers: list[str] = []
    seen_hdrs: set[str] = set()
    for idx, raw_h in enumerate(raw_header_row):
        base_h = sanitize_text_field(raw_h, 80) if raw_h is not None else ""
        if not base_h:
            base_h = f"Column_{idx + 1}"
        candidate = base_h
        suffix_num = 2
        while candidate.lower() in seen_hdrs:
            candidate = f"{base_h}_{suffix_num}"
            suffix_num += 1
        seen_hdrs.add(candidate.lower())
        headers.append(candidate)
    return headers


def read_bounded_spreadsheet(uploaded_file: Any) -> pd.DataFrame:
    if getattr(uploaded_file, "size", 0) > MAX_EXCEL_FILE_BYTES:
        raise ValueError("Uploaded spreadsheet exceeds the 2 MB limit.")

    fname = str(getattr(uploaded_file, "name", "")).lower()
    raw_bytes = uploaded_file.getvalue()

    if fname.endswith(".csv"):
        try:
            text_data = raw_bytes.decode("utf-8-sig")
        except UnicodeDecodeError:
            text_data = raw_bytes.decode("latin-1", errors="replace")

        reader = csv.reader(io.StringIO(text_data))
        header_row = next(reader, None)
        if header_row is None:
            return pd.DataFrame()

        if len(header_row) > MAX_EXCEL_IMPORT_COLS:
            raise ValueError(
                f"File exceeds the maximum limit of {MAX_EXCEL_IMPORT_COLS} columns."
            )

        headers = _dedupe_import_headers(header_row)
        collected_rows: list[list[str]] = []
        physical_rows_scanned = 0

        for raw_row in reader:
            physical_rows_scanned += 1
            if physical_rows_scanned > MAX_PHYSICAL_ROWS_SCANNED:
                raise ValueError(
                    f"CSV exceeds the maximum scan limit of {MAX_PHYSICAL_ROWS_SCANNED} rows (including blank rows)."
                )
            if len(raw_row) > MAX_EXCEL_IMPORT_COLS:
                raise ValueError(
                    f"File exceeds the maximum limit of {MAX_EXCEL_IMPORT_COLS} columns."
                )
            padded = list(raw_row) + [""] * (len(headers) - len(raw_row))
            str_row = [str(cell) for cell in padded[: len(headers)]]
            if not any(cell.strip() for cell in str_row):
                continue
            collected_rows.append(str_row)
            if len(collected_rows) > MAX_EXCEL_IMPORT_ROWS:
                raise ValueError(
                    f"File exceeds the maximum limit of {MAX_EXCEL_IMPORT_ROWS} rows per import."
                )

        return pd.DataFrame(collected_rows, columns=headers)

    wb = openpyxl.load_workbook(
        io.BytesIO(raw_bytes), read_only=True, data_only=True
    )
    try:
        ws = wb.active
        if ws.max_column is not None and ws.max_column > MAX_EXCEL_IMPORT_COLS:
            raise ValueError(
                f"File exceeds the maximum limit of {MAX_EXCEL_IMPORT_COLS} columns."
            )
        if ws.max_row is not None and ws.max_row > (MAX_PHYSICAL_ROWS_SCANNED + 1):
            raise ValueError(
                f"Worksheet exceeds the maximum physical limit of {MAX_PHYSICAL_ROWS_SCANNED} rows "
                "(including blank rows). Remove empty trailing rows and try again."
            )

        row_iter = ws.iter_rows(values_only=True)
        header_row = next(row_iter, None)
        if header_row is None:
            return pd.DataFrame()

        if len(header_row) > MAX_EXCEL_IMPORT_COLS:
            raise ValueError(
                f"File exceeds the maximum limit of {MAX_EXCEL_IMPORT_COLS} columns."
            )

        headers = _dedupe_import_headers(list(header_row))
        collected_rows = []
        physical_rows_scanned = 0

        for raw_row in row_iter:
            physical_rows_scanned += 1
            if physical_rows_scanned > MAX_PHYSICAL_ROWS_SCANNED:
                raise ValueError(
                    f"Worksheet exceeds the maximum physical scan limit of {MAX_PHYSICAL_ROWS_SCANNED} rows "
                    "(including blank rows). Remove empty trailing rows and try again."
                )
            if len(raw_row) > MAX_EXCEL_IMPORT_COLS:
                raise ValueError(
                    f"File exceeds the maximum limit of {MAX_EXCEL_IMPORT_COLS} columns."
                )
            padded = list(raw_row) + [None] * (len(headers) - len(raw_row))
            str_row = [
                "" if cell is None else str(cell) for cell in padded[: len(headers)]
            ]
            if not any(cell.strip() for cell in str_row):
                continue
            collected_rows.append(str_row)
            if len(collected_rows) > MAX_EXCEL_IMPORT_ROWS:
                raise ValueError(
                    f"File exceeds the maximum limit of {MAX_EXCEL_IMPORT_ROWS} rows per import."
                )

        return pd.DataFrame(collected_rows, columns=headers)
    finally:
        wb.close()


def _normalize_col_key(col_name: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(col_name).strip().lower()).strip()


def _auto_detect_excel_mapping(columns: list[str]) -> dict[str, str]:
    norm_to_orig = {_normalize_col_key(c): c for c in columns}
    mapping: dict[str, str] = {}
    used_cols: set[str] = set()

    for field_key, aliases in EXCEL_COLUMN_ALIASES.items():
        matched_col = ""
        for alias in aliases:
            norm_alias = _normalize_col_key(alias)
            if norm_alias in norm_to_orig and norm_to_orig[norm_alias] not in used_cols:
                matched_col = norm_to_orig[norm_alias]
                break
        if not matched_col:
            for norm_col, orig_col in norm_to_orig.items():
                if orig_col in used_cols:
                    continue
                if any(_normalize_col_key(a) in norm_col for a in aliases[:4]):
                    matched_col = orig_col
                    break
        if matched_col:
            mapping[field_key] = matched_col
            used_cols.add(matched_col)
        else:
            mapping[field_key] = ""

    return mapping


def _clean_excel_cell(val: Any) -> str:
    if val is None or pd.isna(val):
        return ""
    s = sanitize_text_field(val, MAX_LONG_FIELD_LEN)
    if s.lower() in ("nan", "none", "nat"):
        return ""
    return s


def preview_excel_merge_rows(
    raw_df: pd.DataFrame,
    col_mapping: dict[str, str],
    unmapped_extra_cols: list[str],
) -> list[dict[str, Any]]:
    preview: list[dict[str, Any]] = []
    for _, row in raw_df.head(5).iterrows():
        raw_vals: dict[str, str] = {}
        for field_key in EXCEL_COLUMN_ALIASES:
            src_col = col_mapping.get(field_key, "")
            raw_vals[field_key] = (
                _clean_excel_cell(row[src_col])
                if src_col and src_col in raw_df.columns
                else ""
            )

        extra_dict: dict[str, str] = {}
        for extra_col in unmapped_extra_cols:
            if extra_col in raw_df.columns:
                val = _clean_excel_cell(row[extra_col])
                if val and val.upper() != "N/A":
                    extra_dict[sanitize_text_field(extra_col, 80)] = sanitize_text_field(
                        val, MAX_FIELD_LEN
                    )

        if not has_at_least_one_field(*raw_vals.values(), *extra_dict.values()):
            continue

        clean_email = format_emails(raw_vals["email"])
        preview.append(
            {
                "company_name": sanitize_text_field(raw_vals["company_name"], MAX_FIELD_LEN) or "N/A",
                "contact_person": sanitize_text_field(raw_vals["contact_person"], MAX_FIELD_LEN) or "N/A",
                "call_phone": format_phone_numbers(raw_vals["call_phone"]),
                "whatsapp_phone": format_phone_numbers(raw_vals["whatsapp_phone"]),
                "email": clean_email,
                "products_services": sanitize_text_field(raw_vals["products_services"], MAX_FIELD_LEN) or "N/A",
                "address": sanitize_text_field(raw_vals["address"], MAX_LONG_FIELD_LEN) or "N/A",
                "city": sanitize_text_field(raw_vals["city"], 100) or "N/A",
                "notes": sanitize_text_field(raw_vals["notes"], MAX_LONG_FIELD_LEN) or "N/A",
                "extra_data": extra_dict,
            }
        )
    return preview


# ---------------------------------------------------------------------------
# Anti-504 Gemini AI Extraction & Marketing Text Generation Helpers
# ---------------------------------------------------------------------------
class ScanUnavailableError(Exception):
    pass


def extract_card_details(
    images: list[Tuple[bytes, str]], api_key: str
) -> Tuple[VisitingCard, dict[str, str], str]:
    if not api_key or not api_key.strip():
        raise ValueError(
            "Scanner API key is missing. Add it in Streamlit Secrets or Settings."
        )
    if not images:
        raise ValueError("Please provide at least one visiting card image.")

    optimized_images = [
        optimize_card_image(raw_bytes, mime) for raw_bytes, mime in images
    ]

    side_note = (
        "You are given 2 images showing the FRONT and BACK sides of the SAME visiting card. "
        "Combine and merge all details found across both sides into one unified record without duplicating numbers or text. "
        if len(optimized_images) == 2
        else "You are given 1 image of a visiting card. "
    )

    prompt = (
        f"{side_note}"
        "Extract the business details accurately.\n\n"
        "IMPORTANT LANGUAGE RULE:\n"
        "- Always output EVERY field strictly in English (Latin alphabet) with standard Western digits (0-9), "
        "regardless of the language printed on the card (Gujarati, Hindi, Marathi, Tamil, etc.).\n"
        "- Transliterate proper nouns (company names, person names, road/area/city names) into clean, readable English.\n"
        "- Translate descriptive words, landmarks, and products/services into natural English "
        "(keep widely known Indian item names in standard English spelling, e.g., Bhajiya, Jalebi, Boondi Laddu, Mohanthal).\n"
        "- Convert ALL regional numerals (e.g., Gujarati ૦-૯, Hindi ०-९) into standard 0-9 digits.\n\n"
        "IMPORTANT PHONE FORMAT & CLASSIFICATION RULE (whatsapp_phone vs call_phone):\n"
        "- Format all numbers cleanly as plain digits without '+91' or dashes, separated by ' / ' "
        "(example: '9876543210 / 9123456789').\n"
        "- Carefully inspect icons (WhatsApp logo vs phone handset/landline icon) and text labels "
        "('WP', 'WA', 'WhatsApp' vs 'Call', 'Ph', 'Tel', 'Office', 'Landline', 'Contact').\n"
        "- If there is ONLY 1 phone number on the card (and it is not explicitly marked as call-only/landline), "
        "put it in `whatsapp_phone` and set `call_phone` to 'N/A'.\n"
        "- If there are 2 or more phone numbers on the card and NO icon or text distinguishes WhatsApp from normal Call, "
        "put ALL of them in `whatsapp_phone` separated by ' / ' and set `call_phone` to 'N/A'.\n"
        "- If icons or text DO specify which number is WhatsApp and which is for normal Call/Office/Landline, "
        "separate them accordingly into `whatsapp_phone` and `call_phone`.\n\n"
        "EMAIL RULE:\n"
        "- Extract ALL email addresses printed anywhere on the card (front or back) into the single `email` field, "
        "in lowercase, separated by ' / ' (example: 'sales@company.com / info@company.com'). "
        "Never move a second email into `extra_details`.\n\n"
        "CITY RULE:\n"
        "- Put ONLY the clean English city/town name in `city` (e.g., 'Ahmedabad', 'Mumbai', 'Kapadvanj', 'Dakor'). "
        "Do not put street, state, or PIN code in `city`. Infer from the address or PIN code if unambiguous; else 'N/A'.\n\n"
        "EXTRA DETAILS RULE:\n"
        "- Put any extra printed details (like Website, GSTIN, PAN, Fax, Instagram, LinkedIn, Branch, Office Timings, "
        "ISO certification) into `extra_details` as {label, value} items so nothing printed on the card is lost.\n\n"
        "OTHER RULES:\n"
        "- For `products_services`: if not explicitly listed, infer what the company offers from the company name, "
        "tagline, logo, or contact person's title.\n"
        "- If any standard field is completely absent and cannot be inferred, return 'N/A'."
    )

    image_parts = [
        types.Part.from_bytes(data=img_bytes, mime_type=mime_type)
        for img_bytes, mime_type in optimized_images
    ]

    started_at = time.monotonic()

    for model in MODEL_CHAIN:
        elapsed = time.monotonic() - started_at
        remaining_sec = TOTAL_SCAN_BUDGET_SEC - elapsed
        if remaining_sec < 4.0:
            break

        attempt_timeout_ms = min(PER_REQUEST_TIMEOUT_MS, int(remaining_sec * 1000))
        client = genai.Client(
            api_key=api_key.strip(),
            http_options=types.HttpOptions(timeout=attempt_timeout_ms),
        )

        try:
            response = client.models.generate_content(
                model=model,
                contents=[*image_parts, prompt],
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=VisitingCard,
                    max_output_tokens=1024,
                ),
            )

            if isinstance(response.parsed, VisitingCard):
                cleaned_card, extra_dict = _clean_card_output(response.parsed)
                return cleaned_card, extra_dict, model

            if not response.text:
                continue

            cleaned_json = re.sub(
                r"^```(?:json)?\s*|\s*```$",
                "",
                response.text.strip(),
                flags=re.IGNORECASE,
            )
            parsed_obj = VisitingCard.model_validate_json(cleaned_json)
            cleaned_card, extra_dict = _clean_card_output(parsed_obj)
            return cleaned_card, extra_dict, model

        except genai_errors.APIError as api_err:
            if api_err.code in (401, 403):
                raise ValueError(
                    "The configured Gemini API key was rejected. Please check your key in Settings."
                ) from api_err
            if api_err.code in (404, 408, 429, 500, 502, 503, 504):
                time.sleep(0.5)
                continue
            continue
        except Exception:
            time.sleep(0.5)
            continue

    raise ScanUnavailableError(
        "The AI scanner is momentarily busy or timed out. "
        "Please tap Scan again in a few seconds — or use 'Fill Details Manually'."
    )


def generate_marketing_ai_text(prompt: str, api_key: str) -> str:
    if not api_key or not api_key.strip():
        raise ValueError("Gemini API key is missing. Add it in Sidebar → Settings.")

    started_at = time.monotonic()
    for model in MODEL_CHAIN:
        elapsed = time.monotonic() - started_at
        remaining_sec = TOTAL_SCAN_BUDGET_SEC - elapsed
        if remaining_sec < 4.0:
            break

        attempt_timeout_ms = min(PER_REQUEST_TIMEOUT_MS, int(remaining_sec * 1000))
        client = genai.Client(
            api_key=api_key.strip(),
            http_options=types.HttpOptions(timeout=attempt_timeout_ms),
        )
        try:
            response = client.models.generate_content(
                model=model,
                contents=prompt,
                config=types.GenerateContentConfig(max_output_tokens=1600),
            )
            if response.text and response.text.strip():
                return response.text.strip()
        except genai_errors.APIError as api_err:
            if api_err.code in (401, 403):
                raise ValueError(
                    "The configured Gemini API key was rejected. Please check your key in Settings."
                ) from api_err
            time.sleep(0.4)
            continue
        except Exception:
            time.sleep(0.4)
            continue

    raise ScanUnavailableError(
        "The AI assistant is momentarily busy. Please try again in a few seconds."
    )


def run_scan(image_files: list, api_key: str, user_id: str) -> None:
    if not api_key:
        st.warning("Scanner API key is not configured yet. Add it in Sidebar → Settings.")
        return
    if not image_files:
        st.warning("Please upload or capture at least 1 card image.")
        return
    if len(image_files) > MAX_CARD_IMAGES:
        st.warning(f"Maximum {MAX_CARD_IMAGES} images (Front & Back) are allowed.")
        return

    for f in image_files:
        if getattr(f, "size", 0) > MAX_IMAGE_FILE_BYTES:
            st.warning(
                f"Image '{f.name}' exceeds the 5 MB upload limit. Please upload a smaller photo."
            )
            return

    daily_limit = get_daily_scan_limit()
    try:
        reserve_user_scan_slot(user_id, daily_limit)
    except QuotaExceededError:
        st.warning(
            f"You have reached your daily limit of **{daily_limit} AI scans**. "
            "Quota resets daily at 1:30 PM IST (12:30 PM IST in summer). "
            "You can still add cards right now using **Fill Details Manually** or **Merge Existing Excel**."
        )
        return
    except Exception:
        st.error(
            "Google Sheets is momentarily busy verifying your scan quota. Please tap Scan again in a few seconds."
        )
        return

    images_payload = [(f.getvalue(), f.type or "image/jpeg") for f in image_files]
    side_label = "both card sides" if len(images_payload) == 2 else "visiting card"

    with st.spinner(f"Scanning {side_label}..."):
        try:
            extracted, extra_dict, _used_model = extract_card_details(
                images_payload, api_key
            )

            card_dict = extracted.model_dump(exclude={"extra_details"})
            card_dict["notes"] = ""
            card_dict["extra_details_text"] = format_extra_data_for_input(extra_dict)

            st.session_state["extracted_card"] = card_dict
            st.session_state["is_manual_entry"] = False
            st.session_state["pending_duplicate_save"] = None
            st.session_state["scan_counter"] += 1
            st.session_state["scroll_to_form_seq"] += 1
            st.session_state["scan_notice"] = (
                f"Scanned {len(images_payload)} image(s) successfully! "
                "Verify or edit the details below and click Save Card."
            )
            st.rerun()
        except ValueError as val_err:
            release_user_scan_slot(user_id)
            st.warning(str(val_err))
        except ScanUnavailableError as busy_err:
            release_user_scan_slot(user_id)
            st.warning(str(busy_err))
        except Exception:
            release_user_scan_slot(user_id)
            st.warning(
                "Could not complete the scan right now. Try a clearer photo, "
                "tap Scan again in a moment, or use 'Fill Details Manually'."
            )


def open_blank_manual_form() -> None:
    st.session_state["extracted_card"] = {
        "company_name": "",
        "contact_person": "",
        "call_phone": "",
        "whatsapp_phone": "",
        "email": "",
        "products_services": "",
        "address": "",
        "city": "",
        "notes": "",
        "extra_details_text": "",
    }
    st.session_state["is_manual_entry"] = True
    st.session_state["pending_duplicate_save"] = None
    st.session_state["scan_counter"] += 1
    st.session_state["scroll_to_form_seq"] += 1
    st.session_state["scan_notice"] = (
        "Manual entry — fill in at least one field below and click Save Card."
    )


# ---------------------------------------------------------------------------
# Authentication UI (Login, OTP-Verified Register & Generic Password Recovery)
# ---------------------------------------------------------------------------
def render_auth_screen() -> None:
    _, center_col, _ = st.columns([1, 1.8, 1])

    with center_col:
        st.title("Company Visiting Card Scanner")
        st.caption(
            "Sign in or create an account to scan, organize, manage CRM deals, and export your visiting cards."
        )

        with st.container(border=True):
            tab_login, tab_register, tab_forgot = st.tabs(
                ["Login", "Register", "Forgot Password"]
            )

            with tab_login:
                with st.form("login_form"):
                    identifier = st.text_input(
                        "Username or Email",
                        placeholder="e.g., business_user or name@example.com",
                    )
                    password = st.text_input(
                        "Password",
                        type="password",
                        placeholder="Enter your password",
                    )
                    login_submitted = st.form_submit_button(
                        "Login", type="primary", use_container_width=True
                    )

                if login_submitted:
                    with st.spinner("Signing in..."):
                        try:
                            ok, msg, user = authenticate_user(identifier, password)
                            if ok and user:
                                login_user_session(user)
                                st.session_state["pending_registration"] = None
                                st.session_state["flash_success"] = (
                                    f"Welcome back, {user['username']}!"
                                )
                                st.rerun()
                            else:
                                st.error(msg)
                        except Exception:
                            st.error("Unable to sign in right now. Please try again.")

            with tab_register:
                pending_reg = st.session_state.get("pending_registration")

                if pending_reg is None:
                    st.caption(
                        "Step 1: Enter your details to receive an email verification OTP."
                    )
                    with st.form("register_step1_form"):
                        reg_username = st.text_input(
                            "Username",
                            placeholder="3–30 characters (letters, numbers, _ . -)",
                        )
                        reg_email = st.text_input("Email", placeholder="name@example.com")
                        reg_password = st.text_input(
                            "Password",
                            type="password",
                            placeholder="Min 8 chars, 1 uppercase, 1 lowercase, 1 number",
                        )
                        reg_confirm = st.text_input(
                            "Confirm Password",
                            type="password",
                            placeholder="Re-enter your password",
                        )
                        send_reg_otp = st.form_submit_button(
                            "Send Verification OTP",
                            type="primary",
                            use_container_width=True,
                        )

                    if send_reg_otp:
                        if reg_password != reg_confirm:
                            st.error("Passwords do not match.")
                        else:
                            with st.spinner("Sending verification OTP..."):
                                try:
                                    ok, msg, pending_data = start_registration_otp(
                                        reg_username, reg_email, reg_password
                                    )
                                    if ok and pending_data:
                                        st.session_state["pending_registration"] = (
                                            pending_data
                                        )
                                        st.session_state["reg_otp_notice"] = msg
                                        st.rerun()
                                    else:
                                        st.error(msg)
                                except Exception:
                                    st.error(
                                        "Unable to start registration right now. Please try again."
                                    )
                else:
                    if st.session_state.get("reg_otp_notice"):
                        st.success(st.session_state["reg_otp_notice"])
                        st.session_state["reg_otp_notice"] = None

                    st.info(
                        f"Step 2: Enter the 6-digit OTP sent to **{pending_reg['email']}** "
                        f"for username **{pending_reg['username']}**."
                    )

                    with st.form("register_step2_otp_form"):
                        reg_otp_input = st.text_input(
                            "6-Digit Verification OTP",
                            placeholder="e.g., 482910",
                            max_chars=6,
                        )
                        verify_reg_btn = st.form_submit_button(
                            "Verify Email & Create Account",
                            type="primary",
                            use_container_width=True,
                        )

                    if verify_reg_btn:
                        with st.spinner("Verifying OTP and creating account..."):
                            try:
                                ok, msg, user = complete_registration_with_otp(
                                    pending_reg, reg_otp_input
                                )
                                if ok and user:
                                    login_user_session(user)
                                    st.session_state["pending_registration"] = None
                                    st.session_state["flash_success"] = (
                                        f"Email verified! Welcome, {user['username']}."
                                    )
                                    st.rerun()
                                else:
                                    st.error(msg)
                            except Exception:
                                st.error("Could not verify OTP right now. Please try again.")

                    resend_col, cancel_col = st.columns(2)
                    with resend_col:
                        if st.button(
                            "Resend OTP",
                            use_container_width=True,
                            key="btn_resend_reg_otp",
                        ):
                            with st.spinner("Resending OTP..."):
                                ok, msg = resend_registration_otp(pending_reg)
                                if ok:
                                    st.success(msg)
                                else:
                                    st.error(msg)
                    with cancel_col:
                        if st.button(
                            "Change Email / Details",
                            use_container_width=True,
                            key="btn_cancel_reg_otp",
                        ):
                            st.session_state["pending_registration"] = None
                            st.session_state["reg_otp_notice"] = None
                            st.rerun()

            with tab_forgot:
                st.caption("Step 1: Enter your email address to request a 6-digit reset code.")
                with st.form("forgot_request_form"):
                    reset_email_input = st.text_input(
                        "Email Address",
                        value=st.session_state.get("reset_email_target", ""),
                        placeholder="name@example.com",
                    )
                    send_code_btn = st.form_submit_button(
                        "Send 6-Digit Reset Code",
                        type="primary",
                        use_container_width=True,
                    )

                if send_code_btn:
                    with st.spinner("Processing request..."):
                        ok, msg = request_password_reset(reset_email_input)
                        if ok:
                            st.session_state["reset_email_target"] = (
                                reset_email_input.strip().lower()
                            )
                            st.success(msg)
                        else:
                            st.error(msg)

                st.divider()
                st.caption("Step 2: Enter the code from your email and choose a new password.")
                with st.form("forgot_confirm_form"):
                    verify_email = st.text_input(
                        "Email",
                        value=st.session_state.get("reset_email_target", ""),
                        placeholder="name@example.com",
                    )
                    otp_code = st.text_input(
                        "6-Digit Verification Code",
                        placeholder="e.g., 482910",
                        max_chars=6,
                    )
                    new_pw = st.text_input(
                        "New Password",
                        type="password",
                        placeholder="Min 8 chars, 1 uppercase, 1 lowercase, 1 number",
                    )
                    confirm_new_pw = st.text_input(
                        "Confirm New Password",
                        type="password",
                        placeholder="Re-enter new password",
                    )
                    reset_pw_btn = st.form_submit_button(
                        "Reset Password", type="primary", use_container_width=True
                    )

                if reset_pw_btn:
                    if new_pw != confirm_new_pw:
                        st.error("Passwords do not match.")
                    else:
                        with st.spinner("Updating password..."):
                            ok, msg = confirm_password_reset(
                                verify_email, otp_code, new_pw
                            )
                            if ok:
                                st.session_state["reset_email_target"] = ""
                                st.success(msg)
                            else:
                                st.error(msg)


# ---------------------------------------------------------------------------
# Analyze & Growth Hub (Bulk WhatsApp, Multi-WP, Multi-Email & Bulk BCC)
# ---------------------------------------------------------------------------
def _compute_analytics_tables(
    df: pd.DataFrame,
) -> Tuple[dict[str, Any], pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    total_leads = len(df)
    if total_leads == 0:
        return {}, pd.DataFrame(), pd.DataFrame(), pd.DataFrame()

    has_wp = df["WhatsApp No."].apply(lambda x: str(x).strip().upper() != "N/A")
    has_call = df["Contact No."].apply(lambda x: str(x).strip().upper() != "N/A")
    has_any_phone = has_wp | has_call
    has_email = df["Email"].apply(lambda x: bool(parse_email_list(str(x))))
    has_city = df["City"].apply(lambda x: str(x).strip().upper() != "N/A")
    has_website = df["Extra Details"].str.contains(
        r"website|www\.|http|\.com|\.in|\.org|\.net", case=False, na=False
    )

    core_cols = [
        "Company Name",
        "Contact Person",
        "WhatsApp No.",
        "Email",
        "Product / Services",
        "City",
    ]
    filled_cells = 0
    for col in core_cols:
        filled_cells += int(
            df[col].apply(lambda x: bool(str(x).strip()) and str(x).strip().upper() != "N/A").sum()
        )
    completeness_pct = round((filled_cells / (total_leads * len(core_cols))) * 100)

    kpis = {
        "total_leads": total_leads,
        "wp_count": int(has_wp.sum()),
        "wp_pct": round((has_wp.sum() / total_leads) * 100),
        "phone_count": int(has_any_phone.sum()),
        "email_count": int(has_email.sum()),
        "email_pct": round((has_email.sum() / total_leads) * 100),
        "city_count": int(
            df.loc[has_city, "City"].astype(str).str.strip().str.title().nunique()
        ),
        "website_count": int(has_website.sum()),
        "completeness_pct": completeness_pct,
        "missing_city_count": int((~has_city).sum()),
        "missing_email_count": int((~has_email).sum()),
    }

    city_rows = []
    temp_df = df.copy()
    temp_df["_clean_city"] = temp_df["City"].apply(
        lambda x: str(x).strip().title()
        if str(x).strip() and str(x).strip().upper() != "N/A"
        else "Unspecified"
    )
    temp_df["_has_wp"] = has_wp
    temp_df["_has_email"] = has_email

    for city_name, grp in temp_df.groupby("_clean_city", sort=False):
        cnt = len(grp)
        city_rows.append(
            {
                "City": city_name,
                "Leads": cnt,
                "Share (%)": round((cnt / total_leads) * 100, 1),
                "WhatsApp Ready": int(grp["_has_wp"].sum()),
                "Email Ready": int(grp["_has_email"].sum()),
            }
        )
    city_df = pd.DataFrame(city_rows).sort_values(
        by=["Leads", "WhatsApp Ready"], ascending=[False, False]
    )

    prod_counter: Counter[str] = Counter()
    for raw_prod in df["Product / Services"].tolist():
        txt = str(raw_prod or "").strip()
        if not txt or txt.upper() == "N/A":
            continue
        tokens = [
            t.strip().title()
            for t in re.split(r"[,;/|\n]+", txt)
            if t.strip() and t.strip().upper() != "N/A"
        ]
        for tok in set(tokens):
            prod_counter[tok] += 1

    prod_df = pd.DataFrame(
        [
            {
                "Product / Service": prod_name,
                "Companies": count,
                "Portfolio Share (%)": round((count / total_leads) * 100, 1),
            }
            for prod_name, count in prod_counter.most_common(15)
        ]
    )

    parsed_dates = pd.to_datetime(df["Saved On"], errors="coerce").dropna()
    if not parsed_dates.empty:
        date_counts = parsed_dates.dt.strftime("%Y-%m-%d").value_counts().sort_index()
        timeline_df = pd.DataFrame(
            {"Date": date_counts.index.tolist(), "New Leads": date_counts.values.tolist()}
        )
    else:
        timeline_df = pd.DataFrame(columns=["Date", "New Leads"])

    return kpis, city_df, prod_df, timeline_df


def _render_campaign_message(template: str, row: pd.Series) -> str:
    company = (
        str(row["Company Name"]).strip()
        if str(row["Company Name"]).strip().upper() != "N/A"
        else "your team"
    )
    raw_person = str(row["Contact Person"]).strip()
    person = (
        raw_person.split(",")[0].split("(")[0].strip()
        if raw_person.upper() != "N/A"
        else "Sir/Madam"
    )
    city = (
        str(row["City"]).strip()
        if str(row["City"]).strip().upper() != "N/A"
        else "your city"
    )
    product = (
        str(row["Product / Services"]).strip()
        if str(row["Product / Services"]).strip().upper() != "N/A"
        else "your business offerings"
    )

    msg = template
    for key, val in (
        ("{company}", company),
        ("{person}", person),
        ("{city}", city),
        ("{product}", product),
    ):
        msg = msg.replace(key, val)
    return msg


def _get_user_bound_ai_text(state_key: str, user_id: str) -> Optional[str]:
    entry = st.session_state.get(state_key)
    if isinstance(entry, dict) and entry.get("user_id") == user_id:
        return entry.get("text")
    return None


def _build_gmail_compose_url(
    to_email: str = "",
    bcc_emails: Optional[list[str]] = None,
    subject: str = "",
    body: str = "",
) -> str:
    params = ["view=cm", "fs=1"]
    if to_email:
        params.append(f"to={quote(to_email)}")
    if bcc_emails:
        params.append(f"bcc={quote(','.join(bcc_emails))}")
    if subject:
        params.append(f"su={quote(subject)}")
    if body:
        params.append(f"body={quote(body)}")
    return f"https://mail.google.com/mail/?{'&'.join(params)}"


def render_analyze_section(
    all_records_df: pd.DataFrame,
    current_username: str,
    current_user_id: str,
    active_api_key: str,
    scans_remaining: int,
    daily_limit: int,
) -> None:
    with st.container(border=True):
        hdr_col, exp_col = st.columns([3.8, 1.4])
        with hdr_col:
            st.subheader("Analyze & Growth Hub")
            st.caption(
                "Market intelligence, bulk WhatsApp & Email campaigns, and AI growth playbooks built from your saved leads."
            )

        if all_records_df.empty:
            st.info(
                "Save or merge at least a few visiting cards first to unlock territory analytics, "
                "campaign launchers, and AI marketing playbooks."
            )
            return

        kpis, city_df, prod_df, timeline_df = _compute_analytics_tables(all_records_df)
        full_export_df = build_expanded_dataframe(
            all_records_df, include_extra_columns=True
        )

        with exp_col:
            summary_df = pd.DataFrame(
                [
                    {"Metric": "Total Saved Leads", "Value": kpis["total_leads"]},
                    {"Metric": "Cities Covered", "Value": kpis["city_count"]},
                    {
                        "Metric": "WhatsApp-Ready Leads",
                        "Value": f"{kpis['wp_count']} ({kpis['wp_pct']}%)",
                    },
                    {
                        "Metric": "Email-Ready Leads",
                        "Value": f"{kpis['email_count']} ({kpis['email_pct']}%)",
                    },
                    {
                        "Metric": "Leads with Website / Digital Presence",
                        "Value": kpis["website_count"],
                    },
                    {
                        "Metric": "Lead Data Completeness Score",
                        "Value": f"{kpis['completeness_pct']}%",
                    },
                ]
            )
            sheets_pack: dict[str, pd.DataFrame] = {
                "Executive Summary": summary_df,
                "City Territories": city_df,
                "All Leads": full_export_df,
            }
            if not prod_df.empty:
                sheets_pack["Product Demand"] = prod_df

            report_bytes = build_multi_sheet_excel_bytes(sheets_pack)
            st.download_button(
                label="Download Growth Report (.xlsx)",
                data=report_bytes,
                file_name=f"marketing_growth_report_{current_username}_{datetime.now().strftime('%Y%m%d')}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                use_container_width=True,
                key="btn_download_growth_report",
            )

        m1, m2, m3, m4 = st.columns(4)
        with m1:
            st.metric("Total Leads", kpis["total_leads"])
        with m2:
            st.metric("WhatsApp Reachable", f"{kpis['wp_count']} ({kpis['wp_pct']}%)")
        with m3:
            st.metric("Email Reachable", f"{kpis['email_count']} ({kpis['email_pct']}%)")
        with m4:
            st.metric("Lead Data Health", f"{kpis['completeness_pct']}%")

        if kpis["missing_city_count"] > 0 or kpis["missing_email_count"] > 0:
            st.info(
                f"**Quick-Win Data Enrichment:** **{kpis['missing_city_count']}** lead(s) are missing a City "
                f"and **{kpis['missing_email_count']}** lead(s) are missing an Email. "
                "Updating those records unlocks stronger city-targeted campaigns."
            )

        tab_market, tab_outreach, tab_ai_growth = st.tabs(
            [
                "Market & Territory Insights",
                "Bulk WhatsApp & Email Campaigns",
                "AI Marketing Strategist & Pitch",
            ]
        )

        with tab_market:
            c_left, c_right = st.columns(2)
            with c_left:
                st.markdown("#### City Territory Breakdown")
                if not city_df.empty:
                    top_cities_chart = city_df.head(10).set_index("City")["Leads"]
                    st.bar_chart(top_cities_chart, use_container_width=True)
                    st.dataframe(city_df, use_container_width=True, hide_index=True)

            with c_right:
                st.markdown("#### Top Products / Services in Network")
                if not prod_df.empty:
                    top_prods_chart = prod_df.head(10).set_index("Product / Service")[
                        "Companies"
                    ]
                    st.bar_chart(top_prods_chart, use_container_width=True)
                    st.dataframe(prod_df, use_container_width=True, hide_index=True)
                else:
                    st.info("Add Product / Services details to leads to see niche demand trends.")

            if len(timeline_df) >= 2:
                st.markdown("#### Lead Capture Velocity (Daily Growth)")
                st.area_chart(
                    timeline_df.set_index("Date")["New Leads"],
                    use_container_width=True,
                )

        with tab_outreach:
            st.caption(
                "Filter contacts by City, Product/Service, or Channel to launch Bulk Email (BCC) "
                "and WhatsApp outreach—supporting cards with multiple WhatsApp numbers or emails."
            )

            unique_cities = sorted(
                {
                    str(c).strip()
                    for c in all_records_df["City"].dropna().tolist()
                    if str(c).strip() and str(c).strip().upper() != "N/A"
                }
            )

            f1, f2, f3 = st.columns([1.2, 1.5, 1.5])
            with f1:
                camp_city = st.selectbox(
                    "Target City",
                    options=["All Cities", *unique_cities],
                    key="camp_target_city",
                )
            with f2:
                camp_keyword = st.text_input(
                    "Filter by Product / Company / Keyword",
                    placeholder="e.g., Educational, PVC, Ahmedabad...",
                    key="camp_keyword_filter",
                )
            with f3:
                camp_channel = st.selectbox(
                    "Channel Filter",
                    options=[
                        "All Contacts",
                        "WhatsApp Ready Only",
                        "Email Ready Only",
                        "Both WhatsApp & Email",
                    ],
                    key="camp_channel_filter",
                )

            camp_df = all_records_df.copy()
            if camp_city != "All Cities":
                camp_df = camp_df[
                    camp_df["City"].astype(str).str.strip().str.lower()
                    == camp_city.lower()
                ]
            if camp_keyword.strip():
                camp_df = search_records_df(camp_df, camp_keyword)

            has_wp_mask = camp_df["WhatsApp No."].apply(
                lambda x: str(x).strip().upper() != "N/A"
            )
            has_email_mask = camp_df["Email"].apply(
                lambda x: bool(parse_email_list(str(x)))
            )

            if camp_channel == "WhatsApp Ready Only":
                camp_df = camp_df[has_wp_mask]
            elif camp_channel == "Email Ready Only":
                camp_df = camp_df[has_email_mask]
            elif camp_channel == "Both WhatsApp & Email":
                camp_df = camp_df[has_wp_mask & has_email_mask]

            if camp_df.empty:
                st.warning("No leads match the selected campaign filters.")
            else:
                label_to_id: dict[str, str] = {}
                for _, r in camp_df.iterrows():
                    lbl = f"{r['Company Name']} ({r['City']}) [{str(r['Record ID'])[:8]}]"
                    label_to_id[lbl] = str(r["Record ID"])

                all_labels = list(label_to_id.keys())
                sel_col1, sel_col2 = st.columns([1.4, 3.6])
                with sel_col1:
                    select_all_filtered = st.checkbox(
                        f"Select all {len(all_labels)} filtered lead(s)",
                        value=True,
                        key=f"camp_select_all_{camp_city}_{camp_channel}_{camp_keyword}",
                    )
                with sel_col2:
                    if select_all_filtered:
                        selected_labels = all_labels
                        st.caption(
                            f"Targeting all **{len(selected_labels)}** filtered lead(s). Uncheck to pick specific companies."
                        )
                    else:
                        selected_labels = st.multiselect(
                            "Choose specific companies to include",
                            options=all_labels,
                            default=all_labels[: min(5, len(all_labels))],
                            label_visibility="collapsed",
                            key=f"camp_multiselect_{camp_city}_{camp_channel}_{camp_keyword}",
                        )

                selected_ids = {label_to_id[lbl] for lbl in selected_labels}
                target_df = camp_df[camp_df["Record ID"].isin(selected_ids)].copy()

                if target_df.empty:
                    st.warning("Please select at least one company above.")
                else:
                    templates = {
                        "Business Intro & Catalog": (
                            "Hello {person},\n\n"
                            "Greetings! We saved your contact from {company} ({city}). "
                            "We'd love to share our latest product catalog and explore working together "
                            "around {product}.\n\n"
                            "Please let us know a good time to connect!"
                        ),
                        "Trade Fair / Meeting Follow-Up": (
                            "Hello {person},\n\n"
                            "It was great connecting with {company}! Following up on our discussion "
                            "regarding {product} in {city}. Sharing our details here so we stay in touch."
                        ),
                        "Seasonal / Special Offer": (
                            "Hello {person},\n\n"
                            "Special update for our partners in {city}! We have fresh stock and priority pricing "
                            "available this month. Reply 'CATALOG' to receive our latest price list for {company}."
                        ),
                        "Distributor / B2B Partnership": (
                            "Hello {person},\n\n"
                            "We are expanding our partner network in {city} and noticed {company}'s strong presence in "
                            "{product}. Would you be open to a quick 5-minute call this week?"
                        ),
                    }

                    tpl_col1, tpl_col2 = st.columns([1.4, 2.6])
                    with tpl_col1:
                        chosen_tpl_name = st.selectbox(
                            "Campaign Template",
                            options=[*templates.keys(), "Custom Message"],
                            key="camp_template_select",
                        )
                        email_subject_tpl = st.text_input(
                            "Email Subject",
                            value="Connecting regarding {product} — {city}",
                            key="camp_email_subject_input",
                        )
                        st.caption(
                            "Personalization tags: `{person}`, `{company}`, `{city}`, `{product}`"
                        )
                    with tpl_col2:
                        default_body = (
                            "Hello {person}, reaching out to {company} regarding {product}."
                            if chosen_tpl_name == "Custom Message"
                            else templates[chosen_tpl_name]
                        )
                        message_template = st.text_area(
                            "Message Template (editable)",
                            value=default_body,
                            height=130,
                            key=f"camp_msg_box_{chosen_tpl_name}",
                        )

                    bulk_emails: list[str] = []
                    seen_emails: set[str] = set()
                    all_wa_entries: list[dict[str, str]] = []

                    for _, r in target_df.iterrows():
                        for clean_em in parse_email_list(str(r["Email"])):
                            if clean_em not in seen_emails:
                                seen_emails.add(clean_em)
                                bulk_emails.append(clean_em)

                        wa_pairs = extract_all_wa_dial_numbers(
                            str(r["WhatsApp No."]), str(r["Contact No."])
                        )
                        for idx_wp, (disp_num, dial_digits) in enumerate(wa_pairs, start=1):
                            all_wa_entries.append(
                                {
                                    "record_id": str(r["Record ID"]),
                                    "company": str(r["Company Name"]),
                                    "disp": disp_num,
                                    "dial": dial_digits,
                                    "slot": str(idx_wp),
                                }
                            )

                    with st.container(border=True):
                        st.markdown("#### Bulk Email Launcher (BCC — Private Group Send)")
                        if not bulk_emails:
                            st.info("None of the selected leads have a valid email address.")
                        else:
                            sample_row = target_df.iloc[0]
                            bulk_subject = _render_campaign_message(
                                email_subject_tpl, sample_row
                            )
                            bulk_body = message_template
                            for tag, fallback in (
                                ("{person}", "Sir/Madam"),
                                ("{company}", "your team"),
                                ("{city}", camp_city if camp_city != "All Cities" else "your city"),
                                ("{product}", camp_keyword.strip() or "your business"),
                            ):
                                bulk_body = bulk_body.replace(tag, fallback)

                            bcc_slice = bulk_emails[:MAX_DIRECT_BCC_EMAILS]
                            gmail_bulk_url = html.escape(
                                _build_gmail_compose_url(
                                    bcc_emails=bcc_slice,
                                    subject=bulk_subject,
                                    body=bulk_body,
                                ),
                                quote=True,
                            )
                            mailto_bulk_url = html.escape(
                                f"mailto:?bcc={quote(','.join(bcc_slice))}&subject={quote(bulk_subject)}&body={quote(bulk_body)}",
                                quote=True,
                            )

                            st.caption(
                                f"**{len(bulk_emails)}** email(s) ready in BCC (including multiple emails per card). "
                                "Use **Open in Gmail Web** if your device does not have Outlook/Mail App configured."
                            )
                            st.markdown(
                                f'<a class="vcard-action-link vcard-gmail-btn" href="{gmail_bulk_url}" target="_blank" rel="noopener noreferrer">'
                                f"Open Bulk Email in Gmail Web ({len(bcc_slice)} BCC)</a>"
                                f'<a class="vcard-action-link vcard-mail-btn" href="{mailto_bulk_url}" target="_blank" rel="noopener noreferrer">'
                                f"Open Bulk Email in Mail App / Outlook ({len(bcc_slice)} BCC)</a>",
                                unsafe_allow_html=True,
                            )

                            if len(bulk_emails) > MAX_DIRECT_BCC_EMAILS:
                                st.warning(
                                    f"Direct browser buttons include the first {MAX_DIRECT_BCC_EMAILS} emails to stay within URL limits. "
                                    f"Copy the full list of {len(bulk_emails)} emails below:"
                                )

                            with st.expander(
                                f"Copy All {len(bulk_emails)} Filtered Email Address(es)"
                            ):
                                st.code(", ".join(bulk_emails), language=None)

                    sent_keys: set[str] = st.session_state.setdefault(
                        "campaign_sent_keys", set()
                    )
                    total_wa_targets = len(all_wa_entries)
                    sent_wa_count = sum(
                        1
                        for item in all_wa_entries
                        if f"{item['record_id']}:{item['dial']}" in sent_keys
                    )

                    q_col1, q_col2, q_col3 = st.columns([2.4, 1.3, 1.5])
                    with q_col1:
                        st.markdown(
                            f"#### Individual & Bulk WhatsApp Queue "
                            f"({sent_wa_count} / {total_wa_targets} marked sent)"
                        )
                    with q_col2:
                        if st.button(
                            "Reset Sent Marks",
                            use_container_width=True,
                            key="btn_reset_camp_sent",
                        ):
                            st.session_state["campaign_sent_keys"] = set()
                            st.rerun()
                    with q_col3:
                        campaign_rows = []
                        for _, r in target_df.iterrows():
                            personalized = _render_campaign_message(message_template, r)
                            wa_pairs = extract_all_wa_dial_numbers(
                                str(r["WhatsApp No."]), str(r["Contact No."])
                            )
                            wp1_disp, wp1_dial = wa_pairs[0] if len(wa_pairs) >= 1 else ("N/A", "")
                            wp2_disp, wp2_dial = wa_pairs[1] if len(wa_pairs) >= 2 else ("N/A", "")
                            campaign_rows.append(
                                {
                                    "Company Name": r["Company Name"],
                                    "Contact Person": r["Contact Person"],
                                    "WhatsApp #1": wp1_disp,
                                    "WhatsApp #2": wp2_disp,
                                    "Contact No.": r["Contact No."],
                                    "Email": r["Email"],
                                    "City": r["City"],
                                    "Product / Services": r["Product / Services"],
                                    "Personalized Message": personalized,
                                    "WhatsApp Link #1": (
                                        f"https://wa.me/{wp1_dial}?text={quote(personalized)}"
                                        if wp1_dial
                                        else "N/A"
                                    ),
                                    "WhatsApp Link #2": (
                                        f"https://wa.me/{wp2_dial}?text={quote(personalized)}"
                                        if wp2_dial
                                        else "N/A"
                                    ),
                                }
                            )
                        st.download_button(
                            label="Export Campaign (.xlsx)",
                            data=build_excel_bytes(
                                pd.DataFrame(campaign_rows), "Campaign Leads"
                            ),
                            file_name=f"campaign_outreach_{datetime.now().strftime('%Y%m%d')}.xlsx",
                            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                            use_container_width=True,
                            key="btn_export_campaign_xlsx",
                        )

                    if all_wa_entries:
                        with st.expander(
                            f"WhatsApp Broadcast Helper — Copy All {total_wa_targets} Number(s)"
                        ):
                            st.caption(
                                "Copy these formatted numbers for a WhatsApp Broadcast list on your phone:"
                            )
                            st.code(
                                "\n".join(
                                    f"{item['company']} — +{item['dial']}"
                                    for item in all_wa_entries
                                ),
                                language=None,
                            )

                    for _, r in target_df.head(30).iterrows():
                        rec_id = str(r["Record ID"])
                        personalized = _render_campaign_message(message_template, r)
                        subj_text = _render_campaign_message(email_subject_tpl, r)
                        wa_pairs = extract_all_wa_dial_numbers(
                            str(r["WhatsApp No."]), str(r["Contact No."])
                        )
                        email_list = parse_email_list(str(r["Email"]))

                        safe_company = html.escape(str(r["Company Name"]), quote=True)
                        safe_person = html.escape(str(r["Contact Person"]), quote=True)
                        safe_city = html.escape(str(r["City"]), quote=True)
                        safe_product = html.escape(str(r["Product / Services"]), quote=True)

                        is_card_sent = any(
                            f"{rec_id}:{dial}" in sent_keys for _, dial in wa_pairs
                        ) or (f"{rec_id}:email" in sent_keys)

                        links_html = ""
                        for wp_idx, (disp_num, wa_dial) in enumerate(wa_pairs, start=1):
                            if re.fullmatch(r"\d{10,15}", wa_dial):
                                wa_url = html.escape(
                                    f"https://wa.me/{wa_dial}?text={quote(personalized)}",
                                    quote=True,
                                )
                                wp_tag = (
                                    f"WhatsApp #{wp_idx}"
                                    if len(wa_pairs) > 1
                                    else "Send WhatsApp"
                                )
                                links_html += (
                                    f'<a class="vcard-action-link vcard-wa-btn" '
                                    f'href="{wa_url}" target="_blank" rel="noopener noreferrer">'
                                    f"{wp_tag} ({html.escape(disp_num, quote=True)})</a>"
                                )

                        if email_list:
                            joined_to = ",".join(email_list)
                            gmail_url = html.escape(
                                _build_gmail_compose_url(
                                    to_email=joined_to,
                                    subject=subj_text,
                                    body=personalized,
                                ),
                                quote=True,
                            )
                            mail_url = html.escape(
                                f"mailto:{quote(joined_to)}?subject={quote(subj_text)}&body={quote(personalized)}",
                                quote=True,
                            )
                            safe_email_lbl = html.escape(
                                " / ".join(email_list), quote=True
                            )
                            links_html += (
                                f'<a class="vcard-action-link vcard-gmail-btn" '
                                f'href="{gmail_url}" target="_blank" rel="noopener noreferrer">'
                                f"Gmail ({safe_email_lbl})</a>"
                                f'<a class="vcard-action-link vcard-mail-btn" '
                                f'href="{mail_url}" target="_blank" rel="noopener noreferrer">'
                                f"Mail App</a>"
                            )

                        if not links_html:
                            links_html = '<span style="opacity:0.65;font-size:0.85rem;">No WhatsApp or Email saved for this contact.</span>'

                        sent_badge_html = (
                            '<span class="vcard-sent-badge">Sent ✓</span>'
                            if is_card_sent
                            else ""
                        )
                        card_cls = (
                            "vcard-outreach-card vcard-outreach-card-sent"
                            if is_card_sent
                            else "vcard-outreach-card"
                        )

                        card_c1, card_c2 = st.columns([4.4, 1.1])
                        with card_c1:
                            st.markdown(
                                f"""
                                <div class="{card_cls}">
                                    <strong>{safe_company}</strong> · {safe_person}
                                    <span style="opacity:0.75;">({safe_city} | {safe_product})</span>
                                    {sent_badge_html}<br/>
                                    {links_html}
                                </div>
                                """,
                                unsafe_allow_html=True,
                            )
                        with card_c2:
                            st.markdown("<div style='height: 0.45rem'></div>", unsafe_allow_html=True)
                            if is_card_sent:
                                if st.button(
                                    "Undo",
                                    use_container_width=True,
                                    key=f"btn_unmark_sent_{rec_id}",
                                ):
                                    for _, dial in wa_pairs:
                                        sent_keys.discard(f"{rec_id}:{dial}")
                                    sent_keys.discard(f"{rec_id}:email")
                                    st.rerun()
                            else:
                                if st.button(
                                    "Mark Sent ✓",
                                    use_container_width=True,
                                    key=f"btn_mark_sent_{rec_id}",
                                ):
                                    for _, dial in wa_pairs:
                                        sent_keys.add(f"{rec_id}:{dial}")
                                    if email_list:
                                        sent_keys.add(f"{rec_id}:email")
                                    st.rerun()

                    if len(target_df) > 30:
                        st.caption(
                            f"Showing top 30 contacts on screen. Download the Excel sheet above to access all {len(target_df)} personalized messages."
                        )

        with tab_ai_growth:
            ai_mode = st.radio(
                "Choose AI Marketing Tool",
                options=[
                    "Portfolio Growth & Campaign Playbook",
                    "1-to-1 Company Sales Pitch Generator",
                ],
                horizontal=True,
                key="ai_marketing_mode",
            )

            if ai_mode == "Portfolio Growth & Campaign Playbook":
                goal_choice = st.selectbox(
                    "Primary Marketing Goal",
                    options=[
                        "Increase Repeat B2B Orders & WhatsApp Conversions",
                        "Expand into Top Cities & Appoint New Dealers/Distributors",
                        "Re-engage Cold Contacts & Exhibition Leads",
                        "Cross-Sell & Upsell Across Existing Product Categories",
                    ],
                    key="ai_growth_goal",
                )

                if st.button(
                    "Generate AI Growth Playbook",
                    type="primary",
                    key="btn_gen_growth_playbook",
                    disabled=(scans_remaining == 0),
                ):
                    try:
                        reserve_user_scan_slot(current_user_id, daily_limit)
                    except QuotaExceededError:
                        st.warning(f"Daily AI limit ({daily_limit}) reached.")
                        return
                    except Exception:
                        st.error("Google Sheets is momentarily busy. Please try again in a few seconds.")
                        return

                    top_cities_list = [
                        f"{row['City']} ({row['Leads']} leads)"
                        for _, row in city_df.head(6).iterrows()
                    ]
                    top_prods_list = [
                        f"{row['Product / Service']} ({row['Companies']} companies)"
                        for _, row in prod_df.head(8).iterrows()
                    ]
                    sample_companies = [
                        f"- {r['Company Name']} ({r['City']}): {r['Product / Services']}"
                        for _, r in all_records_df.head(8).iterrows()
                    ]

                    prompt = (
                        "You are a senior B2B growth & marketing strategist for an Indian business.\n"
                        f"Marketing Goal: {goal_choice}\n"
                        f"Portfolio Metrics: {kpis['total_leads']} total leads across {kpis['city_count']} cities; "
                        f"{kpis['wp_count']} WhatsApp-reachable ({kpis['wp_pct']}%); "
                        f"{kpis['email_count']} Email-reachable ({kpis['email_pct']}%).\n"
                        f"Top Cities: {', '.join(top_cities_list) if top_cities_list else 'Not specified'}.\n"
                        f"Top Product/Service Categories: {', '.join(top_prods_list) if top_prods_list else 'Various'}.\n"
                        f"Sample Accounts:\n" + "\n".join(sample_companies) + "\n\n"
                        "Provide a crisp, practical, high-impact marketing action plan with:\n"
                        "1. **Top 3 Territory & Segment Growth Moves** tailored to these exact cities and industries.\n"
                        "2. **Ready-to-Send WhatsApp Broadcast Script** (under 90 words, warm Indian B2B tone, with clear CTA).\n"
                        "3. **High-Converting Email Subject Lines & Cold/Warm Follow-Up Email**.\n"
                        "4. **7-Day Execution Checklist** for the sales & marketing team."
                    )

                    with st.spinner("Building your custom marketing playbook..."):
                        try:
                            playbook_md = generate_marketing_ai_text(
                                prompt, active_api_key
                            )
                            st.session_state["ai_growth_output"] = {
                                "user_id": current_user_id,
                                "text": playbook_md,
                            }
                        except ValueError as v_err:
                            release_user_scan_slot(current_user_id)
                            st.warning(str(v_err))
                        except ScanUnavailableError as b_err:
                            release_user_scan_slot(current_user_id)
                            st.warning(str(b_err))
                        except Exception:
                            release_user_scan_slot(current_user_id)
                            st.warning(
                                "Could not generate the playbook right now. Please try again."
                            )

                saved_playbook = _get_user_bound_ai_text(
                    "ai_growth_output", current_user_id
                )
                if saved_playbook:
                    st.markdown(saved_playbook)

            else:
                pitch_query = st.text_input(
                    "Search company for 1-to-1 pitch",
                    placeholder="Type company name, contact person, or city...",
                    key="ai_pitch_search",
                )
                pitch_candidates = (
                    search_records_df(all_records_df, pitch_query)
                    if pitch_query.strip()
                    else all_records_df.head(15)
                )

                if pitch_candidates.empty:
                    st.info("No matching company found.")
                else:
                    pitch_options = {
                        _record_summary_label(pitch_candidates.iloc[i]): pitch_candidates.iloc[
                            i
                        ].to_dict()
                        for i in range(len(pitch_candidates))
                    }
                    chosen_pitch_label = st.selectbox(
                        "Select target company",
                        options=list(pitch_options.keys()),
                        key="ai_pitch_company_select",
                    )
                    offer_context = st.text_input(
                        "What are you pitching to them? (optional)",
                        placeholder="e.g., Bulk supply discount, dealership partnership, new product line...",
                        key="ai_pitch_offer_input",
                    )

                    if st.button(
                        "Generate Custom Sales Pitch",
                        type="primary",
                        key="btn_gen_company_pitch",
                        disabled=(scans_remaining == 0),
                    ):
                        try:
                            reserve_user_scan_slot(current_user_id, daily_limit)
                        except QuotaExceededError:
                            st.warning(f"Daily AI limit ({daily_limit}) reached.")
                            return
                        except Exception:
                            st.error("Google Sheets is momentarily busy. Please try again in a few seconds.")
                            return

                        target = pitch_options[chosen_pitch_label]
                        prompt = (
                            "You are an expert B2B sales copywriter in India. Write a tailored 1-to-1 outreach kit "
                            "for this specific visiting card contact:\n"
                            f"- Company: {target['Company Name']}\n"
                            f"- Contact Person: {target['Contact Person']}\n"
                            f"- City: {target['City']}\n"
                            f"- Their Products/Services: {target['Product / Services']}\n"
                            f"- Extra Info: {target.get('Extra Details') or 'N/A'}\n"
                            f"- Notes: {target['Notes']}\n"
                            f"- Our Offer/Angle: {offer_context.strip() or 'Introduce our products/services and explore B2B collaboration'}\n\n"
                            "Deliver:\n"
                            "1. **WhatsApp First-Touch Message** (short, personalized, non-spammy).\n"
                            "2. **30-Second Phone Call Opening Script**.\n"
                            "3. **Follow-Up Email (Subject + Body)**.\n"
                            "4. **2 Smart Discovery Questions** to ask on the call."
                        )

                        with st.spinner("Crafting personalized pitch..."):
                            try:
                                pitch_md = generate_marketing_ai_text(
                                    prompt, active_api_key
                                )
                                st.session_state["ai_pitch_output"] = {
                                    "user_id": current_user_id,
                                    "text": pitch_md,
                                }
                            except ValueError as v_err:
                                release_user_scan_slot(current_user_id)
                                st.warning(str(v_err))
                            except ScanUnavailableError as b_err:
                                release_user_scan_slot(current_user_id)
                                st.warning(str(b_err))
                            except Exception:
                                release_user_scan_slot(current_user_id)
                                st.warning(
                                    "Could not generate the pitch right now. Please try again."
                                )

                saved_pitch = _get_user_bound_ai_text(
                    "ai_pitch_output", current_user_id
                )
                if saved_pitch:
                    st.markdown(saved_pitch)


# ---------------------------------------------------------------------------
# Reusable UI Sections: Show Records, Update, Soft-Delete, Trash & Audit
# ---------------------------------------------------------------------------
def _record_summary_label(row: pd.Series) -> str:
    phones = [
        p
        for p in (str(row["Contact No."]), str(row["WhatsApp No."]))
        if p and p != "N/A"
    ]
    phone_text = " | ".join(phones) if phones else "No Phone"
    city_text = row["City"] if row["City"] != "N/A" else "City N/A"
    short_id = str(row["Record ID"])[:8]
    return (
        f"{row['Company Name']} — {row['Contact Person']} "
        f"({phone_text} • {city_text}) [{short_id}]"
    )


def render_show_records_section(
    all_records_df: pd.DataFrame,
    current_username: str,
    title: str,
    key_prefix: str,
) -> None:
    with st.container(border=True):
        header_col, refresh_col = st.columns([4.5, 1])
        with header_col:
            st.subheader(title)
        with refresh_col:
            if st.button("Refresh", use_container_width=True, key=f"{key_prefix}_refresh"):
                _fetch_all_card_rows.clear()
                st.rerun()

        if all_records_df.empty:
            st.info(
                "No visiting cards saved yet. Upload a card, take a photo, fill manually, or merge an Excel file."
            )
            return

        unique_cities = sorted(
            {
                str(c).strip()
                for c in all_records_df["City"].dropna().tolist()
                if str(c).strip() and str(c).strip().upper() != "N/A"
            }
        )

        search_col, city_col, export_col = st.columns([2.5, 1.3, 1.4])

        with search_col:
            search_query = st.text_input(
                "Search records",
                placeholder="Search company, person, phone, email, city, website...",
                label_visibility="collapsed",
                key=f"{key_prefix}_search_box",
            )

        with city_col:
            selected_city = st.selectbox(
                "Filter by City",
                options=["All Cities", *unique_cities],
                label_visibility="collapsed",
                key=f"{key_prefix}_city_filter",
            )

        filtered_df = all_records_df.copy()

        if selected_city != "All Cities":
            filtered_df = filtered_df[
                filtered_df["City"].astype(str).str.strip().str.lower()
                == selected_city.lower()
            ]

        if search_query.strip():
            filtered_df = search_records_df(filtered_df, search_query)

        is_filtered = bool(search_query.strip()) or selected_city != "All Cities"
        display_df = build_expanded_dataframe(filtered_df, include_extra_columns=True)

        with export_col:
            if not display_df.empty:
                excel_bytes = build_excel_bytes(display_df)
                city_suffix = (
                    f"_{re.sub(r'[^A-Za-z0-9]+', '_', selected_city).strip('_')}"
                    if selected_city != "All Cities"
                    else ""
                )
                filename = (
                    f"visiting_cards_{current_username}{city_suffix}_{datetime.now().strftime('%Y%m%d')}.xlsx"
                )
                btn_label = (
                    "Export Filtered (.xlsx)"
                    if is_filtered
                    else "Export Excel (.xlsx)"
                )
                st.download_button(
                    label=btn_label,
                    data=excel_bytes,
                    file_name=filename,
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    use_container_width=True,
                    key=f"{key_prefix}_download_excel",
                )
            else:
                st.button(
                    "Export Excel (.xlsx)",
                    disabled=True,
                    use_container_width=True,
                    key=f"{key_prefix}_download_disabled",
                )

        if is_filtered:
            st.caption(
                f"Showing **{len(display_df)}** of {len(all_records_df)} saved cards"
            )
        else:
            st.caption(f"Total saved cards: **{len(all_records_df)}**")

        st.dataframe(display_df, use_container_width=True, hide_index=True)


def _render_update_record_body(
    all_records_df: pd.DataFrame, current_user_id: str, key_prefix: str
) -> None:
    if all_records_df.empty:
        st.info("No saved records available to update yet.")
        return

    edit_query = st.text_input(
        "Search card to update",
        placeholder="Type company name, person, phone, email, city, or website...",
        key=f"{key_prefix}_search_record_to_edit",
    )

    if not edit_query.strip():
        st.caption("Enter any keyword above to find the record you want to update.")
        return

    edit_matches = search_records_df(all_records_df, edit_query)
    if edit_matches.empty:
        st.info("No matching record found for that search.")
        return

    selected_edit_row: Optional[pd.Series] = None
    if len(edit_matches) == 1:
        selected_edit_row = edit_matches.iloc[0]
        st.caption(f"Matched 1 record: **{selected_edit_row['Company Name']}**")
    else:
        st.info(
            f"Found {len(edit_matches)} matching records. Choose which one to update:"
        )
        option_indices = list(range(len(edit_matches)))
        option_labels = [
            _record_summary_label(edit_matches.iloc[i]) for i in option_indices
        ]
        chosen_idx = st.radio(
            "Select which record to update",
            options=option_indices,
            format_func=lambda i: option_labels[i],
            index=None,
            key=f"{key_prefix}_radio_select_edit_record",
            label_visibility="collapsed",
        )
        if chosen_idx is not None:
            selected_edit_row = edit_matches.iloc[chosen_idx]

    if selected_edit_row is None:
        return

    edit_id = str(selected_edit_row["Record ID"])
    edit_rev = st.session_state["edit_counter"]
    existing_extra_text = format_extra_data_for_input(
        parse_extra_data(str(selected_edit_row.get("Extra Data JSON", "")))
    )

    with st.form(key=f"{key_prefix}_edit_card_form_{edit_id}_{edit_rev}"):
        er1_c1, er1_c2 = st.columns(2)
        with er1_c1:
            upd_company = st.text_input(
                "Company Name",
                value=str(selected_edit_row["Company Name"]),
                placeholder=FIELD_PLACEHOLDERS["company_name"],
                key=f"{key_prefix}_upd_company_{edit_id}_{edit_rev}",
            )
        with er1_c2:
            upd_contact = st.text_input(
                "Contact Person",
                value=str(selected_edit_row["Contact Person"]),
                placeholder=FIELD_PLACEHOLDERS["contact_person"],
                key=f"{key_prefix}_upd_contact_{edit_id}_{edit_rev}",
            )

        er2_c1, er2_c2 = st.columns(2)
        with er2_c1:
            upd_call = st.text_input(
                "Contact No.",
                value=str(selected_edit_row["Contact No."]),
                placeholder=FIELD_PLACEHOLDERS["call_phone"],
                key=f"{key_prefix}_upd_call_{edit_id}_{edit_rev}",
            )
        with er2_c2:
            upd_whatsapp = st.text_input(
                "WhatsApp No.",
                value=str(selected_edit_row["WhatsApp No."]),
                placeholder=FIELD_PLACEHOLDERS["whatsapp_phone"],
                key=f"{key_prefix}_upd_whatsapp_{edit_id}_{edit_rev}",
            )

        er3_c1, er3_c2 = st.columns(2)
        with er3_c1:
            upd_email = st.text_input(
                "Email",
                value=str(selected_edit_row["Email"]),
                placeholder=FIELD_PLACEHOLDERS["email"],
                key=f"{key_prefix}_upd_email_{edit_id}_{edit_rev}",
            )
        with er3_c2:
            upd_products = st.text_input(
                "Product / Services",
                value=str(selected_edit_row["Product / Services"]),
                placeholder=FIELD_PLACEHOLDERS["products_services"],
                key=f"{key_prefix}_upd_products_{edit_id}_{edit_rev}",
            )

        upd_address = st.text_area(
            "Address",
            value=str(selected_edit_row["Address"]),
            placeholder=FIELD_PLACEHOLDERS["address"],
            height=80,
            key=f"{key_prefix}_upd_address_{edit_id}_{edit_rev}",
        )

        er4_c1, er4_c2 = st.columns(2)
        with er4_c1:
            upd_city = st.text_input(
                "City",
                value=str(selected_edit_row["City"]),
                placeholder=FIELD_PLACEHOLDERS["city"],
                key=f"{key_prefix}_upd_city_{edit_id}_{edit_rev}",
            )
        with er4_c2:
            upd_notes = st.text_input(
                "Notes (Optional)",
                value=str(selected_edit_row["Notes"]),
                placeholder=FIELD_PLACEHOLDERS["notes"],
                key=f"{key_prefix}_upd_notes_{edit_id}_{edit_rev}",
            )

        upd_extra_text = st.text_area(
            "Extra Details (Optional — Website, GSTIN, Fax, etc., one per line as Label: Value)",
            value=existing_extra_text,
            placeholder=FIELD_PLACEHOLDERS["extra_details"],
            height=75,
            key=f"{key_prefix}_upd_extra_{edit_id}_{edit_rev}",
        )

        update_submitted = st.form_submit_button("Update Record", type="primary")

        if update_submitted:
            parsed_extra = parse_extra_data_from_input(upd_extra_text)
            clean_upd_email = sanitize_text_field(upd_email, 220)
            if not are_all_emails_valid(clean_upd_email):
                st.error(
                    "Please enter valid email address(es) separated by ' / ' (or leave it as N/A)."
                )
            elif not has_at_least_one_field(
                upd_company,
                upd_contact,
                upd_call,
                upd_whatsapp,
                upd_email,
                upd_products,
                upd_address,
                upd_city,
                upd_notes,
                *parsed_extra.values(),
            ):
                st.error("Please fill at least one field before updating the record.")
            else:
                try:
                    updated = update_record(
                        record_id=edit_id,
                        user_id=current_user_id,
                        company_name=upd_company,
                        contact_person=upd_contact,
                        call_phone=upd_call,
                        whatsapp_phone=upd_whatsapp,
                        email=upd_email,
                        products_services=upd_products,
                        address=upd_address,
                        city=upd_city,
                        notes=upd_notes,
                        extra_data=parsed_extra,
                    )
                    if updated:
                        st.session_state["edit_counter"] += 1
                        label = upd_company.strip() or upd_contact.strip() or "record"
                        st.session_state["flash_success"] = (
                            f"Updated '{label}' successfully."
                        )
                        st.rerun()
                    else:
                        st.warning(
                            "Record not found or does not belong to your account."
                        )
                except ValueError as val_err:
                    st.error(str(val_err))
                except Exception:
                    st.error("Could not update record right now. Please try again.")


def render_update_record_section(
    all_records_df: pd.DataFrame,
    current_user_id: str,
    as_expander: bool,
    key_prefix: str,
) -> None:
    if as_expander:
        with st.expander("Update a record (by search)"):
            _render_update_record_body(all_records_df, current_user_id, key_prefix)
    else:
        with st.container(border=True):
            st.subheader("Update a Record")
            _render_update_record_body(all_records_df, current_user_id, key_prefix)


def _render_delete_record_body(
    all_records_df: pd.DataFrame, current_user_id: str, key_prefix: str
) -> None:
    if all_records_df.empty:
        st.info("No saved records available to delete yet.")
        return

    del_query = st.text_input(
        "Search card to move to Trash",
        placeholder="Type company name, person, phone, email, city, or website...",
        key=f"{key_prefix}_search_record_to_delete",
    )

    if not del_query.strip():
        st.caption("Enter any keyword above to find the record you want to move to Trash.")
        return

    del_matches = search_records_df(all_records_df, del_query)
    if del_matches.empty:
        st.info("No matching record found for that search.")
        return

    selected_del_row: Optional[pd.Series] = None
    if len(del_matches) == 1:
        selected_del_row = del_matches.iloc[0]
    else:
        st.info(
            f"Found {len(del_matches)} matching records. Choose which one to move to Trash:"
        )
        del_indices = list(range(len(del_matches)))
        del_labels = [
            _record_summary_label(del_matches.iloc[i]) for i in del_indices
        ]
        chosen_del_idx = st.radio(
            "Select which record to delete",
            options=del_indices,
            format_func=lambda i: del_labels[i],
            index=None,
            key=f"{key_prefix}_radio_select_delete_record",
            label_visibility="collapsed",
        )
        if chosen_del_idx is not None:
            selected_del_row = del_matches.iloc[chosen_del_idx]

    if selected_del_row is None:
        return

    del_id = str(selected_del_row["Record ID"])
    st.warning(
        f"Move **{selected_del_row['Company Name']}** "
        f"({selected_del_row['Contact Person']} • {selected_del_row['City']}) to Trash? "
        "(You can restore it anytime from **Trash & Audit**.)"
    )
    if st.button(
        "Move to Trash",
        type="primary",
        key=f"{key_prefix}_btn_confirm_delete_{del_id}",
    ):
        try:
            deleted = soft_delete_record(del_id, current_user_id)
            if deleted:
                st.session_state["flash_success"] = (
                    f"Moved '{selected_del_row['Company Name']}' to Trash."
                )
                st.rerun()
            else:
                st.warning("Record not found or does not belong to your account.")
        except Exception:
            st.error("Could not delete record right now. Please try again.")


def render_delete_record_section(
    all_records_df: pd.DataFrame,
    current_user_id: str,
    as_expander: bool,
    key_prefix: str,
) -> None:
    if as_expander:
        with st.expander("Delete a record (by search)"):
            _render_delete_record_body(all_records_df, current_user_id, key_prefix)
    else:
        with st.container(border=True):
            st.subheader("Delete a Record")
            _render_delete_record_body(all_records_df, current_user_id, key_prefix)


def render_trash_and_audit_section(
    current_user_id: str, current_username: str, key_prefix: str
) -> None:
    with st.container(border=True):
        st.subheader("Trash, Backups & Audit History")

        all_with_deleted = fetch_user_records(current_user_id, include_deleted=True)
        deleted_df = (
            all_with_deleted[all_with_deleted["Deleted At"].astype(str).str.strip() != ""]
            if not all_with_deleted.empty
            else pd.DataFrame(columns=ALL_RECORD_COLUMNS)
        )
        active_df = (
            all_with_deleted[all_with_deleted["Deleted At"].astype(str).str.strip() == ""]
            if not all_with_deleted.empty
            else pd.DataFrame(columns=ALL_RECORD_COLUMNS)
        )
        full_audit_df = fetch_user_audit_logs(current_user_id, limit=None)

        b_col1, b_col2 = st.columns([2.8, 1.5])
        with b_col1:
            st.caption(
                "Download a complete multi-tab Excel backup containing all active cards, Trash items, and your entire audit history."
            )
        with b_col2:
            backup_sheets = {
                "Active Cards": build_expanded_dataframe(active_df, include_extra_columns=True),
                "Trash": build_expanded_dataframe(deleted_df, include_extra_columns=True),
                "Audit History": full_audit_df,
            }
            backup_bytes = build_multi_sheet_excel_bytes(backup_sheets)
            if st.download_button(
                label="Download Full Backup (.xlsx)",
                data=backup_bytes,
                file_name=f"full_backup_{current_username}_{datetime.now().strftime('%Y%m%d_%H%M')}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                use_container_width=True,
                key=f"{key_prefix}_full_backup",
            ):
                append_audit_log(
                    current_user_id,
                    "BACKUP_EXPORT",
                    "all",
                    f"Downloaded full backup ({len(active_df)} active, {len(deleted_df)} trash, {len(full_audit_df)} audit rows)",
                )

        tab_trash, tab_audit = st.tabs(
            [f"Trash ({len(deleted_df)})", f"Audit History ({len(full_audit_df)})"]
        )

        with tab_trash:
            if deleted_df.empty:
                st.info("Trash is empty.")
            else:
                st.dataframe(
                    deleted_df[
                        [
                            "Record ID",
                            "Company Name",
                            "Contact Person",
                            "WhatsApp No.",
                            "City",
                            "Deleted At",
                        ]
                    ],
                    use_container_width=True,
                    hide_index=True,
                )
                restore_options = {
                    f"{r['Company Name']} — {r['Contact Person']} (Deleted: {r['Deleted At']}) [{str(r['Record ID'])[:8]}]": r[
                        "Record ID"
                    ]
                    for _, r in deleted_df.iterrows()
                }
                chosen_restore = st.selectbox(
                    "Select card to restore",
                    options=list(restore_options.keys()),
                    key=f"{key_prefix}_restore_select",
                )
                if st.button(
                    "Restore Selected Card",
                    type="primary",
                    key=f"{key_prefix}_btn_restore",
                ):
                    if restore_deleted_record(
                        restore_options[chosen_restore], current_user_id
                    ):
                        st.session_state["flash_success"] = "Card restored successfully."
                        st.rerun()
                    else:
                        st.error("Could not restore record.")

        with tab_audit:
            if full_audit_df.empty:
                st.info("No audit history recorded yet.")
            else:
                if len(full_audit_df) > 100:
                    st.caption(
                        f"Showing latest 100 of {len(full_audit_df)} audit entries (all {len(full_audit_df)} entries are included in Full Backup)."
                    )
                st.dataframe(full_audit_df.head(100), use_container_width=True, hide_index=True)


# ---------------------------------------------------------------------------
# Main Application
# ---------------------------------------------------------------------------
def main() -> None:
    inject_clean_ui_css()

    for key, default in (
        ("auth_user", None),
        ("bound_user_id", None),
        ("session_token", None),
        ("session_action", "read"),
        ("active_view", "home"),
        ("extracted_card", None),
        ("is_manual_entry", False),
        ("pending_duplicate_save", None),
        ("pending_registration", None),
        ("reg_otp_notice", None),
        ("scan_counter", 0),
        ("edit_counter", 0),
        ("uploader_reset_counter", 0),
        ("close_sidebar_seq", 0),
        ("scroll_to_form_seq", 0),
        ("flash_success", None),
        ("flash_info", None),
        ("audit_warning", None),
        ("scan_notice", None),
        ("reset_email_target", ""),
        ("ai_growth_output", None),
        ("ai_pitch_output", None),
        ("otp_sends_this_session", 0),
        ("campaign_sent_keys", set()),
    ):
        if key not in st.session_state:
            st.session_state[key] = default

    storage_ready = False
    storage_error = None
    try:
        get_spreadsheet(SCHEMA_VERSION)
        storage_ready = True
    except Exception as exc:
        cause = f" | Cause: {exc.__cause__}" if exc.__cause__ else ""
        storage_error = f"{type(exc).__name__}: {exc}{cause}"

    if not storage_ready:
        st.title("Company Visiting Card Scanner")
        st.error(f"Storage & Security setup required: {storage_error}")
        st.info(
            "Verify `SESSION_SECRET` (32+ chars), `GSHEET_URL`, and `[gcp_service_account]` "
            "in Streamlit Secrets, and ensure Google Sheets API is enabled."
        )
        return

    auth_user, is_checking_session = sync_and_restore_session()
    if is_checking_session:
        st.caption("Checking your session...")
        return

    if auth_user is None:
        render_auth_screen()
        return

    current_user_id = auth_user["user_id"]
    current_username = auth_user["username"]
    current_email = auth_user["email"]

    if st.session_state.get("bound_user_id") != current_user_id:
        clear_account_specific_state(preserve_flash=True)
        st.session_state["bound_user_id"] = current_user_id

    daily_limit = get_daily_scan_limit()
    try:
        scans_used_today = get_user_scans_today(current_user_id)
        quota_readable = True
    except Exception:
        scans_used_today = daily_limit
        quota_readable = False
    scans_remaining = max(0, daily_limit - scans_used_today) if quota_readable else 0

    try:
        all_records_df = fetch_user_records(current_user_id, include_deleted=False)
    except Exception:
        st.warning(
            "Google Sheets is momentarily busy (rate limit). Please wait 10 seconds and click Refresh."
        )
        if st.button("Refresh", key="btn_retry_load_cards"):
            st.rerun()
        return

    # ---- Sidebar: Menu, Account, Security & Collapsible Settings ----
    with st.sidebar:
        st.markdown("### Menu")
        active_view = st.session_state["active_view"]

        nav_items = [
            ("home", "Home"),
            ("crm", "CRM Pipeline"),
            ("show", "Show Records"),
            ("analyze", "Analyze & Growth"),
            ("update", "Update Record"),
            ("delete", "Delete Record"),
            ("trash", "Trash & Audit"),
        ]
        for view_key, view_label in nav_items:
            if st.button(
                view_label,
                type="primary" if active_view == view_key else "secondary",
                use_container_width=True,
                key=f"nav_btn_{view_key}",
            ):
                st.session_state["active_view"] = view_key
                st.session_state["close_sidebar_seq"] += 1
                st.rerun()

        if st.button("Logout", use_container_width=True, key="nav_btn_logout"):
            logout_user_session()
            st.session_state["close_sidebar_seq"] += 1
            st.rerun()

        st.divider()
        st.markdown("### Account")
        st.markdown(f"**{current_username}**")
        st.caption(current_email)
        st.progress(min(1.0, scans_used_today / daily_limit))
        st.caption(
            f"**{scans_remaining} / {daily_limit}** AI scans left today · "
            "Resets 1:30 PM IST (12:30 PM summer)"
        )

        if st.button(
            "Sign Out All Devices",
            use_container_width=True,
            key="btn_revoke_all_sessions",
        ):
            revoke_all_user_sessions(current_user_id)
            logout_user_session()
            st.session_state["close_sidebar_seq"] += 1
            st.rerun()

        st.divider()
        server_api_key = str(get_secret("GEMINI_API_KEY", "") or "").strip()
        with st.expander("Settings", expanded=not bool(server_api_key)):
            if server_api_key:
                st.success("AI Scanner ready")
                override_key = st.text_input(
                    "Use your own Gemini API Key (optional)",
                    value="",
                    type="password",
                    placeholder="Leave blank to use default key",
                )
                active_api_key = override_key.strip() or server_api_key
            else:
                user_api_key = st.text_input(
                    "Gemini API Key",
                    value="",
                    type="password",
                    placeholder="Enter your Gemini API key",
                )
                active_api_key = user_api_key.strip()
                if active_api_key:
                    st.success("AI Scanner ready")
                else:
                    st.warning("Enter a Gemini API key to scan cards.")

            st.success("Cloud storage connected")

    trigger_ui_bridge()

    # ---- Clean Page Header & Escaped Quick-Stats Strip ----
    st.title("Company Visiting Card Scanner & CRM")
    safe_username_html = html.escape(str(current_username), quote=True)
    st.markdown(
        f"""
        <div class="vcard-stat-strip">
            <div class="vcard-stat-pill">
                <div class="vcard-stat-label">Account</div>
                <div class="vcard-stat-value">{safe_username_html}</div>
            </div>
            <div class="vcard-stat-pill">
                <div class="vcard-stat-label">Saved Cards</div>
                <div class="vcard-stat-value">{len(all_records_df)}</div>
            </div>
            <div class="vcard-stat-pill">
                <div class="vcard-stat-label">AI Scans Left Today</div>
                <div class="vcard-stat-value">{scans_remaining} / {daily_limit}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if not quota_readable:
        st.warning(
            "Google Sheets is momentarily busy checking your daily AI quota — AI scanning will resume shortly."
        )

    if st.session_state.get("audit_warning"):
        st.warning(st.session_state["audit_warning"])
        st.session_state["audit_warning"] = None

    if st.session_state["flash_success"]:
        st.success(st.session_state["flash_success"])
        st.session_state["flash_success"] = None

    if st.session_state["flash_info"]:
        st.info(st.session_state["flash_info"])
        st.session_state["flash_info"] = None

    # ---- Dedicated Sidebar Views ----
    if active_view == "crm":
        render_crm_section(
            spreadsheet=get_spreadsheet(SCHEMA_VERSION),
            all_records_df=all_records_df,
            current_user_id=current_user_id,
            current_username=current_username,
            build_multi_sheet_excel_fn=build_multi_sheet_excel_bytes,
        )
        return

    if active_view == "show":
        render_show_records_section(
            all_records_df=all_records_df,
            current_username=current_username,
            title="Your Saved Visiting Cards",
            key_prefix="nav_show",
        )
        return

    if active_view == "analyze":
        render_analyze_section(
            all_records_df=all_records_df,
            current_username=current_username,
            current_user_id=current_user_id,
            active_api_key=active_api_key,
            scans_remaining=scans_remaining,
            daily_limit=daily_limit,
        )
        return

    if active_view == "update":
        render_update_record_section(
            all_records_df=all_records_df,
            current_user_id=current_user_id,
            as_expander=False,
            key_prefix="nav_update",
        )
        return

    if active_view == "delete":
        render_delete_record_section(
            all_records_df=all_records_df,
            current_user_id=current_user_id,
            as_expander=False,
            key_prefix="nav_delete",
        )
        return

    if active_view == "trash":
        render_trash_and_audit_section(
            current_user_id=current_user_id,
            current_username=current_username,
            key_prefix="nav_trash",
        )
        return

    # ---- Home-Page CRM Follow-Up Reminder Banner ----
    overdue_cnt, due_today_cnt, open_pipe_val = get_crm_due_summary(
        get_spreadsheet(SCHEMA_VERSION), all_records_df, current_user_id
    )
    if overdue_cnt > 0 or due_today_cnt > 0:
        alert_col1, alert_col2 = st.columns([4.0, 1.3])
        with alert_col1:
            st.warning(
                f"**CRM Reminder:** You have **{overdue_cnt}** overdue and **{due_today_cnt}** due-today "
                f"follow-up(s) · Open Pipeline: **{format_inr(open_pipe_val)}**."
            )
        with alert_col2:
            if st.button(
                "Open CRM Queue",
                type="primary",
                use_container_width=True,
                key="btn_home_open_crm",
            ):
                st.session_state["active_view"] = "crm"
                st.rerun()

    # ---- HOME VIEW: Step 1 (Upload / Camera / Merge Excel + Manual Entry) ----
    upload_rev = st.session_state["uploader_reset_counter"]

    with st.container(border=True):
        step1_col, manual_col = st.columns([3.5, 1.5])
        with step1_col:
            st.subheader("1. Add Visiting Card")
            st.caption(
                f"Scan 1 or 2 card sides with AI (max 5 MB/photo), merge an Excel sheet (max {MAX_EXCEL_IMPORT_ROWS} rows), or fill manually."
            )
        with manual_col:
            st.markdown("<div style='height: 0.35rem'></div>", unsafe_allow_html=True)
            if st.button(
                "Fill Details Manually",
                type="secondary",
                use_container_width=True,
                key="btn_open_manual_form",
            ):
                open_blank_manual_form()
                st.rerun()

        tab_upload, tab_camera, tab_excel = st.tabs(
            ["Upload Image(s)", "Take Photo", "Merge Existing Excel"]
        )

        with tab_upload:
            uploaded_files = st.file_uploader(
                "Upload 1 or 2 card photos (Front & Back — JPG or PNG, max 5 MB each)",
                type=["jpg", "jpeg", "png"],
                accept_multiple_files=True,
                key=f"card_file_uploader_{upload_rev}",
            )
            if uploaded_files:
                if len(uploaded_files) > MAX_CARD_IMAGES:
                    st.error(
                        f"Maximum {MAX_CARD_IMAGES} images allowed (Front & Back). "
                        f"You selected {len(uploaded_files)} — please remove the extra file(s)."
                    )
                elif any(
                    getattr(f, "size", 0) > MAX_IMAGE_FILE_BYTES for f in uploaded_files
                ):
                    st.error("Each image must be 5 MB or smaller.")
                else:
                    preview_cols = st.columns(2)
                    side_labels = ["Side 1 (Front)", "Side 2 (Back)"]
                    for idx, file_obj in enumerate(uploaded_files):
                        with preview_cols[idx]:
                            st.image(
                                file_obj.getvalue(),
                                caption=side_labels[idx],
                                width=280,
                            )
                    if st.button(
                        f"Scan Card ({len(uploaded_files)} image{'s' if len(uploaded_files) > 1 else ''})",
                        type="primary",
                        use_container_width=True,
                        key=f"btn_scan_upload_{upload_rev}",
                        disabled=(scans_remaining == 0),
                    ):
                        run_scan(uploaded_files, active_api_key, current_user_id)

        with tab_camera:
            cam_front = st.camera_input(
                "Side 1 (Front) — Capture front of the visiting card",
                key=f"card_camera_front_{upload_rev}",
            )
            add_back_side = st.checkbox(
                "Card has details on the back side (capture 2nd photo)",
                key=f"toggle_camera_back_{upload_rev}",
            )
            cam_back = None
            if add_back_side:
                cam_back = st.camera_input(
                    "Side 2 (Back) — Capture back of the visiting card",
                    key=f"card_camera_back_{upload_rev}",
                )

            captured_photos = [p for p in (cam_front, cam_back) if p is not None]
            if captured_photos:
                if st.button(
                    f"Scan Captured Photo{'s' if len(captured_photos) > 1 else ''} ({len(captured_photos)})",
                    type="primary",
                    use_container_width=True,
                    key=f"btn_scan_camera_{upload_rev}",
                    disabled=(scans_remaining == 0),
                ):
                    run_scan(captured_photos, active_api_key, current_user_id)

        with tab_excel:
            st.caption(
                f"Upload an `.xlsx` or `.csv` file (max 2 MB, up to {MAX_EXCEL_IMPORT_ROWS} rows, {MAX_EXCEL_IMPORT_COLS} columns). "
                "Standard columns auto-map into our format, empty cells save as `N/A`, and extra columns are preserved."
            )
            uploaded_excel = st.file_uploader(
                "Choose an Excel (.xlsx) or CSV file to merge",
                type=["xlsx", "csv"],
                key=f"excel_merge_uploader_{upload_rev}",
            )

            if uploaded_excel is not None:
                try:
                    raw_excel_df = read_bounded_spreadsheet(uploaded_excel)
                except ValueError as bound_err:
                    st.error(str(bound_err))
                    raw_excel_df = None
                except Exception as excel_err:
                    st.error(f"Could not read the file: {excel_err}")
                    raw_excel_df = None

                if raw_excel_df is not None:
                    if raw_excel_df.empty:
                        st.warning("The uploaded file has no data rows.")
                    else:
                        excel_cols = [str(c) for c in raw_excel_df.columns.tolist()]
                        auto_map = _auto_detect_excel_mapping(excel_cols)
                        dropdown_options = ["— Leave as N/A —", *excel_cols]

                        st.caption(
                            f"Found **{len(raw_excel_df)}** row(s). Verify standard column mapping:"
                        )

                        field_labels = [
                            ("company_name", "Company Name"),
                            ("contact_person", "Contact Person"),
                            ("call_phone", "Contact No."),
                            ("whatsapp_phone", "WhatsApp No."),
                            ("email", "Email"),
                            ("products_services", "Product / Services"),
                            ("address", "Address"),
                            ("city", "City"),
                            ("notes", "Notes"),
                        ]

                        chosen_mapping: dict[str, str] = {}
                        map_cols = st.columns(3)
                        for idx, (f_key, f_label) in enumerate(field_labels):
                            default_col = auto_map.get(f_key, "")
                            default_idx = (
                                dropdown_options.index(default_col)
                                if default_col in dropdown_options
                                else 0
                            )
                            with map_cols[idx % 3]:
                                selected_col = st.selectbox(
                                    f_label,
                                    options=dropdown_options,
                                    index=default_idx,
                                    key=f"map_{f_key}_{upload_rev}_{uploaded_excel.name}",
                                )
                                chosen_mapping[f_key] = (
                                    ""
                                    if selected_col == "— Leave as N/A —"
                                    else selected_col
                                )

                        mapped_source_set = {
                            c for c in chosen_mapping.values() if c
                        }
                        detected_extra_cols = [
                            c
                            for c in excel_cols
                            if c not in mapped_source_set
                            and not c.lower().startswith("column_")
                        ]

                        preserve_extra_cols = False
                        if detected_extra_cols:
                            preserve_extra_cols = st.checkbox(
                                f"Preserve {len(detected_extra_cols)} extra column(s) automatically "
                                f"({', '.join(detected_extra_cols)})",
                                value=True,
                                key=f"preserve_extra_cols_{upload_rev}_{uploaded_excel.name}",
                            )

                        active_extra_cols = (
                            detected_extra_cols if preserve_extra_cols else []
                        )

                        skip_excel_dups = st.checkbox(
                            "Skip rows that already exist in my account (match by phone or email)",
                            value=True,
                            key=f"skip_excel_dups_{upload_rev}",
                        )

                        preview_records = preview_excel_merge_rows(
                            raw_excel_df,
                            chosen_mapping,
                            active_extra_cols,
                        )
                        if preview_records:
                            preview_rows_dicts = []
                            for r in preview_records:
                                p_row = {
                                    "Company Name": r["company_name"],
                                    "Contact Person": r["contact_person"],
                                    "Contact No.": r["call_phone"],
                                    "WhatsApp No.": r["whatsapp_phone"],
                                    "Email": r["email"],
                                    "Product / Services": r["products_services"],
                                    "Address": r["address"],
                                    "City": r["city"],
                                    "Notes": r["notes"],
                                }
                                for ec in active_extra_cols:
                                    p_row[ec] = r["extra_data"].get(
                                        sanitize_text_field(ec, 80), "N/A"
                                    )
                                preview_rows_dicts.append(p_row)
                            st.caption("Preview (first 5 formatted rows):")
                            st.dataframe(
                                pd.DataFrame(preview_rows_dicts),
                                use_container_width=True,
                                hide_index=True,
                            )

                        if st.button(
                            "Merge into My Cards",
                            type="primary",
                            use_container_width=True,
                            key=f"btn_merge_excel_{upload_rev}",
                        ):
                            if not any(chosen_mapping.values()) and not active_extra_cols:
                                st.error(
                                    "Please map at least one column before merging."
                                )
                            else:
                                with st.spinner("Merging records into your account..."):
                                    try:
                                        (
                                            added,
                                            dup_count,
                                            empty_count,
                                            dropped_keys,
                                        ) = merge_excel_records_atomic(
                                            raw_df=raw_excel_df,
                                            col_mapping=chosen_mapping,
                                            unmapped_extra_cols=active_extra_cols,
                                            user_id=current_user_id,
                                            skip_duplicates=skip_excel_dups,
                                            source_name=uploaded_excel.name,
                                        )
                                        if added == 0:
                                            st.warning(
                                                f"No new records to merge "
                                                f"(skipped {dup_count} duplicate(s), {empty_count} empty row(s))."
                                            )
                                        else:
                                            clear_uploaded_inputs()
                                            extra_notes = []
                                            if active_extra_cols:
                                                extra_notes.append(
                                                    f"preserved extra column(s): {', '.join(active_extra_cols)}"
                                                )
                                            if dropped_keys:
                                                extra_notes.append(
                                                    f"trimmed long extra column(s) over 800 chars: {', '.join(dropped_keys)}"
                                                )
                                            if dup_count:
                                                extra_notes.append(
                                                    f"{dup_count} duplicate(s) skipped"
                                                )
                                            if empty_count:
                                                extra_notes.append(
                                                    f"{empty_count} empty row(s) skipped"
                                                )
                                            suffix_txt = (
                                                f" ({'; '.join(extra_notes)})"
                                                if extra_notes
                                                else ""
                                            )
                                            st.session_state["flash_success"] = (
                                                f"Merged {added} record(s) from '{uploaded_excel.name}'{suffix_txt}."
                                            )
                                            st.rerun()
                                    except Exception:
                                        st.error(
                                            "Could not merge the Excel file right now. Please try again."
                                        )

        if scans_remaining == 0 and quota_readable:
            st.info(
                f"You have used all {daily_limit} AI scans for today. "
                "Use **Fill Details Manually** or **Merge Existing Excel** above to keep adding cards."
            )

    # ---- Step 2: Slide-Down Verification / Manual Entry Form ----
    if st.session_state["extracted_card"] is not None:
        st.markdown(
            '<div id="card-entry-form-anchor" class="vcard-form-anchor"></div>',
            unsafe_allow_html=True,
        )
        with st.container(border=True):
            is_manual = bool(st.session_state.get("is_manual_entry", False))
            st.subheader(
                "2. Enter Card Details" if is_manual else "2. Verify & Save Details"
            )

            pending_dup = st.session_state["pending_duplicate_save"]

            if pending_dup is not None:
                st.warning(
                    "**Duplicate Card Detected!** A card with the same phone number or email "
                    "is already saved in your account."
                )
                st.caption("Existing matching card(s) in your account:")
                st.dataframe(
                    pd.DataFrame(pending_dup["matches"]),
                    use_container_width=True,
                    hide_index=True,
                )

                st.markdown("**Do you want to upload this same card data again?**")
                dup_col1, dup_col2, _ = st.columns([1.4, 1.4, 3.2])
                with dup_col1:
                    if st.button(
                        "Yes, Upload Again",
                        type="primary",
                        use_container_width=True,
                        key="btn_dup_yes",
                    ):
                        data = pending_dup["payload"]
                        try:
                            save_record_atomic(
                                user_id=current_user_id,
                                company_name=data["company_name"],
                                contact_person=data["contact_person"],
                                call_phone=data["call_phone"],
                                whatsapp_phone=data["whatsapp_phone"],
                                email=data["email"],
                                products_services=data["products_services"],
                                address=data["address"],
                                city=data["city"],
                                notes=data["notes"],
                                extra_data=data.get("extra_data") or {},
                                allow_duplicate=True,
                            )
                            st.session_state["pending_duplicate_save"] = None
                            st.session_state["extracted_card"] = None
                            st.session_state["is_manual_entry"] = False
                            clear_uploaded_inputs()
                            saved_label = (
                                data["company_name"].strip()
                                or data["contact_person"].strip()
                                or "Card"
                            )
                            st.session_state["flash_success"] = (
                                f"Saved '{saved_label}' to your account."
                            )
                            st.rerun()
                        except ValueError as val_err:
                            st.error(str(val_err))
                        except Exception:
                            st.error("Could not save right now. Please try again.")

                with dup_col2:
                    if st.button(
                        "No, Cancel",
                        type="secondary",
                        use_container_width=True,
                        key="btn_dup_no",
                    ):
                        st.session_state["pending_duplicate_save"] = None
                        st.session_state["extracted_card"] = None
                        st.session_state["is_manual_entry"] = False
                        clear_uploaded_inputs()
                        st.session_state["flash_info"] = (
                            "Duplicate upload cancelled — card was not saved again."
                        )
                        st.rerun()

            else:
                if st.session_state["scan_notice"]:
                    st.info(st.session_state["scan_notice"])
                    st.session_state["scan_notice"] = None

                card = st.session_state["extracted_card"]
                suffix = st.session_state["scan_counter"]

                with st.form(key=f"verify_card_form_{suffix}"):
                    r1_c1, r1_c2 = st.columns(2)
                    with r1_c1:
                        company_name = st.text_input(
                            "Company Name",
                            value="" if is_manual else card.get("company_name", "N/A"),
                            placeholder=FIELD_PLACEHOLDERS["company_name"],
                            key=f"company_{suffix}",
                        )
                    with r1_c2:
                        contact_person = st.text_input(
                            "Contact Person",
                            value="" if is_manual else card.get("contact_person", "N/A"),
                            placeholder=FIELD_PLACEHOLDERS["contact_person"],
                            key=f"contact_{suffix}",
                        )

                    r2_c1, r2_c2 = st.columns(2)
                    with r2_c1:
                        call_phone = st.text_input(
                            "Contact No.",
                            value="" if is_manual else card.get("call_phone", "N/A"),
                            placeholder=FIELD_PLACEHOLDERS["call_phone"],
                            key=f"call_{suffix}",
                        )
                    with r2_c2:
                        whatsapp_phone = st.text_input(
                            "WhatsApp No.",
                            value="" if is_manual else card.get("whatsapp_phone", "N/A"),
                            placeholder=FIELD_PLACEHOLDERS["whatsapp_phone"],
                            key=f"whatsapp_{suffix}",
                        )

                    r3_c1, r3_c2 = st.columns(2)
                    with r3_c1:
                        email = st.text_input(
                            "Email",
                            value="" if is_manual else card.get("email", "N/A"),
                            placeholder=FIELD_PLACEHOLDERS["email"],
                            key=f"email_{suffix}",
                        )
                    with r3_c2:
                        products_services = st.text_input(
                            "Product / Services",
                            value="" if is_manual else card.get("products_services", "N/A"),
                            placeholder=FIELD_PLACEHOLDERS["products_services"],
                            key=f"products_{suffix}",
                        )

                    address = st.text_area(
                        "Address",
                        value="" if is_manual else card.get("address", "N/A"),
                        placeholder=FIELD_PLACEHOLDERS["address"],
                        height=80,
                        key=f"address_{suffix}",
                    )

                    r4_c1, r4_c2 = st.columns(2)
                    with r4_c1:
                        city = st.text_input(
                            "City",
                            value="" if is_manual else card.get("city", "N/A"),
                            placeholder=FIELD_PLACEHOLDERS["city"],
                            key=f"city_{suffix}",
                        )
                    with r4_c2:
                        notes = st.text_input(
                            "Notes (Optional)",
                            value="" if is_manual else card.get("notes", ""),
                            placeholder=FIELD_PLACEHOLDERS["notes"],
                            key=f"notes_{suffix}",
                        )

                    extra_details_text = st.text_area(
                        "Extra Details (Optional — Website, GSTIN, Fax, etc., one per line as Label: Value)",
                        value="" if is_manual else card.get("extra_details_text", ""),
                        placeholder=FIELD_PLACEHOLDERS["extra_details"],
                        height=75,
                        key=f"extra_details_{suffix}",
                    )

                    btn_col1, btn_col2, _ = st.columns([1.4, 1.2, 3.4])
                    with btn_col1:
                        submitted = st.form_submit_button(
                            "Save Card", type="primary", use_container_width=True
                        )
                    with btn_col2:
                        discarded = st.form_submit_button(
                            "Discard", use_container_width=True
                        )

                    if submitted:
                        parsed_extra = parse_extra_data_from_input(extra_details_text)
                        clean_email_val = sanitize_text_field(email, 220)
                        if not are_all_emails_valid(clean_email_val):
                            st.error(
                                "Please enter valid email address(es) separated by ' / ' (or leave blank / N/A)."
                            )
                        elif not has_at_least_one_field(
                            company_name,
                            contact_person,
                            call_phone,
                            whatsapp_phone,
                            email,
                            products_services,
                            address,
                            city,
                            notes,
                            *parsed_extra.values(),
                        ):
                            st.error("Please fill at least one field before saving.")
                        else:
                            try:
                                saved_id, matches = save_record_atomic(
                                    user_id=current_user_id,
                                    company_name=company_name,
                                    contact_person=contact_person,
                                    call_phone=call_phone,
                                    whatsapp_phone=whatsapp_phone,
                                    email=email,
                                    products_services=products_services,
                                    address=address,
                                    city=city,
                                    notes=notes,
                                    extra_data=parsed_extra,
                                    allow_duplicate=False,
                                )
                                if saved_id is None and matches:
                                    st.session_state["pending_duplicate_save"] = {
                                        "payload": {
                                            "company_name": company_name,
                                            "contact_person": contact_person,
                                            "call_phone": call_phone,
                                            "whatsapp_phone": whatsapp_phone,
                                            "email": email,
                                            "products_services": products_services,
                                            "address": address,
                                            "city": city,
                                            "notes": notes,
                                            "extra_data": parsed_extra,
                                        },
                                        "matches": matches,
                                    }
                                    st.rerun()
                                else:
                                    st.session_state["extracted_card"] = None
                                    st.session_state["is_manual_entry"] = False
                                    clear_uploaded_inputs()
                                    saved_label = (
                                        company_name.strip()
                                        or contact_person.strip()
                                        or "Card"
                                    )
                                    st.session_state["flash_success"] = (
                                        f"Saved '{saved_label}' to your account."
                                    )
                                    st.rerun()
                            except ValueError as val_err:
                                st.error(str(val_err))
                            except Exception:
                                st.error("Could not save right now. Please try again.")

                    if discarded:
                        st.session_state["extracted_card"] = None
                        st.session_state["is_manual_entry"] = False
                        st.session_state["pending_duplicate_save"] = None
                        clear_uploaded_inputs()
                        st.rerun()

    # ---- Step 3 (Still on Home Page): Show Records, Update & Delete ----
    st.markdown("<div style='height: 0.4rem'></div>", unsafe_allow_html=True)
    render_show_records_section(
        all_records_df=all_records_df,
        current_username=current_username,
        title="3. Your Saved Visiting Cards",
        key_prefix="home_show",
    )

    if not all_records_df.empty:
        render_update_record_section(
            all_records_df=all_records_df,
            current_user_id=current_user_id,
            as_expander=True,
            key_prefix="home_update",
        )
        render_delete_record_section(
            all_records_df=all_records_df,
            current_user_id=current_user_id,
            as_expander=True,
            key_prefix="home_delete",
        )


if __name__ == "__main__":
    main()