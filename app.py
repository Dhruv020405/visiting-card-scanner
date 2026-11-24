import base64
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import smtplib
import time
import unicodedata
import uuid
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Any, Optional, Tuple
from zoneinfo import ZoneInfo

import gspread
import pandas as pd
import streamlit as st
from google import genai
from google.genai import errors as genai_errors
from google.genai import types
from gspread.utils import rowcol_to_a1
from PIL import Image, ImageOps
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCHEMA_VERSION = "v6_extra_data_and_clean_ui"

MODEL_CHAIN = [
    "gemini-3.5-flash-lite",
    "gemini-3.1-flash-lite",
    "gemini-3.6-flash",
    "gemini-3.8-flash",
]

# Anti-504 Timeout & Image Optimization Settings
PER_REQUEST_TIMEOUT_MS = 22_000
TOTAL_SCAN_BUDGET_SEC = 45.0
MAX_IMAGE_SIDE_PX = 1400
JPEG_QUALITY = 82

# Free-tier protection, session & OTP settings
DEFAULT_DAILY_SCAN_LIMIT = 40
SESSION_TTL_SECONDS = 7 * 24 * 60 * 60  # 7-day browser session
OTP_TTL_SECONDS = 10 * 60               # 10-minute email OTP validity

CARDS_WORKSHEET = "visiting_cards"
USERS_WORKSHEET = "users"
USAGE_WORKSHEET = "scan_usage"
RESETS_WORKSHEET = "password_resets"
REGISTER_OTPS_WORKSHEET = "register_otps"

PBKDF2_ITERATIONS = 260_000
MAX_CARD_IMAGES = 2

# Google Sheet column order (adds single `extra_data` JSON column at the end)
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
]

# Exact default table column order
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
}

USER_HEADERS = [
    "user_id",
    "username",
    "email",
    "password_hash",
    "role",
    "created_at",
]

USAGE_HEADERS = [
    "user_id",
    "quota_date",
    "scan_count",
    "updated_at",
]

OTP_HEADERS = [
    "email",
    "code_hash",
    "expires_at",
    "used",
    "created_at",
]

# Aliases for auto-mapping uploaded Excel/CSV columns to our standard fields
EXCEL_COLUMN_ALIASES: dict[str, list[str]] = {
    "company_name": [
        "company name",
        "company",
        "business name",
        "business",
        "firm name",
        "firm",
        "organization",
        "org",
        "party name",
        "party",
        "shop name",
        "shop",
        "client",
    ],
    "contact_person": [
        "contact person",
        "person",
        "name",
        "full name",
        "contact name",
        "owner",
        "owner name",
        "director",
        "manager",
        "representative",
    ],
    "call_phone": [
        "contact no",
        "contact no.",
        "contact number",
        "call no",
        "call number",
        "call",
        "phone",
        "phone no",
        "phone number",
        "mobile",
        "mobile no",
        "mobile number",
        "telephone",
        "tel",
        "landline",
        "office no",
        "contact",
    ],
    "whatsapp_phone": [
        "whatsapp no",
        "whatsapp no.",
        "whatsapp number",
        "whatsapp",
        "wp no",
        "wp number",
        "wp",
        "wa no",
        "wa number",
        "wa",
    ],
    "email": [
        "email",
        "email id",
        "email address",
        "e-mail",
        "mail",
        "mail id",
    ],
    "products_services": [
        "product / services",
        "products / services",
        "product/services",
        "products/services",
        "products",
        "product",
        "services",
        "service",
        "business type",
        "category",
        "items",
        "dealing in",
    ],
    "address": [
        "address",
        "full address",
        "office address",
        "shop address",
        "factory address",
        "location",
    ],
    "city": [
        "city",
        "town",
        "district",
        "place",
    ],
    "notes": [
        "notes",
        "note",
        "remarks",
        "remark",
        "comments",
        "comment",
    ],
}

# Realistic dummy placeholders used across Scan, Manual Entry, and Update forms
FIELD_PLACEHOLDERS = {
    "company_name": "e.g., Apex Industrial Solutions",
    "contact_person": "e.g., Rajesh Patel (Sales Manager)",
    "call_phone": "e.g., 9876543210 / 07926300000",
    "whatsapp_phone": "e.g., 9876543210 / 9123456789",
    "email": "e.g., contact@example.com",
    "products_services": "e.g., Industrial Valves, Pumps, Automation",
    "address": "e.g., Plot 12, GIDC Estate, Main Road",
    "city": "e.g., Ahmedabad",
    "notes": "e.g., Met at trade fair, wholesale supplier",
    "extra_details": "Website: www.example.com\nGSTIN: 24ABCDE1234F1Z5",
}

st.set_page_config(
    page_title="Company Visiting Card Scanner",
    page_icon="📇",
    layout="wide",
    initial_sidebar_state="auto",
)


# ---------------------------------------------------------------------------
# Clean Responsive UI Styling (Phone + Laptop) & Toolbar Cleanup
# ---------------------------------------------------------------------------
def inject_clean_ui_css() -> None:
    st.markdown(
        """
        <style>
            /* Hide GitHub, Fork, Deploy & extra chrome while keeping sidebar toggle intact */
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

            /* Balanced layout spacing for desktop and mobile */
            .block-container {
                padding-top: 1.4rem;
                padding-bottom: 2.5rem;
                max-width: 1200px;
            }

            /* Touch-friendly rounded buttons */
            .stButton > button,
            .stDownloadButton > button,
            .stFormSubmitButton > button {
                min-height: 2.65rem;
                border-radius: 8px;
                font-weight: 500;
            }

            /* Compact summary pill strip */
            .vcard-stat-strip {
                display: flex;
                flex-wrap: wrap;
                gap: 0.65rem;
                margin: 0.35rem 0 1rem 0;
            }
            .vcard-stat-pill {
                flex: 1 1 160px;
                padding: 0.65rem 0.95rem;
                border-radius: 10px;
                border: 1px solid rgba(128, 128, 128, 0.22);
                background: rgba(128, 128, 128, 0.06);
            }
            .vcard-stat-label {
                font-size: 0.78rem;
                opacity: 0.72;
                margin-bottom: 0.15rem;
            }
            .vcard-stat-value {
                font-size: 1.15rem;
                font-weight: 600;
            }

            /* Smooth slide-down reveal for the card form */
            @keyframes vcardSlideDown {
                from {
                    opacity: 0;
                    transform: translateY(-10px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            .vcard-form-anchor {
                scroll-margin-top: 1rem;
                animation: vcardSlideDown 0.3s ease-out;
            }

            /* Mobile tweaks */
            @media (max-width: 768px) {
                .block-container {
                    padding-top: 0.9rem;
                    padding-left: 0.85rem;
                    padding-right: 0.85rem;
                }
                h1 {
                    font-size: 1.65rem !important;
                }
                h2, h3 {
                    font-size: 1.2rem !important;
                }
            }
            /* Keep card image previews & camera compact on laptop and phone */
            [data-testid="stImage"] img {
                max-height: 240px !important;
                max-width: min(300px, 100%) !important;
                width: auto !important;
                height: auto !important;
                object-fit: contain;
                border-radius: 8px;
                border: 1px solid rgba(128, 128, 128, 0.25);
            }
            [data-testid="stCameraInput"] {
                max-width: 420px;
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
    const STORAGE_KEY = "vcard_scanner_auth_token_v1";
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
        if (val && val.trim()) {
            existing = val.trim();
        }
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
            if (!sidebar) return;
            if (sidebar.getAttribute("aria-expanded") === "false") return;
            const btn =
                document.querySelector('[data-testid="stSidebarCollapseButton"] button') ||
                sidebar.querySelector('[data-testid="stSidebarHeader"] button') ||
                sidebar.querySelector(
                    'button[aria-label*="Close"], button[aria-label*="Collapse"], button[kind="headerNoPadding"]'
                );
            if (btn) btn.click();
        };
        setTimeout(tryCloseMobileSidebar, 60);
        setTimeout(tryCloseMobileSidebar, 240);
    }

    if (scrollSeq > 0 && window.__vcardLastScrollSeq !== scrollSeq) {
        window.__vcardLastScrollSeq = scrollSeq;
        const tryScrollToForm = () => {
            const el = document.getElementById("card-entry-form-anchor");
            if (el) {
                el.scrollIntoView({ behavior: "smooth", block: "start" });
                return true;
            }
            return false;
        };
        setTimeout(() => {
            if (!tryScrollToForm()) {
                setTimeout(tryScrollToForm, 250);
            }
        }, 120);
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
    """Run lightweight browser actions (mobile sidebar auto-close & scroll-to-form)."""
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
# Secret, Session Token, Hashing, Phone & Extra-Data Helpers
# ---------------------------------------------------------------------------
def get_secret(key: str, default: Any = None) -> Any:
    """Safely read a key from st.secrets or environment variables."""
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
    """Return today's date in Pacific Time to match Google's free-tier quota reset."""
    try:
        tz = ZoneInfo("America/Los_Angeles")
    except Exception:
        tz = timezone(timedelta(hours=-8))
    return datetime.now(tz).strftime("%Y-%m-%d")


def _get_session_signing_key() -> bytes:
    explicit = get_secret("SESSION_SECRET")
    if explicit:
        material = str(explicit)
    else:
        creds = get_secret("gcp_service_account")
        if creds and "private_key" in creds:
            material = str(creds["private_key"])
        else:
            material = str(get_secret("GEMINI_API_KEY", "local-dev-session-key"))
    return hashlib.sha256(f"vcard-session-v2:{material}".encode("utf-8")).digest()


def create_session_token(user_id: str) -> str:
    expires_at = int(time.time()) + SESSION_TTL_SECONDS
    payload = f"{user_id}|{expires_at}"
    sig = hmac.new(
        _get_session_signing_key(), payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()[:32]
    raw = f"{payload}|{sig}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def verify_session_token(token: str) -> Optional[str]:
    try:
        decoded = base64.urlsafe_b64decode(token.encode("ascii")).decode("utf-8")
        user_id, exp_str, sig = decoded.split("|")
        expires_at = int(exp_str)
        if expires_at < int(time.time()):
            return None
        payload = f"{user_id}|{expires_at}"
        expected_sig = hmac.new(
            _get_session_signing_key(), payload.encode("utf-8"), hashlib.sha256
        ).hexdigest()[:32]
        if hmac.compare_digest(sig, expected_sig):
            return user_id
    except Exception:
        return None
    return None


def login_user_session(user: dict[str, str]) -> None:
    token = create_session_token(user["user_id"])
    st.session_state["auth_user"] = user
    st.session_state["session_token"] = token
    st.session_state["session_action"] = "set"
    st.session_state["active_view"] = "home"


def logout_user_session() -> None:
    st.session_state["auth_user"] = None
    st.session_state["session_token"] = None
    st.session_state["session_action"] = "clear"
    st.session_state["active_view"] = "home"


def sync_and_restore_session() -> Tuple[Optional[dict[str, str]], bool]:
    """Synchronize hidden browser localStorage session without touching URL params."""
    try:
        if "session" in st.query_params:
            st.query_params.pop("session", None)
    except Exception:
        pass

    if _SESSION_BRIDGE is None:
        return st.session_state.get("auth_user"), False

    action = st.session_state.get("session_action", "read")
    token_to_write = st.session_state.get("session_token") or ""

    if action == "set" and st.session_state.get("auth_user") and token_to_write:
        _SESSION_BRIDGE(
            data={"action": "set", "token": token_to_write},
            default={"token": token_to_write},
            key="session_bridge",
            on_token_change=lambda: None,
        )
        return st.session_state["auth_user"], False

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

    if st.session_state.get("auth_user") is not None:
        return st.session_state["auth_user"], False

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
        user_id = verify_session_token(stored_token)
        if user_id:
            for user in fetch_all_users():
                if user.get("user_id") == user_id:
                    restored = {
                        "user_id": user.get("user_id", ""),
                        "username": user.get("username", ""),
                        "email": user.get("email", ""),
                        "role": user.get("role", "user"),
                    }
                    st.session_state["auth_user"] = restored
                    st.session_state["session_token"] = stored_token
                    st.session_state["session_action"] = "set"
                    return restored, False
        st.session_state["session_action"] = "clear"

    return None, False


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
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            int(iter_str),
        )
        return hmac.compare_digest(dk.hex(), expected_hex)
    except Exception:
        return False


def is_valid_email(email: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email))


def is_valid_username(username: str) -> bool:
    return bool(re.match(r"^[A-Za-z0-9_.-]{3,30}$", username))


def has_at_least_one_field(*values: str) -> bool:
    """Return True if at least one field contains real user input (not empty or N/A)."""
    for val in values:
        cleaned = str(val or "").strip()
        if cleaned and cleaned.upper() != "N/A":
            return True
    return False


def normalize_digits(text: str) -> str:
    """Convert regional Unicode digits (Gujarati ૦-૯, Hindi ०-९, etc.) to ASCII 0-9."""
    return "".join(
        str(unicodedata.digit(ch)) if ch.isdecimal() and not ch.isascii() else ch
        for ch in text
    )


def format_phone_numbers(raw: str) -> str:
    """
    Format phone/WhatsApp numbers cleanly as '9876543210 / 9123456789'.
    Strips +91 / 91 Indian mobile prefixes, trailing Excel '.0', spaces, and dashes.
    """
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


def extract_normalized_emails(email_str: str) -> set[str]:
    if not email_str or email_str.strip().upper() == "N/A":
        return set()
    parts = re.split(r"[,;/|\s]+", email_str.strip().lower())
    return {p for p in parts if is_valid_email(p)}


# ---------------------------------------------------------------------------
# Extra Data (Option 1: JSON Column -> Auto-Expanded Excel Columns)
# ---------------------------------------------------------------------------
def parse_extra_data(raw_json: str) -> dict[str, str]:
    """Safely parse the JSON stored in Google Sheets' `extra_data` column."""
    if not raw_json or not str(raw_json).strip():
        return {}
    try:
        parsed = json.loads(str(raw_json))
        if not isinstance(parsed, dict):
            return {}
        cleaned: dict[str, str] = {}
        for k, v in parsed.items():
            ck = str(k).strip()
            cv = normalize_digits(str(v)).strip()
            if ck and cv and cv.upper() != "N/A":
                cleaned[ck] = cv
        return cleaned
    except Exception:
        return {}


def serialize_extra_data(extra: dict[str, str]) -> str:
    """Serialize extra key-value pairs to compact JSON for Google Sheets storage."""
    cleaned = {
        str(k).strip(): normalize_digits(str(v)).strip()
        for k, v in extra.items()
        if str(k).strip()
        and normalize_digits(str(v)).strip()
        and normalize_digits(str(v)).strip().upper() != "N/A"
    }
    if not cleaned:
        return ""
    return json.dumps(cleaned, ensure_ascii=False)


def format_extra_data_for_input(extra: dict[str, str]) -> str:
    """Format extra fields as editable `Key: Value` lines for form text areas."""
    if not extra:
        return ""
    return "\n".join(f"{k}: {v}" for k, v in extra.items())


def parse_extra_data_from_input(text: str) -> dict[str, str]:
    """Parse user-entered `Key: Value` lines into a clean extra-fields dictionary."""
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
            ck = k.strip()
            cv = normalize_digits(v).strip()
            if ck and cv and cv.upper() != "N/A":
                result[ck] = cv
        elif "=" in line:
            k, v = line.split("=", 1)
            ck = k.strip()
            cv = normalize_digits(v).strip()
            if ck and cv and cv.upper() != "N/A":
                result[ck] = cv
        else:
            other_lines.append(normalize_digits(line))

    if other_lines:
        existing_other = result.get("Other Info", "")
        combined = " | ".join([x for x in [existing_other, *other_lines] if x])
        result["Other Info"] = combined

    return result


def format_extra_data_summary(extra: dict[str, str]) -> str:
    """Compact one-line summary for search indexing."""
    if not extra:
        return ""
    return " | ".join(f"{k}: {v}" for k, v in extra.items())


def collect_extra_column_names(df: pd.DataFrame) -> list[str]:
    """Collect unique extra column names present in a user's records (case-normalized)."""
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
    df: pd.DataFrame, include_extra_columns: bool
) -> pd.DataFrame:
    """
    Build the display or Excel export DataFrame.
    When `include_extra_columns=True`, expands all `extra_data` keys into real columns
    at the right end (filling 'N/A' where absent).
    """
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
    """Auto-orient and compress visiting card photos to JPEG (max 1400px side)."""
    try:
        with Image.open(io.BytesIO(raw_bytes)) as img:
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
    except Exception:
        return raw_bytes, fallback_mime or "image/jpeg"


def clear_uploaded_inputs() -> None:
    """Reset file uploaders and camera inputs so previous photos clear after save/discard."""
    st.session_state["uploader_reset_counter"] = (
        st.session_state.get("uploader_reset_counter", 0) + 1
    )


# ---------------------------------------------------------------------------
# Pydantic Schema for Gemini Structured Outputs (Includes Extra Printed Details)
# ---------------------------------------------------------------------------
class ExtraDetail(BaseModel):
    label: str = Field(
        description=(
            "Short clean English Title Case label for an extra detail on the card "
            "(e.g., 'Website', 'GSTIN', 'PAN', 'Instagram', 'LinkedIn', 'Branch', 'Timings')."
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
        description="Email address in English (Latin script). Return 'N/A' if missing."
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
            "'Kapadvanj', 'Dakor', 'Surat', 'Vadodara'). Do NOT include street, state, country, or PIN code here. "
            "Infer from the address or PIN code if clear; return 'N/A' if completely absent."
        )
    )
    extra_details: list[ExtraDetail] = Field(
        default_factory=list,
        description=(
            "Any additional useful details printed on the card that do NOT belong in the standard fields "
            "(such as Website, GSTIN, PAN, Instagram, LinkedIn, Facebook, Branch, Office Timings, ISO Certification). "
            "Do NOT repeat company name, contact person, phone, email, products, address, or city here. "
            "Return an empty list [] if none are printed."
        ),
    )


def _clean_card_output(card: VisitingCard) -> Tuple[VisitingCard, dict[str, str]]:
    raw_city = normalize_digits(card.city).strip()
    clean_city = raw_city if raw_city and raw_city.upper() != "N/A" else "N/A"

    extra_dict: dict[str, str] = {}
    for item in card.extra_details or []:
        lbl = normalize_digits(item.label).strip()
        val = normalize_digits(item.value).strip()
        if (
            lbl
            and val
            and val.upper() != "N/A"
            and lbl.lower() not in STANDARD_FIELD_LABELS_LOWER
        ):
            extra_dict[lbl] = val

    cleaned = card.model_copy(
        update={
            "company_name": normalize_digits(card.company_name).strip() or "N/A",
            "contact_person": normalize_digits(card.contact_person).strip() or "N/A",
            "call_phone": format_phone_numbers(card.call_phone),
            "whatsapp_phone": format_phone_numbers(card.whatsapp_phone),
            "email": normalize_digits(card.email).strip() or "N/A",
            "products_services": normalize_digits(card.products_services).strip() or "N/A",
            "address": normalize_digits(card.address).strip() or "N/A",
            "city": clean_city,
        }
    )
    return cleaned, extra_dict


# ---------------------------------------------------------------------------
# Google Sheets Storage Layer (Auto-Creates, Migrates & Repairs Headers)
# ---------------------------------------------------------------------------
@st.cache_resource(show_spinner=False)
def get_spreadsheet(_schema_version: str = SCHEMA_VERSION) -> gspread.Spreadsheet:
    creds_section = get_secret("gcp_service_account")
    sheet_url = get_secret("GSHEET_URL")

    if not creds_section or not sheet_url:
        raise ValueError(
            "Google Sheets is not configured. Add `GSHEET_URL` and "
            "`[gcp_service_account]` to Streamlit Secrets."
        )

    creds_dict = dict(creds_section)
    client = gspread.service_account_from_dict(creds_dict)
    spreadsheet = client.open_by_url(str(sheet_url).strip())
    ensure_worksheets(spreadsheet)
    return spreadsheet


def _migrate_cards_worksheet_if_needed(cards_ws: gspread.Worksheet) -> None:
    """Align `visiting_cards` rows to CARD_HEADERS (adds `extra_data` column safely)."""
    all_rows = cards_ws.get_all_values()
    if not all_rows:
        cards_ws.append_row(CARD_HEADERS, value_input_option="RAW")
        return

    current_headers = all_rows[0]
    if cards_ws.col_count < len(CARD_HEADERS):
        cards_ws.resize(cols=len(CARD_HEADERS))

    if "record_id" not in current_headers and "user_id" not in current_headers:
        cards_ws.insert_row(CARD_HEADERS, index=1, value_input_option="RAW")
        return

    if current_headers == CARD_HEADERS:
        return

    migrated_rows = [CARD_HEADERS]
    for row in all_rows[1:]:
        if not any(cell.strip() for cell in row):
            continue
        padded = row + [""] * (len(current_headers) - len(row))
        old_rec = dict(zip(current_headers, padded))

        wp_val = format_phone_numbers(
            old_rec.get("whatsapp_phone") or old_rec.get("phone") or "N/A"
        )
        call_val = format_phone_numbers(old_rec.get("call_phone") or "N/A")

        new_rec = {
            "record_id": old_rec.get("record_id", uuid.uuid4().hex[:8]),
            "user_id": old_rec.get("user_id", "default_user"),
            "company_name": old_rec.get("company_name", "N/A"),
            "contact_person": old_rec.get("contact_person", "N/A"),
            "call_phone": call_val,
            "whatsapp_phone": wp_val,
            "email": old_rec.get("email", "N/A"),
            "products_services": old_rec.get("products_services", "N/A"),
            "address": old_rec.get("address", "N/A"),
            "city": old_rec.get("city", "N/A") or "N/A",
            "notes": old_rec.get("notes", ""),
            "created_at": old_rec.get("created_at", ""),
            "extra_data": old_rec.get("extra_data", ""),
        }
        migrated_rows.append([new_rec[col] for col in CARD_HEADERS])

    cards_ws.update(
        values=migrated_rows,
        range_name="A1",
        value_input_option="RAW",
    )


def ensure_worksheets(spreadsheet: gspread.Spreadsheet) -> None:
    existing_titles = {ws.title for ws in spreadsheet.worksheets()}

    if CARDS_WORKSHEET not in existing_titles:
        cards_ws = spreadsheet.add_worksheet(
            title=CARDS_WORKSHEET, rows=1000, cols=len(CARD_HEADERS)
        )
        cards_ws.append_row(CARD_HEADERS, value_input_option="RAW")
    else:
        cards_ws = spreadsheet.worksheet(CARDS_WORKSHEET)
        _migrate_cards_worksheet_if_needed(cards_ws)

    for ws_name, headers in (
        (USERS_WORKSHEET, USER_HEADERS),
        (USAGE_WORKSHEET, USAGE_HEADERS),
        (RESETS_WORKSHEET, OTP_HEADERS),
        (REGISTER_OTPS_WORKSHEET, OTP_HEADERS),
    ):
        if ws_name not in existing_titles:
            ws = spreadsheet.add_worksheet(title=ws_name, rows=500, cols=len(headers))
            ws.append_row(headers, value_input_option="RAW")
        else:
            ws = spreadsheet.worksheet(ws_name)
            if not ws.row_values(1):
                ws.append_row(headers, value_input_option="RAW")


def _get_or_create_worksheet(title: str, headers: list[str]) -> gspread.Worksheet:
    spreadsheet = get_spreadsheet(SCHEMA_VERSION)
    try:
        ws = spreadsheet.worksheet(title)
    except gspread.WorksheetNotFound:
        ws = spreadsheet.add_worksheet(title=title, rows=500, cols=len(headers))
        ws.append_row(headers, value_input_option="RAW")
        return ws

    if not ws.row_values(1):
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


# ---------------------------------------------------------------------------
# Per-User Daily Scan Quota Tracking
# ---------------------------------------------------------------------------
@st.cache_data(ttl=60, show_spinner=False)
def _fetch_all_usage_rows() -> list[list[str]]:
    ws = get_usage_worksheet()
    rows = ws.get_all_values()
    if not rows:
        ws.append_row(USAGE_HEADERS, value_input_option="RAW")
        return [USAGE_HEADERS]
    return rows


def get_user_scans_today(user_id: str) -> int:
    today = get_quota_date_str()
    rows = _fetch_all_usage_rows()
    if len(rows) <= 1:
        return 0
    for row in rows[1:]:
        if len(row) >= 3 and row[0] == user_id and row[1] == today:
            try:
                return int(row[2])
            except ValueError:
                return 0
    return 0


def increment_user_scan_count(user_id: str) -> int:
    ws = get_usage_worksheet()
    today = get_quota_date_str()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rows = ws.get_all_values()
    if not rows:
        ws.append_row(USAGE_HEADERS, value_input_option="RAW")
        rows = [USAGE_HEADERS]

    for row_idx, row in enumerate(rows[1:], start=2):
        if len(row) >= 3 and row[0] == user_id and row[1] == today:
            try:
                current = int(row[2])
            except ValueError:
                current = 0
            new_count = current + 1
            ws.update(
                values=[[str(new_count), now_str]],
                range_name=f"C{row_idx}:D{row_idx}",
                value_input_option="RAW",
            )
            _fetch_all_usage_rows.clear()
            return new_count

    ws.append_row(
        [user_id, today, "1", now_str], value_input_option="RAW", table_range="A1"
    )
    _fetch_all_usage_rows.clear()
    return 1


# ---------------------------------------------------------------------------
# Email OTP Delivery & Verification Helpers (Register + Forgot Password)
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
        f"This code is valid for 10 minutes. If you did not request this code, "
        f"you can safely ignore this email.\n"
    )

    with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=15) as server:
        server.login(smtp_email, smtp_password)
        server.send_message(msg)


def _issue_otp(
    ws: gspread.Worksheet,
    email: str,
    username: str,
    subject: str,
    purpose_line: str,
) -> Tuple[bool, str]:
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

    ws.append_row(
        [email, code_hash, expires_at, "no", created_at],
        value_input_option="RAW",
        table_range="A1",
    )
    return True, f"A 6-digit verification code has been sent to {email} (valid for 10 minutes)."


def _verify_and_consume_otp(
    ws: gspread.Worksheet, email: str, code: str
) -> Tuple[bool, str]:
    clean_email = email.strip().lower()
    clean_code = re.sub(r"\s+", "", code.strip())

    if not re.match(r"^\d{6}$", clean_code):
        return False, "Please enter the 6-digit verification code from your email."

    otp_rows = ws.get_all_values()
    if len(otp_rows) <= 1:
        return False, "No verification code found. Please request a new code."

    matched_row_idx: Optional[int] = None
    matched_data: Optional[list[str]] = None
    for idx in range(len(otp_rows) - 1, 0, -1):
        row = otp_rows[idx]
        if (
            len(row) >= 4
            and row[0].strip().lower() == clean_email
            and row[3].strip().lower() != "yes"
        ):
            matched_row_idx = idx + 1
            matched_data = row
            break

    if matched_row_idx is None or matched_data is None:
        return False, "No active code found for this email. Please request a new code."

    try:
        expires_at = int(matched_data[2])
    except ValueError:
        return False, "Verification code is invalid. Please request a new code."

    if int(time.time()) > expires_at:
        return False, "This verification code has expired. Please request a new code."

    if not verify_password(clean_code, matched_data[1]):
        return False, "Incorrect verification code. Please check your email and try again."

    ws.update(
        values=[["yes"]],
        range_name=f"D{matched_row_idx}",
        value_input_option="RAW",
    )
    return True, "Verified."


# ---------------------------------------------------------------------------
# User Authentication, OTP Registration & Forgot Password
# ---------------------------------------------------------------------------
@st.cache_data(ttl=60, show_spinner=False)
def fetch_all_users() -> list[dict[str, str]]:
    ws = get_users_worksheet()
    all_rows = ws.get_all_values()
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
    if len(password) < 6:
        return False, "Password must be at least 6 characters long.", None

    fetch_all_users.clear()
    for user in fetch_all_users():
        if user.get("username", "").strip().lower() == clean_username.lower():
            return False, "That username is already taken. Try another one.", None
        if user.get("email", "").strip().lower() == clean_email:
            return False, "An account with this email already exists. Please log in.", None

    ok, msg = _issue_otp(
        ws=get_register_otps_worksheet(),
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

    fetch_all_users.clear()
    for user in fetch_all_users():
        if user.get("username", "").strip().lower() == clean_username.lower():
            return False, "That username was just taken. Please pick another one.", None
        if user.get("email", "").strip().lower() == clean_email:
            return False, "An account with this email already exists. Please log in.", None

    user_id = f"usr_{uuid.uuid4().hex[:10]}"
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

    fetch_all_users.clear()
    for user in fetch_all_users():
        uname = user.get("username", "").strip().lower()
        uemail = user.get("email", "").strip().lower()
        if clean_id in (uname, uemail):
            if verify_password(password, user.get("password_hash", "")):
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
            return False, "Incorrect password. Please try again.", None

    return False, "No account found with that username or email.", None


def request_password_reset(email: str) -> Tuple[bool, str]:
    clean_email = email.strip().lower()
    if not is_valid_email(clean_email):
        return False, "Please enter a valid email address."

    fetch_all_users.clear()
    matched_user = None
    for user in fetch_all_users():
        if user.get("email", "").strip().lower() == clean_email:
            matched_user = user
            break

    if not matched_user:
        return False, "No account found with that email address."

    return _issue_otp(
        ws=get_resets_worksheet(),
        email=clean_email,
        username=matched_user.get("username", "User"),
        subject="Your Visiting Card Scanner Password Reset Code",
        purpose_line="Your password reset verification code is",
    )


def confirm_password_reset(
    email: str, code: str, new_password: str
) -> Tuple[bool, str]:
    clean_email = email.strip().lower()

    if not is_valid_email(clean_email):
        return False, "Please enter a valid email address."
    if len(new_password) < 6:
        return False, "New password must be at least 6 characters long."

    ok, msg = _verify_and_consume_otp(
        ws=get_resets_worksheet(),
        email=clean_email,
        code=code,
    )
    if not ok:
        return False, msg

    users_ws = get_users_worksheet()
    user_rows = users_ws.get_all_values()
    updated_user = False
    for row_idx, row in enumerate(user_rows[1:], start=2):
        if len(row) >= 4 and row[2].strip().lower() == clean_email:
            new_hash = hash_password(new_password)
            users_ws.update(
                values=[[new_hash]],
                range_name=f"D{row_idx}",
                value_input_option="RAW",
            )
            updated_user = True
            break

    if not updated_user:
        return False, "Account could not be found."

    fetch_all_users.clear()
    return True, "Password updated successfully! You can now log in with your new password."


# ---------------------------------------------------------------------------
# Visiting Card CRUD, Search, Excel Merge & Duplicate Detection
# ---------------------------------------------------------------------------
@st.cache_data(ttl=60, show_spinner=False)
def _fetch_all_card_rows() -> list[list[str]]:
    ws = get_cards_worksheet()
    all_rows = ws.get_all_values()
    if not all_rows:
        ws.append_row(CARD_HEADERS, value_input_option="RAW")
        return [CARD_HEADERS]

    first_row = all_rows[0]
    if "record_id" not in first_row and "user_id" not in first_row:
        ws.insert_row(CARD_HEADERS, index=1, value_input_option="RAW")
        return [CARD_HEADERS, *all_rows]

    return all_rows


def fetch_user_records(user_id: str) -> pd.DataFrame:
    """Return ONLY visiting cards uploaded by `user_id`, newest first."""
    all_rows = _fetch_all_card_rows()
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
            extra_dict = parse_extra_data(record.get("extra_data", ""))
            data_rows.append(
                {
                    "Record ID": record.get("record_id", ""),
                    "Company Name": record.get("company_name", "N/A") or "N/A",
                    "Contact Person": record.get("contact_person", "N/A") or "N/A",
                    "Contact No.": format_phone_numbers(record.get("call_phone", "N/A")),
                    "WhatsApp No.": format_phone_numbers(
                        record.get("whatsapp_phone", "N/A")
                    ),
                    "Email": record.get("email", "N/A") or "N/A",
                    "Product / Services": record.get("products_services", "N/A") or "N/A",
                    "Address": record.get("address", "N/A") or "N/A",
                    "City": record.get("city", "N/A") or "N/A",
                    "Notes": record.get("notes", "") or "N/A",
                    "Saved On": record.get("created_at", ""),
                    "Extra Details": format_extra_data_summary(extra_dict),
                    "Extra Data JSON": serialize_extra_data(extra_dict),
                }
            )

    if not data_rows:
        return pd.DataFrame(columns=ALL_RECORD_COLUMNS)

    return pd.DataFrame(data_rows[::-1], columns=ALL_RECORD_COLUMNS)


def search_records_df(df: pd.DataFrame, query: str) -> pd.DataFrame:
    """Search across all standard and extra card fields (case-insensitive)."""
    q = query.strip()
    if not q or df.empty:
        return df.iloc[0:0]

    mask = (
        df["Company Name"].str.contains(q, case=False, na=False)
        | df["Contact Person"].str.contains(q, case=False, na=False)
        | df["Contact No."].str.contains(q, case=False, na=False)
        | df["WhatsApp No."].str.contains(q, case=False, na=False)
        | df["Email"].str.contains(q, case=False, na=False)
        | df["Product / Services"].str.contains(q, case=False, na=False)
        | df["Address"].str.contains(q, case=False, na=False)
        | df["City"].str.contains(q, case=False, na=False)
        | df["Notes"].str.contains(q, case=False, na=False)
        | df["Extra Details"].str.contains(q, case=False, na=False)
    )
    return df[mask]


def find_duplicate_records(
    user_id: str,
    call_phone: str,
    whatsapp_phone: str,
    email: str,
) -> list[dict[str, Any]]:
    new_phones = extract_normalized_phones(call_phone) | extract_normalized_phones(
        whatsapp_phone
    )
    new_emails = extract_normalized_emails(email)

    if not new_phones and not new_emails:
        return []

    _fetch_all_card_rows.clear()
    existing_df = fetch_user_records(user_id)
    if existing_df.empty:
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


def save_record(
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
) -> str:
    ws = get_cards_worksheet()
    _ensure_cards_header(ws)

    record_id = uuid.uuid4().hex[:8]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    extra_json = serialize_extra_data(extra_data or {})

    row = [
        record_id,
        user_id,
        normalize_digits(company_name).strip() or "N/A",
        normalize_digits(contact_person).strip() or "N/A",
        format_phone_numbers(call_phone),
        format_phone_numbers(whatsapp_phone),
        normalize_digits(email).strip() or "N/A",
        normalize_digits(products_services).strip() or "N/A",
        normalize_digits(address).strip() or "N/A",
        normalize_digits(city).strip() or "N/A",
        notes.strip() or "N/A",
        timestamp,
        extra_json,
    ]

    ws.append_row(row, value_input_option="RAW", table_range="A1")
    _fetch_all_card_rows.clear()
    return record_id


def save_records_batch(user_id: str, records: list[dict[str, Any]]) -> int:
    """Append multiple merged Excel/CSV records in one Google Sheets API call."""
    if not records:
        return 0
    ws = get_cards_worksheet()
    _ensure_cards_header(ws)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows_to_append: list[list[str]] = []

    for rec in records:
        extra_json = serialize_extra_data(rec.get("extra_data") or {})
        rows_to_append.append(
            [
                uuid.uuid4().hex[:8],
                user_id,
                normalize_digits(rec.get("company_name", "")).strip() or "N/A",
                normalize_digits(rec.get("contact_person", "")).strip() or "N/A",
                format_phone_numbers(rec.get("call_phone", "")),
                format_phone_numbers(rec.get("whatsapp_phone", "")),
                normalize_digits(rec.get("email", "")).strip() or "N/A",
                normalize_digits(rec.get("products_services", "")).strip() or "N/A",
                normalize_digits(rec.get("address", "")).strip() or "N/A",
                normalize_digits(rec.get("city", "")).strip() or "N/A",
                normalize_digits(rec.get("notes", "")).strip() or "N/A",
                timestamp,
                extra_json,
            ]
        )

    ws.append_rows(rows_to_append, value_input_option="RAW", table_range="A1")
    _fetch_all_card_rows.clear()
    return len(rows_to_append)


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
    ws = get_cards_worksheet()
    all_rows = ws.get_all_values()
    if len(all_rows) <= 1:
        return False

    headers = all_rows[0]
    for sheet_row_idx, row in enumerate(all_rows[1:], start=2):
        padded = row + [""] * (len(headers) - len(row))
        existing = dict(zip(headers, padded))

        if existing.get("record_id") == record_id and existing.get("user_id") == user_id:
            original_created_at = existing.get(
                "created_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )
            extra_json = serialize_extra_data(extra_data or {})
            updated_row = [
                record_id,
                user_id,
                normalize_digits(company_name).strip() or "N/A",
                normalize_digits(contact_person).strip() or "N/A",
                format_phone_numbers(call_phone),
                format_phone_numbers(whatsapp_phone),
                normalize_digits(email).strip() or "N/A",
                normalize_digits(products_services).strip() or "N/A",
                normalize_digits(address).strip() or "N/A",
                normalize_digits(city).strip() or "N/A",
                notes.strip() or "N/A",
                original_created_at,
                extra_json,
            ]
            end_cell = rowcol_to_a1(sheet_row_idx, len(CARD_HEADERS))
            ws.update(
                values=[updated_row],
                range_name=f"A{sheet_row_idx}:{end_cell}",
                value_input_option="RAW",
            )
            _fetch_all_card_rows.clear()
            return True

    return False


def delete_record(record_id: str, user_id: str) -> bool:
    ws = get_cards_worksheet()
    all_rows = ws.get_all_values()

    for sheet_row_idx, row in enumerate(all_rows[1:], start=2):
        row_record_id = row[0] if len(row) > 0 else ""
        row_user_id = row[1] if len(row) > 1 else ""
        if row_record_id == record_id and row_user_id == user_id:
            ws.delete_rows(sheet_row_idx)
            _fetch_all_card_rows.clear()
            return True

    return False


# ---------------------------------------------------------------------------
# Excel Export & Existing Excel Merge Helpers (With Extra-Column Preservation)
# ---------------------------------------------------------------------------
def build_excel_bytes(df: pd.DataFrame) -> bytes:
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Visiting Cards")
        worksheet = writer.sheets["Visiting Cards"]

        for col_idx, col_name in enumerate(df.columns, start=1):
            max_cell_len = (
                df[col_name].astype(str).map(len).max() if not df.empty else 0
            )
            col_width = min(max(len(str(col_name)), max_cell_len) + 4, 50)
            col_letter = worksheet.cell(row=1, column=col_idx).column_letter
            worksheet.column_dimensions[col_letter].width = col_width

    return output.getvalue()


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
    s = str(val).strip()
    if s.lower() in ("nan", "none", "nat"):
        return ""
    return s


def prepare_excel_merge_rows(
    raw_df: pd.DataFrame,
    col_mapping: dict[str, str],
    unmapped_extra_cols: list[str],
    user_id: str,
    skip_duplicates: bool,
) -> Tuple[list[dict[str, Any]], int, int]:
    """
    Convert an uploaded Excel/CSV DataFrame into our standard format while saving any
    unmapped extra columns (e.g., Website, GSTIN) inside `extra_data`.
    """
    existing_phones: set[str] = set()
    existing_emails: set[str] = set()

    if skip_duplicates:
        _fetch_all_card_rows.clear()
        existing_df = fetch_user_records(user_id)
        for _, ex_row in existing_df.iterrows():
            existing_phones |= extract_normalized_phones(str(ex_row.get("Contact No.", "")))
            existing_phones |= extract_normalized_phones(str(ex_row.get("WhatsApp No.", "")))
            existing_emails |= extract_normalized_emails(str(ex_row.get("Email", "")))

    prepared: list[dict[str, Any]] = []
    skipped_dups = 0
    skipped_empty = 0

    for _, row in raw_df.iterrows():
        raw_vals: dict[str, str] = {}
        for field_key in EXCEL_COLUMN_ALIASES:
            src_col = col_mapping.get(field_key, "")
            raw_vals[field_key] = (
                _clean_excel_cell(row[src_col]) if src_col and src_col in raw_df.columns else ""
            )

        extra_dict: dict[str, str] = {}
        for extra_col in unmapped_extra_cols:
            if extra_col in raw_df.columns:
                val = _clean_excel_cell(row[extra_col])
                if val and val.upper() != "N/A":
                    extra_dict[extra_col.strip()] = normalize_digits(val)

        if not has_at_least_one_field(*raw_vals.values(), *extra_dict.values()):
            skipped_empty += 1
            continue

        formatted_call = format_phone_numbers(raw_vals["call_phone"])
        formatted_wp = format_phone_numbers(raw_vals["whatsapp_phone"])
        clean_email = normalize_digits(raw_vals["email"]).strip() or "N/A"

        row_phones = extract_normalized_phones(formatted_call) | extract_normalized_phones(
            formatted_wp
        )
        row_emails = extract_normalized_emails(clean_email)

        if skip_duplicates and (
            (row_phones and (row_phones & existing_phones))
            or (row_emails and (row_emails & existing_emails))
        ):
            skipped_dups += 1
            continue

        existing_phones |= row_phones
        existing_emails |= row_emails

        prepared.append(
            {
                "company_name": normalize_digits(raw_vals["company_name"]).strip() or "N/A",
                "contact_person": normalize_digits(raw_vals["contact_person"]).strip() or "N/A",
                "call_phone": formatted_call,
                "whatsapp_phone": formatted_wp,
                "email": clean_email,
                "products_services": normalize_digits(raw_vals["products_services"]).strip()
                or "N/A",
                "address": normalize_digits(raw_vals["address"]).strip() or "N/A",
                "city": normalize_digits(raw_vals["city"]).strip() or "N/A",
                "notes": normalize_digits(raw_vals["notes"]).strip() or "N/A",
                "extra_data": extra_dict,
            }
        )

    return prepared, skipped_dups, skipped_empty


# ---------------------------------------------------------------------------
# Anti-504 Gemini AI Extraction Helper
# ---------------------------------------------------------------------------
class ScanUnavailableError(Exception):
    """Raised when all free models are temporarily busy or timed out."""


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
        "CITY RULE:\n"
        "- Put ONLY the clean English city/town name in `city` (e.g., 'Ahmedabad', 'Mumbai', 'Kapadvanj', 'Dakor'). "
        "Do not put street, state, or PIN code in `city`. Infer from the address or PIN code if unambiguous; else 'N/A'.\n\n"
        "EXTRA DETAILS RULE:\n"
        "- Put any extra printed details (like Website, GSTIN, PAN, Instagram, LinkedIn, Branch, Office Timings, "
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

    daily_limit = get_daily_scan_limit()
    try:
        used_today = get_user_scans_today(user_id)
    except Exception:
        used_today = 0

    if used_today >= daily_limit:
        st.warning(
            f"You have reached your daily limit of **{daily_limit} AI scans**. "
            "Quota resets daily at 1:30 PM IST (12:30 PM IST in summer). "
            "You can still add cards right now using **Fill Details Manually** or **Merge Existing Excel**."
        )
        return

    images_payload = [(f.getvalue(), f.type or "image/jpeg") for f in image_files]
    side_label = "both card sides" if len(images_payload) == 2 else "visiting card"

    with st.spinner(f"Scanning {side_label}..."):
        try:
            extracted, extra_dict, _used_model = extract_card_details(
                images_payload, api_key
            )
            try:
                increment_user_scan_count(user_id)
            except Exception:
                pass

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
            st.warning(str(val_err))
        except ScanUnavailableError as busy_err:
            st.warning(str(busy_err))
        except Exception:
            st.warning(
                "Could not read the card right now. Try a clearer photo, "
                "tap Scan again in a moment, or use 'Fill Details Manually'."
            )


def open_blank_manual_form() -> None:
    """Open an empty manual entry form (no N/A defaults) and smoothly scroll down to it."""
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
# Authentication UI (Login, OTP-Verified Register & Forgot Password)
# ---------------------------------------------------------------------------
def render_auth_screen() -> None:
    _, center_col, _ = st.columns([1, 1.8, 1])

    with center_col:
        st.title("Company Visiting Card Scanner")
        st.caption(
            "Sign in or create an account to scan, organize, and export your visiting cards."
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
                                st.session_state["extracted_card"] = None
                                st.session_state["is_manual_entry"] = False
                                st.session_state["pending_duplicate_save"] = None
                                st.session_state["pending_registration"] = None
                                st.session_state["scan_notice"] = None
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
                            placeholder="Minimum 6 characters",
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
                                    st.session_state["extracted_card"] = None
                                    st.session_state["is_manual_entry"] = False
                                    st.session_state["pending_duplicate_save"] = None
                                    st.session_state["scan_notice"] = None
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
                st.caption("Step 1: Enter your registered email to receive a 6-digit code.")
                with st.form("forgot_request_form"):
                    reset_email_input = st.text_input(
                        "Registered Email",
                        value=st.session_state.get("reset_email_target", ""),
                        placeholder="name@example.com",
                    )
                    send_code_btn = st.form_submit_button(
                        "Send 6-Digit Reset Code",
                        type="primary",
                        use_container_width=True,
                    )

                if send_code_btn:
                    with st.spinner("Sending verification code..."):
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
                        placeholder="Minimum 6 characters",
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
# Reusable UI Sections: Show Records, Search-Based Update, Search-Based Delete
# ---------------------------------------------------------------------------
def _record_summary_label(row: pd.Series) -> str:
    phones = [
        p
        for p in (str(row["Contact No."]), str(row["WhatsApp No."]))
        if p and p != "N/A"
    ]
    phone_text = " | ".join(phones) if phones else "No Phone"
    city_text = row["City"] if row["City"] != "N/A" else "City N/A"
    return (
        f"{row['Company Name']} — {row['Contact Person']} "
        f"({phone_text} • {city_text}) [{row['Record ID']}]"
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
                _fetch_all_usage_rows.clear()
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
        extra_col_names = collect_extra_column_names(filtered_df)

        # Excel export ALWAYS expands extra_data keys (e.g., Website, GSTIN) into real columns
        export_df = build_expanded_dataframe(filtered_df, include_extra_columns=True)

        with export_col:
            if not export_df.empty:
                excel_bytes = build_excel_bytes(export_df)
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

        # Keep default 10-column table clean; offer quick toggle when extra columns exist
        show_extra_in_table = False
        if extra_col_names:
            meta_col1, meta_col2 = st.columns([2.2, 2.8])
            with meta_col1:
                if is_filtered:
                    st.caption(
                        f"Showing **{len(filtered_df)}** of {len(all_records_df)} saved cards"
                    )
                else:
                    st.caption(f"Total saved cards: **{len(all_records_df)}**")
            with meta_col2:
                preview_names = ", ".join(extra_col_names[:3])
                more = f" +{len(extra_col_names) - 3} more" if len(extra_col_names) > 3 else ""
                show_extra_in_table = st.checkbox(
                    f"Show extra columns ({preview_names}{more}) — always included in Excel export",
                    value=False,
                    key=f"{key_prefix}_toggle_extra_cols",
                )
        else:
            if is_filtered:
                st.caption(
                    f"Showing **{len(filtered_df)}** of {len(all_records_df)} saved cards"
                )
            else:
                st.caption(f"Total saved cards: **{len(all_records_df)}**")

        display_df = build_expanded_dataframe(
            filtered_df, include_extra_columns=show_extra_in_table
        )
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
            "Extra Details (Optional — Website, GSTIN, etc., one per line as Label: Value)",
            value=existing_extra_text,
            placeholder=FIELD_PLACEHOLDERS["extra_details"],
            height=75,
            key=f"{key_prefix}_upd_extra_{edit_id}_{edit_rev}",
        )

        update_submitted = st.form_submit_button("Update Record", type="primary")

        if update_submitted:
            parsed_extra = parse_extra_data_from_input(upd_extra_text)
            if not has_at_least_one_field(
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
        "Search card to delete",
        placeholder="Type company name, person, phone, email, city, or website...",
        key=f"{key_prefix}_search_record_to_delete",
    )

    if not del_query.strip():
        st.caption("Enter any keyword above to find the record you want to delete.")
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
            f"Found {len(del_matches)} matching records. Choose which one to delete:"
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
        f"Are you sure you want to delete **{selected_del_row['Company Name']}** "
        f"({selected_del_row['Contact Person']} • {selected_del_row['City']})?"
    )
    if st.button(
        "Confirm Delete",
        type="primary",
        key=f"{key_prefix}_btn_confirm_delete_{del_id}",
    ):
        try:
            deleted = delete_record(del_id, current_user_id)
            if deleted:
                st.session_state["flash_success"] = (
                    f"Deleted '{selected_del_row['Company Name']}'."
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


# ---------------------------------------------------------------------------
# Main Application
# ---------------------------------------------------------------------------
def main() -> None:
    inject_clean_ui_css()

    for key, default in (
        ("auth_user", None),
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
        ("scan_notice", None),
        ("reset_email_target", ""),
    ):
        if key not in st.session_state:
            st.session_state[key] = default

    # Verify Google Sheets connection & auto-migrate schema if needed
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
        st.error(f"Storage setup required: {storage_error}")
        st.info(
            "Check `GSHEET_URL` and `[gcp_service_account]` in Streamlit Secrets, "
            "and confirm the Google Sheets API is enabled and shared with your service account."
        )
        return

    # Restore hidden browser session (clean URL, no session ID in link)
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

    daily_limit = get_daily_scan_limit()
    try:
        scans_used_today = get_user_scans_today(current_user_id)
    except Exception:
        scans_used_today = 0
    scans_remaining = max(0, daily_limit - scans_used_today)

    # Fetch user records once so both summary strip and sections stay in sync
    try:
        all_records_df = fetch_user_records(current_user_id)
    except Exception:
        st.error("Unable to load your saved cards right now. Please refresh.")
        return

    # ---- Sidebar: Menu (with Logout), Account Info, Collapsible Settings ----
    with st.sidebar:
        st.markdown("### Menu")
        active_view = st.session_state["active_view"]

        nav_items = [
            ("home", "Home"),
            ("show", "Show Records"),
            ("update", "Update Record"),
            ("delete", "Delete Record"),
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

        # Logout grouped cleanly with Menu navigation buttons (not inside Account)
        if st.button("Logout", use_container_width=True, key="nav_btn_logout"):
            logout_user_session()
            st.session_state["extracted_card"] = None
            st.session_state["is_manual_entry"] = False
            st.session_state["pending_duplicate_save"] = None
            st.session_state["scan_notice"] = None
            st.session_state["flash_success"] = None
            st.session_state["flash_info"] = None
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

    # Mount hidden UI bridge for mobile sidebar auto-close & smooth form scroll
    trigger_ui_bridge()

    # ---- Clean Page Header & Quick-Stats Strip ----
    st.title("Company Visiting Card Scanner")
    st.markdown(
        f"""
        <div class="vcard-stat-strip">
            <div class="vcard-stat-pill">
                <div class="vcard-stat-label">Account</div>
                <div class="vcard-stat-value">{current_username}</div>
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

    if st.session_state["flash_success"]:
        st.success(st.session_state["flash_success"])
        st.session_state["flash_success"] = None

    if st.session_state["flash_info"]:
        st.info(st.session_state["flash_info"])
        st.session_state["flash_info"] = None

    # ---- Dedicated Sidebar Views (Show / Update / Delete) ----
    if active_view == "show":
        render_show_records_section(
            all_records_df=all_records_df,
            current_username=current_username,
            title="Your Saved Visiting Cards",
            key_prefix="nav_show",
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

    # ---- HOME VIEW: Step 1 (Upload / Camera / Merge Excel + Manual Entry) ----
    upload_rev = st.session_state["uploader_reset_counter"]

    with st.container(border=True):
        step1_col, manual_col = st.columns([3.5, 1.5])
        with step1_col:
            st.subheader("1. Add Visiting Card")
            st.caption(
                "Scan 1 or 2 card sides with AI, merge an existing Excel sheet, or fill details manually."
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
                "Upload 1 or 2 card photos (Front & Back — JPG or PNG)",
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
                "Upload any `.xlsx` or `.csv` file. Standard columns auto-map into our format, "
                "empty cells save as `N/A`, and any extra columns (like `Website` or `GSTIN`) are preserved automatically."
            )
            uploaded_excel = st.file_uploader(
                "Choose an Excel (.xlsx) or CSV file to merge",
                type=["xlsx", "csv"],
                key=f"excel_merge_uploader_{upload_rev}",
            )

            if uploaded_excel is not None:
                try:
                    if uploaded_excel.name.lower().endswith(".csv"):
                        raw_excel_df = pd.read_csv(uploaded_excel, dtype=str)
                    else:
                        raw_excel_df = pd.read_excel(
                            uploaded_excel, engine="openpyxl", dtype=str
                        )
                    raw_excel_df = raw_excel_df.dropna(how="all")
                except Exception as excel_err:
                    st.error(f"Could not read the file: {excel_err}")
                    raw_excel_df = None

                if raw_excel_df is not None:
                    if raw_excel_df.empty:
                        st.warning("The uploaded file has no data rows.")
                    else:
                        excel_cols = [str(c) for c in raw_excel_df.columns.tolist()]
                        raw_excel_df.columns = excel_cols
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
                            and not c.lower().startswith("unnamed:")
                        ]

                        preserve_extra_cols = False
                        if detected_extra_cols:
                            preserve_extra_cols = st.checkbox(
                                f"Preserve {len(detected_extra_cols)} extra column(s) automatically "
                                f"({', '.join(detected_extra_cols)}) — exported as separate columns in Excel",
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

                        # Preview top 5 formatted rows including any preserved extra columns
                        preview_records, _, _ = prepare_excel_merge_rows(
                            raw_excel_df.head(5),
                            chosen_mapping,
                            active_extra_cols,
                            current_user_id,
                            skip_duplicates=False,
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
                                    p_row[ec] = r["extra_data"].get(ec.strip(), "N/A")
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
                                        ready_rows, dup_count, empty_count = (
                                            prepare_excel_merge_rows(
                                                raw_excel_df,
                                                chosen_mapping,
                                                active_extra_cols,
                                                current_user_id,
                                                skip_duplicates=skip_excel_dups,
                                            )
                                        )
                                        if not ready_rows:
                                            st.warning(
                                                f"No new records to merge "
                                                f"(skipped {dup_count} duplicate(s), {empty_count} empty row(s))."
                                            )
                                        else:
                                            added = save_records_batch(
                                                current_user_id, ready_rows
                                            )
                                            clear_uploaded_inputs()
                                            extra_notes = []
                                            if active_extra_cols:
                                                extra_notes.append(
                                                    f"preserved extra column(s): {', '.join(active_extra_cols)}"
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

        if scans_remaining == 0:
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
                            save_record(
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
                        "Extra Details (Optional — Website, GSTIN, etc., one per line as Label: Value)",
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
                        if not has_at_least_one_field(
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
                                matches = find_duplicate_records(
                                    user_id=current_user_id,
                                    call_phone=call_phone,
                                    whatsapp_phone=whatsapp_phone,
                                    email=email,
                                )
                                if matches:
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
                                    save_record(
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
                                    )
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