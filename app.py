import base64
import hashlib
import hmac
import io
import os
import re
import secrets
import time
import unicodedata
import uuid
from datetime import datetime, timedelta, timezone
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
# Bump SCHEMA_VERSION whenever worksheet columns change so Streamlit's
# cached spreadsheet handle automatically runs migration on deploy.
SCHEMA_VERSION = "v2_city_field"

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

# Free-tier protection & persistent session settings
DEFAULT_DAILY_SCAN_LIMIT = 40
SESSION_TTL_SECONDS = 7 * 24 * 60 * 60  # Stay logged in for 7 days across refreshes

CARDS_WORKSHEET = "visiting_cards"
USERS_WORKSHEET = "users"
USAGE_WORKSHEET = "scan_usage"

PBKDF2_ITERATIONS = 260_000
MAX_CARD_IMAGES = 2

# Email stays second-to-last, immediately before Address; City is its own column
CARD_HEADERS = [
    "record_id",
    "user_id",
    "company_name",
    "contact_person",
    "whatsapp_phone",
    "call_phone",
    "products_services",
    "city",
    "notes",
    "created_at",
    "email",
    "address",
]

DISPLAY_COLUMNS = [
    "Record ID",
    "Company Name",
    "Contact Person",
    "WhatsApp Number",
    "Call Number",
    "Products / Services",
    "City",
    "Notes",
    "Saved On",
    "Email",
    "Address",
]

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

st.set_page_config(
    page_title="Company Visiting Card Scanner",
    page_icon="📇",
    layout="wide",
)


# ---------------------------------------------------------------------------
# Secret, Session Token, Hashing & Normalization Helpers
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
    """Read configurable daily limit from Streamlit Secrets (default: 40/user/day)."""
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
    """
    Derive a stable server-side HMAC key from Streamlit Secrets so signed
    sessions survive browser refreshes and Streamlit Cloud restarts.
    """
    explicit = get_secret("SESSION_SECRET")
    if explicit:
        material = str(explicit)
    else:
        creds = get_secret("gcp_service_account")
        if creds and isinstance(creds, dict) and creds.get("private_key"):
            material = str(creds["private_key"])
        elif creds and "private_key" in creds:
            material = str(creds["private_key"])
        else:
            material = str(get_secret("GEMINI_API_KEY", "local-dev-session-key"))
    return hashlib.sha256(f"vcard-session-v1:{material}".encode("utf-8")).digest()


def create_session_token(user_id: str) -> str:
    """Create a URL-safe HMAC-signed session token valid for SESSION_TTL_SECONDS."""
    expires_at = int(time.time()) + SESSION_TTL_SECONDS
    payload = f"{user_id}|{expires_at}"
    sig = hmac.new(
        _get_session_signing_key(), payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()[:32]
    raw = f"{payload}|{sig}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def verify_session_token(token: str) -> Optional[str]:
    """Validate token signature and expiry; return user_id if valid, else None."""
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


def set_browser_session(user: dict[str, str]) -> None:
    """Persist logged-in user in both session_state and signed URL query param."""
    st.session_state["auth_user"] = user
    try:
        st.query_params["session"] = create_session_token(user["user_id"])
    except Exception:
        pass


def clear_browser_session() -> None:
    """Clear user from session_state and remove session token from URL."""
    st.session_state["auth_user"] = None
    try:
        st.query_params.pop("session", None)
    except Exception:
        pass


def restore_session_if_valid() -> Optional[dict[str, str]]:
    """
    On page refresh, check URL query params for a valid signed session token
    and restore the user's account automatically.
    """
    if st.session_state.get("auth_user") is not None:
        return st.session_state["auth_user"]

    try:
        raw_token = st.query_params.get("session")
    except Exception:
        raw_token = None

    if not raw_token:
        return None

    token = raw_token[0] if isinstance(raw_token, list) else str(raw_token)
    user_id = verify_session_token(token)
    if not user_id:
        clear_browser_session()
        return None

    for user in fetch_all_users():
        if user.get("user_id") == user_id:
            restored = {
                "user_id": user.get("user_id", ""),
                "username": user.get("username", ""),
                "email": user.get("email", ""),
                "role": user.get("role", "user"),
            }
            st.session_state["auth_user"] = restored
            return restored

    clear_browser_session()
    return None


def hash_password(password: str) -> str:
    """Hash a password using salted PBKDF2-HMAC-SHA256."""
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), PBKDF2_ITERATIONS
    )
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt}${dk.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a plaintext password against a stored PBKDF2 hash."""
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


def normalize_digits(text: str) -> str:
    """Convert regional Unicode digits (Gujarati ૦-૯, Hindi ०-९, etc.) to ASCII 0-9."""
    return "".join(
        str(unicodedata.digit(ch)) if ch.isdecimal() and not ch.isascii() else ch
        for ch in text
    )


def extract_normalized_phones(phone_str: str) -> set[str]:
    """Extract comparable phone tokens (last 10 digits for mobile/STD numbers)."""
    if not phone_str or phone_str.strip().upper() == "N/A":
        return set()
    cleaned = normalize_digits(phone_str)
    parts = re.split(r"[,;/|\n]+", cleaned)
    phones: set[str] = set()
    for part in parts:
        digits = re.sub(r"\D", "", part)
        if len(digits) >= 7:
            phones.add(digits[-10:] if len(digits) >= 10 else digits)
    return phones


def extract_normalized_emails(email_str: str) -> set[str]:
    """Extract lowercase valid email addresses for duplicate matching."""
    if not email_str or email_str.strip().upper() == "N/A":
        return set()
    parts = re.split(r"[,;/|\s]+", email_str.strip().lower())
    return {p for p in parts if is_valid_email(p)}


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


# ---------------------------------------------------------------------------
# Pydantic Schema for Gemini Structured Outputs (English + City + Dual Phones)
# ---------------------------------------------------------------------------
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
    whatsapp_phone: str = Field(
        description=(
            "WhatsApp phone number(s) using ONLY standard ASCII digits (0-9), comma-separated. "
            "Rules: (1) If WhatsApp icon/logo or text ('WP', 'WA', 'WhatsApp') marks specific number(s), put those here. "
            "(2) If only 1 number is on the card without a call-only/landline distinction, put it here by default. "
            "(3) If 2 or more numbers are on the card with NO icon or text distinguishing WhatsApp from Call, "
            "put ALL of them here. Return 'N/A' only if no number applies."
        )
    )
    call_phone: str = Field(
        description=(
            "Normal call / office / landline phone number(s) using ONLY standard ASCII digits (0-9), comma-separated. "
            "ONLY populate this when the card explicitly distinguishes a call/phone/landline number using a phone/call "
            "icon or text label ('Call', 'Ph', 'Tel', 'Office', 'Landline', 'Contact') separately from WhatsApp. "
            "If there is only 1 unspecified number, or 2+ unspecified numbers, return 'N/A' here."
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
    city: str = Field(
        description=(
            "Only the City or Town name in standard English Title Case (e.g., 'Ahmedabad', 'Mumbai', "
            "'Kapadvanj', 'Dakor', 'Surat', 'Vadodara'). Do NOT include street, state, country, or PIN code here. "
            "Infer the city from the address or PIN code if clear; return 'N/A' if completely absent."
        )
    )
    email: str = Field(
        description="Email address in English (Latin script). Return 'N/A' if missing."
    )
    address: str = Field(
        description=(
            "Complete physical shop, office, or factory address translated and transliterated into clear English "
            "with standard 0-9 digits (translate directional words like 'near' or 'next to'; transliterate street "
            "and city names). Return 'N/A' if missing."
        )
    )


def _clean_card_output(card: VisitingCard) -> VisitingCard:
    """Guarantee standard ASCII 0-9 digits and clean formatting across fields."""
    raw_city = normalize_digits(card.city).strip()
    clean_city = raw_city if raw_city.upper() != "N/A" and raw_city else "N/A"
    return card.model_copy(
        update={
            "company_name": normalize_digits(card.company_name).strip() or "N/A",
            "contact_person": normalize_digits(card.contact_person).strip() or "N/A",
            "whatsapp_phone": normalize_digits(card.whatsapp_phone).strip() or "N/A",
            "call_phone": normalize_digits(card.call_phone).strip() or "N/A",
            "products_services": normalize_digits(card.products_services).strip() or "N/A",
            "city": clean_city,
            "email": normalize_digits(card.email).strip() or "N/A",
            "address": normalize_digits(card.address).strip() or "N/A",
        }
    )


# ---------------------------------------------------------------------------
# Google Sheets Storage Layer (Auto-Creates, Migrates & Repairs Headers)
# ---------------------------------------------------------------------------
@st.cache_resource(show_spinner=False)
def get_spreadsheet(_schema_version: str = SCHEMA_VERSION) -> gspread.Spreadsheet:
    """Authenticate via service account from Streamlit secrets and open the Sheet."""
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
    """Align existing `visiting_cards` rows to CARD_HEADERS (adds `city` safely)."""
    all_rows = cards_ws.get_all_values()
    if not all_rows:
        cards_ws.append_row(CARD_HEADERS, value_input_option="RAW")
        return

    current_headers = all_rows[0]
    if current_headers == CARD_HEADERS:
        return

    if cards_ws.col_count < len(CARD_HEADERS):
        cards_ws.resize(cols=len(CARD_HEADERS))

    # If Row 1 has data instead of headers, insert headers above it safely
    if "record_id" not in current_headers and "user_id" not in current_headers:
        cards_ws.insert_row(CARD_HEADERS, index=1, value_input_option="RAW")
        return

    migrated_rows = [CARD_HEADERS]
    for row in all_rows[1:]:
        if not any(cell.strip() for cell in row):
            continue
        padded = row + [""] * (len(current_headers) - len(row))
        old_rec = dict(zip(current_headers, padded))

        wp_val = old_rec.get("whatsapp_phone") or old_rec.get("phone") or "N/A"
        call_val = old_rec.get("call_phone") or "N/A"
        city_val = old_rec.get("city") or "N/A"

        new_rec = {
            "record_id": old_rec.get("record_id", uuid.uuid4().hex[:8]),
            "user_id": old_rec.get("user_id", "default_user"),
            "company_name": old_rec.get("company_name", "N/A"),
            "contact_person": old_rec.get("contact_person", "N/A"),
            "whatsapp_phone": wp_val,
            "call_phone": call_val,
            "products_services": old_rec.get("products_services", "N/A"),
            "city": city_val,
            "notes": old_rec.get("notes", ""),
            "created_at": old_rec.get("created_at", ""),
            "email": old_rec.get("email", "N/A"),
            "address": old_rec.get("address", "N/A"),
        }
        migrated_rows.append([new_rec[col] for col in CARD_HEADERS])

    cards_ws.update(
        values=migrated_rows,
        range_name="A1",
        value_input_option="RAW",
    )


def ensure_worksheets(spreadsheet: gspread.Spreadsheet) -> None:
    """Create or repair 'visiting_cards', 'users', and 'scan_usage' worksheets."""
    existing_titles = {ws.title for ws in spreadsheet.worksheets()}

    if CARDS_WORKSHEET not in existing_titles:
        cards_ws = spreadsheet.add_worksheet(
            title=CARDS_WORKSHEET, rows=1000, cols=len(CARD_HEADERS)
        )
        cards_ws.append_row(CARD_HEADERS, value_input_option="RAW")
    else:
        cards_ws = spreadsheet.worksheet(CARDS_WORKSHEET)
        _migrate_cards_worksheet_if_needed(cards_ws)

    if USERS_WORKSHEET not in existing_titles:
        users_ws = spreadsheet.add_worksheet(
            title=USERS_WORKSHEET, rows=500, cols=len(USER_HEADERS)
        )
        users_ws.append_row(USER_HEADERS, value_input_option="RAW")
    else:
        users_ws = spreadsheet.worksheet(USERS_WORKSHEET)
        if not users_ws.row_values(1):
            users_ws.append_row(USER_HEADERS, value_input_option="RAW")

    if USAGE_WORKSHEET not in existing_titles:
        usage_ws = spreadsheet.add_worksheet(
            title=USAGE_WORKSHEET, rows=500, cols=len(USAGE_HEADERS)
        )
        usage_ws.append_row(USAGE_HEADERS, value_input_option="RAW")
    else:
        usage_ws = spreadsheet.worksheet(USAGE_WORKSHEET)
        if not usage_ws.row_values(1):
            usage_ws.append_row(USAGE_HEADERS, value_input_option="RAW")


def get_cards_worksheet() -> gspread.Worksheet:
    return get_spreadsheet(SCHEMA_VERSION).worksheet(CARDS_WORKSHEET)


def get_users_worksheet() -> gspread.Worksheet:
    return get_spreadsheet(SCHEMA_VERSION).worksheet(USERS_WORKSHEET)


def get_usage_worksheet() -> gspread.Worksheet:
    """Return the scan_usage worksheet, auto-creating it if missing."""
    spreadsheet = get_spreadsheet(SCHEMA_VERSION)
    try:
        ws = spreadsheet.worksheet(USAGE_WORKSHEET)
    except gspread.WorksheetNotFound:
        ws = spreadsheet.add_worksheet(
            title=USAGE_WORKSHEET, rows=500, cols=len(USAGE_HEADERS)
        )
        ws.append_row(USAGE_HEADERS, value_input_option="RAW")
        return ws

    if not ws.row_values(1):
        ws.append_row(USAGE_HEADERS, value_input_option="RAW")
    return ws


# ---------------------------------------------------------------------------
# Per-User Daily Scan Quota Tracking (Backed by `scan_usage` Tab)
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
    """Return how many successful AI scans `user_id` has used in the current quota day."""
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
    """Increment `user_id`'s scan counter for today and return the new total."""
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
# User Authentication Functions (Backed by `users` Tab)
# ---------------------------------------------------------------------------
@st.cache_data(ttl=60, show_spinner=False)
def fetch_all_users() -> list[dict[str, str]]:
    """Fetch all user records from Google Sheets (cached 60s for fast refreshes)."""
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


def register_user(
    username: str, email: str, password: str
) -> Tuple[bool, str, Optional[dict[str, str]]]:
    """Create a new user in the `users` worksheet if username/email are unique."""
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
    existing_users = fetch_all_users()
    for user in existing_users:
        if user.get("username", "").strip().lower() == clean_username.lower():
            return False, "That username is already taken. Try another one.", None
        if user.get("email", "").strip().lower() == clean_email:
            return False, "An account with this email already exists. Please log in.", None

    user_id = f"usr_{uuid.uuid4().hex[:10]}"
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pw_hash = hash_password(password)

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
    return True, "Account created! Welcome.", new_user


def authenticate_user(
    identifier: str, password: str
) -> Tuple[bool, str, Optional[dict[str, str]]]:
    """Verify login by username or email against the `users` worksheet."""
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


# ---------------------------------------------------------------------------
# Visiting Card CRUD & Duplicate Detection (Strictly Scoped to User)
# ---------------------------------------------------------------------------
@st.cache_data(ttl=60, show_spinner=False)
def _fetch_all_card_rows() -> list[list[str]]:
    """Fetch all raw rows from `visiting_cards` and auto-repair missing headers."""
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
    """Return ONLY the visiting cards uploaded by `user_id`, newest first."""
    all_rows = _fetch_all_card_rows()
    if len(all_rows) <= 1:
        return pd.DataFrame(columns=DISPLAY_COLUMNS)

    headers = all_rows[0]
    data_rows = []
    for row in all_rows[1:]:
        if not any(cell.strip() for cell in row):
            continue
        padded = row + [""] * (len(headers) - len(row))
        record = dict(zip(headers, padded))
        if record.get("user_id") == user_id:
            data_rows.append(
                {
                    "Record ID": record.get("record_id", ""),
                    "Company Name": record.get("company_name", "N/A"),
                    "Contact Person": record.get("contact_person", "N/A"),
                    "WhatsApp Number": record.get("whatsapp_phone", "N/A"),
                    "Call Number": record.get("call_phone", "N/A"),
                    "Products / Services": record.get("products_services", "N/A"),
                    "City": record.get("city", "N/A") or "N/A",
                    "Notes": record.get("notes", ""),
                    "Saved On": record.get("created_at", ""),
                    "Email": record.get("email", "N/A"),
                    "Address": record.get("address", "N/A"),
                }
            )

    if not data_rows:
        return pd.DataFrame(columns=DISPLAY_COLUMNS)

    return pd.DataFrame(data_rows[::-1], columns=DISPLAY_COLUMNS)


def find_duplicate_records(
    user_id: str,
    whatsapp_phone: str,
    call_phone: str,
    email: str,
) -> list[dict[str, Any]]:
    """Check if the logged-in user already uploaded a card matching phone or email."""
    new_phones = extract_normalized_phones(whatsapp_phone) | extract_normalized_phones(
        call_phone
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
            str(row.get("WhatsApp Number", ""))
        ) | extract_normalized_phones(str(row.get("Call Number", "")))
        existing_emails = extract_normalized_emails(str(row.get("Email", "")))

        matched_phones = sorted(new_phones & existing_phones)
        matched_emails = sorted(new_emails & existing_emails)

        if matched_phones or matched_emails:
            reasons = []
            if matched_phones:
                reasons.append(f"Phone: {', '.join(matched_phones)}")
            if matched_emails:
                reasons.append(f"Email: {', '.join(matched_emails)}")
            matches.append(
                {
                    "Record ID": row["Record ID"],
                    "Company Name": row["Company Name"],
                    "Contact Person": row["Contact Person"],
                    "WhatsApp Number": row["WhatsApp Number"],
                    "Call Number": row["Call Number"],
                    "City": row["City"],
                    "Email": row["Email"],
                    "Saved On": row["Saved On"],
                    "Matched By": " | ".join(reasons),
                }
            )

    return matches


def save_record(
    user_id: str,
    company_name: str,
    contact_person: str,
    whatsapp_phone: str,
    call_phone: str,
    products_services: str,
    city: str,
    notes: str,
    email: str,
    address: str,
) -> str:
    """Append a verified visiting card row in CARD_HEADERS order (Email before Address)."""
    ws = get_cards_worksheet()

    first_row = ws.row_values(1)
    if not first_row:
        ws.append_row(CARD_HEADERS, value_input_option="RAW", table_range="A1")
    elif "record_id" not in first_row and "user_id" not in first_row:
        ws.insert_row(CARD_HEADERS, index=1, value_input_option="RAW")

    record_id = uuid.uuid4().hex[:8]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    row = [
        record_id,
        user_id,
        normalize_digits(company_name).strip() or "N/A",
        normalize_digits(contact_person).strip() or "N/A",
        normalize_digits(whatsapp_phone).strip() or "N/A",
        normalize_digits(call_phone).strip() or "N/A",
        normalize_digits(products_services).strip() or "N/A",
        normalize_digits(city).strip() or "N/A",
        notes.strip(),
        timestamp,
        normalize_digits(email).strip() or "N/A",
        normalize_digits(address).strip() or "N/A",
    ]

    ws.append_row(row, value_input_option="RAW", table_range="A1")
    _fetch_all_card_rows.clear()
    return record_id


def update_record(
    record_id: str,
    user_id: str,
    company_name: str,
    contact_person: str,
    whatsapp_phone: str,
    call_phone: str,
    products_services: str,
    city: str,
    notes: str,
    email: str,
    address: str,
) -> bool:
    """Update an existing card ONLY if both record_id and user_id belong to the user."""
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
            updated_row = [
                record_id,
                user_id,
                normalize_digits(company_name).strip() or "N/A",
                normalize_digits(contact_person).strip() or "N/A",
                normalize_digits(whatsapp_phone).strip() or "N/A",
                normalize_digits(call_phone).strip() or "N/A",
                normalize_digits(products_services).strip() or "N/A",
                normalize_digits(city).strip() or "N/A",
                notes.strip(),
                original_created_at,
                normalize_digits(email).strip() or "N/A",
                normalize_digits(address).strip() or "N/A",
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
    """Delete a card ONLY if both record_id and user_id belong to the logged-in user."""
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
# Excel Export Helper
# ---------------------------------------------------------------------------
def build_excel_bytes(df: pd.DataFrame) -> bytes:
    """Convert a DataFrame into an in-memory .xlsx file with neat column widths."""
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


# ---------------------------------------------------------------------------
# Anti-504 Gemini AI Extraction Helper
# ---------------------------------------------------------------------------
class ScanUnavailableError(Exception):
    """Raised when all free models are temporarily busy or timed out."""


def extract_card_details(
    images: list[Tuple[bytes, str]], api_key: str
) -> Tuple[VisitingCard, str]:
    """
    Send 1 or 2 compressed visiting card images to Gemini across 4 free models,
    enforcing strict per-request and total time budgets so users never hit 504s.
    """
    if not api_key or not api_key.strip():
        raise ValueError(
            "Scanner API key is missing. Add it in Streamlit Secrets or the sidebar Settings."
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
        "IMPORTANT PHONE NUMBER CLASSIFICATION RULE (whatsapp_phone vs call_phone):\n"
        "- Carefully inspect icons (WhatsApp logo vs phone handset/landline icon) and text labels "
        "('WP', 'WA', 'WhatsApp' vs 'Call', 'Ph', 'Tel', 'Office', 'Landline', 'Contact').\n"
        "- If there is ONLY 1 phone number on the card (and it is not explicitly marked as call-only/landline), "
        "put it in `whatsapp_phone` and set `call_phone` to 'N/A'.\n"
        "- If there are 2 or more phone numbers on the card and NO icon or text distinguishes WhatsApp from normal Call, "
        "put ALL of them (comma-separated) in `whatsapp_phone` and set `call_phone` to 'N/A'.\n"
        "- If icons or text DO specify which number is WhatsApp and which is for normal Call/Office/Landline, "
        "separate them accordingly into `whatsapp_phone` and `call_phone`.\n\n"
        "CITY RULE:\n"
        "- Put ONLY the clean English city/town name in `city` (e.g., 'Ahmedabad', 'Mumbai', 'Kapadvanj', 'Dakor'). "
        "Do not put street, state, or PIN code in `city`. Infer from the address or PIN code if unambiguous; else 'N/A'.\n\n"
        "OTHER RULES:\n"
        "- For `products_services`: if not explicitly listed, infer what the company offers from the company name, "
        "tagline, logo, or contact person's title.\n"
        "- If any field is completely absent and cannot be inferred, return 'N/A'."
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
                return _clean_card_output(response.parsed), model

            if not response.text:
                continue

            cleaned_json = re.sub(
                r"^```(?:json)?\s*|\s*```$",
                "",
                response.text.strip(),
                flags=re.IGNORECASE,
            )
            return (
                _clean_card_output(VisitingCard.model_validate_json(cleaned_json)),
                model,
            )

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
        "Please tap Scan again in a few seconds — or use 'Fill Details Manually' below."
    )


def run_scan(image_files: list, api_key: str, user_id: str) -> None:
    """Enforce daily free quota, scan 1–2 card images, and hide raw server errors."""
    if not api_key:
        st.warning(
            "Scanner API key is not configured yet. Please add it in the sidebar Settings."
        )
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
            "Your quota resets automatically at 1:30 PM IST (12:30 PM IST in summer). "
            "You can still add cards right now using **Fill Details Manually** below."
        )
        return

    images_payload = [(f.getvalue(), f.type or "image/jpeg") for f in image_files]
    side_label = "both card sides" if len(images_payload) == 2 else "visiting card"

    with st.spinner(f"Scanning {side_label}..."):
        try:
            extracted, _used_model = extract_card_details(images_payload, api_key)
            try:
                increment_user_scan_count(user_id)
            except Exception:
                pass

            st.session_state["extracted_card"] = extracted.model_dump()
            st.session_state["pending_duplicate_save"] = None
            st.session_state["scan_counter"] += 1
            st.session_state["scan_notice"] = (
                f"Scanned {len(images_payload)} image(s) successfully! "
                "Please verify or edit the details below and click Save Card."
            )
            st.rerun()
        except ValueError as val_err:
            st.warning(str(val_err))
        except ScanUnavailableError as busy_err:
            st.warning(str(busy_err))
        except Exception:
            st.warning(
                "Could not read the card right now. Please try a clearer photo, "
                "tap Scan again in a moment, or use 'Fill Details Manually' below."
            )


def open_blank_manual_form() -> None:
    """Open an empty verification form so users can add cards even without AI."""
    st.session_state["extracted_card"] = {
        "company_name": "",
        "contact_person": "",
        "whatsapp_phone": "",
        "call_phone": "N/A",
        "products_services": "",
        "city": "",
        "email": "N/A",
        "address": "",
    }
    st.session_state["pending_duplicate_save"] = None
    st.session_state["scan_counter"] += 1
    st.session_state["scan_notice"] = (
        "Manual entry mode — type the visiting card details below and click Save Card."
    )


# ---------------------------------------------------------------------------
# Authentication UI (Login & Register)
# ---------------------------------------------------------------------------
def render_auth_screen() -> None:
    """Render Login and Register tabs when no user is signed in."""
    _, center_col, _ = st.columns([1, 1.8, 1])

    with center_col:
        st.title("Company Visiting Card Scanner")
        st.caption(
            "Sign in or create an account to scan, save, and manage your own visiting cards."
        )

        tab_login, tab_register = st.tabs(["Login", "Register"])

        with tab_login:
            with st.form("login_form"):
                identifier = st.text_input(
                    "Username or Email",
                    placeholder="e.g., uncle_business or name@example.com",
                )
                password = st.text_input("Password", type="password")
                login_submitted = st.form_submit_button(
                    "Login", type="primary", use_container_width=True
                )

            if login_submitted:
                with st.spinner("Signing in..."):
                    try:
                        ok, msg, user = authenticate_user(identifier, password)
                        if ok and user:
                            set_browser_session(user)
                            st.session_state["extracted_card"] = None
                            st.session_state["pending_duplicate_save"] = None
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
            with st.form("register_form"):
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
                reg_confirm = st.text_input("Confirm Password", type="password")
                reg_submitted = st.form_submit_button(
                    "Create Account", type="primary", use_container_width=True
                )

            if reg_submitted:
                if reg_password != reg_confirm:
                    st.error("Passwords do not match.")
                else:
                    with st.spinner("Creating account..."):
                        try:
                            ok, msg, user = register_user(
                                reg_username, reg_email, reg_password
                            )
                            if ok and user:
                                set_browser_session(user)
                                st.session_state["extracted_card"] = None
                                st.session_state["pending_duplicate_save"] = None
                                st.session_state["scan_notice"] = None
                                st.session_state["flash_success"] = (
                                    f"Account created! Welcome, {user['username']}."
                                )
                                st.rerun()
                            else:
                                st.error(msg)
                        except Exception:
                            st.error(
                                "Unable to create account right now. Please try again."
                            )


# ---------------------------------------------------------------------------
# Main Application
# ---------------------------------------------------------------------------
def main() -> None:
    if "auth_user" not in st.session_state:
        st.session_state["auth_user"] = None
    if "extracted_card" not in st.session_state:
        st.session_state["extracted_card"] = None
    if "pending_duplicate_save" not in st.session_state:
        st.session_state["pending_duplicate_save"] = None
    if "scan_counter" not in st.session_state:
        st.session_state["scan_counter"] = 0
    if "edit_counter" not in st.session_state:
        st.session_state["edit_counter"] = 0
    if "flash_success" not in st.session_state:
        st.session_state["flash_success"] = None
    if "flash_info" not in st.session_state:
        st.session_state["flash_info"] = None
    if "scan_notice" not in st.session_state:
        st.session_state["scan_notice"] = None

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

    # Check persistent session token before showing Login / Register
    auth_user = restore_session_if_valid()
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

    # ---- Sidebar: Account, Daily Limit & Settings ----
    with st.sidebar:
        st.header("Account")
        st.markdown(f"**{current_username}**")
        st.caption(current_email)

        st.metric(
            label="AI Scans Left Today",
            value=f"{scans_remaining} / {daily_limit}",
        )
        st.progress(min(1.0, scans_used_today / daily_limit))
        st.caption("Resets daily at 1:30 PM IST (12:30 PM in summer)")

        if st.button("Logout", use_container_width=True):
            clear_browser_session()
            st.session_state["extracted_card"] = None
            st.session_state["pending_duplicate_save"] = None
            st.session_state["scan_notice"] = None
            st.session_state["flash_success"] = None
            st.session_state["flash_info"] = None
            st.rerun()

        st.divider()
        st.header("Settings")

        server_api_key = str(get_secret("GEMINI_API_KEY", "") or "").strip()
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
                placeholder="AIza... or AQ...",
            )
            active_api_key = user_api_key.strip()
            if active_api_key:
                st.success("AI Scanner ready")
            else:
                st.warning("Enter a Gemini API key to scan cards.")

        st.success("Cloud storage connected")

    # ---- Page Header ----
    st.title("Company Visiting Card Scanner")
    st.caption(
        f"Signed in as **{current_username}** — you only see and manage cards saved to your account."
    )

    if st.session_state["flash_success"]:
        st.success(st.session_state["flash_success"])
        st.session_state["flash_success"] = None

    if st.session_state["flash_info"]:
        st.info(st.session_state["flash_info"])
        st.session_state["flash_info"] = None

    # ---- Step 1: Image Capture & Upload (1 or 2 Sides) ----
    step1_col, manual_col = st.columns([4, 1.4])
    with step1_col:
        st.subheader("1. Capture or Upload Visiting Card (1 or 2 Sides)")
    with manual_col:
        if st.button("Fill Details Manually", use_container_width=True):
            open_blank_manual_form()
            st.rerun()

    tab_upload, tab_camera = st.tabs(["Upload Image(s)", "Take Photo with Camera"])

    with tab_upload:
        uploaded_files = st.file_uploader(
            "Choose 1 or 2 visiting card images (Front & Back — JPG or PNG)",
            type=["jpg", "jpeg", "png"],
            accept_multiple_files=True,
            key="card_file_uploader",
        )
        if uploaded_files:
            if len(uploaded_files) > MAX_CARD_IMAGES:
                st.error(
                    f"Maximum {MAX_CARD_IMAGES} images allowed (Front & Back side). "
                    f"You selected {len(uploaded_files)} — please remove the extra file(s)."
                )
            else:
                preview_cols = st.columns(len(uploaded_files))
                side_labels = ["Side 1 (Front)", "Side 2 (Back)"]
                for idx, file_obj in enumerate(uploaded_files):
                    with preview_cols[idx]:
                        st.image(
                            file_obj.getvalue(),
                            caption=side_labels[idx],
                            width=360,
                        )
                if st.button(
                    f"Scan Uploaded Card ({len(uploaded_files)} image{'s' if len(uploaded_files) > 1 else ''})",
                    type="primary",
                    key="btn_scan_upload",
                    disabled=(scans_remaining == 0),
                ):
                    run_scan(uploaded_files, active_api_key, current_user_id)

    with tab_camera:
        cam_front = st.camera_input(
            "Side 1 (Front) — Point your camera at the front of the visiting card",
            key="card_camera_front",
        )
        add_back_side = st.checkbox(
            "Card has details on the back side (capture 2nd photo)",
            key="toggle_camera_back",
        )
        cam_back = None
        if add_back_side:
            cam_back = st.camera_input(
                "Side 2 (Back) — Point your camera at the back of the visiting card",
                key="card_camera_back",
            )

        captured_photos = [p for p in (cam_front, cam_back) if p is not None]
        if captured_photos:
            if st.button(
                f"Scan Captured Photo{'s' if len(captured_photos) > 1 else ''} ({len(captured_photos)})",
                type="primary",
                key="btn_scan_camera",
                disabled=(scans_remaining == 0),
            ):
                run_scan(captured_photos, active_api_key, current_user_id)

    if scans_remaining == 0:
        st.info(
            f"You have used all {daily_limit} AI scans for today. "
            "Click **Fill Details Manually** above to keep adding cards, or scan again after reset."
        )

    # ---- Step 2: Verification Form & Duplicate Confirmation ----
    if st.session_state["extracted_card"] is not None:
        st.divider()
        st.subheader("2. Verify & Save Details")

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
            dup_col1, dup_col2, _ = st.columns([1.3, 1.3, 3.4])
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
                            whatsapp_phone=data["whatsapp_phone"],
                            call_phone=data["call_phone"],
                            products_services=data["products_services"],
                            city=data["city"],
                            notes=data["notes"],
                            email=data["email"],
                            address=data["address"],
                        )
                        st.session_state["pending_duplicate_save"] = None
                        st.session_state["extracted_card"] = None
                        st.session_state["flash_success"] = (
                            f"Saved '{data['company_name']}' to your account."
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
                        value=card.get("company_name", "N/A"),
                        key=f"company_{suffix}",
                    )
                with r1_c2:
                    contact_person = st.text_input(
                        "Contact Person",
                        value=card.get("contact_person", "N/A"),
                        key=f"contact_{suffix}",
                    )

                r2_c1, r2_c2 = st.columns(2)
                with r2_c1:
                    whatsapp_phone = st.text_input(
                        "WhatsApp Number",
                        value=card.get("whatsapp_phone", "N/A"),
                        key=f"whatsapp_{suffix}",
                    )
                with r2_c2:
                    call_phone = st.text_input(
                        "Call Number (Normal)",
                        value=card.get("call_phone", "N/A"),
                        key=f"call_{suffix}",
                    )

                r3_c1, r3_c2 = st.columns(2)
                with r3_c1:
                    products_services = st.text_input(
                        "Products / Services",
                        value=card.get("products_services", "N/A"),
                        key=f"products_{suffix}",
                    )
                with r3_c2:
                    city = st.text_input(
                        "City",
                        value=card.get("city", "N/A"),
                        placeholder="e.g., Ahmedabad, Mumbai, Surat...",
                        key=f"city_{suffix}",
                    )

                notes = st.text_input(
                    "Additional Notes (Optional)",
                    placeholder="e.g., Met at trade fair, wholesale supplier...",
                    key=f"notes_{suffix}",
                )

                # Final fields: Email strictly before Address
                email = st.text_input(
                    "Email",
                    value=card.get("email", "N/A"),
                    key=f"email_{suffix}",
                )
                address = st.text_area(
                    "Address",
                    value=card.get("address", "N/A"),
                    height=85,
                    key=f"address_{suffix}",
                )

                btn_col1, btn_col2, _ = st.columns([1.2, 1, 4])
                with btn_col1:
                    submitted = st.form_submit_button("Save Card", type="primary")
                with btn_col2:
                    discarded = st.form_submit_button("Discard")

                if submitted:
                    try:
                        matches = find_duplicate_records(
                            user_id=current_user_id,
                            whatsapp_phone=whatsapp_phone,
                            call_phone=call_phone,
                            email=email,
                        )
                        if matches:
                            st.session_state["pending_duplicate_save"] = {
                                "payload": {
                                    "company_name": company_name,
                                    "contact_person": contact_person,
                                    "whatsapp_phone": whatsapp_phone,
                                    "call_phone": call_phone,
                                    "products_services": products_services,
                                    "city": city,
                                    "notes": notes,
                                    "email": email,
                                    "address": address,
                                },
                                "matches": matches,
                            }
                            st.rerun()
                        else:
                            save_record(
                                user_id=current_user_id,
                                company_name=company_name,
                                contact_person=contact_person,
                                whatsapp_phone=whatsapp_phone,
                                call_phone=call_phone,
                                products_services=products_services,
                                city=city,
                                notes=notes,
                                email=email,
                                address=address,
                            )
                            st.session_state["extracted_card"] = None
                            st.session_state["flash_success"] = (
                                f"Saved '{company_name}' to your account."
                            )
                            st.rerun()
                    except Exception:
                        st.error("Could not save right now. Please try again.")

                if discarded:
                    st.session_state["extracted_card"] = None
                    st.session_state["pending_duplicate_save"] = None
                    st.rerun()

    # ---- Step 3: User's Saved Records, City Filter, Search, Update & Delete ----
    st.divider()
    header_col, refresh_col = st.columns([5, 1])
    with header_col:
        st.subheader("3. Your Saved Visiting Cards")
    with refresh_col:
        if st.button("Refresh", use_container_width=True):
            _fetch_all_card_rows.clear()
            _fetch_all_usage_rows.clear()
            st.rerun()

    try:
        all_records_df = fetch_user_records(current_user_id)
    except Exception:
        st.error("Unable to load your saved cards right now. Please click Refresh.")
        return

    if all_records_df.empty:
        st.info("You haven't saved any visiting cards yet. Scan your first card above!")
        return

    # Build city list for dropdown filter
    unique_cities = sorted(
        {
            str(c).strip()
            for c in all_records_df["City"].dropna().tolist()
            if str(c).strip() and str(c).strip().upper() != "N/A"
        }
    )

    search_col, city_col, export_col = st.columns([2.6, 1.3, 1.2])

    with search_col:
        search_query = st.text_input(
            "Search records",
            placeholder="Search by company, product, city, phone, email, or address...",
            label_visibility="collapsed",
        )

    with city_col:
        selected_city = st.selectbox(
            "Filter by City",
            options=["All Cities", *unique_cities],
            label_visibility="collapsed",
        )

    # Apply City dropdown filter + free-text search
    filtered_df = all_records_df.copy()

    if selected_city != "All Cities":
        filtered_df = filtered_df[
            filtered_df["City"].astype(str).str.strip().str.lower()
            == selected_city.lower()
        ]

    if search_query.strip():
        q = search_query.strip()
        mask = (
            filtered_df["Company Name"].str.contains(q, case=False, na=False)
            | filtered_df["Contact Person"].str.contains(q, case=False, na=False)
            | filtered_df["Products / Services"].str.contains(q, case=False, na=False)
            | filtered_df["City"].str.contains(q, case=False, na=False)
            | filtered_df["Address"].str.contains(q, case=False, na=False)
            | filtered_df["WhatsApp Number"].str.contains(q, case=False, na=False)
            | filtered_df["Call Number"].str.contains(q, case=False, na=False)
            | filtered_df["Email"].str.contains(q, case=False, na=False)
        )
        filtered_df = filtered_df[mask]

    is_filtered = bool(search_query.strip()) or selected_city != "All Cities"

    with export_col:
        if not filtered_df.empty:
            excel_bytes = build_excel_bytes(filtered_df)
            city_suffix = (
                f"_{re.sub(r'[^A-Za-z0-9]+', '_', selected_city).strip('_')}"
                if selected_city != "All Cities"
                else ""
            )
            filename = (
                f"visiting_cards_{current_username}{city_suffix}_{datetime.now().strftime('%Y%m%d')}.xlsx"
            )
            btn_label = (
                "Download Filtered (.xlsx)"
                if is_filtered
                else "Download Excel (.xlsx)"
            )
            st.download_button(
                label=btn_label,
                data=excel_bytes,
                file_name=filename,
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                use_container_width=True,
            )
        else:
            st.button(
                "Download Excel (.xlsx)",
                disabled=True,
                use_container_width=True,
            )

    if is_filtered:
        st.caption(f"Showing {len(filtered_df)} of {len(all_records_df)} saved cards")
    else:
        st.caption(f"Total saved cards: {len(all_records_df)}")

    st.dataframe(filtered_df, use_container_width=True, hide_index=True)

    # Map labels -> full record dict for Edit and Delete utilities
    records_by_label = {
        f"{row['Record ID']} — {row['Company Name']} ({row['City']})": row.to_dict()
        for _, row in all_records_df.iterrows()
    }
    record_labels = list(records_by_label.keys())

    # ---- Edit / Update Record ----
    with st.expander("Edit / Update one of your records"):
        selected_edit_label = st.selectbox(
            "Select record to edit",
            options=record_labels,
            key="select_record_to_edit",
        )
        edit_rec = records_by_label[selected_edit_label]
        edit_id = edit_rec["Record ID"]
        edit_rev = st.session_state["edit_counter"]

        with st.form(key=f"edit_card_form_{edit_id}_{edit_rev}"):
            er1_c1, er1_c2 = st.columns(2)
            with er1_c1:
                upd_company = st.text_input(
                    "Company Name",
                    value=edit_rec["Company Name"],
                    key=f"upd_company_{edit_id}_{edit_rev}",
                )
            with er1_c2:
                upd_contact = st.text_input(
                    "Contact Person",
                    value=edit_rec["Contact Person"],
                    key=f"upd_contact_{edit_id}_{edit_rev}",
                )

            er2_c1, er2_c2 = st.columns(2)
            with er2_c1:
                upd_whatsapp = st.text_input(
                    "WhatsApp Number",
                    value=edit_rec["WhatsApp Number"],
                    key=f"upd_whatsapp_{edit_id}_{edit_rev}",
                )
            with er2_c2:
                upd_call = st.text_input(
                    "Call Number (Normal)",
                    value=edit_rec["Call Number"],
                    key=f"upd_call_{edit_id}_{edit_rev}",
                )

            er3_c1, er3_c2 = st.columns(2)
            with er3_c1:
                upd_products = st.text_input(
                    "Products / Services",
                    value=edit_rec["Products / Services"],
                    key=f"upd_products_{edit_id}_{edit_rev}",
                )
            with er3_c2:
                upd_city = st.text_input(
                    "City",
                    value=edit_rec["City"],
                    key=f"upd_city_{edit_id}_{edit_rev}",
                )

            upd_notes = st.text_input(
                "Additional Notes (Optional)",
                value=edit_rec["Notes"],
                key=f"upd_notes_{edit_id}_{edit_rev}",
            )

            # Final fields: Email strictly before Address
            upd_email = st.text_input(
                "Email",
                value=edit_rec["Email"],
                key=f"upd_email_{edit_id}_{edit_rev}",
            )
            upd_address = st.text_area(
                "Address",
                value=edit_rec["Address"],
                height=85,
                key=f"upd_address_{edit_id}_{edit_rev}",
            )

            update_submitted = st.form_submit_button("Update Record", type="primary")

            if update_submitted:
                try:
                    updated = update_record(
                        record_id=edit_id,
                        user_id=current_user_id,
                        company_name=upd_company,
                        contact_person=upd_contact,
                        whatsapp_phone=upd_whatsapp,
                        call_phone=upd_call,
                        products_services=upd_products,
                        city=upd_city,
                        notes=upd_notes,
                        email=upd_email,
                        address=upd_address,
                    )
                    if updated:
                        st.session_state["edit_counter"] += 1
                        st.session_state["flash_success"] = (
                            f"Updated '{upd_company}' successfully."
                        )
                        st.rerun()
                    else:
                        st.warning(
                            "Record not found or does not belong to your account."
                        )
                except Exception:
                    st.error("Could not update record right now. Please try again.")

    # ---- Delete Record ----
    with st.expander("Delete one of your records"):
        selected_del_label = st.selectbox(
            "Select record to delete",
            options=record_labels,
            key="select_record_to_delete",
        )
        del_id = records_by_label[selected_del_label]["Record ID"]

        if st.button("Delete Selected Record", type="secondary"):
            try:
                deleted = delete_record(del_id, current_user_id)
                if deleted:
                    st.session_state["flash_success"] = "Record deleted."
                    st.rerun()
                else:
                    st.warning("Record not found or does not belong to your account.")
            except Exception:
                st.error("Could not delete record right now. Please try again.")


if __name__ == "__main__":
    main()