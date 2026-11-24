import hashlib
import hmac
import io
import os
import re
import secrets
import time
import unicodedata
import uuid
from datetime import datetime
from typing import Any, Optional, Tuple

import gspread
import pandas as pd
import streamlit as st
from google import genai
from google.genai import errors as genai_errors
from google.genai import types
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
MODEL_NAME = "gemini-3.5-flash-lite"
FALLBACK_MODELS = ["gemini-3.6-flash", "gemini-3.8-flash"]

CARDS_WORKSHEET = "visiting_cards"
USERS_WORKSHEET = "users"
PBKDF2_ITERATIONS = 260_000
MAX_CARD_IMAGES = 2

# Email is placed second-to-last, immediately before Address
CARD_HEADERS = [
    "record_id",
    "user_id",
    "company_name",
    "contact_person",
    "whatsapp_phone",
    "call_phone",
    "products_services",
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

st.set_page_config(
    page_title="Company Visiting Card Scanner",
    page_icon="📇",
    layout="wide",
)


# ---------------------------------------------------------------------------
# Secret, Hashing & Normalization Helpers
# ---------------------------------------------------------------------------
def get_secret(key: str, default: Any = None) -> Any:
    """Safely read a key from st.secrets or environment variables."""
    try:
        if key in st.secrets:
            return st.secrets[key]
    except Exception:
        pass
    return os.getenv(key, default)


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
    """Convert any regional Unicode digits (e.g., Gujarati ૦-૯, Hindi ०-९) to ASCII 0-9."""
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


# ---------------------------------------------------------------------------
# Pydantic Schema for Gemini Structured Outputs (English + Dual Phone Fields)
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
    """Guarantee standard ASCII 0-9 digits across all extracted fields."""
    return card.model_copy(
        update={
            "company_name": normalize_digits(card.company_name).strip() or "N/A",
            "contact_person": normalize_digits(card.contact_person).strip() or "N/A",
            "whatsapp_phone": normalize_digits(card.whatsapp_phone).strip() or "N/A",
            "call_phone": normalize_digits(card.call_phone).strip() or "N/A",
            "products_services": normalize_digits(card.products_services).strip() or "N/A",
            "email": normalize_digits(card.email).strip() or "N/A",
            "address": normalize_digits(card.address).strip() or "N/A",
        }
    )


# ---------------------------------------------------------------------------
# Google Sheets Storage Layer (Auto-Migrates Columns Safely)
# ---------------------------------------------------------------------------
@st.cache_resource(show_spinner=False)
def get_spreadsheet() -> gspread.Spreadsheet:
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
    """Align existing `visiting_cards` sheet rows to the latest CARD_HEADERS order."""
    all_rows = cards_ws.get_all_values()
    if not all_rows:
        cards_ws.append_row(CARD_HEADERS, value_input_option="RAW")
        return

    current_headers = all_rows[0]
    if current_headers == CARD_HEADERS:
        return

    if cards_ws.col_count < len(CARD_HEADERS):
        cards_ws.resize(cols=len(CARD_HEADERS))

    migrated_rows = [CARD_HEADERS]
    for row in all_rows[1:]:
        if not any(cell.strip() for cell in row):
            continue
        padded = row + [""] * (len(current_headers) - len(row))
        old_rec = dict(zip(current_headers, padded))

        # Preserve old single `phone` column into `whatsapp_phone` by default
        wp_val = old_rec.get("whatsapp_phone") or old_rec.get("phone") or "N/A"
        call_val = old_rec.get("call_phone") or "N/A"

        new_rec = {
            "record_id": old_rec.get("record_id", uuid.uuid4().hex[:8]),
            "user_id": old_rec.get("user_id", "default_user"),
            "company_name": old_rec.get("company_name", "N/A"),
            "contact_person": old_rec.get("contact_person", "N/A"),
            "whatsapp_phone": wp_val,
            "call_phone": call_val,
            "products_services": old_rec.get("products_services", "N/A"),
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
    """Create or migrate 'visiting_cards' and 'users' worksheets."""
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


def get_cards_worksheet() -> gspread.Worksheet:
    return get_spreadsheet().worksheet(CARDS_WORKSHEET)


def get_users_worksheet() -> gspread.Worksheet:
    return get_spreadsheet().worksheet(USERS_WORKSHEET)


# ---------------------------------------------------------------------------
# User Authentication Functions (Backed by `users` Tab)
# ---------------------------------------------------------------------------
def fetch_all_users() -> list[dict[str, str]]:
    """Fetch all user records directly from Google Sheets."""
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
    """Fetch all raw rows from `visiting_cards` (cached 60s to respect API quota)."""
    ws = get_cards_worksheet()
    return ws.get_all_values()


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
    """
    Check if the logged-in user already uploaded a card matching any of the
    new card's phone numbers (WhatsApp or Call) or email addresses.
    """
    new_phones = extract_normalized_phones(whatsapp_phone) | extract_normalized_phones(
        call_phone
    )
    new_emails = extract_normalized_emails(email)

    if not new_phones and not new_emails:
        return []

    # Refresh cache before checking so recently added cards are never missed
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
    notes: str,
    email: str,
    address: str,
) -> str:
    """Append a verified visiting card row in CARD_HEADERS order (Email before Address)."""
    ws = get_cards_worksheet()
    record_id = uuid.uuid4().hex[:8]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Enforce default rule if user cleared WhatsApp but left a single number in Call only?
    # Respect whatever the user manually edited in the verification form.
    row = [
        record_id,
        user_id,
        normalize_digits(company_name).strip() or "N/A",
        normalize_digits(contact_person).strip() or "N/A",
        normalize_digits(whatsapp_phone).strip() or "N/A",
        normalize_digits(call_phone).strip() or "N/A",
        normalize_digits(products_services).strip() or "N/A",
        notes.strip(),
        timestamp,
        normalize_digits(email).strip() or "N/A",
        normalize_digits(address).strip() or "N/A",
    ]

    ws.append_row(row, value_input_option="RAW", table_range="A1")
    _fetch_all_card_rows.clear()
    return record_id


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
# Gemini AI Extraction Helper (Supports 1 or 2 Sides + Retry & Fallback)
# ---------------------------------------------------------------------------
def extract_card_details(
    images: list[Tuple[bytes, str]], api_key: str
) -> Tuple[VisitingCard, str]:
    """Send 1 or 2 visiting card images (front/back) to Gemini with retry & fallback."""
    if not api_key or not api_key.strip():
        raise ValueError(
            "Gemini API key is missing. Add it in Streamlit Secrets or the sidebar Settings."
        )
    if not images:
        raise ValueError("Please provide at least one visiting card image.")

    client = genai.Client(api_key=api_key.strip())

    side_note = (
        "You are given 2 images showing the FRONT and BACK sides of the SAME visiting card. "
        "Combine and merge all details found across both sides into one unified record without duplicating numbers or text. "
        if len(images) == 2
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
        "OTHER RULES:\n"
        "- For `products_services`: if not explicitly listed, infer what the company offers from the company name, "
        "tagline, logo, or contact person's title.\n"
        "- If any field is completely absent and cannot be inferred, return 'N/A'."
    )

    image_parts = [
        types.Part.from_bytes(data=img_bytes, mime_type=mime_type)
        for img_bytes, mime_type in images
    ]

    models_to_try = [MODEL_NAME, *FALLBACK_MODELS]
    last_error: Optional[Exception] = None

    for model in models_to_try:
        for attempt in range(2):
            try:
                response = client.models.generate_content(
                    model=model,
                    contents=[*image_parts, prompt],
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        response_schema=VisitingCard,
                    ),
                )

                if isinstance(response.parsed, VisitingCard):
                    return _clean_card_output(response.parsed), model

                if not response.text:
                    raise RuntimeError(
                        "Gemini returned an empty response. Try a clearer, well-lit photo."
                    )

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
                last_error = api_err
                if api_err.code in (429, 503):
                    time.sleep(2 * (attempt + 1))
                    continue
                if api_err.code == 404:
                    break
                raise

    if last_error:
        raise last_error
    raise RuntimeError("All Gemini models failed to process the visiting card.")


def run_scan(image_files: list, api_key: str) -> None:
    """Process 1 or 2 UploadedFile objects from file_uploader or camera_input."""
    if not api_key:
        st.error(
            "Gemini API key is not configured. Please add it in the sidebar Settings."
        )
        return
    if not image_files:
        st.error("Please upload or capture at least 1 card image.")
        return
    if len(image_files) > MAX_CARD_IMAGES:
        st.error(f"Maximum {MAX_CARD_IMAGES} images (Front & Back) are allowed.")
        return

    images_payload = [
        (f.getvalue(), f.type or "image/jpeg") for f in image_files
    ]
    side_label = "both card sides" if len(images_payload) == 2 else "visiting card"

    with st.spinner(f"Scanning {side_label} with Gemini..."):
        try:
            extracted, used_model = extract_card_details(images_payload, api_key)
            st.session_state["extracted_card"] = extracted.model_dump()
            st.session_state["pending_duplicate_save"] = None
            st.session_state["scan_counter"] += 1
            st.session_state["scan_notice"] = (
                f"Scanned {len(images_payload)} image(s) using `{used_model}`! "
                "Please verify or edit the details below and click Save."
            )
        except genai_errors.APIError as api_err:
            st.error(f"Gemini API error ({api_err.code}): {api_err.message}")
        except ValueError as val_err:
            st.error(str(val_err))
        except Exception as exc:
            st.error(f"Could not extract card details: {exc}")


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
                            st.session_state["auth_user"] = user
                            st.session_state["extracted_card"] = None
                            st.session_state["pending_duplicate_save"] = None
                            st.session_state["scan_notice"] = None
                            st.session_state["flash_success"] = (
                                f"Welcome back, {user['username']}!"
                            )
                            st.rerun()
                        else:
                            st.error(msg)
                    except Exception as exc:
                        st.error(f"Login failed: {exc}")

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
                                st.session_state["auth_user"] = user
                                st.session_state["extracted_card"] = None
                                st.session_state["pending_duplicate_save"] = None
                                st.session_state["scan_notice"] = None
                                st.session_state["flash_success"] = (
                                    f"Account created! Welcome, {user['username']}."
                                )
                                st.rerun()
                            else:
                                st.error(msg)
                        except Exception as exc:
                            st.error(f"Registration failed: {exc}")


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
    if "flash_success" not in st.session_state:
        st.session_state["flash_success"] = None
    if "flash_info" not in st.session_state:
        st.session_state["flash_info"] = None
    if "scan_notice" not in st.session_state:
        st.session_state["scan_notice"] = None

    # Verify Google Sheets connection upfront
    storage_ready = False
    storage_error = None
    try:
        get_spreadsheet()
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

    # Gate the app behind Login / Register
    auth_user = st.session_state["auth_user"]
    if auth_user is None:
        render_auth_screen()
        return

    current_user_id = auth_user["user_id"]
    current_username = auth_user["username"]
    current_email = auth_user["email"]

    # ---- Sidebar: Account, Logout & Settings ----
    with st.sidebar:
        st.header("Account")
        st.markdown(f"**{current_username}**")
        st.caption(current_email)

        if st.button("Logout", use_container_width=True):
            st.session_state["auth_user"] = None
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
            st.success("Gemini API key configured")
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
                st.success("Gemini API key configured")
            else:
                st.warning("Enter a Gemini API key to scan cards.")

        st.success("Google Sheets connected")
        st.divider()
        st.caption(f"Primary model: `{MODEL_NAME}`")
        st.caption(f"Fallbacks: `{', '.join(FALLBACK_MODELS)}`")

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
    st.subheader("1. Capture or Upload Visiting Card (1 or 2 Sides)")
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
                ):
                    run_scan(uploaded_files, active_api_key)

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
            ):
                run_scan(captured_photos, active_api_key)

    # ---- Step 2: Verification Form & Duplicate Confirmation ----
    if st.session_state["extracted_card"] is not None:
        st.divider()
        st.subheader("2. Verify & Save Details")

        pending_dup = st.session_state["pending_duplicate_save"]

        if pending_dup is not None:
            # Show duplicate warning & Yes/No confirmation prompt
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

            st.markdown(
                "**Do you want to upload this same card data again?**"
            )
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
                    except Exception as sheet_err:
                        st.error(f"Could not save to Google Sheets: {sheet_err}")

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
                # Row 1: Company Name & Contact Person
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

                # Row 2: WhatsApp Number & Normal Call Number
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

                # Row 3: Products / Services & Additional Notes
                r3_c1, r3_c2 = st.columns(2)
                with r3_c1:
                    products_services = st.text_input(
                        "Products / Services",
                        value=card.get("products_services", "N/A"),
                        key=f"products_{suffix}",
                    )
                with r3_c2:
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
                                notes=notes,
                                email=email,
                                address=address,
                            )
                            st.session_state["extracted_card"] = None
                            st.session_state["flash_success"] = (
                                f"Saved '{company_name}' to your account."
                            )
                            st.rerun()
                    except Exception as sheet_err:
                        st.error(f"Could not save to Google Sheets: {sheet_err}")

                if discarded:
                    st.session_state["extracted_card"] = None
                    st.session_state["pending_duplicate_save"] = None
                    st.rerun()

    # ---- Step 3: User's Saved Records, Search & Excel Export ----
    st.divider()
    header_col, refresh_col = st.columns([5, 1])
    with header_col:
        st.subheader("3. Your Saved Visiting Cards")
    with refresh_col:
        if st.button("Refresh", use_container_width=True):
            _fetch_all_card_rows.clear()
            st.rerun()

    try:
        all_records_df = fetch_user_records(current_user_id)
    except Exception as sheet_err:
        st.error(f"Failed to load your records from Google Sheets: {sheet_err}")
        return

    search_col, export_col = st.columns([3, 1])

    with search_col:
        search_query = st.text_input(
            "Search records",
            placeholder="Filter by company name, products/services, phone, email, or address...",
            label_visibility="collapsed",
        )

    with export_col:
        if not all_records_df.empty:
            excel_bytes = build_excel_bytes(all_records_df)
            filename = (
                f"visiting_cards_{current_username}_{datetime.now().strftime('%Y%m%d')}.xlsx"
            )
            st.download_button(
                label="Download Excel (.xlsx)",
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

    if all_records_df.empty:
        st.info("You haven't saved any visiting cards yet. Scan your first card above!")
        return

    if search_query.strip():
        q = search_query.strip()
        mask = (
            all_records_df["Company Name"].str.contains(q, case=False, na=False)
            | all_records_df["Products / Services"].str.contains(q, case=False, na=False)
            | all_records_df["Address"].str.contains(q, case=False, na=False)
            | all_records_df["WhatsApp Number"].str.contains(q, case=False, na=False)
            | all_records_df["Call Number"].str.contains(q, case=False, na=False)
            | all_records_df["Email"].str.contains(q, case=False, na=False)
        )
        filtered_df = all_records_df[mask]
        st.caption(f"Showing {len(filtered_df)} of {len(all_records_df)} saved cards")
    else:
        filtered_df = all_records_df
        st.caption(f"Total saved cards: {len(all_records_df)}")

    st.dataframe(filtered_df, use_container_width=True, hide_index=True)

    # Delete strictly scoped to the logged-in user's records
    with st.expander("Delete one of your records"):
        record_options = {
            f"{row['Record ID']} — {row['Company Name']} ({row['Contact Person']})": row[
                "Record ID"
            ]
            for _, row in all_records_df.iterrows()
        }
        selected_label = st.selectbox(
            "Select record to delete", options=list(record_options.keys())
        )
        if st.button("Delete Selected Record", type="secondary"):
            try:
                deleted = delete_record(record_options[selected_label], current_user_id)
                if deleted:
                    st.session_state["flash_success"] = "Record deleted."
                    st.rerun()
                else:
                    st.warning("Record not found or does not belong to your account.")
            except Exception as sheet_err:
                st.error(f"Could not delete record: {sheet_err}")


if __name__ == "__main__":
    main()