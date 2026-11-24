import hashlib
import hmac
import io
import os
import re
import secrets
import time
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

CARD_HEADERS = [
    "record_id",
    "user_id",
    "company_name",
    "contact_person",
    "phone",
    "email",
    "address",
    "products_services",
    "notes",
    "created_at",
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
# Secret & Password Hashing Helpers
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


# ---------------------------------------------------------------------------
# Pydantic Schema for Gemini Structured Outputs
# ---------------------------------------------------------------------------
class VisitingCard(BaseModel):
    company_name: str = Field(
        description="Name of the company or business. Return 'N/A' if missing."
    )
    contact_person: str = Field(
        description="Full name of the contact person (include designation if printed). Return 'N/A' if missing."
    )
    phone: str = Field(
        description="All phone or mobile numbers found, comma-separated. Return 'N/A' if missing."
    )
    email: str = Field(
        description="Email address. Return 'N/A' if missing."
    )
    address: str = Field(
        description="Complete physical shop, office, or factory address. Return 'N/A' if missing."
    )
    products_services: str = Field(
        description=(
            "Products or services offered by the company. If not explicitly listed on the card, "
            "infer what the business deals in based on the company name, job title, or tagline. "
            "Return 'N/A' only if it is completely impossible to determine."
        )
    )


# ---------------------------------------------------------------------------
# Google Sheets Storage Layer
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


def ensure_worksheets(spreadsheet: gspread.Spreadsheet) -> None:
    """Create 'visiting_cards' and 'users' worksheets with headers if missing."""
    existing_titles = {ws.title for ws in spreadsheet.worksheets()}

    if CARDS_WORKSHEET not in existing_titles:
        cards_ws = spreadsheet.add_worksheet(
            title=CARDS_WORKSHEET, rows=1000, cols=len(CARD_HEADERS)
        )
        cards_ws.append_row(CARD_HEADERS, value_input_option="RAW")
    else:
        cards_ws = spreadsheet.worksheet(CARDS_WORKSHEET)
        if not cards_ws.row_values(1):
            cards_ws.append_row(CARD_HEADERS, value_input_option="RAW")

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
    """Fetch all user records directly from Google Sheets (fresh, uncached)."""
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
# Visiting Card CRUD (Strictly Scoped to Logged-In User)
# ---------------------------------------------------------------------------
@st.cache_data(ttl=60, show_spinner=False)
def _fetch_all_card_rows() -> list[list[str]]:
    """Fetch all raw rows from `visiting_cards` (cached 60s to respect API quota)."""
    ws = get_cards_worksheet()
    return ws.get_all_values()


def fetch_user_records(user_id: str) -> pd.DataFrame:
    """Return ONLY the visiting cards uploaded by `user_id`, newest first."""
    all_rows = _fetch_all_card_rows()
    display_cols = [
        "Record ID",
        "Company Name",
        "Contact Person",
        "Phone",
        "Email",
        "Products / Services",
        "Address",
        "Notes",
        "Saved On",
    ]

    if len(all_rows) <= 1:
        return pd.DataFrame(columns=display_cols)

    headers = all_rows[0]
    data_rows = []
    for row in all_rows[1:]:
        padded = row + [""] * (len(headers) - len(row))
        record = dict(zip(headers, padded))
        if record.get("user_id") == user_id:
            data_rows.append(
                {
                    "Record ID": record.get("record_id", ""),
                    "Company Name": record.get("company_name", "N/A"),
                    "Contact Person": record.get("contact_person", "N/A"),
                    "Phone": record.get("phone", "N/A"),
                    "Email": record.get("email", "N/A"),
                    "Products / Services": record.get("products_services", "N/A"),
                    "Address": record.get("address", "N/A"),
                    "Notes": record.get("notes", ""),
                    "Saved On": record.get("created_at", ""),
                }
            )

    if not data_rows:
        return pd.DataFrame(columns=display_cols)

    return pd.DataFrame(data_rows[::-1], columns=display_cols)


def save_record(
    user_id: str,
    company_name: str,
    contact_person: str,
    phone: str,
    email: str,
    address: str,
    products_services: str,
    notes: str,
) -> str:
    """Append a verified visiting card row tagged with the logged-in user's ID."""
    ws = get_cards_worksheet()
    record_id = uuid.uuid4().hex[:8]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    row = [
        record_id,
        user_id,
        company_name.strip() or "N/A",
        contact_person.strip() or "N/A",
        phone.strip() or "N/A",
        email.strip() or "N/A",
        address.strip() or "N/A",
        products_services.strip() or "N/A",
        notes.strip(),
        timestamp,
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
# Gemini AI Extraction Helper (with Retry & Fallback)
# ---------------------------------------------------------------------------
def extract_card_details(
    image_bytes: bytes, mime_type: str, api_key: str
) -> Tuple[VisitingCard, str]:
    """Send the visiting card image to Gemini with automatic retry and model fallback."""
    if not api_key or not api_key.strip():
        raise ValueError(
            "Gemini API key is missing. Add it in Streamlit Secrets or the sidebar Settings."
        )

    client = genai.Client(api_key=api_key.strip())

    prompt = (
        "Extract the business details from this visiting card image accurately. "
        "Pay close attention to Indian phone number formats, GST/company suffixes, "
        "and multi-line addresses. "
        "For 'products_services': if products or services are not explicitly written "
        "on the card, infer what the company likely sells or provides from the company "
        "name, tagline, logo, or contact person's title. "
        "If any field is completely absent and cannot be inferred, return 'N/A'."
    )

    models_to_try = [MODEL_NAME, *FALLBACK_MODELS]
    last_error: Optional[Exception] = None

    for model in models_to_try:
        for attempt in range(2):
            try:
                response = client.models.generate_content(
                    model=model,
                    contents=[
                        types.Part.from_bytes(data=image_bytes, mime_type=mime_type),
                        prompt,
                    ],
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        response_schema=VisitingCard,
                    ),
                )

                if isinstance(response.parsed, VisitingCard):
                    return response.parsed, model

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
                return VisitingCard.model_validate_json(cleaned_json), model

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


def run_scan(image_file, api_key: str) -> None:
    """Process an UploadedFile from either file_uploader or camera_input."""
    if not api_key:
        st.error("Gemini API key is not configured. Please add it in the sidebar Settings.")
        return

    image_bytes = image_file.getvalue()
    mime_type = image_file.type or "image/jpeg"

    with st.spinner("Scanning visiting card with Gemini..."):
        try:
            extracted, used_model = extract_card_details(
                image_bytes, mime_type, api_key
            )
            st.session_state["extracted_card"] = extracted.model_dump()
            st.session_state["scan_counter"] += 1
            st.session_state["scan_notice"] = (
                f"Card scanned using `{used_model}`! Please verify or edit the details below and click Save."
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
                reg_email = st.text_input(
                    "Email", placeholder="name@example.com"
                )
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
    if "scan_counter" not in st.session_state:
        st.session_state["scan_counter"] = 0
    if "flash_success" not in st.session_state:
        st.session_state["flash_success"] = None
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
            st.session_state["scan_notice"] = None
            st.session_state["flash_success"] = None
            st.rerun()

        st.divider()
        st.header("Settings")

        server_api_key = str(get_secret("GEMINI_API_KEY", "") or "").strip()
        if server_api_key:
            # Keep server secret hidden from users on shared/multi-user deployments
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

    # ---- Step 1: Image Capture & Upload ----
    st.subheader("1. Capture or Upload Visiting Card")
    tab_upload, tab_camera = st.tabs(["Upload Image", "Take Photo with Camera"])

    with tab_upload:
        uploaded_file = st.file_uploader(
            "Choose a visiting card image (JPG or PNG)",
            type=["jpg", "jpeg", "png"],
            key="card_file_uploader",
        )
        if uploaded_file is not None:
            st.image(
                uploaded_file.getvalue(),
                caption="Uploaded Card Preview",
                width=400,
            )
            if st.button(
                "Scan Uploaded Card",
                type="primary",
                key="btn_scan_upload",
            ):
                run_scan(uploaded_file, active_api_key)

    with tab_camera:
        camera_photo = st.camera_input(
            "Point your mobile or laptop camera at the visiting card",
            key="card_camera_input",
        )
        if camera_photo is not None:
            if st.button(
                "Scan Captured Photo",
                type="primary",
                key="btn_scan_camera",
            ):
                run_scan(camera_photo, active_api_key)

    # ---- Step 2: Verification & Edit Form ----
    if st.session_state["extracted_card"] is not None:
        st.divider()
        st.subheader("2. Verify & Save Details")

        if st.session_state["scan_notice"]:
            st.info(st.session_state["scan_notice"])
            st.session_state["scan_notice"] = None

        card = st.session_state["extracted_card"]
        suffix = st.session_state["scan_counter"]

        with st.form(key=f"verify_card_form_{suffix}"):
            col1, col2 = st.columns(2)

            with col1:
                company_name = st.text_input(
                    "Company Name",
                    value=card.get("company_name", "N/A"),
                    key=f"company_{suffix}",
                )
                contact_person = st.text_input(
                    "Contact Person",
                    value=card.get("contact_person", "N/A"),
                    key=f"contact_{suffix}",
                )
                phone = st.text_input(
                    "Phone",
                    value=card.get("phone", "N/A"),
                    key=f"phone_{suffix}",
                )

            with col2:
                email = st.text_input(
                    "Email",
                    value=card.get("email", "N/A"),
                    key=f"email_{suffix}",
                )
                products_services = st.text_input(
                    "Products / Services",
                    value=card.get("products_services", "N/A"),
                    key=f"products_{suffix}",
                )
                address = st.text_area(
                    "Address",
                    value=card.get("address", "N/A"),
                    height=80,
                    key=f"address_{suffix}",
                )

            notes = st.text_area(
                "Additional Notes (Optional)",
                placeholder="e.g., Met at trade fair, wholesale supplier, call next week...",
                height=70,
                key=f"notes_{suffix}",
            )

            btn_col1, btn_col2, _ = st.columns([1.2, 1, 4])
            with btn_col1:
                submitted = st.form_submit_button("Save Card", type="primary")
            with btn_col2:
                discarded = st.form_submit_button("Discard")

            if submitted:
                try:
                    save_record(
                        user_id=current_user_id,
                        company_name=company_name,
                        contact_person=contact_person,
                        phone=phone,
                        email=email,
                        address=address,
                        products_services=products_services,
                        notes=notes,
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
            placeholder="Filter your cards by company name, products/services, or address...",
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