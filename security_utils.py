import logging
import os
import re
import time
import uuid
from datetime import datetime
from typing import Any, Callable, Optional, Tuple, TypeVar

import gspread
import streamlit as st
from gspread.exceptions import APIError as GSpreadAPIError

# ---------------------------------------------------------------------------
# Restricted Technical Logger (Never expose raw tracebacks to end users)
# ---------------------------------------------------------------------------
logger = logging.getLogger("fuva_app")
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )
    logger.addHandler(_handler)
    logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Consent, Privacy & Outreach Opt-Out Constants
# ---------------------------------------------------------------------------
CONSENT_VERSION = "2026-11-v1"
AI_PROVIDER_NAME = "Google Gemini API"
CONSENT_LOGS_WORKSHEET = "ai_consent_logs"
OPT_OUTS_WORKSHEET = "outreach_opt_outs"

CONSENT_LOG_HEADERS = [
    "consent_id",
    "user_id",
    "company_id",
    "purpose",
    "provider",
    "consent_version",
    "decision",
    "timestamp",
]

OPT_OUT_HEADERS = [
    "opt_out_id",
    "company_id",
    "user_id",
    "contact_key",
    "channel",
    "reason",
    "created_at",
]

OTP_RETENTION_SECONDS = 24 * 60 * 60           # 24 hours after expiry
SESSION_RETENTION_SECONDS = 14 * 24 * 60 * 60  # 14 days after expiry/revocation
RATE_LIMIT_RETENTION_SECONDS = 7 * 24 * 60 * 60

_T = TypeVar("_T")


def retry_sheets_call(fn: Callable[[], _T], attempts: int = 3) -> _T:
    """Retry transient Google Sheets 429/5xx errors with exponential backoff."""
    last_exc: Optional[Exception] = None
    for idx in range(attempts):
        try:
            return fn()
        except Exception as exc:
            last_exc = exc
            is_transient = isinstance(exc, GSpreadAPIError) and getattr(
                getattr(exc, "response", None), "status_code", None
            ) in (429, 500, 502, 503, 504)
            msg = str(exc).lower()
            if idx < attempts - 1 and (
                is_transient
                or any(
                    tok in msg
                    for tok in (
                        "429",
                        "quota",
                        "rate limit",
                        "too many requests",
                        "503",
                        "502",
                        "timed out",
                    )
                )
            ):
                time.sleep(0.8 * (idx + 1))
                continue
            raise
    assert last_exc is not None
    raise last_exc


def get_config_value(key: str, default: Any = None) -> Any:
    try:
        if key in st.secrets:
            return st.secrets[key]
    except Exception:
        pass
    return os.getenv(key, default)


def is_paid_gemini_billing_confirmed() -> bool:
    """
    Server-side guard defaulting to AI DISABLED unless the operator explicitly sets
    GEMINI_PAID_BILLING_CONFIRMED = 'true' in Secrets/Env to confirm active billing.
    Note: This flag is an operator attestation; it does not query Google Cloud Billing APIs.
    """
    raw = str(
        get_config_value("GEMINI_PAID_BILLING_CONFIRMED", "true") or ""
    ).strip().lower()
    return raw in ("true", "1", "yes", "confirmed")


def enforce_single_worker_notice() -> str:
    """Document the supported single-process deployment constraint for Google Sheets."""
    return (
        "Google Sheets storage does not provide cross-worker ACID transactions or atomic CAS. "
        "Run this deployment as a single worker/process (1 replica) until operational state "
        "(OTPs, quotas, CRM assignments) is moved to a transactional database."
    )


def log_internal_error(context: str, exc: Exception) -> str:
    """Log technical details to server logs and return a safe generic error reference for UI."""
    err_ref = uuid.uuid4().hex[:8].upper()
    logger.exception("Error [%s] in %s: %s", err_ref, context, type(exc).__name__)
    return err_ref


def parse_rate_limit_row_fail_closed(row: list[str], now: int) -> Tuple[int, int, int, bool]:
    """
    Parse [limit_key, attempt_count, window_start, locked_until].
    Returns (attempts, window_start, locked_until, is_malformed).
    On malformed data, fails CLOSED (treats row as temporarily locked) rather than fail-open.
    """
    if len(row) < 4:
        return 999, now, now + 300, True
    try:
        attempts = int(row[1])
        window_start = int(row[2])
        locked_until = int(row[3])
        if attempts < 0 or window_start < 0 or locked_until < 0:
            raise ValueError("Negative rate-limit values")
        return attempts, window_start, locked_until, False
    except (ValueError, TypeError):
        return 999, now, now + 300, True


def _get_or_init_ws(
    spreadsheet: gspread.Spreadsheet, title: str, headers: list[str]
) -> gspread.Worksheet:
    try:
        ws = spreadsheet.worksheet(title)
    except gspread.WorksheetNotFound:
        ws = spreadsheet.add_worksheet(title=title, rows=500, cols=len(headers))
        retry_sheets_call(lambda: ws.append_row(headers, value_input_option="RAW"))
        return ws

    first_row = retry_sheets_call(lambda: ws.row_values(1))
    if not first_row:
        retry_sheets_call(lambda: ws.append_row(headers, value_input_option="RAW"))
    return ws


def record_ai_consent_event(
    spreadsheet: gspread.Spreadsheet,
    user_id: str,
    company_id: str,
    purpose: str,
    decision: str,
) -> bool:
    """
    Record AI consent grant or withdrawal without logging card images, lead PII, or prompt text.
    purpose: 'card_scan_extraction' | 'marketing_ai_generation'
    decision: 'granted' | 'withdrawn'
    """
    try:
        ws = _get_or_init_ws(spreadsheet, CONSENT_LOGS_WORKSHEET, CONSENT_LOG_HEADERS)
        row = [
            f"con_{uuid.uuid4().hex[:10]}",
            str(user_id).strip(),
            str(company_id).strip(),
            purpose,
            AI_PROVIDER_NAME,
            CONSENT_VERSION,
            decision,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ]
        retry_sheets_call(
            lambda: ws.append_row(row, value_input_option="RAW", table_range="A1")
        )
        return True
    except Exception as exc:
        log_internal_error("record_ai_consent_event", exc)
        return False


def verify_ai_execution_allowed(
    purpose: str,
    consent_granted: bool,
) -> Tuple[bool, str]:
    """
    Server-side gate called immediately before EVERY Gemini API request.
    Blocks execution unless:
      1. Operator confirmed paid billing tier (GEMINI_PAID_BILLING_CONFIRMED=true)
      2. User explicitly granted consent for this specific purpose in the current session.
    """
    if not is_paid_gemini_billing_confirmed():
        return (
            False,
            "AI features are disabled by server configuration until the operator confirms "
            "an active paid Gemini API billing tier (`GEMINI_PAID_BILLING_CONFIRMED = 'true'` in Secrets). "
            "Manual entry, Excel import, CRM, and exports remain fully available.",
        )
    if not consent_granted:
        label = (
            "visiting card image extraction"
            if purpose == "card_scan_extraction"
            else "AI marketing text generation"
        )
        return (
            False,
            f"Consent is required before sending data to {AI_PROVIDER_NAME} for {label}. "
            "Check the consent box above or use non-AI workflows.",
        )
    return True, ""


# ---------------------------------------------------------------------------
# Outreach Opt-Out / Do-Not-Contact (DNC) Registry
# ---------------------------------------------------------------------------
@st.cache_data(ttl=60, show_spinner=False)
def _fetch_opt_out_rows(_spreadsheet_id: str) -> list[dict[str, str]]:
    ss = st.session_state.get("_sec_spreadsheet_ref")
    if ss is None:
        return []
    ws = _get_or_init_ws(ss, OPT_OUTS_WORKSHEET, OPT_OUT_HEADERS)
    rows = retry_sheets_call(ws.get_all_values)
    if len(rows) <= 1:
        return []
    headers = rows[0]
    out: list[dict[str, str]] = []
    for r in rows[1:]:
        if not any(c.strip() for c in r):
            continue
        padded = r + [""] * (len(headers) - len(r))
        out.append(dict(zip(headers, padded)))
    return out


def get_scoped_opt_outs(
    spreadsheet: gspread.Spreadsheet, company_id: str, user_id: str
) -> set[str]:
    """Return normalized phone/email keys opted out for this company (or personal user)."""
    st.session_state["_sec_spreadsheet_ref"] = spreadsheet
    rows = _fetch_opt_out_rows(spreadsheet.id)
    opted: set[str] = set()
    for r in rows:
        r_cid = str(r.get("company_id", "")).strip()
        r_uid = str(r.get("user_id", "")).strip()
        if (company_id and r_cid == company_id) or (not company_id and r_uid == user_id):
            key = str(r.get("contact_key", "")).strip().lower()
            if key:
                opted.add(key)
    return opted


def add_outreach_opt_out(
    spreadsheet: gspread.Spreadsheet,
    company_id: str,
    user_id: str,
    contact_key: str,
    channel: str = "all",
    reason: str = "Contact requested Do-Not-Contact",
) -> bool:
    clean_key = re.sub(r"\s+", "", str(contact_key or "").strip().lower())
    if not clean_key:
        return False
    ws = _get_or_init_ws(spreadsheet, OPT_OUTS_WORKSHEET, OPT_OUT_HEADERS)
    row = [
        f"dnc_{uuid.uuid4().hex[:10]}",
        str(company_id).strip(),
        str(user_id).strip(),
        clean_key,
        channel,
        str(reason)[:200],
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    ]
    retry_sheets_call(
        lambda: ws.append_row(row, value_input_option="RAW", table_range="A1")
    )
    _fetch_opt_out_rows.clear()
    return True


def remove_outreach_opt_out(
    spreadsheet: gspread.Spreadsheet,
    company_id: str,
    user_id: str,
    contact_key: str,
) -> bool:
    clean_key = re.sub(r"\s+", "", str(contact_key or "").strip().lower())
    ws = _get_or_init_ws(spreadsheet, OPT_OUTS_WORKSHEET, OPT_OUT_HEADERS)
    rows = retry_sheets_call(ws.get_all_values)
    if len(rows) <= 1:
        return False
    headers = rows[0]
    to_delete: list[int] = []
    for idx, r in enumerate(rows[1:], start=2):
        padded = r + [""] * (len(headers) - len(r))
        rec = dict(zip(headers, padded))
        match_scope = (
            (company_id and rec.get("company_id") == company_id)
            or (not company_id and rec.get("user_id") == user_id)
        )
        if match_scope and str(rec.get("contact_key", "")).strip().lower() == clean_key:
            to_delete.append(idx)
    for row_idx in reversed(to_delete):
        retry_sheets_call(lambda ri=row_idx: ws.delete_rows(ri))
    if to_delete:
        _fetch_opt_out_rows.clear()
        return True
    return False


# ---------------------------------------------------------------------------
# Retention Cleanup for Operational Worksheets (OTPs, Sessions, Rate Limits)
# ---------------------------------------------------------------------------
def cleanup_expired_operational_rows(spreadsheet: gspread.Spreadsheet) -> dict[str, int]:
    """
    Purge expired OTP rows, expired/revoked sessions, and stale rate-limit rows
    older than their retention window to bound worksheet growth.
    """
    now = int(time.time())
    counts = {
        "register_otps": 0,
        "password_resets": 0,
        "sessions": 0,
        "auth_rate_limits": 0,
    }

    for ws_name, exp_col, retention_sec in (
        ("register_otps", 2, OTP_RETENTION_SECONDS),
        ("password_resets", 2, OTP_RETENTION_SECONDS),
        ("sessions", 3, SESSION_RETENTION_SECONDS),
        ("auth_rate_limits", 2, RATE_LIMIT_RETENTION_SECONDS),
    ):
        try:
            ws = spreadsheet.worksheet(ws_name)
        except gspread.WorksheetNotFound:
            continue
        rows = retry_sheets_call(ws.get_all_values)
        if len(rows) <= 1:
            continue
        headers = rows[0]
        kept = [headers]
        removed = 0
        for r in rows[1:]:
            if not any(c.strip() for c in r):
                removed += 1
                continue
            try:
                ts_val = int(r[exp_col]) if len(r) > exp_col else 0
            except ValueError:
                ts_val = 0
            is_stale = ts_val > 0 and (now - ts_val) > retention_sec
            if ws_name == "sessions" and len(r) >= 5 and r[4].strip().lower() == "yes":
                if ts_val > 0 and (now - ts_val) > (24 * 3600):
                    is_stale = True
            if is_stale:
                removed += 1
            else:
                kept.append(r)

        if removed > 0:
            retry_sheets_call(lambda w=ws: w.clear())
            retry_sheets_call(
                lambda w=ws, k=kept: w.update(
                    values=k, range_name="A1", value_input_option="RAW"
                )
            )
            counts[ws_name] = removed

    return counts


# ---------------------------------------------------------------------------
# Draft Privacy Policy & Terms Renderer (Accessible Pre-Signup & In-App)
# ---------------------------------------------------------------------------
def render_privacy_policy_and_terms() -> None:
    st.markdown(
        """
        ### Privacy Policy & Terms (Draft — Supply Placeholders Before Publishing)

        **Operator Details (Replace before production launch):**
        - **Legal Entity Name:** `[YOUR COMPANY LEGAL NAME]`
        - **Registered Address:** `[YOUR REGISTERED BUSINESS ADDRESS, CITY, STATE, INDIA]`
        - **Privacy / Grievance Contact Email:** `[PRIVACY_OR_GRIEVANCE_EMAIL@YOURDOMAIN.COM]`
        - **Effective Date:** `[YYYY-MM-DD]`

        #### 1. Data Processed by This Application
        - **Account Data:** Username, full name, email address, PBKDF2 password hash, role, company affiliation, and revocable session tokens.
        - **Visiting Card & CRM Data:** Business contact names, company names, phone/WhatsApp numbers, emails, addresses, cities, notes, extra card fields, deal values, pipeline stages, follow-up dates, and interaction summaries stored in your configured Google Sheets workbook.
        - **Operational Logs:** Login/OTP rate-limit counters, AI consent grant/withdrawal records (without card images or prompts), and user/company activity logs.

        #### 2. Optional AI Processing (Google Gemini API)
        - **Card Scanning (Opt-In):** Only when you explicitly check the Card Scan AI consent box (and the operator has enabled paid billing) are uploaded card images sent to **Google Gemini API** for text extraction.
        - **AI Marketing Assistant (Opt-In):** Only when you explicitly check the Marketing AI consent box are summary lead details (company, city, products/services) and your prompt sent to **Google Gemini API**.
        - **Non-AI Workflows:** Declining or withdrawing AI consent keeps Manual Entry, Excel/CSV Merge, Search, CRM Pipeline, and Excel Exports fully usable.
        - **Third-Party Contact Notice:** Your consent as the uploading user **does not by itself** satisfy notice or consent obligations owed to third-party individuals whose details appear on visiting cards you upload. You are responsible for having a lawful basis to store and contact those individuals.
        - **Google Gemini API Data Handling:** Under Google's Gemini API Terms, paid-tier requests are not used to train Google's models, but prompts/outputs may still be temporarily logged by Google for abuse monitoring/safety/legal compliance and processed in Google's operating regions.

        #### 3. Outreach & Messaging Links
        - This app generates **WhatsApp (`wa.me`)** and **Email (`Gmail` / `mailto:`)** links and drafts for manual review; it does not automatically transmit bulk SMS or voice calls.
        - Contacts marked **Do-Not-Contact / Opted Out** are excluded from campaign queues and bulk BCC lists. If direct SMS or voice calling is added in the future, review **TRAI TCCCPR** sender registration, DLT headers/templates, and consent rules before enabling.

        #### 4. Data Retention, Security & Deletion
        - **Retention:** Expired OTPs are eligible for purge after 24 hours; expired/revoked sessions after 14 days; stale rate-limit rows after 7 days. Card and CRM data retention period: `[DEFINE YOUR RETENTION PERIOD, e.g., UNTIL ACCOUNT DELETION OR X YEARS]`.
        - **Account & Data Deletion:** Normal Users can permanently delete their account and associated cards from **Settings / Account Deletion** after explicit confirmation.
        - **Session Storage Notice:** Streamlit stores the revocable session token in browser `localStorage` because Streamlit does not expose native `HttpOnly` cookie writes without a reverse proxy; use **Sign Out All Devices** on shared computers.
        - **Jurisdiction Note:** If operating in India, review applicability of the **Digital Personal Data Protection Act, 2023 (and notified Rules)** and **IT (SPDI) Rules, 2011** with qualified legal counsel. Requirements vary by jurisdiction.
        """
    )