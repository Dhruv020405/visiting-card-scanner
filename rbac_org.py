import hashlib
import os
import re
import secrets
import threading
import time
import uuid
from datetime import datetime
from typing import Any, Callable, Optional, Tuple

import gspread
import pandas as pd
import streamlit as st

from security_utils import (
    cleanup_expired_operational_rows,
    log_internal_error,
    retry_sheets_call,
)

# ---------------------------------------------------------------------------
# Role & Organization Constants
# ---------------------------------------------------------------------------
ROLE_ADMIN = "admin"
ROLE_COMPANY_HEAD = "company_head"
ROLE_EMPLOYEE = "employee"
ROLE_USER = "user"

VALID_ROLES = {ROLE_ADMIN, ROLE_COMPANY_HEAD, ROLE_EMPLOYEE, ROLE_USER}
CRM_ALLOWED_ROLES = {ROLE_ADMIN, ROLE_COMPANY_HEAD, ROLE_EMPLOYEE}

ROLE_DISPLAY_NAMES: dict[str, str] = {
    ROLE_ADMIN: "Platform Admin",
    ROLE_COMPANY_HEAD: "Company Head (Boss)",
    ROLE_EMPLOYEE: "Employee",
    ROLE_USER: "Normal User",
}

COMPANIES_WORKSHEET = "companies"
USERS_WORKSHEET = "users"
INVITES_WORKSHEET = "company_invites"

INVITE_TTL_SECONDS = 7 * 24 * 60 * 60  # 7-day employee/head invite validity

COMPANY_HEADERS = [
    "company_id",
    "company_name",
    "industry",
    "city",
    "head_user_id",
    "status",
    "created_at",
]

EXTENDED_USER_HEADERS = [
    "user_id",
    "username",
    "email",
    "password_hash",
    "role",
    "company_id",
    "full_name",
    "status",
    "created_at",
]

INVITE_HEADERS = [
    "invite_id",
    "company_id",
    "email",
    "target_role",
    "token_hash",
    "invited_by",
    "expires_at",
    "used",
    "created_at",
]

_ORG_LOCK = threading.Lock()


def _hash_pw(password: str, iterations: int = 260_000) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations
    )
    return f"pbkdf2_sha256${iterations}${salt}${dk.hex()}"


def _verify_hash(raw_val: str, stored_hash: str) -> bool:
    try:
        algo, iter_str, salt, expected_hex = stored_hash.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256", raw_val.encode("utf-8"), salt.encode("utf-8"), int(iter_str)
        )
        return secrets.compare_digest(dk.hex(), expected_hex)
    except Exception:
        return False


def _validate_pw(password: str, min_len: int = 8) -> Tuple[bool, str]:
    if len(password) < min_len:
        return False, f"Password must be at least {min_len} characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must include at least one uppercase letter (A-Z)."
    if not re.search(r"[a-z]", password):
        return False, "Password must include at least one lowercase letter (a-z)."
    if not re.search(r"\d", password):
        return False, "Password must include at least one number (0-9)."
    return True, ""


def _clean_str(val: Any, max_len: int = 120) -> str:
    if val is None:
        return ""
    return str(val).replace("\x00", "").strip()[:max_len].strip()


def _is_valid_email(email: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email))


def _is_valid_username(username: str) -> bool:
    return bool(re.match(r"^[A-Za-z0-9_.-]{3,30}$", username))


def get_admin_emails_from_secrets() -> set[str]:
    raw = ""
    try:
        if "ADMIN_EMAILS" in st.secrets:
            raw = str(st.secrets["ADMIN_EMAILS"] or "")
    except Exception:
        pass
    if not raw:
        raw = os.getenv("ADMIN_EMAILS", "")
    return {e.strip().lower() for e in raw.split(",") if e.strip()}


def normalize_role(raw_role: Any, email: str = "") -> str:
    clean_email = str(email or "").strip().lower()
    if clean_email and clean_email in get_admin_emails_from_secrets():
        return ROLE_ADMIN
    r = str(raw_role or ROLE_USER).strip().lower()
    return r if r in VALID_ROLES else ROLE_USER


def get_role_badge_label(role: str) -> str:
    return ROLE_DISPLAY_NAMES.get(role, "Normal User")


def can_access_crm(
    user: Optional[dict[str, Any]],
    spreadsheet: Optional[gspread.Spreadsheet] = None,
) -> bool:
    if not user:
        return False
    role = normalize_role(user.get("role", ROLE_USER), user.get("email", ""))
    if role == ROLE_ADMIN:
        return True
    if role in (ROLE_COMPANY_HEAD, ROLE_EMPLOYEE):
        cid = str(user.get("company_id", "")).strip()
        if not cid:
            return False
        if spreadsheet is not None:
            co = get_company_by_id(spreadsheet, cid)
            if co and str(co.get("status", "active")).strip().lower() == "suspended":
                return False
        return True
    return False


def ensure_org_worksheets(spreadsheet: gspread.Spreadsheet) -> None:
    """Create/migrate `companies`, `company_invites`, and `users` tabs safely."""
    existing_ws = retry_sheets_call(spreadsheet.worksheets)
    titles = {ws.title for ws in existing_ws}

    for ws_name, expected_headers in (
        (COMPANIES_WORKSHEET, COMPANY_HEADERS),
        (INVITES_WORKSHEET, INVITE_HEADERS),
    ):
        if ws_name not in titles:
            ws = spreadsheet.add_worksheet(title=ws_name, rows=300, cols=len(expected_headers))
            retry_sheets_call(
                lambda w=ws, h=expected_headers: w.append_row(h, value_input_option="RAW")
            )
        else:
            ws = spreadsheet.worksheet(ws_name)
            rows = retry_sheets_call(ws.get_all_values)
            if not rows:
                retry_sheets_call(
                    lambda w=ws, h=expected_headers: w.append_row(h, value_input_option="RAW")
                )
            elif rows[0] != expected_headers:
                if ws.col_count < len(expected_headers):
                    ws.resize(cols=len(expected_headers))
                hdrs = [h.strip() for h in rows[0] if h.strip()]
                migrated = [expected_headers]
                for r in rows[1:]:
                    if not any(x.strip() for x in r):
                        continue
                    padded = r + [""] * (len(hdrs) - len(r))
                    rec = dict(zip(hdrs, padded))
                    migrated.append([rec.get(col, "") for col in expected_headers])
                retry_sheets_call(
                    lambda w=ws, m=migrated: w.update(
                        values=m, range_name="A1", value_input_option="RAW"
                    )
                )

    if USERS_WORKSHEET in titles:
        u_ws = spreadsheet.worksheet(USERS_WORKSHEET)
        u_rows = retry_sheets_call(u_ws.get_all_values)
        if not u_rows:
            retry_sheets_call(
                lambda: u_ws.append_row(EXTENDED_USER_HEADERS, value_input_option="RAW")
            )
        elif u_rows[0] != EXTENDED_USER_HEADERS:
            if u_ws.col_count < len(EXTENDED_USER_HEADERS):
                u_ws.resize(cols=len(EXTENDED_USER_HEADERS))
            hdrs = [h.strip() for h in u_rows[0] if h.strip()]
            migrated_u = [EXTENDED_USER_HEADERS]
            for r in u_rows[1:]:
                if not any(x.strip() for x in r):
                    continue
                padded = r + [""] * (len(hdrs) - len(r))
                rec = dict(zip(hdrs, padded))
                migrated_u.append(
                    [
                        rec.get("user_id", ""),
                        rec.get("username", ""),
                        rec.get("email", ""),
                        rec.get("password_hash", ""),
                        rec.get("role", ROLE_USER) or ROLE_USER,
                        rec.get("company_id", ""),
                        rec.get("full_name", "") or rec.get("username", ""),
                        rec.get("status", "active") or "active",
                        rec.get("created_at", ""),
                    ]
                )
            retry_sheets_call(
                lambda: u_ws.update(
                    values=migrated_u, range_name="A1", value_input_option="RAW"
                )
            )


@st.cache_data(ttl=60, show_spinner=False)
def fetch_all_companies(_spreadsheet_id: str) -> list[dict[str, str]]:
    ss = st.session_state["_org_spreadsheet_ref"]
    ensure_org_worksheets(ss)
    ws = ss.worksheet(COMPANIES_WORKSHEET)
    rows = retry_sheets_call(ws.get_all_values)
    if len(rows) <= 1:
        return []
    headers = rows[0]
    out: list[dict[str, str]] = []
    for row in rows[1:]:
        if not any(c.strip() for c in row):
            continue
        padded = row + [""] * (len(headers) - len(row))
        out.append(dict(zip(headers, padded)))
    return out


def get_company_by_id(
    spreadsheet: gspread.Spreadsheet, company_id: str
) -> Optional[dict[str, str]]:
    if not company_id:
        return None
    st.session_state["_org_spreadsheet_ref"] = spreadsheet
    for co in fetch_all_companies(spreadsheet.id):
        if co.get("company_id") == company_id:
            return co
    return None


def get_company_members(
    all_users: list[dict[str, str]], company_id: str, include_disabled: bool = False
) -> list[dict[str, str]]:
    if not company_id:
        return []
    out = []
    for u in all_users:
        if str(u.get("company_id", "")).strip() != company_id:
            continue
        status = str(u.get("status", "active")).strip().lower()
        if not include_disabled and status == "disabled":
            continue
        out.append(u)
    return out


# ---------------------------------------------------------------------------
# Verified Invitation Flow (Replaces Manager-Assigned Passwords)
# ---------------------------------------------------------------------------
def create_company_invite(
    spreadsheet: gspread.Spreadsheet,
    company_id: str,
    invitee_email: str,
    target_role: str,
    invited_by_uid: str,
    send_email_fn: Optional[Callable[[str, str, str, str, str], None]] = None,
    audit_fn: Optional[Callable[[str, str, str, str], bool]] = None,
) -> Tuple[bool, str, str]:
    """
    Create a single-use 7-day invite code so the employee/boss sets their own password
    (or upgrades their existing Normal User account). Returns (ok, msg, invite_code).
    """
    clean_email = _clean_str(invitee_email, 160).lower()
    if not _is_valid_email(clean_email):
        return False, "Please enter a valid email address.", ""
    if target_role not in (ROLE_COMPANY_HEAD, ROLE_EMPLOYEE):
        return False, "Invalid target role.", ""

    co = get_company_by_id(spreadsheet, company_id)
    if not co:
        return False, "Target company not found.", ""

    raw_code = f"INV-{secrets.token_hex(4).upper()}"
    token_hash = _hash_pw(raw_code)
    expires_at = str(int(time.time()) + INVITE_TTL_SECONDS)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    invite_id = f"inv_{uuid.uuid4().hex[:10]}"

    with _ORG_LOCK:
        ensure_org_worksheets(spreadsheet)
        ws = spreadsheet.worksheet(INVITES_WORKSHEET)
        retry_sheets_call(
            lambda: ws.append_row(
                [
                    invite_id,
                    company_id,
                    clean_email,
                    target_role,
                    token_hash,
                    invited_by_uid,
                    expires_at,
                    "no",
                    now_str,
                ],
                value_input_option="RAW",
                table_range="A1",
            )
        )

    emailed = False
    if send_email_fn is not None:
        try:
            send_email_fn(
                clean_email,
                clean_email.split("@")[0],
                raw_code,
                f"Invitation to join {co['company_name']} — Fuva CRM",
                f"You have been invited as {get_role_badge_label(target_role)} for {co['company_name']}. "
                f"Your single-use invite code (valid 7 days) is",
            )
            emailed = True
        except Exception as exc:
            log_internal_error("create_company_invite.send_email", exc)

    if audit_fn:
        audit_fn(
            invited_by_uid,
            "INVITE_CREATED",
            invite_id,
            f"Invited {clean_email} as {target_role} for company {co['company_name']}",
        )

    delivery_note = (
        f"Invitation email sent to {clean_email}."
        if emailed
        else f"Invite created for {clean_email} (SMTP not sent — share the invite code securely)."
    )
    return True, delivery_note, raw_code


def accept_company_invite(
    spreadsheet: gspread.Spreadsheet,
    invitee_email: str,
    invite_code: str,
    full_name: str,
    username: str,
    new_password: str,
    clear_users_cache_fn: Callable[[], None],
    audit_fn: Optional[Callable[[str, str, str, str], bool]] = None,
) -> Tuple[bool, str]:
    """
    Verify invite code + email.
    - If user already exists as Normal User, upgrades them to the invited company/role.
    - Otherwise creates a new account with the employee's self-chosen strong password.
    """
    clean_email = _clean_str(invitee_email, 160).lower()
    clean_code = _clean_str(invite_code, 40).upper()
    clean_fname = _clean_str(full_name, 100)
    clean_uname = _clean_str(username, 30)

    if not _is_valid_email(clean_email) or not clean_code:
        return False, "Enter both your invited email address and invite code."

    with _ORG_LOCK:
        ensure_org_worksheets(spreadsheet)
        inv_ws = spreadsheet.worksheet(INVITES_WORKSHEET)
        inv_rows = retry_sheets_call(inv_ws.get_all_values)
        if len(inv_rows) <= 1:
            return False, "Invalid or expired invitation code."

        matched_inv_idx = None
        matched_inv = None
        now = int(time.time())
        for idx in range(len(inv_rows) - 1, 0, -1):
            row = inv_rows[idx]
            if (
                len(row) >= 8
                and row[2].strip().lower() == clean_email
                and row[7].strip().lower() == "no"
            ):
                try:
                    exp = int(row[6])
                except ValueError:
                    continue
                if exp >= now and _verify_hash(clean_code, row[4]):
                    matched_inv_idx = idx + 1
                    matched_inv = row
                    break

        if matched_inv_idx is None or matched_inv is None:
            return False, "Invalid, already used, or expired invitation code."

        company_id = matched_inv[1]
        target_role = matched_inv[3]

        u_ws = spreadsheet.worksheet(USERS_WORKSHEET)
        u_rows = retry_sheets_call(u_ws.get_all_values)
        headers = u_rows[0] if u_rows else EXTENDED_USER_HEADERS

        existing_user_idx = None
        existing_user_rec = None
        for idx, r in enumerate(u_rows[1:], start=2):
            if not any(c.strip() for c in r):
                continue
            padded = r + [""] * (len(headers) - len(r))
            rec = dict(zip(headers, padded))
            if rec.get("email", "").strip().lower() == clean_email:
                existing_user_idx = idx
                existing_user_rec = rec
                break

        if existing_user_idx is not None and existing_user_rec is not None:
            uid = existing_user_rec["user_id"]
            retry_sheets_call(
                lambda: u_ws.update(
                    values=[
                        [
                            target_role,
                            company_id,
                            clean_fname or existing_user_rec.get("full_name", ""),
                            "active",
                        ]
                    ],
                    range_name=f"E{existing_user_idx}:H{existing_user_idx}",
                    value_input_option="RAW",
                )
            )
        else:
            if not clean_fname:
                return False, "Please enter your full name."
            if not _is_valid_username(clean_uname):
                return False, "Username must be 3-30 characters (letters, numbers, _ . -)."
            pw_ok, pw_msg = _validate_pw(new_password)
            if not pw_ok:
                return False, pw_msg

            for r in u_rows[1:]:
                if len(r) >= 2 and r[1].strip().lower() == clean_uname.lower():
                    return False, f"Username '{clean_uname}' is already taken. Choose another."

            uid = f"usr_{uuid.uuid4().hex[:12]}"
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            retry_sheets_call(
                lambda: u_ws.append_row(
                    [
                        uid,
                        clean_uname,
                        clean_email,
                        _hash_pw(new_password),
                        target_role,
                        company_id,
                        clean_fname,
                        "active",
                        now_str,
                    ],
                    value_input_option="RAW",
                    table_range="A1",
                )
            )

        retry_sheets_call(
            lambda: inv_ws.update(
                values=[["yes"]],
                range_name=f"H{matched_inv_idx}",
                value_input_option="RAW",
            )
        )
        if target_role == ROLE_COMPANY_HEAD:
            c_ws = spreadsheet.worksheet(COMPANIES_WORKSHEET)
            c_rows = retry_sheets_call(c_ws.get_all_values)
            for c_idx, cr in enumerate(c_rows[1:], start=2):
                if len(cr) >= 1 and cr[0] == company_id:
                    retry_sheets_call(
                        lambda ci=c_idx: c_ws.update(
                            values=[[uid]], range_name=f"E{ci}", value_input_option="RAW"
                        )
                    )
                    break

        fetch_all_companies.clear()
        clear_users_cache_fn()

    if audit_fn:
        audit_fn(
            uid,
            "INVITE_ACCEPTED",
            matched_inv[0],
            f"{clean_email} joined company {company_id} as {target_role}",
        )
    return True, "Invitation accepted! You can now sign in with your email and password."


# ---------------------------------------------------------------------------
# Admin Operations: Register Company, Suspend/Reactivate Company
# ---------------------------------------------------------------------------
def create_company_record(
    spreadsheet: gspread.Spreadsheet,
    company_name: str,
    industry: str,
    city: str,
    head_email: str,
    admin_uid: str,
    send_email_fn: Optional[Callable[[str, str, str, str, str], None]] = None,
    audit_fn: Optional[Callable[[str, str, str, str], bool]] = None,
) -> Tuple[bool, str, str]:
    """Admin-only: Register a Company and issue a verified invite for its Company Head."""
    clean_co = _clean_str(company_name, 120)
    clean_ind = _clean_str(industry, 100) or "General"
    clean_city = _clean_str(city, 80) or "N/A"
    clean_email = _clean_str(head_email, 160).lower()

    if len(clean_co) < 2:
        return False, "Please enter a valid Company Name.", ""
    if not _is_valid_email(clean_email):
        return False, "Please enter a valid Company Head email address.", ""

    with _ORG_LOCK:
        ensure_org_worksheets(spreadsheet)
        st.session_state["_org_spreadsheet_ref"] = spreadsheet
        fetch_all_companies.clear()
        for existing_co in fetch_all_companies(spreadsheet.id):
            if existing_co.get("company_name", "").strip().lower() == clean_co.lower():
                return False, f"Company '{clean_co}' is already registered.", ""

        company_id = f"comp_{uuid.uuid4().hex[:10]}"
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c_ws = spreadsheet.worksheet(COMPANIES_WORKSHEET)
        retry_sheets_call(
            lambda: c_ws.append_row(
                [company_id, clean_co, clean_ind, clean_city, "", "active", now_str],
                value_input_option="RAW",
                table_range="A1",
            )
        )
        fetch_all_companies.clear()

    if audit_fn:
        audit_fn(admin_uid, "ADMIN_CREATE_COMPANY", company_id, f"Registered company '{clean_co}'")

    ok, inv_msg, inv_code = create_company_invite(
        spreadsheet=spreadsheet,
        company_id=company_id,
        invitee_email=clean_email,
        target_role=ROLE_COMPANY_HEAD,
        invited_by_uid=admin_uid,
        send_email_fn=send_email_fn,
        audit_fn=audit_fn,
    )
    if not ok:
        return False, inv_msg, ""
    return True, f"Registered '{clean_co}'. {inv_msg}", inv_code


def set_company_status(
    spreadsheet: gspread.Spreadsheet,
    company_id: str,
    new_status: str,
    admin_uid: str,
    all_users: list[dict[str, str]],
    revoke_sessions_fn: Callable[[str], int],
    audit_fn: Optional[Callable[[str, str, str, str], bool]] = None,
) -> Tuple[bool, str]:
    """Admin-only: Suspend or reactivate a company (revoking active sessions on suspension)."""
    clean_status = "suspended" if new_status.lower() == "suspended" else "active"
    with _ORG_LOCK:
        c_ws = spreadsheet.worksheet(COMPANIES_WORKSHEET)
        rows = retry_sheets_call(c_ws.get_all_values)
        for idx, r in enumerate(rows[1:], start=2):
            if len(r) >= 2 and r[0] == company_id:
                co_name = r[1]
                retry_sheets_call(
                    lambda ci=idx: c_ws.update(
                        values=[[clean_status]], range_name=f"F{ci}", value_input_option="RAW"
                    )
                )
                fetch_all_companies.clear()
                if clean_status == "suspended":
                    for u in all_users:
                        if u.get("company_id") == company_id:
                            revoke_sessions_fn(u["user_id"])
                if audit_fn:
                    audit_fn(
                        admin_uid,
                        "ADMIN_COMPANY_STATUS",
                        company_id,
                        f"Set company '{co_name}' status to {clean_status}",
                    )
                return True, f"Company '{co_name}' is now {clean_status}."
    return False, "Company not found."


def update_member_status(
    spreadsheet: gspread.Spreadsheet,
    target_user_id: str,
    new_status: str,
    expected_company_id: Optional[str],
    actor_uid: str,
    clear_users_cache_fn: Callable[[], None],
    revoke_sessions_fn: Callable[[str], int],
    audit_fn: Optional[Callable[[str, str, str, str], bool]] = None,
) -> Tuple[bool, str]:
    clean_status = "disabled" if new_status.lower() == "disabled" else "active"
    with _ORG_LOCK:
        u_ws = spreadsheet.worksheet(USERS_WORKSHEET)
        u_rows = retry_sheets_call(u_ws.get_all_values)
        if len(u_rows) <= 1:
            return False, "User not found."
        headers = u_rows[0]
        for idx, r in enumerate(u_rows[1:], start=2):
            padded = r + [""] * (len(headers) - len(r))
            rec = dict(zip(headers, padded))
            if rec.get("user_id") == target_user_id:
                if expected_company_id and rec.get("company_id") != expected_company_id:
                    return False, "You can only manage employees in your own company."
                if rec.get("role") == ROLE_ADMIN:
                    return False, "Admin accounts cannot be disabled here."
                retry_sheets_call(
                    lambda ri=idx: u_ws.update(
                        values=[[clean_status]], range_name=f"H{ri}", value_input_option="RAW"
                    )
                )
                clear_users_cache_fn()
                if clean_status == "disabled":
                    revoke_sessions_fn(target_user_id)
                if audit_fn:
                    audit_fn(
                        actor_uid,
                        "MEMBER_STATUS_UPDATED",
                        target_user_id,
                        f"Set user '{rec.get('username')}' status to {clean_status}",
                    )
                return True, f"Updated '{rec.get('username')}' status to {clean_status}."
    return False, "User not found."


def purge_normal_user_account(
    spreadsheet: gspread.Spreadsheet,
    user_id: str,
    clear_caches_fn: Callable[[], None],
    revoke_sessions_fn: Callable[[str], int],
) -> Tuple[bool, str]:
    """
    Permanently purge a Normal User's personal account, cards, usage, and sessions.
    Refuses to purge Admin or active company-scoped accounts without Admin offboarding.
    """
    with _ORG_LOCK:
        u_ws = spreadsheet.worksheet(USERS_WORKSHEET)
        u_rows = retry_sheets_call(u_ws.get_all_values)
        if len(u_rows) <= 1:
            return False, "Account not found."
        headers = u_rows[0]
        target_row_idx = None
        for idx, r in enumerate(u_rows[1:], start=2):
            padded = r + [""] * (len(headers) - len(r))
            rec = dict(zip(headers, padded))
            if rec.get("user_id") == user_id:
                if rec.get("role") != ROLE_USER or str(rec.get("company_id", "")).strip():
                    return (
                        False,
                        "Company/Admin accounts must be offboarded by your Company Head or Admin.",
                    )
                target_row_idx = idx
                break
        if target_row_idx is None:
            return False, "Account not found."

        revoke_sessions_fn(user_id)

        for ws_name, uid_col in (("visiting_cards", 1), ("scan_usage", 0)):
            try:
                ws = spreadsheet.worksheet(ws_name)
                rows = retry_sheets_call(ws.get_all_values)
                if len(rows) > 1:
                    kept = [rows[0]] + [
                        r for r in rows[1:] if len(r) <= uid_col or r[uid_col] != user_id
                    ]
                    if len(kept) != len(rows):
                        retry_sheets_call(lambda w=ws: w.clear())
                        retry_sheets_call(
                            lambda w=ws, k=kept: w.update(
                                values=k, range_name="A1", value_input_option="RAW"
                            )
                        )
            except gspread.WorksheetNotFound:
                continue

        retry_sheets_call(lambda ri=target_row_idx: u_ws.delete_rows(ri))
        clear_caches_fn()

    return True, "Your account and all personal visiting cards have been permanently deleted."


# ---------------------------------------------------------------------------
# Platform Admin Console UI
# ---------------------------------------------------------------------------
def render_admin_console(
    spreadsheet: gspread.Spreadsheet,
    current_user: dict[str, str],
    all_users: list[dict[str, str]],
    clear_users_cache_fn: Callable[[], None],
    revoke_sessions_fn: Callable[[str], int],
    send_email_fn: Optional[Callable[[str, str, str, str, str], None]] = None,
    audit_fn: Optional[Callable[[str, str, str, str], bool]] = None,
    fetch_audit_fn: Optional[Callable[[Optional[str], Optional[int]], pd.DataFrame]] = None,
) -> None:
    st.session_state["_org_spreadsheet_ref"] = spreadsheet
    ensure_org_worksheets(spreadsheet)
    companies = fetch_all_companies(spreadsheet.id)
    admin_uid = str(current_user.get("user_id", ""))

    with st.container(border=True):
        st.subheader("Platform Admin — Company, Governance & Maintenance")
        st.caption(
            "Register companies via verified Boss invitations, suspend/reactivate companies, "
            "review platform audit logs, and run operational retention cleanups."
        )

        k1, k2, k3, k4 = st.columns(4)
        with k1:
            st.metric("Registered Companies", len(companies))
        with k2:
            st.metric(
                "Company Heads",
                sum(1 for u in all_users if u.get("role") == ROLE_COMPANY_HEAD),
            )
        with k3:
            st.metric(
                "Employees",
                sum(1 for u in all_users if u.get("role") == ROLE_EMPLOYEE),
            )
        with k4:
            st.metric(
                "Normal Users",
                sum(1 for u in all_users if u.get("role", ROLE_USER) == ROLE_USER),
            )

        t_reg, t_manage, t_audit, t_maint = st.tabs(
            [
                "Register Company & Invite Boss",
                f"Manage Companies ({len(companies)})",
                "Platform Audit Logs",
                "Retention Cleanup",
            ]
        )

        with t_reg:
            with st.form("admin_reg_company_invite_form"):
                c1, c2 = st.columns(2)
                with c1:
                    co_name = st.text_input("Company Name *", placeholder="e.g., R.H. Enterprise")
                    co_ind = st.text_input("Industry", placeholder="e.g., Industrial Automation")
                with c2:
                    co_city = st.text_input("City", placeholder="e.g., Ahmedabad")
                    boss_email = st.text_input(
                        "Company Head (Boss) Email *",
                        placeholder="boss@company.com (Boss sets their own password via invite)",
                    )
                if st.form_submit_button(
                    "Register Company & Send Boss Invite",
                    type="primary",
                    use_container_width=True,
                ):
                    ok, msg, inv_code = create_company_record(
                        spreadsheet=spreadsheet,
                        company_name=co_name,
                        industry=co_ind,
                        city=co_city,
                        head_email=boss_email,
                        admin_uid=admin_uid,
                        send_email_fn=send_email_fn,
                        audit_fn=audit_fn,
                    )
                    if ok:
                        st.success(msg)
                        st.info(f"Single-use Boss Invite Code (valid 7 days): `{inv_code}`")
                    else:
                        st.error(msg)

        with t_manage:
            if not companies:
                st.info("No companies registered yet.")
            else:
                user_map = {u["user_id"]: u for u in all_users}
                rows_disp = []
                for co in companies:
                    cid = co.get("company_id", "")
                    head = user_map.get(co.get("head_user_id", ""), {})
                    emp_cnt = sum(
                        1
                        for u in all_users
                        if u.get("company_id") == cid and u.get("role") == ROLE_EMPLOYEE
                    )
                    rows_disp.append(
                        {
                            "Company Name": co.get("company_name", ""),
                            "Industry": co.get("industry", ""),
                            "City": co.get("city", ""),
                            "Head": head.get("email", "Pending Invite"),
                            "Employees": emp_cnt,
                            "Status": co.get("status", "active").title(),
                            "Created": co.get("created_at", ""),
                        }
                    )
                st.dataframe(pd.DataFrame(rows_disp), use_container_width=True, hide_index=True)

                st.divider()
                co_opts = {
                    f"{c['company_name']} ({c.get('status', 'active').title()})": c
                    for c in companies
                }
                sel_co_lbl = st.selectbox(
                    "Select Company to Suspend / Reactivate",
                    options=list(co_opts.keys()),
                    key="adm_susp_sel",
                )
                sel_co = co_opts[sel_co_lbl]
                curr_st = sel_co.get("status", "active").lower()
                next_st = "suspended" if curr_st == "active" else "active"
                if st.button(
                    "Suspend Company" if next_st == "suspended" else "Reactivate Company",
                    type="secondary",
                    key="btn_adm_toggle_co",
                ):
                    ok, msg = set_company_status(
                        spreadsheet=spreadsheet,
                        company_id=sel_co["company_id"],
                        new_status=next_st,
                        admin_uid=admin_uid,
                        all_users=all_users,
                        revoke_sessions_fn=revoke_sessions_fn,
                        audit_fn=audit_fn,
                    )
                    if ok:
                        st.session_state["flash_success"] = msg
                        st.rerun()
                    else:
                        st.error(msg)

        with t_audit:
            if fetch_audit_fn:
                df_audit = fetch_audit_fn(None, 200)
                if df_audit.empty:
                    st.info("No platform audit entries recorded yet.")
                else:
                    st.dataframe(df_audit, use_container_width=True, hide_index=True)

        with t_maint:
            st.caption(
                "Purge expired OTPs (>24h), expired/revoked sessions (>14d), and stale rate-limit rows (>7d) "
                "to keep Google Sheets fast and within cell limits."
            )
            if st.button(
                "Run Operational Retention Cleanup Now",
                type="primary",
                key="btn_admin_cleanup",
            ):
                counts = cleanup_expired_operational_rows(spreadsheet)
                if audit_fn:
                    audit_fn(
                        admin_uid,
                        "ADMIN_RETENTION_CLEANUP",
                        "system",
                        f"Cleaned rows: {counts}",
                    )
                st.success(f"Cleanup complete: {counts}")


# ---------------------------------------------------------------------------
# Company Head (Boss) Team Management UI (Verified Invites + Open Deal Handling)
# ---------------------------------------------------------------------------
def render_team_management_section(
    spreadsheet: gspread.Spreadsheet,
    current_user: dict[str, str],
    all_users: list[dict[str, str]],
    clear_users_cache_fn: Callable[[], None],
    revoke_sessions_fn: Callable[[str], int],
    count_open_deals_fn: Callable[[str, str], int],
    reassign_open_deals_fn: Callable[[str, str, str], Tuple[bool, str]],
    send_email_fn: Optional[Callable[[str, str, str, str, str], None]] = None,
    audit_fn: Optional[Callable[[str, str, str, str], bool]] = None,
) -> None:
    company_id = str(current_user.get("company_id", "")).strip()
    boss_uid = str(current_user.get("user_id", "")).strip()
    co_info = get_company_by_id(spreadsheet, company_id)
    co_title = co_info.get("company_name", "Your Company") if co_info else "Your Company"

    with st.container(border=True):
        st.subheader(f"My Team — {co_title}")
        st.caption(
            "Invite employees via verified single-use invite codes (employees set their own password). "
            "Disabling an employee prompts you to safely reassign or unassign their open CRM deals."
        )

        members = get_company_members(all_users, company_id, include_disabled=True)
        active_members = [
            m for m in members if m.get("status", "active").lower() != "disabled"
        ]
        employees = [m for m in members if m.get("role") == ROLE_EMPLOYEE]

        t1, t2 = st.tabs([f"Team Members ({len(members)})", "Invite New Employee"])

        with t1:
            if not members:
                st.info("No team members found.")
            else:
                team_rows = [
                    {
                        "Full Name": m.get("full_name") or m.get("username", ""),
                        "Username": m.get("username", ""),
                        "Email": m.get("email", ""),
                        "Role": get_role_badge_label(m.get("role", ROLE_EMPLOYEE)),
                        "Status": m.get("status", "active").title(),
                        "Joined": m.get("created_at", ""),
                    }
                    for m in members
                ]
                st.dataframe(pd.DataFrame(team_rows), use_container_width=True, hide_index=True)

                if employees:
                    st.divider()
                    st.markdown("#### Disable / Re-Activate Employee & Handle Open Deals")
                    emp_opts = {
                        f"{e.get('full_name') or e['username']} ({e['email']}) — {e.get('status', 'active').title()}": e
                        for e in employees
                    }
                    chosen_emp_lbl = st.selectbox(
                        "Select Employee",
                        options=list(emp_opts.keys()),
                        key="boss_manage_emp_sel",
                    )
                    chosen_emp = emp_opts[chosen_emp_lbl]
                    curr_stat = chosen_emp.get("status", "active").lower()

                    if curr_stat == "active":
                        open_deal_cnt = count_open_deals_fn(company_id, chosen_emp["user_id"])
                        reassign_target = ""
                        if open_deal_cnt > 0:
                            st.warning(
                                f"**{chosen_emp.get('full_name') or chosen_emp['username']}** currently owns "
                                f"**{open_deal_cnt}** open CRM deal(s). Choose how to handle them before disabling:"
                            )
                            other_active = [
                                m
                                for m in active_members
                                if m["user_id"] != chosen_emp["user_id"]
                            ]
                            deal_choice_map = {"Leave deals explicitly Unassigned": ""}
                            for m in other_active:
                                deal_choice_map[
                                    f"Reassign to {m.get('full_name') or m['username']} ({get_role_badge_label(m.get('role', ''))})"
                                ] = m["user_id"]
                            chosen_deal_action = st.selectbox(
                                "Open Deals Action",
                                options=list(deal_choice_map.keys()),
                                key=f"boss_disable_deal_action_{chosen_emp['user_id']}",
                            )
                            reassign_target = deal_choice_map[chosen_deal_action]

                        if st.button(
                            "Confirm & Disable Employee",
                            type="primary",
                            key="btn_boss_disable_emp",
                        ):
                            if open_deal_cnt > 0:
                                r_ok, r_msg = reassign_open_deals_fn(
                                    company_id, chosen_emp["user_id"], reassign_target
                                )
                                if not r_ok:
                                    st.error(f"Could not update open deals: {r_msg}")
                                    return
                            ok, msg = update_member_status(
                                spreadsheet=spreadsheet,
                                target_user_id=chosen_emp["user_id"],
                                new_status="disabled",
                                expected_company_id=company_id,
                                actor_uid=boss_uid,
                                clear_users_cache_fn=clear_users_cache_fn,
                                revoke_sessions_fn=revoke_sessions_fn,
                                audit_fn=audit_fn,
                            )
                            if ok:
                                st.session_state["flash_success"] = msg
                                st.rerun()
                            else:
                                st.error(msg)
                    else:
                        if st.button(
                            "Re-Activate Employee Login",
                            type="secondary",
                            key="btn_boss_reactivate_emp",
                        ):
                            ok, msg = update_member_status(
                                spreadsheet=spreadsheet,
                                target_user_id=chosen_emp["user_id"],
                                new_status="active",
                                expected_company_id=company_id,
                                actor_uid=boss_uid,
                                clear_users_cache_fn=clear_users_cache_fn,
                                revoke_sessions_fn=revoke_sessions_fn,
                                audit_fn=audit_fn,
                            )
                            if ok:
                                st.session_state["flash_success"] = msg
                                st.rerun()
                            else:
                                st.error(msg)

        with t2:
            with st.form("boss_invite_employee_form"):
                emp_email = st.text_input(
                    "Employee Email *",
                    placeholder="amit@company.com (employee sets their own password on signup)",
                )
                if st.form_submit_button(
                    "Send Verified Employee Invite",
                    type="primary",
                    use_container_width=True,
                ):
                    ok, msg, inv_code = create_company_invite(
                        spreadsheet=spreadsheet,
                        company_id=company_id,
                        invitee_email=emp_email,
                        target_role=ROLE_EMPLOYEE,
                        invited_by_uid=boss_uid,
                        send_email_fn=send_email_fn,
                        audit_fn=audit_fn,
                    )
                    if ok:
                        st.success(msg)
                        st.info(f"Single-use Employee Invite Code (valid 7 days): `{inv_code}`")
                    else:
                        st.error(msg)