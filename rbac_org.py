import hashlib
import os
import re
import secrets
import threading
import time
import uuid
from datetime import datetime
from typing import Any, Callable, Optional, Tuple, TypeVar

import gspread
import pandas as pd
import streamlit as st
from gspread.exceptions import APIError as GSpreadAPIError

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

_ORG_LOCK = threading.Lock()
_T = TypeVar("_T")


def _retry_sheets(fn: Callable[[], _T], attempts: int = 3) -> _T:
    last_exc: Optional[Exception] = None
    for idx in range(attempts):
        try:
            return fn()
        except Exception as exc:
            last_exc = exc
            is_429 = isinstance(exc, GSpreadAPIError) and getattr(
                getattr(exc, "response", None), "status_code", None
            ) in (429, 500, 502, 503, 504)
            msg = str(exc).lower()
            if idx < attempts - 1 and (
                is_429 or "429" in msg or "quota" in msg or "rate limit" in msg
            ):
                time.sleep(0.8 * (idx + 1))
                continue
            raise
    assert last_exc is not None
    raise last_exc


def _hash_pw(password: str, iterations: int = 260_000) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations
    )
    return f"pbkdf2_sha256${iterations}${salt}${dk.hex()}"


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
    s = str(val).replace("\x00", "").strip()
    return s[:max_len].strip()


def _is_valid_email(email: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email))


def _is_valid_username(username: str) -> bool:
    return bool(re.match(r"^[A-Za-z0-9_.-]{3,30}$", username))


def get_admin_emails_from_secrets() -> set[str]:
    """Read comma-separated ADMIN_EMAILS from Streamlit Secrets or environment."""
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


def can_access_crm(user: Optional[dict[str, Any]]) -> bool:
    if not user:
        return False
    role = normalize_role(user.get("role", ROLE_USER), user.get("email", ""))
    if role == ROLE_ADMIN:
        return True
    if role in (ROLE_COMPANY_HEAD, ROLE_EMPLOYEE):
        return bool(str(user.get("company_id", "")).strip())
    return False


def ensure_org_worksheets(spreadsheet: gspread.Spreadsheet) -> None:
    """Create `companies` tab and safely migrate `users` to EXTENDED_USER_HEADERS."""
    existing_ws = _retry_sheets(spreadsheet.worksheets)
    titles = {ws.title for ws in existing_ws}

    if COMPANIES_WORKSHEET not in titles:
        c_ws = spreadsheet.add_worksheet(
            title=COMPANIES_WORKSHEET, rows=300, cols=len(COMPANY_HEADERS)
        )
        _retry_sheets(lambda: c_ws.append_row(COMPANY_HEADERS, value_input_option="RAW"))
    else:
        c_ws = spreadsheet.worksheet(COMPANIES_WORKSHEET)
        c_rows = _retry_sheets(c_ws.get_all_values)
        if not c_rows:
            _retry_sheets(lambda: c_ws.append_row(COMPANY_HEADERS, value_input_option="RAW"))
        elif c_rows[0] != COMPANY_HEADERS:
            if c_ws.col_count < len(COMPANY_HEADERS):
                c_ws.resize(cols=len(COMPANY_HEADERS))
            hdrs = [h.strip() for h in c_rows[0] if h.strip()]
            migrated_c = [COMPANY_HEADERS]
            for r in c_rows[1:]:
                if not any(x.strip() for x in r):
                    continue
                padded = r + [""] * (len(hdrs) - len(r))
                rec = dict(zip(hdrs, padded))
                migrated_c.append(
                    [
                        rec.get("company_id", ""),
                        rec.get("company_name", ""),
                        rec.get("industry", ""),
                        rec.get("city", ""),
                        rec.get("head_user_id", ""),
                        rec.get("status", "active") or "active",
                        rec.get("created_at", ""),
                    ]
                )
            _retry_sheets(
                lambda: c_ws.update(values=migrated_c, range_name="A1", value_input_option="RAW")
            )

    if USERS_WORKSHEET in titles:
        u_ws = spreadsheet.worksheet(USERS_WORKSHEET)
        u_rows = _retry_sheets(u_ws.get_all_values)
        if not u_rows:
            _retry_sheets(
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
            _retry_sheets(
                lambda: u_ws.update(values=migrated_u, range_name="A1", value_input_option="RAW")
            )


@st.cache_data(ttl=60, show_spinner=False)
def fetch_all_companies(_spreadsheet_id: str) -> list[dict[str, str]]:
    ss = st.session_state["_org_spreadsheet_ref"]
    ensure_org_worksheets(ss)
    ws = ss.worksheet(COMPANIES_WORKSHEET)
    rows = _retry_sheets(ws.get_all_values)
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


def create_company_with_head(
    spreadsheet: gspread.Spreadsheet,
    company_name: str,
    industry: str,
    city: str,
    head_full_name: str,
    head_username: str,
    head_email: str,
    head_password: str,
    clear_users_cache_fn: Callable[[], None],
) -> Tuple[bool, str]:
    """Admin-only: Register a new Company and create/assign its Company Head (Boss)."""
    clean_co = _clean_str(company_name, 120)
    clean_ind = _clean_str(industry, 100) or "General"
    clean_city = _clean_str(city, 80) or "N/A"
    clean_fname = _clean_str(head_full_name, 100)
    clean_uname = _clean_str(head_username, 30)
    clean_email = _clean_str(head_email, 160).lower()

    if len(clean_co) < 2:
        return False, "Please enter a valid Company Name."
    if not clean_fname:
        return False, "Please enter the Company Head's full name."
    if not _is_valid_username(clean_uname):
        return False, "Boss Username must be 3-30 characters (letters, numbers, _ . -)."
    if not _is_valid_email(clean_email):
        return False, "Please enter a valid email address for the Company Head."

    pw_ok, pw_msg = _validate_pw(head_password)
    if not pw_ok:
        return False, pw_msg

    with _ORG_LOCK:
        ensure_org_worksheets(spreadsheet)
        st.session_state["_org_spreadsheet_ref"] = spreadsheet
        fetch_all_companies.clear()
        for existing_co in fetch_all_companies(spreadsheet.id):
            if existing_co.get("company_name", "").strip().lower() == clean_co.lower():
                return False, f"Company '{clean_co}' is already registered."

        u_ws = spreadsheet.worksheet(USERS_WORKSHEET)
        u_rows = _retry_sheets(u_ws.get_all_values)
        headers = u_rows[0] if u_rows else EXTENDED_USER_HEADERS
        for r in u_rows[1:]:
            if not any(c.strip() for c in r):
                continue
            padded = r + [""] * (len(headers) - len(r))
            rec = dict(zip(headers, padded))
            if rec.get("username", "").strip().lower() == clean_uname.lower():
                return False, f"Username '{clean_uname}' is already taken."
            if rec.get("email", "").strip().lower() == clean_email:
                return False, f"Email '{clean_email}' is already registered."

        company_id = f"comp_{uuid.uuid4().hex[:10]}"
        head_user_id = f"usr_{uuid.uuid4().hex[:12]}"
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        pw_hash = _hash_pw(head_password)

        c_ws = spreadsheet.worksheet(COMPANIES_WORKSHEET)
        _retry_sheets(
            lambda: c_ws.append_row(
                [company_id, clean_co, clean_ind, clean_city, head_user_id, "active", now_str],
                value_input_option="RAW",
                table_range="A1",
            )
        )
        _retry_sheets(
            lambda: u_ws.append_row(
                [
                    head_user_id,
                    clean_uname,
                    clean_email,
                    pw_hash,
                    ROLE_COMPANY_HEAD,
                    company_id,
                    clean_fname,
                    "active",
                    now_str,
                ],
                value_input_option="RAW",
                table_range="A1",
            )
        )
        fetch_all_companies.clear()
        clear_users_cache_fn()

    return True, f"Registered '{clean_co}' and assigned '{clean_fname}' ({clean_uname}) as Company Head."


def assign_existing_user_as_head(
    spreadsheet: gspread.Spreadsheet,
    company_id: str,
    target_user_id: str,
    clear_users_cache_fn: Callable[[], None],
) -> Tuple[bool, str]:
    """Admin-only: Assign an existing user as Company Head of a company."""
    with _ORG_LOCK:
        ensure_org_worksheets(spreadsheet)
        u_ws = spreadsheet.worksheet(USERS_WORKSHEET)
        u_rows = _retry_sheets(u_ws.get_all_values)
        if len(u_rows) <= 1:
            return False, "No users found."

        found_row_idx = None
        target_name = ""
        for idx, r in enumerate(u_rows[1:], start=2):
            if len(r) >= 2 and r[0] == target_user_id:
                found_row_idx = idx
                target_name = r[1]
                break

        if found_row_idx is None:
            return False, "Selected user not found."

        _retry_sheets(
            lambda: u_ws.update(
                values=[[ROLE_COMPANY_HEAD, company_id, "active"]],
                range_name=f"E{found_row_idx}:H{found_row_idx}",
                value_input_option="RAW",
            )
        )

        c_ws = spreadsheet.worksheet(COMPANIES_WORKSHEET)
        c_rows = _retry_sheets(c_ws.get_all_values)
        for idx, r in enumerate(c_rows[1:], start=2):
            if len(r) >= 1 and r[0] == company_id:
                _retry_sheets(
                    lambda: c_ws.update(
                        values=[[target_user_id]],
                        range_name=f"E{idx}",
                        value_input_option="RAW",
                    )
                )
                break

        fetch_all_companies.clear()
        clear_users_cache_fn()

    return True, f"Assigned '{target_name}' as Company Head."


def create_company_employee(
    spreadsheet: gspread.Spreadsheet,
    company_id: str,
    emp_full_name: str,
    emp_username: str,
    emp_email: str,
    emp_password: str,
    clear_users_cache_fn: Callable[[], None],
) -> Tuple[bool, str]:
    """Company Head (Boss): Create and assign an Employee under their company."""
    if not company_id:
        return False, "Your account is not linked to a company."

    clean_fname = _clean_str(emp_full_name, 100)
    clean_uname = _clean_str(emp_username, 30)
    clean_email = _clean_str(emp_email, 160).lower()

    if not clean_fname:
        return False, "Please enter the employee's full name."
    if not _is_valid_username(clean_uname):
        return False, "Employee username must be 3-30 characters (letters, numbers, _ . -)."
    if not _is_valid_email(clean_email):
        return False, "Please enter a valid employee email address."

    pw_ok, pw_msg = _validate_pw(emp_password)
    if not pw_ok:
        return False, pw_msg

    with _ORG_LOCK:
        ensure_org_worksheets(spreadsheet)
        u_ws = spreadsheet.worksheet(USERS_WORKSHEET)
        u_rows = _retry_sheets(u_ws.get_all_values)
        headers = u_rows[0] if u_rows else EXTENDED_USER_HEADERS
        for r in u_rows[1:]:
            if not any(c.strip() for c in r):
                continue
            padded = r + [""] * (len(headers) - len(r))
            rec = dict(zip(headers, padded))
            if rec.get("username", "").strip().lower() == clean_uname.lower():
                return False, f"Username '{clean_uname}' is already taken."
            if rec.get("email", "").strip().lower() == clean_email:
                return False, f"Email '{clean_email}' is already registered."

        emp_user_id = f"usr_{uuid.uuid4().hex[:12]}"
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        pw_hash = _hash_pw(emp_password)

        _retry_sheets(
            lambda: u_ws.append_row(
                [
                    emp_user_id,
                    clean_uname,
                    clean_email,
                    pw_hash,
                    ROLE_EMPLOYEE,
                    company_id,
                    clean_fname,
                    "active",
                    now_str,
                ],
                value_input_option="RAW",
                table_range="A1",
            )
        )
        clear_users_cache_fn()

    return True, f"Created employee '{clean_fname}' ({clean_uname}) under your company."


def update_member_status(
    spreadsheet: gspread.Spreadsheet,
    target_user_id: str,
    new_status: str,
    expected_company_id: Optional[str],
    clear_users_cache_fn: Callable[[], None],
    revoke_sessions_fn: Callable[[str], int],
) -> Tuple[bool, str]:
    """Enable or disable a company employee (revoking active sessions when disabled)."""
    clean_status = "disabled" if new_status.lower() == "disabled" else "active"
    with _ORG_LOCK:
        u_ws = spreadsheet.worksheet(USERS_WORKSHEET)
        u_rows = _retry_sheets(u_ws.get_all_values)
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
                _retry_sheets(
                    lambda: u_ws.update(
                        values=[[clean_status]],
                        range_name=f"H{idx}",
                        value_input_option="RAW",
                    )
                )
                clear_users_cache_fn()
                if clean_status == "disabled":
                    revoke_sessions_fn(target_user_id)
                return True, f"Updated '{rec.get('username')}' status to {clean_status}."
    return False, "User not found."


def render_admin_console(
    spreadsheet: gspread.Spreadsheet,
    all_users: list[dict[str, str]],
    clear_users_cache_fn: Callable[[], None],
) -> None:
    """Platform Admin Console: Register Companies & Assign Company Heads (Bosses)."""
    st.session_state["_org_spreadsheet_ref"] = spreadsheet
    ensure_org_worksheets(spreadsheet)
    companies = fetch_all_companies(spreadsheet.id)

    with st.container(border=True):
        st.subheader("Platform Admin — Company & Boss Management")
        st.caption(
            "Only Platform Admins can register companies and assign a Company Head (Boss). "
            "Public self-registered accounts start as Normal Users without CRM access."
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

        tab_new_co, tab_co_list, tab_promote = st.tabs(
            [
                "Register New Company + Boss",
                f"Registered Companies ({len(companies)})",
                "Assign Existing User as Boss",
            ]
        )

        with tab_new_co:
            with st.form("admin_create_company_form"):
                c1, c2 = st.columns(2)
                with c1:
                    co_name = st.text_input(
                        "Company Name *", placeholder="e.g., R.H. Enterprise"
                    )
                    co_industry = st.text_input(
                        "Industry", placeholder="e.g., Industrial Automation & Gearboxes"
                    )
                    co_city = st.text_input("City", placeholder="e.g., Ahmedabad")
                with c2:
                    boss_name = st.text_input(
                        "Company Head (Boss) Full Name *", placeholder="e.g., Rajesh Patel"
                    )
                    boss_username = st.text_input(
                        "Boss Login Username *", placeholder="e.g., rh_boss"
                    )
                    boss_email = st.text_input(
                        "Boss Email *", placeholder="boss@company.com"
                    )
                    boss_pw = st.text_input(
                        "Initial Password *",
                        type="password",
                        placeholder="Min 8 chars, 1 upper, 1 lower, 1 digit",
                    )

                if st.form_submit_button(
                    "Register Company & Create Boss Login",
                    type="primary",
                    use_container_width=True,
                ):
                    ok, msg = create_company_with_head(
                        spreadsheet=spreadsheet,
                        company_name=co_name,
                        industry=co_industry,
                        city=co_city,
                        head_full_name=boss_name,
                        head_username=boss_username,
                        head_email=boss_email,
                        head_password=boss_pw,
                        clear_users_cache_fn=clear_users_cache_fn,
                    )
                    if ok:
                        st.session_state["flash_success"] = msg
                        st.rerun()
                    else:
                        st.error(msg)

        with tab_co_list:
            if not companies:
                st.info("No companies registered yet.")
            else:
                user_lookup = {u["user_id"]: u for u in all_users}
                rows_disp = []
                for co in companies:
                    cid = co.get("company_id", "")
                    head = user_lookup.get(co.get("head_user_id", ""), {})
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
                            "Company Head": f"{head.get('full_name') or head.get('username', 'N/A')} ({head.get('email', 'N/A')})",
                            "Employees": emp_cnt,
                            "Status": co.get("status", "active"),
                            "Created On": co.get("created_at", ""),
                        }
                    )
                st.dataframe(pd.DataFrame(rows_disp), use_container_width=True, hide_index=True)

        with tab_promote:
            if not companies:
                st.info("Register a company first before assigning a Company Head.")
            else:
                non_admins = [
                    u
                    for u in all_users
                    if normalize_role(u.get("role"), u.get("email", "")) != ROLE_ADMIN
                ]
                if not non_admins:
                    st.info("No non-admin users available.")
                else:
                    co_opts = {
                        f"{c['company_name']} ({c['city']}) [{c['company_id']}]": c["company_id"]
                        for c in companies
                    }
                    usr_opts = {
                        f"{u.get('full_name') or u['username']} — {u['email']} (Current: {get_role_badge_label(u.get('role', ROLE_USER))})": u["user_id"]
                        for u in non_admins
                    }
                    sel_co = st.selectbox("Select Company", options=list(co_opts.keys()), key="adm_prom_co")
                    sel_usr = st.selectbox("Select User to Make Company Head", options=list(usr_opts.keys()), key="adm_prom_usr")
                    if st.button("Assign as Company Head", type="primary", key="btn_adm_assign_head"):
                        ok, msg = assign_existing_user_as_head(
                            spreadsheet=spreadsheet,
                            company_id=co_opts[sel_co],
                            target_user_id=usr_opts[sel_usr],
                            clear_users_cache_fn=clear_users_cache_fn,
                        )
                        if ok:
                            st.session_state["flash_success"] = msg
                            st.rerun()
                        else:
                            st.error(msg)


def render_team_management_section(
    spreadsheet: gspread.Spreadsheet,
    current_user: dict[str, str],
    all_users: list[dict[str, str]],
    clear_users_cache_fn: Callable[[], None],
    revoke_sessions_fn: Callable[[str], int],
) -> None:
    """Company Head (Boss) Console: Add Employees & Manage Company Team."""
    company_id = str(current_user.get("company_id", "")).strip()
    co_info = get_company_by_id(spreadsheet, company_id)
    co_title = co_info.get("company_name", "Your Company") if co_info else "Your Company"

    with st.container(border=True):
        st.subheader(f"My Team — {co_title}")
        st.caption(
            "As Company Head, you can create employee logins under your company, assign leads/deals to them in CRM, "
            "and activate or disable access."
        )

        members = get_company_members(all_users, company_id, include_disabled=True)
        employees = [m for m in members if m.get("role") == ROLE_EMPLOYEE]

        t1, t2 = st.tabs([f"Team Members ({len(members)})", "Add New Employee"])

        with t1:
            if not members:
                st.info("No team members found.")
            else:
                team_rows = []
                for m in members:
                    team_rows.append(
                        {
                            "Full Name": m.get("full_name") or m.get("username", ""),
                            "Username": m.get("username", ""),
                            "Email": m.get("email", ""),
                            "Role": get_role_badge_label(m.get("role", ROLE_EMPLOYEE)),
                            "Status": m.get("status", "active").title(),
                            "Joined": m.get("created_at", ""),
                        }
                    )
                st.dataframe(pd.DataFrame(team_rows), use_container_width=True, hide_index=True)

                if employees:
                    st.divider()
                    st.markdown("#### Activate / Disable Employee Access")
                    emp_opts = {
                        f"{e.get('full_name') or e['username']} ({e['email']}) — {e.get('status', 'active').title()}": e
                        for e in employees
                    }
                    chosen_emp_lbl = st.selectbox(
                        "Select Employee", options=list(emp_opts.keys()), key="boss_manage_emp_sel"
                    )
                    chosen_emp = emp_opts[chosen_emp_lbl]
                    curr_stat = chosen_emp.get("status", "active").lower()
                    target_stat = "disabled" if curr_stat == "active" else "active"
                    btn_txt = (
                        "Disable Employee Login"
                        if curr_stat == "active"
                        else "Re-Activate Employee Login"
                    )
                    if st.button(btn_txt, type="secondary", key="btn_boss_toggle_emp"):
                        ok, msg = update_member_status(
                            spreadsheet=spreadsheet,
                            target_user_id=chosen_emp["user_id"],
                            new_status=target_stat,
                            expected_company_id=company_id,
                            clear_users_cache_fn=clear_users_cache_fn,
                            revoke_sessions_fn=revoke_sessions_fn,
                        )
                        if ok:
                            st.session_state["flash_success"] = msg
                            st.rerun()
                        else:
                            st.error(msg)

        with t2:
            with st.form("boss_add_employee_form"):
                e1, e2 = st.columns(2)
                with e1:
                    emp_fname = st.text_input(
                        "Employee Full Name *", placeholder="e.g., Amit Shah"
                    )
                    emp_uname = st.text_input(
                        "Employee Login Username *", placeholder="e.g., amit_sales"
                    )
                with e2:
                    emp_email = st.text_input(
                        "Employee Email *", placeholder="amit@company.com"
                    )
                    emp_pw = st.text_input(
                        "Initial Password *",
                        type="password",
                        placeholder="Min 8 chars, 1 upper, 1 lower, 1 digit",
                    )

                if st.form_submit_button(
                    "Create & Assign Employee",
                    type="primary",
                    use_container_width=True,
                ):
                    ok, msg = create_company_employee(
                        spreadsheet=spreadsheet,
                        company_id=company_id,
                        emp_full_name=emp_fname,
                        emp_username=emp_uname,
                        emp_email=emp_email,
                        emp_password=emp_pw,
                        clear_users_cache_fn=clear_users_cache_fn,
                    )
                    if ok:
                        st.session_state["flash_success"] = msg
                        st.rerun()
                    else:
                        st.error(msg)