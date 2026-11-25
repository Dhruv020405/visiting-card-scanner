import html
import re
import threading
import time
import uuid
from datetime import date, datetime, timedelta
from typing import Any, Callable, Optional, Tuple, TypeVar
from urllib.parse import quote

import gspread
import pandas as pd
import streamlit as st
from gspread.exceptions import APIError as GSpreadAPIError

from rbac_org import (
    ROLE_ADMIN,
    ROLE_COMPANY_HEAD,
    ROLE_EMPLOYEE,
    ROLE_USER,
    can_access_crm,
    get_company_by_id,
    get_company_members,
    get_role_badge_label,
    normalize_role,
)

CRM_PIPELINE_WORKSHEET = "crm_pipeline"
CRM_ACTIVITIES_WORKSHEET = "crm_activities"

CRM_PIPELINE_HEADERS = [
    "record_id",
    "user_id",
    "company_id",
    "assigned_to",
    "lead_stage",
    "priority",
    "deal_value",
    "next_followup",
    "lead_source",
    "expected_close",
    "updated_at",
]

CRM_ACTIVITY_HEADERS = [
    "activity_id",
    "user_id",
    "company_id",
    "record_id",
    "activity_type",
    "summary",
    "stage_after",
    "next_followup",
    "logged_by_name",
    "created_at",
]

CRM_STAGES = [
    "New Lead",
    "Contacted",
    "Follow-Up Needed",
    "Quote Sent",
    "Negotiation",
    "Won",
    "Lost",
]

STAGE_WIN_PROBABILITY: dict[str, float] = {
    "New Lead": 0.10,
    "Contacted": 0.20,
    "Follow-Up Needed": 0.35,
    "Quote Sent": 0.55,
    "Negotiation": 0.80,
    "Won": 1.00,
    "Lost": 0.00,
}

STAGE_COLORS: dict[str, str] = {
    "New Lead": "#6366f1",
    "Contacted": "#0ea5e9",
    "Follow-Up Needed": "#f59e0b",
    "Quote Sent": "#8b5cf6",
    "Negotiation": "#ec4899",
    "Won": "#16a34a",
    "Lost": "#64748b",
}

CRM_PRIORITIES = ["Hot", "Warm", "Cold"]
PRIORITY_COLORS: dict[str, str] = {"Hot": "#dc2626", "Warm": "#d97706", "Cold": "#0284c7"}

CRM_SOURCES = [
    "Visiting Card Scan",
    "Trade Fair / Expo",
    "Referral",
    "Walk-In",
    "Website / Inquiry",
    "Cold Outreach",
    "Other",
]

ACTIVITY_TYPES = [
    "Phone Call",
    "WhatsApp Chat",
    "Email Sent",
    "Meeting / Visit",
    "Quote Shared",
    "Lead Assigned",
    "Stage Updated",
    "Note",
]

_CRM_LOCK = threading.Lock()
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


def format_inr(amount: float) -> str:
    try:
        val = int(round(float(amount)))
    except Exception:
        val = 0
    neg = val < 0
    s = str(abs(val))
    if len(s) > 3:
        last3 = s[-3:]
        rest = s[:-3]
        groups = []
        while len(rest) > 2:
            groups.append(rest[-2:])
            rest = rest[:-2]
        if rest:
            groups.append(rest)
        formatted = ",".join(reversed(groups)) + "," + last3
    else:
        formatted = s
    return f"{'-' if neg else ''}₹{formatted}"


def _parse_deal_value(raw: Any) -> float:
    try:
        cleaned = re.sub(r"[^\d.\-]", "", str(raw or "0"))
        return max(0.0, float(cleaned)) if cleaned else 0.0
    except Exception:
        return 0.0


def _normalize_company_key(company_name: str) -> str:
    raw = str(company_name or "").strip().lower()
    if not raw or raw == "n/a":
        return ""
    cleaned = re.sub(
        r"\b(pvt|private|ltd|limited|llp|inc|corp|co|company|enterprises|enterprise|industries|solutions|traders|trading)\b\.?",
        "",
        raw,
    )
    cleaned = re.sub(r"[^a-z0-9]+", " ", cleaned).strip()
    return cleaned or raw


def _parse_emails(raw_email: str) -> list[str]:
    if not raw_email or str(raw_email).strip().upper() == "N/A":
        return []
    out: list[str] = []
    seen: set[str] = set()
    for part in re.split(r"[,;/\|\s]+", str(raw_email).strip()):
        em = part.strip().lower()
        if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", em) and em not in seen:
            seen.add(em)
            out.append(em)
    return out


def _get_or_init_ws(
    spreadsheet: gspread.Spreadsheet, title: str, headers: list[str]
) -> gspread.Worksheet:
    try:
        ws = spreadsheet.worksheet(title)
    except gspread.WorksheetNotFound:
        ws = spreadsheet.add_worksheet(title=title, rows=500, cols=len(headers))
        _retry_sheets(lambda: ws.append_row(headers, value_input_option="RAW"))
        return ws

    all_rows = _retry_sheets(ws.get_all_values)
    if not all_rows:
        if ws.col_count < len(headers):
            ws.resize(cols=len(headers))
        _retry_sheets(lambda: ws.append_row(headers, value_input_option="RAW"))
        return ws

    current_headers = [h.strip() for h in all_rows[0] if h.strip()]
    if current_headers != headers:
        if ws.col_count < len(headers):
            ws.resize(cols=len(headers))
        migrated = [headers]
        for row in all_rows[1:]:
            if not any(c.strip() for c in row):
                continue
            padded = row + [""] * (len(current_headers) - len(row))
            rec = dict(zip(current_headers, padded))
            migrated.append([rec.get(col, "") for col in headers])
        _retry_sheets(
            lambda: ws.update(values=migrated, range_name="A1", value_input_option="RAW")
        )
    return ws


@st.cache_data(ttl=60, show_spinner=False)
def _fetch_pipeline_rows(
    _spreadsheet_id: str, scope_key: str, company_id: str, user_id: str, role: str
) -> dict[str, dict[str, str]]:
    ss = st.session_state["_crm_spreadsheet_ref"]
    ws = _get_or_init_ws(ss, CRM_PIPELINE_WORKSHEET, CRM_PIPELINE_HEADERS)
    rows = _retry_sheets(ws.get_all_values)
    result: dict[str, dict[str, str]] = {}
    if len(rows) <= 1:
        return result
    headers = rows[0]
    for row in rows[1:]:
        if not any(c.strip() for c in row):
            continue
        padded = row + [""] * (len(headers) - len(row))
        rec = dict(zip(headers, padded))
        rid = rec.get("record_id", "")
        if not rid:
            continue
        if role == ROLE_ADMIN:
            result[rid] = rec
        elif company_id and rec.get("company_id") == company_id:
            result[rid] = rec
        elif not rec.get("company_id") and rec.get("user_id") == user_id:
            result[rid] = rec
    return result


@st.cache_data(ttl=60, show_spinner=False)
def _fetch_activity_rows(
    _spreadsheet_id: str, scope_key: str, company_id: str, user_id: str, role: str
) -> list[dict[str, str]]:
    ss = st.session_state["_crm_spreadsheet_ref"]
    ws = _get_or_init_ws(ss, CRM_ACTIVITIES_WORKSHEET, CRM_ACTIVITY_HEADERS)
    rows = _retry_sheets(ws.get_all_values)
    if len(rows) <= 1:
        return []
    headers = rows[0]
    out: list[dict[str, str]] = []
    for row in rows[1:]:
        if not any(c.strip() for c in row):
            continue
        padded = row + [""] * (len(headers) - len(row))
        rec = dict(zip(headers, padded))
        if role == ROLE_ADMIN:
            out.append(rec)
        elif company_id and rec.get("company_id") == company_id:
            out.append(rec)
        elif not rec.get("company_id") and rec.get("user_id") == user_id:
            out.append(rec)
    return out[::-1]


def get_crm_due_summary(
    spreadsheet: gspread.Spreadsheet,
    all_records_df: pd.DataFrame,
    current_user: dict[str, str],
) -> Tuple[int, int, float]:
    if not can_access_crm(current_user) or all_records_df.empty:
        return 0, 0, 0.0

    user_id = str(current_user.get("user_id", ""))
    company_id = str(current_user.get("company_id", ""))
    role = normalize_role(current_user.get("role", ROLE_USER), current_user.get("email", ""))
    scope_key = f"{role}:{company_id}:{user_id}"

    st.session_state["_crm_spreadsheet_ref"] = spreadsheet
    try:
        pipeline_map = _fetch_pipeline_rows(
            spreadsheet.id, scope_key, company_id, user_id, role
        )
    except Exception:
        return 0, 0, 0.0

    today_str = date.today().strftime("%Y-%m-%d")
    overdue = 0
    due_today = 0
    open_val = 0.0

    for _, r in all_records_df.iterrows():
        rid = str(r["Record ID"])
        meta = pipeline_map.get(rid, {})
        assignee = str(meta.get("assigned_to") or r.get("Assigned To") or user_id).strip()
        if role == ROLE_EMPLOYEE and assignee not in (user_id, ""):
            continue
        stage = meta.get("lead_stage") if meta.get("lead_stage") in CRM_STAGES else "New Lead"
        if stage in ("Won", "Lost"):
            continue
        open_val += _parse_deal_value(meta.get("deal_value", 0))
        fu = str(meta.get("next_followup", "")).strip()
        if fu:
            if fu < today_str:
                overdue += 1
            elif fu == today_str:
                due_today += 1
    return overdue, due_today, open_val


def upsert_crm_pipeline(
    spreadsheet: gspread.Spreadsheet,
    user_id: str,
    company_id: str,
    assigned_to: str,
    record_id: str,
    lead_stage: str,
    priority: str,
    deal_value: float,
    next_followup: str,
    lead_source: str,
    expected_close: str = "",
) -> None:
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    clean_val = str(int(round(max(0.0, float(deal_value)))))
    clean_stage = lead_stage if lead_stage in CRM_STAGES else "New Lead"
    clean_prio = priority if priority in CRM_PRIORITIES else "Warm"
    clean_assignee = assigned_to.strip() or user_id

    new_row = [
        record_id,
        user_id,
        company_id.strip(),
        clean_assignee,
        clean_stage,
        clean_prio,
        clean_val,
        next_followup.strip(),
        lead_source.strip() or "Visiting Card Scan",
        expected_close.strip(),
        now_str,
    ]
    with _CRM_LOCK:
        ws = _get_or_init_ws(spreadsheet, CRM_PIPELINE_WORKSHEET, CRM_PIPELINE_HEADERS)
        rows = _retry_sheets(ws.get_all_values)
        for idx, row in enumerate(rows[1:], start=2):
            if len(row) >= 1 and row[0] == record_id:
                _retry_sheets(
                    lambda: ws.update(
                        values=[new_row],
                        range_name=f"A{idx}:K{idx}",
                        value_input_option="RAW",
                    )
                )
                _fetch_pipeline_rows.clear()
                return
        _retry_sheets(
            lambda: ws.append_row(new_row, value_input_option="RAW", table_range="A1")
        )
        _fetch_pipeline_rows.clear()


def log_crm_activity(
    spreadsheet: gspread.Spreadsheet,
    user_id: str,
    company_id: str,
    assigned_to: str,
    logged_by_name: str,
    record_id: str,
    activity_type: str,
    summary: str,
    new_stage: str,
    priority: str,
    deal_value: float,
    next_followup_str: str,
    lead_source: str,
    expected_close: str = "",
) -> None:
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    act_id = f"act_{uuid.uuid4().hex[:10]}"
    clean_summary = str(summary or "").replace("\x00", "").strip()[:300]

    with _CRM_LOCK:
        act_ws = _get_or_init_ws(
            spreadsheet, CRM_ACTIVITIES_WORKSHEET, CRM_ACTIVITY_HEADERS
        )
        _retry_sheets(
            lambda: act_ws.append_row(
                [
                    act_id,
                    user_id,
                    company_id.strip(),
                    record_id,
                    activity_type,
                    clean_summary,
                    new_stage,
                    next_followup_str,
                    logged_by_name,
                    now_str,
                ],
                value_input_option="RAW",
                table_range="A1",
            )
        )
        _fetch_activity_rows.clear()

    upsert_crm_pipeline(
        spreadsheet=spreadsheet,
        user_id=user_id,
        company_id=company_id,
        assigned_to=assigned_to,
        record_id=record_id,
        lead_stage=new_stage,
        priority=priority,
        deal_value=deal_value,
        next_followup=next_followup_str,
        lead_source=lead_source,
        expected_close=expected_close,
    )


def _extract_wa_and_tel(wp_str: str, call_str: str) -> Tuple[list[Tuple[str, str]], str]:
    wa_pairs: list[Tuple[str, str]] = []
    seen_wa: set[str] = set()
    tel_digits = ""

    for raw in (wp_str, call_str):
        if not raw or str(raw).strip().upper() == "N/A":
            continue
        for part in str(raw).split(" / "):
            disp = part.strip()
            digits = re.sub(r"\D", "", disp)
            if not digits:
                continue
            if not tel_digits and len(digits) >= 7:
                tel_digits = digits
            if raw == wp_str or not wa_pairs:
                if len(digits) == 10 and digits[0] in "6789":
                    dial = f"91{digits}"
                elif len(digits) >= 10:
                    dial = digits
                else:
                    continue
                if dial not in seen_wa:
                    seen_wa.add(dial)
                    wa_pairs.append((disp, dial))
    return wa_pairs, tel_digits


def _inject_crm_css() -> None:
    st.markdown(
        """
        <style>
            .crm-card {
                padding: 0.85rem 1rem;
                border-radius: 10px;
                border: 1px solid rgba(128, 128, 128, 0.22);
                background: rgba(128, 128, 128, 0.04);
                margin-bottom: 0.6rem;
            }
            .crm-pill {
                display: inline-block;
                padding: 0.14rem 0.55rem;
                border-radius: 999px;
                font-size: 0.74rem;
                font-weight: 600;
                color: #ffffff;
                margin-right: 0.35rem;
                vertical-align: middle;
            }
            .crm-owner-pill {
                display: inline-block;
                padding: 0.12rem 0.5rem;
                border-radius: 6px;
                font-size: 0.74rem;
                font-weight: 600;
                background: rgba(99, 102, 241, 0.16);
                color: #6366f1;
                margin-left: 0.35rem;
            }
            .crm-stage-header {
                padding: 0.5rem 0.75rem;
                border-radius: 8px;
                color: #ffffff;
                font-weight: 600;
                font-size: 0.88rem;
                margin-bottom: 0.55rem;
            }
            .crm-board-item {
                padding: 0.65rem 0.75rem;
                border-radius: 8px;
                border: 1px solid rgba(128, 128, 128, 0.24);
                background: rgba(128, 128, 128, 0.05);
                margin-bottom: 0.5rem;
                font-size: 0.86rem;
            }
            .crm-btn-link {
                display: inline-block;
                padding: 0.34rem 0.75rem;
                border-radius: 6px;
                text-decoration: none !important;
                font-size: 0.82rem;
                font-weight: 600;
                margin-right: 0.4rem;
                margin-top: 0.38rem;
            }
            .crm-btn-wa { background: #16a34a; color: #ffffff !important; }
            .crm-btn-gmail { background: #dc2626; color: #ffffff !important; }
            .crm-btn-call { background: #0284c7; color: #ffffff !important; }
            .crm-timeline-item {
                padding: 0.65rem 0.85rem;
                border-left: 3px solid #6366f1;
                background: rgba(128, 128, 128, 0.04);
                border-radius: 0 8px 8px 0;
                margin-bottom: 0.5rem;
            }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _build_quick_action_links(row_like: Any, msg_text: str, subject_text: str) -> str:
    wa_pairs, tel_digits = _extract_wa_and_tel(
        str(row_like["WhatsApp No."]), str(row_like["Contact No."])
    )
    emails = _parse_emails(str(row_like["Email"]))
    links = ""
    for idx, (disp, wa_dial) in enumerate(wa_pairs, start=1):
        wa_href = html.escape(
            f"https://wa.me/{wa_dial}?text={quote(msg_text)}", quote=True
        )
        lbl = f"WhatsApp #{idx}" if len(wa_pairs) > 1 else "WhatsApp"
        links += (
            f'<a class="crm-btn-link crm-btn-wa" href="{wa_href}" '
            f'target="_blank" rel="noopener noreferrer">{lbl} ({html.escape(disp)})</a>'
        )
    if emails:
        joined_em = ",".join(emails)
        gmail_href = html.escape(
            f"https://mail.google.com/mail/?view=cm&fs=1&to={quote(joined_em)}"
            f"&su={quote(subject_text)}&body={quote(msg_text)}",
            quote=True,
        )
        links += (
            f'<a class="crm-btn-link crm-btn-gmail" href="{gmail_href}" '
            f'target="_blank" rel="noopener noreferrer">Gmail ({html.escape(" / ".join(emails))})</a>'
        )
    if tel_digits:
        links += (
            f'<a class="crm-btn-link crm-btn-call" href="tel:{html.escape(tel_digits, quote=True)}">'
            f"Call ({html.escape(tel_digits)})</a>"
        )
    return links


def render_crm_section(
    spreadsheet: gspread.Spreadsheet,
    all_records_df: pd.DataFrame,
    current_user: dict[str, str],
    all_users: list[dict[str, str]],
    build_multi_sheet_excel_fn: Callable[[dict[str, pd.DataFrame]], bytes],
    assign_card_owner_fn: Optional[Callable[[str, str], bool]] = None,
) -> None:
    """Role-Aware Company CRM Workspace (Company Head + Employees; blocked for Normal Users)."""
    if not can_access_crm(current_user):
        st.error(
            "CRM access is restricted to Company Heads and Employees. "
            "Contact your Platform Admin to register your company."
        )
        return

    _inject_crm_css()
    st.session_state["_crm_spreadsheet_ref"] = spreadsheet

    current_user_id = str(current_user.get("user_id", ""))
    current_username = str(current_user.get("username", ""))
    current_full_name = str(current_user.get("full_name") or current_username)
    company_id = str(current_user.get("company_id", "")).strip()
    role = normalize_role(current_user.get("role", ROLE_USER), current_user.get("email", ""))
    is_boss = role in (ROLE_COMPANY_HEAD, ROLE_ADMIN)

    co_info = get_company_by_id(spreadsheet, company_id)
    co_name_banner = (
        co_info.get("company_name", "Company CRM")
        if co_info
        else ("All Companies (Admin View)" if role == ROLE_ADMIN else "Company CRM")
    )

    team_members = get_company_members(all_users, company_id, include_disabled=False)
    if not team_members:
        team_members = [current_user]
    member_id_to_label: dict[str, str] = {}
    for m in team_members:
        uid = str(m.get("user_id", ""))
        disp = f"{m.get('full_name') or m.get('username')} ({get_role_badge_label(m.get('role', ROLE_EMPLOYEE))})"
        member_id_to_label[uid] = disp
    if current_user_id not in member_id_to_label:
        member_id_to_label[current_user_id] = f"{current_full_name} ({get_role_badge_label(role)})"

    with st.container(border=True):
        hdr_c1, hdr_c2, hdr_c3 = st.columns([3.4, 1.0, 1.4])
        with hdr_c1:
            st.subheader(f"CRM Workspace — {co_name_banner}")
            st.caption(
                f"Signed in as **{current_full_name}** ({get_role_badge_label(role)}) · "
                + (
                    "Full company-wide pipeline, employee assignment & revenue analytics."
                    if is_boss
                    else "Your assigned company leads, follow-ups & interaction logs."
                )
            )
        with hdr_c2:
            if st.button("Refresh CRM", use_container_width=True, key="btn_crm_refresh"):
                _fetch_pipeline_rows.clear()
                _fetch_activity_rows.clear()
                st.rerun()

        if all_records_df.empty:
            st.info(
                "Add or import at least one visiting card first to unlock your company's CRM pipeline."
            )
            return

        scope_key = f"{role}:{company_id}:{current_user_id}"
        pipeline_map = _fetch_pipeline_rows(
            spreadsheet.id, scope_key, company_id, current_user_id, role
        )
        activities = _fetch_activity_rows(
            spreadsheet.id, scope_key, company_id, current_user_id, role
        )
        today_str = date.today().strftime("%Y-%m-%d")

        crm_rows: list[dict[str, Any]] = []
        for _, r in all_records_df.iterrows():
            rid = str(r["Record ID"])
            meta = pipeline_map.get(rid, {})
            default_owner = str(r.get("Assigned To") or r.get("User ID") or current_user_id).strip()
            assigned_uid = str(meta.get("assigned_to") or default_owner or current_user_id).strip()

            if role == ROLE_EMPLOYEE and assigned_uid not in (current_user_id, ""):
                continue

            stage = (
                meta.get("lead_stage")
                if meta.get("lead_stage") in CRM_STAGES
                else "New Lead"
            )
            prio = (
                meta.get("priority")
                if meta.get("priority") in CRM_PRIORITIES
                else "Warm"
            )
            val = _parse_deal_value(meta.get("deal_value", 0))
            fu_date = str(meta.get("next_followup", "")).strip()
            exp_close = str(meta.get("expected_close", "")).strip()
            source = str(meta.get("lead_source", "")).strip() or "Visiting Card Scan"
            prob = STAGE_WIN_PROBABILITY.get(stage, 0.10)

            due_status = "None"
            if fu_date and stage not in ("Won", "Lost"):
                if fu_date < today_str:
                    due_status = "Overdue"
                elif fu_date == today_str:
                    due_status = "Due Today"
                else:
                    due_status = "Upcoming"

            co_name = str(r["Company Name"])
            owner_label = member_id_to_label.get(assigned_uid, "Unassigned")
            crm_rows.append(
                {
                    "Record ID": rid,
                    "Company Name": co_name,
                    "Company Key": _normalize_company_key(co_name),
                    "Contact Person": str(r["Contact Person"]),
                    "WhatsApp No.": str(r["WhatsApp No."]),
                    "Contact No.": str(r["Contact No."]),
                    "Email": str(r["Email"]),
                    "City": str(r["City"]),
                    "Product / Services": str(r["Product / Services"]),
                    "Address": str(r["Address"]),
                    "Notes": str(r["Notes"]),
                    "Assigned To": assigned_uid,
                    "Owner Name": owner_label,
                    "Stage": stage,
                    "Priority": prio,
                    "Deal Value": val,
                    "Weighted Value": val * prob,
                    "Next Follow-Up": fu_date,
                    "Expected Close": exp_close,
                    "Due Status": due_status,
                    "Lead Source": source,
                }
            )

        if not crm_rows:
            st.info("No deals assigned to you yet.")
            return

        crm_df = pd.DataFrame(crm_rows)

        account_rows: list[dict[str, Any]] = []
        valid_co_df = crm_df[crm_df["Company Key"] != ""]
        for _, grp in valid_co_df.groupby("Company Key", sort=False):
            display_co = grp["Company Name"].iloc[0]
            contacts_list = [
                p for p in grp["Contact Person"].tolist() if p and p.upper() != "N/A"
            ]
            cities_list = sorted(
                {c for c in grp["City"].tolist() if c and c.upper() != "N/A"}
            )
            open_grp = grp[~grp["Stage"].isin(["Won", "Lost"])]
            won_grp = grp[grp["Stage"] == "Won"]
            account_rows.append(
                {
                    "Company Account": display_co,
                    "Contacts": len(grp),
                    "Decision Makers": ", ".join(contacts_list[:4]) or "N/A",
                    "Cities": ", ".join(cities_list) or "N/A",
                    "Open Deals": len(open_grp),
                    "Open Pipeline": float(open_grp["Deal Value"].sum()),
                    "Won Revenue": float(won_grp["Deal Value"].sum()),
                    "Top Priority": (
                        "Hot"
                        if "Hot" in grp["Priority"].values
                        else ("Warm" if "Warm" in grp["Priority"].values else "Cold")
                    ),
                }
            )
        accounts_df = (
            pd.DataFrame(account_rows).sort_values(
                by=["Open Pipeline", "Contacts"], ascending=[False, False]
            )
            if account_rows
            else pd.DataFrame()
        )

        with hdr_c3:
            exp_deals = crm_df[
                [
                    "Company Name",
                    "Contact Person",
                    "Owner Name",
                    "Stage",
                    "Priority",
                    "Deal Value",
                    "Next Follow-Up",
                    "Expected Close",
                    "Lead Source",
                    "WhatsApp No.",
                    "Contact No.",
                    "Email",
                    "City",
                ]
            ].copy()
            exp_deals["Deal Value (INR)"] = exp_deals["Deal Value"].map(format_inr)
            exp_deals = exp_deals.drop(columns=["Deal Value"])

            sheets_to_export: dict[str, pd.DataFrame] = {"Pipeline Deals": exp_deals}
            if not accounts_df.empty:
                exp_accts = accounts_df.copy()
                exp_accts["Open Pipeline (INR)"] = exp_accts["Open Pipeline"].map(format_inr)
                exp_accts["Won Revenue (INR)"] = exp_accts["Won Revenue"].map(format_inr)
                exp_accts = exp_accts.drop(columns=["Open Pipeline", "Won Revenue"])
                sheets_to_export["Company Accounts"] = exp_accts

            if activities:
                id_to_co = {
                    str(r["Record ID"]): str(r["Company Name"])
                    for _, r in crm_df.iterrows()
                }
                sheets_to_export["Activity History"] = pd.DataFrame(
                    [
                        {
                            "Timestamp": a.get("created_at", ""),
                            "Logged By": a.get("logged_by_name", ""),
                            "Company": id_to_co.get(a.get("record_id", ""), "Company Card"),
                            "Activity": a.get("activity_type", ""),
                            "Summary": a.get("summary", ""),
                            "Stage": a.get("stage_after", ""),
                            "Next Follow-Up": a.get("next_followup", ""),
                        }
                        for a in activities
                    ]
                )

            st.download_button(
                label="Export CRM (.xlsx)",
                data=build_multi_sheet_excel_fn(sheets_to_export),
                file_name=f"company_crm_{current_username}_{datetime.now().strftime('%Y%m%d')}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                use_container_width=True,
                key="btn_export_full_crm_xlsx",
            )

        open_df = crm_df[~crm_df["Stage"].isin(["Won", "Lost"])]
        won_df = crm_df[crm_df["Stage"] == "Won"]
        closed_df = crm_df[crm_df["Stage"].isin(["Won", "Lost"])]
        win_rate = (
            round((len(won_df) / len(closed_df)) * 100) if len(closed_df) > 0 else 0
        )
        due_df = crm_df[crm_df["Due Status"].isin(["Overdue", "Due Today"])].sort_values(
            by=["Next Follow-Up", "Priority"]
        )

        m1, m2, m3, m4, m5, m6 = st.columns(6)
        with m1:
            st.metric("Open Deals", len(open_df))
        with m2:
            st.metric("Open Pipeline", format_inr(open_df["Deal Value"].sum()))
        with m3:
            st.metric("Weighted Forecast", format_inr(open_df["Weighted Value"].sum()))
        with m4:
            st.metric("Won Revenue", format_inr(won_df["Deal Value"].sum()))
        with m5:
            st.metric("Win Rate", f"{win_rate}%")
        with m6:
            st.metric("Due / Overdue", len(due_df))

        tab_names = [
            f"Action Queue ({len(due_df)})",
            "Pipeline Board",
            "360° Lead & Deal Workspace",
            f"Company Accounts ({len(accounts_df)})",
        ]
        if is_boss:
            tab_names.append("Team Performance")

        tabs = st.tabs(tab_names)
        tab_action, tab_board, tab_workspace, tab_accounts = tabs[:4]

        # ---- TAB 1: Action Queue ----
        with tab_action:
            hot_open_df = open_df[
                (open_df["Priority"] == "Hot")
                & (~open_df["Due Status"].isin(["Overdue", "Due Today"]))
            ]

            if due_df.empty and hot_open_df.empty:
                st.success("No overdue follow-ups today! Use **360° Lead & Deal Workspace** to schedule next actions.")
            else:
                if not due_df.empty:
                    st.markdown("#### Follow-Ups Due Today & Overdue")
                    for _, item in due_df.iterrows():
                        rid = item["Record ID"]
                        safe_co = html.escape(item["Company Name"], quote=True)
                        safe_person = html.escape(item["Contact Person"], quote=True)
                        safe_stage = html.escape(item["Stage"], quote=True)
                        safe_fu = html.escape(item["Next Follow-Up"], quote=True)
                        safe_owner = html.escape(item["Owner Name"], quote=True)
                        prio_col = PRIORITY_COLORS.get(item["Priority"], "#d97706")
                        border_col = "#dc2626" if item["Due Status"] == "Overdue" else "#f59e0b"

                        msg_text = (
                            f"Hello {item['Contact Person'] if item['Contact Person'] != 'N/A' else 'Sir/Madam'}, "
                            f"following up regarding {item['Company Name']} ({item['Product / Services']})."
                        )
                        links = _build_quick_action_links(
                            item, msg_text, f"Follow-up: {item['Company Name']}"
                        )

                        c_card, c_act1, c_act2 = st.columns([3.8, 1.0, 1.0])
                        with c_card:
                            st.markdown(
                                f"""
                                <div class="crm-card" style="border-left: 4px solid {border_col};">
                                    <span class="crm-pill" style="background:{prio_col};">{html.escape(item['Priority'])}</span>
                                    <strong>{safe_co}</strong> · {safe_person}
                                    <span class="crm-owner-pill">{safe_owner}</span>
                                    <span style="color:{border_col};font-weight:600;font-size:0.82rem;">
                                        [{html.escape(item['Due Status'])}: {safe_fu}]
                                    </span><br/>
                                    <span style="opacity:0.82;font-size:0.85rem;">
                                        Stage: <strong>{safe_stage}</strong> · Value: <strong>{format_inr(item['Deal Value'])}</strong> · City: {html.escape(item['City'])}
                                    </span><br/>
                                    {links}
                                </div>
                                """,
                                unsafe_allow_html=True,
                            )
                        with c_act1:
                            st.markdown("<div style='height:0.35rem'></div>", unsafe_allow_html=True)
                            if st.button("Snooze +3d", use_container_width=True, key=f"crm_snooze_{rid}"):
                                next_3d = (date.today() + timedelta(days=3)).strftime("%Y-%m-%d")
                                upsert_crm_pipeline(
                                    spreadsheet=spreadsheet,
                                    user_id=current_user_id,
                                    company_id=company_id,
                                    assigned_to=item["Assigned To"],
                                    record_id=rid,
                                    lead_stage=item["Stage"],
                                    priority=item["Priority"],
                                    deal_value=item["Deal Value"],
                                    next_followup=next_3d,
                                    lead_source=item["Lead Source"],
                                    expected_close=item["Expected Close"],
                                )
                                st.session_state["flash_success"] = (
                                    f"Rescheduled '{item['Company Name']}' follow-up to {next_3d}."
                                )
                                st.rerun()
                        with c_act2:
                            st.markdown("<div style='height:0.35rem'></div>", unsafe_allow_html=True)
                            if st.button("Done ✓", type="primary", use_container_width=True, key=f"crm_done_{rid}"):
                                next_stage = "Contacted" if item["Stage"] == "New Lead" else item["Stage"]
                                log_crm_activity(
                                    spreadsheet=spreadsheet,
                                    user_id=current_user_id,
                                    company_id=company_id,
                                    assigned_to=item["Assigned To"],
                                    logged_by_name=current_full_name,
                                    record_id=rid,
                                    activity_type="Phone Call",
                                    summary="Completed scheduled follow-up.",
                                    new_stage=next_stage,
                                    priority=item["Priority"],
                                    deal_value=item["Deal Value"],
                                    next_followup_str="",
                                    lead_source=item["Lead Source"],
                                    expected_close=item["Expected Close"],
                                )
                                st.session_state["flash_success"] = (
                                    f"Marked follow-up complete for '{item['Company Name']}'."
                                )
                                st.rerun()

                if not hot_open_df.empty:
                    st.markdown("#### Priority Hot Deals in Progress")
                    for _, h_item in hot_open_df.head(10).iterrows():
                        st.markdown(
                            f"""
                            <div class="crm-card" style="border-left: 4px solid #dc2626;">
                                <span class="crm-pill" style="background:#dc2626;">Hot</span>
                                <strong>{html.escape(h_item['Company Name'])}</strong> · {html.escape(h_item['Contact Person'])}
                                <span class="crm-owner-pill">{html.escape(h_item['Owner Name'])}</span>
                                <span style="opacity:0.8;font-size:0.85rem;">
                                    — Stage: <strong>{html.escape(h_item['Stage'])}</strong> · Value: <strong>{format_inr(h_item['Deal Value'])}</strong>
                                </span>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )

        # ---- TAB 2: Pipeline Board ----
        with tab_board:
            b_cols = st.columns([1.3, 1.2, 1.3, 1.6]) if is_boss else st.columns([1.4, 1.3, 1.8])
            with b_cols[0]:
                board_mode = st.radio(
                    "View Mode",
                    options=["Visual Board", "Pipeline Table"],
                    horizontal=True,
                    key="crm_board_view_mode",
                )
            with b_cols[1]:
                prio_filter = st.selectbox(
                    "Priority",
                    options=["All Priorities", *CRM_PRIORITIES],
                    key="crm_board_prio_filter",
                )
            owner_filter_uid = "ALL"
            if is_boss:
                with b_cols[2]:
                    owner_opts = {"All Team Members": "ALL", **{v: k for k, v in member_id_to_label.items()}}
                    chosen_owner_lbl = st.selectbox(
                        "Employee Filter",
                        options=list(owner_opts.keys()),
                        key="crm_board_owner_filter",
                    )
                    owner_filter_uid = owner_opts[chosen_owner_lbl]
                search_col = b_cols[3]
            else:
                search_col = b_cols[2]

            with search_col:
                board_search = st.text_input(
                    "Search board",
                    placeholder="Filter by company, contact, or city...",
                    key="crm_board_search",
                )

            filtered_crm = crm_df.copy()
            if prio_filter != "All Priorities":
                filtered_crm = filtered_crm[filtered_crm["Priority"] == prio_filter]
            if is_boss and owner_filter_uid != "ALL":
                filtered_crm = filtered_crm[filtered_crm["Assigned To"] == owner_filter_uid]
            if board_search.strip():
                q = board_search.strip()
                mask = (
                    filtered_crm["Company Name"].str.contains(q, case=False, na=False, regex=False)
                    | filtered_crm["Contact Person"].str.contains(q, case=False, na=False, regex=False)
                    | filtered_crm["City"].str.contains(q, case=False, na=False, regex=False)
                )
                filtered_crm = filtered_crm[mask]

            if board_mode == "Visual Board":
                active_stages = [
                    "New Lead",
                    "Contacted",
                    "Follow-Up Needed",
                    "Quote Sent",
                    "Negotiation",
                    "Won",
                ]
                stage_cols = st.columns(len(active_stages))
                for s_idx, stg in enumerate(active_stages):
                    stg_df = filtered_crm[filtered_crm["Stage"] == stg]
                    stg_total = format_inr(stg_df["Deal Value"].sum())
                    hdr_bg = STAGE_COLORS.get(stg, "#6366f1")
                    with stage_cols[s_idx]:
                        st.markdown(
                            f"""
                            <div class="crm-stage-header" style="background:{hdr_bg};">
                                <span>{html.escape(stg)} ({len(stg_df)})</span>
                            </div>
                            <div style="font-size:0.78rem;opacity:0.75;margin:-0.3rem 0 0.5rem 0.15rem;">
                                {stg_total}
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )
                        for _, deal in stg_df.head(8).iterrows():
                            p_col = PRIORITY_COLORS.get(deal["Priority"], "#d97706")
                            st.markdown(
                                f"""
                                <div class="crm-board-item">
                                    <span class="crm-pill" style="background:{p_col};font-size:0.68rem;">{html.escape(deal['Priority'])}</span>
                                    <strong>{html.escape(deal['Company Name'])}</strong><br/>
                                    <span style="opacity:0.78;font-size:0.8rem;">{html.escape(deal['Contact Person'])}</span><br/>
                                    <span style="opacity:0.7;font-size:0.74rem;">Owner: {html.escape(deal['Owner Name'].split(' (')[0])}</span><br/>
                                    <span style="font-weight:600;font-size:0.82rem;">{format_inr(deal['Deal Value'])}</span>
                                </div>
                                """,
                                unsafe_allow_html=True,
                            )
                            if s_idx < len(active_stages) - 1:
                                next_stg = active_stages[s_idx + 1]
                                if st.button(
                                    f"Move → {next_stg}",
                                    use_container_width=True,
                                    key=f"kanban_adv_{deal['Record ID']}_{stg}",
                                ):
                                    upsert_crm_pipeline(
                                        spreadsheet=spreadsheet,
                                        user_id=current_user_id,
                                        company_id=company_id,
                                        assigned_to=deal["Assigned To"],
                                        record_id=deal["Record ID"],
                                        lead_stage=next_stg,
                                        priority=deal["Priority"],
                                        deal_value=deal["Deal Value"],
                                        next_followup=deal["Next Follow-Up"],
                                        lead_source=deal["Lead Source"],
                                        expected_close=deal["Expected Close"],
                                    )
                                    st.rerun()
                        if len(stg_df) > 8:
                            st.caption(f"+{len(stg_df) - 8} more in {stg}")
            else:
                tbl = filtered_crm[
                    [
                        "Company Name",
                        "Contact Person",
                        "Owner Name",
                        "Stage",
                        "Priority",
                        "Deal Value",
                        "Next Follow-Up",
                        "City",
                    ]
                ].copy()
                tbl["Deal Value"] = tbl["Deal Value"].map(format_inr)
                tbl["Next Follow-Up"] = tbl["Next Follow-Up"].replace("", "—")
                st.dataframe(tbl, use_container_width=True, hide_index=True)

            st.divider()
            st.markdown("#### Pipeline Value by Stage (₹)")
            stage_summary = (
                filtered_crm.groupby("Stage", as_index=False)["Deal Value"]
                .sum()
                .set_index("Stage")
            )
            st.bar_chart(stage_summary, use_container_width=True)

        # ---- TAB 3: 360° Lead & Deal Workspace ----
        with tab_workspace:
            lead_lookup = {
                f"{r['Company Name']} — {r['Contact Person']} ({r['Stage']} • {r['Owner Name'].split(' (')[0]}) [{r['Record ID'][:8]}]": r
                for _, r in crm_df.iterrows()
            }
            selected_lead_lbl = st.selectbox(
                "Select Lead / Contact",
                options=list(lead_lookup.keys()),
                key="crm_360_lead_select",
            )
            lead = lead_lookup[selected_lead_lbl]
            rid = lead["Record ID"]

            quick_msg = (
                f"Hello {lead['Contact Person'] if lead['Contact Person'] != 'N/A' else 'Sir/Madam'}, "
                f"connecting from {co_name_banner} regarding {lead['Company Name']}."
            )
            quick_links = _build_quick_action_links(
                lead, quick_msg, f"Regarding {lead['Company Name']}"
            )

            p_badge_col = PRIORITY_COLORS.get(lead["Priority"], "#d97706")
            s_badge_col = STAGE_COLORS.get(lead["Stage"], "#6366f1")
            st.markdown(
                f"""
                <div class="crm-card">
                    <span class="crm-pill" style="background:{s_badge_col};">{html.escape(lead['Stage'])}</span>
                    <span class="crm-pill" style="background:{p_badge_col};">{html.escape(lead['Priority'])}</span>
                    <strong style="font-size:1.05rem;">{html.escape(lead['Company Name'])}</strong> · {html.escape(lead['Contact Person'])}
                    <span class="crm-owner-pill">Assigned: {html.escape(lead['Owner Name'])}</span><br/>
                    <span style="opacity:0.82;font-size:0.86rem;">
                        <strong>Products/Services:</strong> {html.escape(lead['Product / Services'])} ·
                        <strong>City:</strong> {html.escape(lead['City'])}<br/>
                        <strong>Address:</strong> {html.escape(lead['Address'])}<br/>
                        <strong>Deal Value:</strong> {format_inr(lead['Deal Value'])} ·
                        <strong>Next Follow-Up:</strong> {html.escape(lead['Next Follow-Up'] or 'Not set')}
                    </span><br/>
                    {quick_links}
                </div>
                """,
                unsafe_allow_html=True,
            )

            left_form, right_log = st.columns(2)

            with left_form:
                st.markdown("#### Update Deal, Assignment & Follow-Up")
                with st.form(key=f"crm_360_deal_form_{rid}"):
                    f1, f2 = st.columns(2)
                    with f1:
                        upd_stage = st.selectbox(
                            "Stage",
                            options=CRM_STAGES,
                            index=CRM_STAGES.index(lead["Stage"]),
                        )
                        upd_val = st.number_input(
                            "Deal Value (₹)",
                            min_value=0,
                            step=1000,
                            value=int(round(lead["Deal Value"])),
                        )
                    with f2:
                        upd_prio = st.selectbox(
                            "Priority",
                            options=CRM_PRIORITIES,
                            index=CRM_PRIORITIES.index(lead["Priority"]),
                        )
                        upd_src = st.selectbox(
                            "Lead Source",
                            options=CRM_SOURCES,
                            index=(
                                CRM_SOURCES.index(lead["Lead Source"])
                                if lead["Lead Source"] in CRM_SOURCES
                                else 0
                            ),
                        )

                    if is_boss:
                        owner_choices = list(member_id_to_label.keys())
                        curr_owner_idx = (
                            owner_choices.index(lead["Assigned To"])
                            if lead["Assigned To"] in owner_choices
                            else 0
                        )
                        upd_assignee = st.selectbox(
                            "Assign Deal / Lead To Employee",
                            options=owner_choices,
                            format_func=lambda uid: member_id_to_label.get(uid, uid),
                            index=curr_owner_idx,
                        )
                    else:
                        upd_assignee = lead["Assigned To"]

                    d1, d2 = st.columns(2)
                    with d1:
                        has_fu = st.checkbox(
                            "Schedule Next Follow-Up",
                            value=bool(lead["Next Follow-Up"]),
                        )
                        try:
                            fu_init = (
                                datetime.strptime(lead["Next Follow-Up"], "%Y-%m-%d").date()
                                if lead["Next Follow-Up"]
                                else date.today()
                            )
                        except ValueError:
                            fu_init = date.today()
                        fu_dt = st.date_input("Follow-Up Date", value=fu_init)
                    with d2:
                        has_close = st.checkbox(
                            "Set Target Close Date",
                            value=bool(lead["Expected Close"]),
                        )
                        try:
                            cl_init = (
                                datetime.strptime(lead["Expected Close"], "%Y-%m-%d").date()
                                if lead["Expected Close"]
                                else date.today() + timedelta(days=14)
                            )
                        except ValueError:
                            cl_init = date.today() + timedelta(days=14)
                        cl_dt = st.date_input("Expected Close", value=cl_init)

                    if st.form_submit_button(
                        "Save Deal Settings", type="primary", use_container_width=True
                    ):
                        try:
                            upsert_crm_pipeline(
                                spreadsheet=spreadsheet,
                                user_id=current_user_id,
                                company_id=company_id,
                                assigned_to=upd_assignee,
                                record_id=rid,
                                lead_stage=upd_stage,
                                priority=upd_prio,
                                deal_value=float(upd_val),
                                next_followup=fu_dt.strftime("%Y-%m-%d") if has_fu else "",
                                lead_source=upd_src,
                                expected_close=cl_dt.strftime("%Y-%m-%d") if has_close else "",
                            )
                            if assign_card_owner_fn and upd_assignee != lead["Assigned To"]:
                                assign_card_owner_fn(rid, upd_assignee)
                            st.session_state["flash_success"] = (
                                f"Saved deal settings for '{lead['Company Name']}'."
                            )
                            st.rerun()
                        except Exception:
                            st.error("Could not save deal settings right now.")

            with right_log:
                st.markdown("#### Log Interaction / Call / Quote")
                with st.form(key=f"crm_360_act_form_{rid}"):
                    a1, a2 = st.columns(2)
                    with a1:
                        act_type = st.selectbox("Interaction Type", options=ACTIVITY_TYPES)
                    with a2:
                        act_stage_after = st.selectbox(
                            "Stage After Interaction",
                            options=CRM_STAGES,
                            index=CRM_STAGES.index(lead["Stage"]),
                        )

                    act_note = st.text_area(
                        "Summary / Outcome",
                        placeholder="e.g., Discussed bulk order pricing; customer requested quotation by tomorrow.",
                        height=95,
                    )
                    act_sched = st.checkbox("Update Follow-Up Date", value=True)
                    act_fu_date = st.date_input(
                        "Next Follow-Up",
                        value=date.today() + timedelta(days=2),
                    )

                    if st.form_submit_button(
                        "Log Interaction", type="primary", use_container_width=True
                    ):
                        if not act_note.strip():
                            st.error("Please enter a brief interaction summary.")
                        else:
                            try:
                                next_fu_val = (
                                    act_fu_date.strftime("%Y-%m-%d")
                                    if act_sched
                                    else lead["Next Follow-Up"]
                                )
                                log_crm_activity(
                                    spreadsheet=spreadsheet,
                                    user_id=current_user_id,
                                    company_id=company_id,
                                    assigned_to=lead["Assigned To"],
                                    logged_by_name=current_full_name,
                                    record_id=rid,
                                    activity_type=act_type,
                                    summary=act_note,
                                    new_stage=act_stage_after,
                                    priority=lead["Priority"],
                                    deal_value=lead["Deal Value"],
                                    next_followup_str=next_fu_val,
                                    lead_source=lead["Lead Source"],
                                    expected_close=lead["Expected Close"],
                                )
                                st.session_state["flash_success"] = (
                                    f"Logged {act_type} for '{lead['Company Name']}'."
                                )
                                st.rerun()
                            except Exception:
                                st.error("Could not log interaction right now.")

            st.divider()
            st.markdown(f"#### Interaction Timeline — {lead['Company Name']}")
            lead_acts = [a for a in activities if a.get("record_id") == rid]
            if not lead_acts:
                st.info("No interactions logged for this contact yet.")
            else:
                for act in lead_acts[:25]:
                    actor_txt = act.get("logged_by_name") or "Team Member"
                    st.markdown(
                        f"""
                        <div class="crm-timeline-item">
                            <strong>{html.escape(act.get('activity_type', 'Note'))}</strong>
                            <span style="opacity:0.75;font-size:0.8rem;"> by <strong>{html.escape(actor_txt)}</strong> · {html.escape(act.get('created_at', ''))}</span>
                            <span class="crm-pill" style="background:{STAGE_COLORS.get(act.get('stage_after', ''), '#6366f1')};font-size:0.7rem;margin-left:0.4rem;">
                                {html.escape(act.get('stage_after', ''))}
                            </span><br/>
                            <span style="font-size:0.88rem;">{html.escape(act.get('summary', ''))}</span>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

        # ---- TAB 4: Company Accounts ----
        with tab_accounts:
            st.caption(
                "Multiple visiting cards from the same organization are grouped into one Company Account."
            )
            if accounts_df.empty:
                st.info("No named company accounts available yet.")
            else:
                disp_accts = accounts_df.copy()
                disp_accts["Open Pipeline"] = disp_accts["Open Pipeline"].map(format_inr)
                disp_accts["Won Revenue"] = disp_accts["Won Revenue"].map(format_inr)
                st.dataframe(disp_accts, use_container_width=True, hide_index=True)

                chosen_acct = st.selectbox(
                    "Inspect All Contacts Under Company Account",
                    options=accounts_df["Company Account"].tolist(),
                    key="crm_acct_drilldown",
                )
                acct_key = _normalize_company_key(chosen_acct)
                members_df = crm_df[crm_df["Company Key"] == acct_key][
                    [
                        "Contact Person",
                        "Owner Name",
                        "Stage",
                        "Priority",
                        "Deal Value",
                        "WhatsApp No.",
                        "Contact No.",
                        "Email",
                        "Next Follow-Up",
                    ]
                ].copy()
                members_df["Deal Value"] = members_df["Deal Value"].map(format_inr)
                st.dataframe(members_df, use_container_width=True, hide_index=True)

        # ---- TAB 5 (Company Head / Boss Only): Team Performance ----
        if is_boss and len(tabs) == 5:
            with tabs[4]:
                st.markdown("#### Employee Pipeline & Revenue Performance")
                perf_rows = []
                for uid, m_label in member_id_to_label.items():
                    emp_deals = crm_df[crm_df["Assigned To"] == uid]
                    emp_open = emp_deals[~emp_deals["Stage"].isin(["Won", "Lost"])]
                    emp_won = emp_deals[emp_deals["Stage"] == "Won"]
                    emp_due = emp_deals[emp_deals["Due Status"].isin(["Overdue", "Due Today"])]
                    perf_rows.append(
                        {
                            "Team Member": m_label,
                            "Total Leads": len(emp_deals),
                            "Open Deals": len(emp_open),
                            "Open Pipeline": format_inr(emp_open["Deal Value"].sum()),
                            "Won Deals": len(emp_won),
                            "Won Revenue": format_inr(emp_won["Deal Value"].sum()),
                            "Due / Overdue": len(emp_due),
                        }
                    )
                st.dataframe(
                    pd.DataFrame(perf_rows), use_container_width=True, hide_index=True
                )