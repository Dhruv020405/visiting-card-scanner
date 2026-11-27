import hashlib
import html
import re
import threading
import uuid
from datetime import date, datetime, timedelta
from typing import Any, Callable, Optional, Tuple
from urllib.parse import quote

import gspread
import pandas as pd
import streamlit as st

from rbac_org import (
    ROLE_ADMIN,
    ROLE_COMPANY_HEAD,
    ROLE_EMPLOYEE,
    ROLE_USER,
    can_access_crm,
    fetch_all_companies,
    get_company_by_id,
    get_company_members,
    get_role_badge_label,
    normalize_role,
)
from security_utils import (
    get_scoped_opt_outs,
    log_internal_error,
    retry_sheets_call,
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
    "lost_reason",
    "stage_changed_at",
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

LOST_REASONS = [
    "",
    "Price / Budget",
    "Competitor Chosen",
    "No Response / Ghosted",
    "Requirement Postponed",
    "Out of Service Area",
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
    "Deal Updated",
    "Note",
]

_CRM_LOCK = threading.Lock()


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


def _stable_account_id(company_key: str) -> str:
    if not company_key:
        return ""
    return f"acc_{hashlib.sha1(company_key.encode('utf-8')).hexdigest()[:8]}"


def _days_since(date_str: str) -> int:
    if not date_str:
        return 0
    try:
        dt = datetime.strptime(date_str[:10], "%Y-%m-%d").date()
        return max(0, (date.today() - dt).days)
    except ValueError:
        return 0


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
        retry_sheets_call(lambda: ws.append_row(headers, value_input_option="RAW"))
        return ws

    all_rows = retry_sheets_call(ws.get_all_values)
    if not all_rows:
        if ws.col_count < len(headers):
            ws.resize(cols=len(headers))
        retry_sheets_call(lambda: ws.append_row(headers, value_input_option="RAW"))
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
        retry_sheets_call(
            lambda: ws.update(values=migrated, range_name="A1", value_input_option="RAW")
        )
    return ws


@st.cache_data(ttl=60, show_spinner=False)
def _fetch_pipeline_rows(
    _spreadsheet_id: str, scope_key: str, company_id: str, user_id: str, role: str
) -> dict[str, dict[str, str]]:
    ss = st.session_state["_crm_spreadsheet_ref"]
    ws = _get_or_init_ws(ss, CRM_PIPELINE_WORKSHEET, CRM_PIPELINE_HEADERS)
    rows = retry_sheets_call(ws.get_all_values)
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
            if not company_id or rec.get("company_id") == company_id:
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
    rows = retry_sheets_call(ws.get_all_values)
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
            if not company_id or rec.get("company_id") == company_id:
                out.append(rec)
        elif company_id and rec.get("company_id") == company_id:
            out.append(rec)
        elif not rec.get("company_id") and rec.get("user_id") == user_id:
            out.append(rec)
    return out[::-1]


# ---------------------------------------------------------------------------
# Offboarding & Full Backup Helpers
# ---------------------------------------------------------------------------
def count_open_deals_for_user(
    spreadsheet: gspread.Spreadsheet, company_id: str, target_user_id: str
) -> int:
    st.session_state["_crm_spreadsheet_ref"] = spreadsheet
    pmap = _fetch_pipeline_rows(
        spreadsheet.id, f"count:{company_id}", company_id, target_user_id, ROLE_COMPANY_HEAD
    )
    count = 0
    for rec in pmap.values():
        if (
            rec.get("company_id") == company_id
            and rec.get("assigned_to") == target_user_id
            and rec.get("lead_stage") not in ("Won", "Lost")
        ):
            count += 1
    return count


def reassign_open_deals_for_user(
    spreadsheet: gspread.Spreadsheet,
    company_id: str,
    old_user_id: str,
    new_user_id: str,
    actor_uid: str,
    actor_name: str,
    assign_card_owner_fn: Optional[Callable[[str, str], bool]] = None,
) -> Tuple[bool, str]:
    """Reassign (or explicitly unassign via new_user_id='') all open deals of a disabled employee."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    updated_rids: list[str] = []
    try:
        with _CRM_LOCK:
            ws = _get_or_init_ws(spreadsheet, CRM_PIPELINE_WORKSHEET, CRM_PIPELINE_HEADERS)
            rows = retry_sheets_call(ws.get_all_values)
            if len(rows) <= 1:
                return True, "No open deals to update."
            headers = rows[0]
            for idx, r in enumerate(rows[1:], start=2):
                padded = r + [""] * (len(headers) - len(r))
                rec = dict(zip(headers, padded))
                if (
                    rec.get("company_id") == company_id
                    and rec.get("assigned_to") == old_user_id
                    and rec.get("lead_stage") not in ("Won", "Lost")
                ):
                    rid = rec["record_id"]
                    if assign_card_owner_fn is not None:
                        if not assign_card_owner_fn(rid, new_user_id):
                            return False, f"Failed to update card ownership for record {rid[:8]}."
                    retry_sheets_call(
                        lambda ri=idx: ws.update(
                            values=[[new_user_id]], range_name=f"D{ri}", value_input_option="RAW"
                        )
                    )
                    updated_rids.append(rid)
            _fetch_pipeline_rows.clear()

        if updated_rids:
            act_ws = _get_or_init_ws(spreadsheet, CRM_ACTIVITIES_WORKSHEET, CRM_ACTIVITY_HEADERS)
            act_rows = [
                [
                    f"act_{uuid.uuid4().hex[:10]}",
                    actor_uid,
                    company_id,
                    rid,
                    "Lead Assigned",
                    f"Reassigned during employee offboarding to {'Unassigned' if not new_user_id else new_user_id}.",
                    "",
                    "",
                    actor_name,
                    now_str,
                ]
                for rid in updated_rids
            ]
            retry_sheets_call(
                lambda: act_ws.append_rows(act_rows, value_input_option="RAW", table_range="A1")
            )
            _fetch_activity_rows.clear()
        return True, f"Updated {len(updated_rids)} open deal(s)."
    except Exception as exc:
        ref = log_internal_error("reassign_open_deals_for_user", exc)
        return False, f"Storage error during deal reassignment (Ref: {ref})."


def build_crm_backup_sheets(
    spreadsheet: gspread.Spreadsheet,
    all_records_df: pd.DataFrame,
    current_user: dict[str, str],
) -> dict[str, pd.DataFrame]:
    """Return scoped CRM Deals & CRM Activities DataFrames for the Full Backup export."""
    if not can_access_crm(current_user, spreadsheet):
        return {}
    st.session_state["_crm_spreadsheet_ref"] = spreadsheet
    uid = str(current_user.get("user_id", "")).strip()
    cid = str(current_user.get("company_id", "")).strip()
    role = normalize_role(current_user.get("role", ROLE_USER), current_user.get("email", ""))
    scope_key = f"bkp:{role}:{cid}:{uid}"

    pmap = _fetch_pipeline_rows(spreadsheet.id, scope_key, cid, uid, role)
    acts = _fetch_activity_rows(spreadsheet.id, scope_key, cid, uid, role)

    allowed_rids = (
        set(all_records_df["Record ID"].astype(str).tolist())
        if not all_records_df.empty
        else set()
    )
    deals_rows = [
        rec
        for rid, rec in pmap.items()
        if role != ROLE_EMPLOYEE or rid in allowed_rids
    ]
    scoped_acts = [
        a
        for a in acts
        if role != ROLE_EMPLOYEE or a.get("record_id", "") in allowed_rids
    ]

    return {
        "CRM Pipeline": pd.DataFrame(deals_rows) if deals_rows else pd.DataFrame(columns=CRM_PIPELINE_HEADERS),
        "CRM Activities": pd.DataFrame(scoped_acts) if scoped_acts else pd.DataFrame(columns=CRM_ACTIVITY_HEADERS),
    }


def get_crm_due_summary(
    spreadsheet: gspread.Spreadsheet,
    all_records_df: pd.DataFrame,
    current_user: dict[str, str],
) -> Tuple[int, int, float]:
    if not can_access_crm(current_user, spreadsheet) or all_records_df.empty:
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
        assignee = str(meta.get("assigned_to") or r.get("Assigned To") or "").strip()
        if role == ROLE_EMPLOYEE and assignee != user_id:
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


# ---------------------------------------------------------------------------
# Coordinated Pipeline + Card Ownership + Automatic Activity Writes
# ---------------------------------------------------------------------------
def save_crm_deal_coordinated(
    spreadsheet: gspread.Spreadsheet,
    user_id: str,
    company_id: str,
    assigned_to: str,
    prev_assigned_to: str,
    logged_by_name: str,
    record_id: str,
    lead_stage: str,
    prev_stage: str,
    priority: str,
    deal_value: float,
    prev_value: float,
    next_followup: str,
    prev_followup: str,
    lead_source: str,
    expected_close: str,
    lost_reason: str,
    assign_card_owner_fn: Optional[Callable[[str, str], bool]] = None,
    custom_activity: Optional[Tuple[str, str]] = None,
) -> Tuple[bool, str]:
    """
    Save CRM pipeline state, coordinate card ownership updates with rollback on failure,
    and automatically append a matching activity entry for every deal/owner change.
    """
    if not company_id.strip():
        return False, "Cannot save CRM deal without an explicit Company context."

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    today_str = date.today().strftime("%Y-%m-%d")
    clean_val = str(int(round(max(0.0, float(deal_value)))))
    clean_stage = lead_stage if lead_stage in CRM_STAGES else "New Lead"
    clean_prio = priority if priority in CRM_PRIORITIES else "Warm"
    clean_lost = lost_reason.strip() if clean_stage == "Lost" else ""
    stage_changed_at = today_str if clean_stage != prev_stage else ""

    # Step 1: If owner changed, update visiting_cards.assigned_to FIRST and verify success
    owner_changed = assigned_to != prev_assigned_to
    if owner_changed and assign_card_owner_fn is not None:
        if not assign_card_owner_fn(record_id, assigned_to):
            return False, "Failed to update card ownership. Deal changes were not saved."

    # Step 2: Upsert crm_pipeline row; roll back card ownership if Sheets write fails
    try:
        with _CRM_LOCK:
            ws = _get_or_init_ws(spreadsheet, CRM_PIPELINE_WORKSHEET, CRM_PIPELINE_HEADERS)
            rows = retry_sheets_call(ws.get_all_values)
            existing_idx = None
            prev_stage_dt = today_str
            for idx, row in enumerate(rows[1:], start=2):
                if len(row) >= 1 and row[0] == record_id:
                    existing_idx = idx
                    if len(row) >= 12 and row[11].strip():
                        prev_stage_dt = row[11].strip()
                    break

            final_stage_dt = stage_changed_at or prev_stage_dt
            new_row = [
                record_id,
                user_id,
                company_id.strip(),
                assigned_to.strip(),
                clean_stage,
                clean_prio,
                clean_val,
                next_followup.strip(),
                lead_source.strip() or "Visiting Card Scan",
                expected_close.strip(),
                clean_lost,
                final_stage_dt,
                now_str,
            ]
            if existing_idx is not None:
                retry_sheets_call(
                    lambda: ws.update(
                        values=[new_row],
                        range_name=f"A{existing_idx}:M{existing_idx}",
                        value_input_option="RAW",
                    )
                )
            else:
                retry_sheets_call(
                    lambda: ws.append_row(new_row, value_input_option="RAW", table_range="A1")
                )
            _fetch_pipeline_rows.clear()
    except Exception as exc:
        if owner_changed and assign_card_owner_fn is not None:
            try:
                assign_card_owner_fn(record_id, prev_assigned_to)
            except Exception:
                pass
        ref = log_internal_error("save_crm_deal_coordinated.pipeline", exc)
        return False, f"Could not save CRM deal (Ref: {ref}). Changes were rolled back."

    # Step 3: Build automatic activity summary for all field changes (or custom interaction)
    act_type = "Deal Updated"
    summary_parts: list[str] = []
    if custom_activity is not None:
        act_type, custom_sum = custom_activity
        summary_parts.append(custom_sum.strip()[:250])
    else:
        if clean_stage != prev_stage:
            act_type = "Stage Updated"
            summary_parts.append(f"Stage: {prev_stage} → {clean_stage}")
            if clean_lost:
                summary_parts.append(f"Lost Reason: {clean_lost}")
        if int(round(deal_value)) != int(round(prev_value)):
            summary_parts.append(f"Value: {format_inr(prev_value)} → {format_inr(deal_value)}")
        if next_followup.strip() != prev_followup.strip():
            summary_parts.append(f"Follow-Up: {prev_followup or 'None'} → {next_followup or 'Cleared'}")
        if owner_changed:
            act_type = "Lead Assigned"
            summary_parts.append(f"Owner updated to {assigned_to or 'Unassigned'}")

    if summary_parts:
        try:
            with _CRM_LOCK:
                act_ws = _get_or_init_ws(
                    spreadsheet, CRM_ACTIVITIES_WORKSHEET, CRM_ACTIVITY_HEADERS
                )
                retry_sheets_call(
                    lambda: act_ws.append_row(
                        [
                            f"act_{uuid.uuid4().hex[:10]}",
                            user_id,
                            company_id.strip(),
                            record_id,
                            act_type,
                            " | ".join(summary_parts)[:300],
                            clean_stage,
                            next_followup.strip(),
                            logged_by_name,
                            now_str,
                        ],
                        value_input_option="RAW",
                        table_range="A1",
                    )
                )
                _fetch_activity_rows.clear()
        except Exception as exc:
            ref = log_internal_error("save_crm_deal_coordinated.activity", exc)
            return True, f"Deal saved, but activity history could not be logged (Ref: {ref})."

    return True, "Saved successfully."


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
                padding: 0.85rem 1rem; border-radius: 10px;
                border: 1px solid rgba(128, 128, 128, 0.22);
                background: rgba(128, 128, 128, 0.04); margin-bottom: 0.6rem;
            }
            .crm-pill {
                display: inline-block; padding: 0.14rem 0.55rem; border-radius: 999px;
                font-size: 0.74rem; font-weight: 600; color: #ffffff;
                margin-right: 0.35rem; vertical-align: middle;
            }
            .crm-owner-pill {
                display: inline-block; padding: 0.12rem 0.5rem; border-radius: 6px;
                font-size: 0.74rem; font-weight: 600;
                background: rgba(99, 102, 241, 0.16); color: #6366f1; margin-left: 0.35rem;
            }
            .crm-stage-header {
                padding: 0.5rem 0.75rem; border-radius: 8px; color: #ffffff;
                font-weight: 600; font-size: 0.88rem; margin-bottom: 0.55rem;
            }
            .crm-board-item {
                padding: 0.65rem 0.75rem; border-radius: 8px;
                border: 1px solid rgba(128, 128, 128, 0.24);
                background: rgba(128, 128, 128, 0.05); margin-bottom: 0.5rem; font-size: 0.86rem;
            }
            .crm-btn-link {
                display: inline-block; padding: 0.34rem 0.75rem; border-radius: 6px;
                text-decoration: none !important; font-size: 0.82rem; font-weight: 600;
                margin-right: 0.4rem; margin-top: 0.38rem;
            }
            .crm-btn-wa { background: #16a34a; color: #ffffff !important; }
            .crm-btn-gmail { background: #dc2626; color: #ffffff !important; }
            .crm-btn-call { background: #0284c7; color: #ffffff !important; }
            .crm-timeline-item {
                padding: 0.65rem 0.85rem; border-left: 3px solid #6366f1;
                background: rgba(128, 128, 128, 0.04); border-radius: 0 8px 8px 0; margin-bottom: 0.5rem;
            }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _build_quick_action_links(
    row_like: Any, msg_text: str, subject_text: str, opted_out_keys: set[str]
) -> str:
    wa_pairs, tel_digits = _extract_wa_and_tel(
        str(row_like["WhatsApp No."]), str(row_like["Contact No."])
    )
    emails = _parse_emails(str(row_like["Email"]))

    # Check if any phone or email on this card is in the Do-Not-Contact registry
    contact_keys = {d[-10:] for _, d in wa_pairs} | set(emails)
    if contact_keys & opted_out_keys:
        return '<span style="color:#dc2626;font-size:0.82rem;font-weight:600;">Opted Out / Do-Not-Contact</span>'

    links = ""
    for idx, (disp, wa_dial) in enumerate(wa_pairs, start=1):
        wa_href = html.escape(f"https://wa.me/{wa_dial}?text={quote(msg_text)}", quote=True)
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


# ---------------------------------------------------------------------------
# Main Role-Aware Company CRM Section
# ---------------------------------------------------------------------------
def render_crm_section(
    spreadsheet: gspread.Spreadsheet,
    all_records_df: pd.DataFrame,
    current_user: dict[str, str],
    all_users: list[dict[str, str]],
    build_multi_sheet_excel_fn: Callable[[dict[str, pd.DataFrame]], bytes],
    assign_card_owner_fn: Optional[Callable[[str, str], bool]] = None,
) -> None:
    if not can_access_crm(current_user, spreadsheet):
        st.error(
            "CRM access is restricted to active Company Heads and Employees. "
            "Contact your Platform Admin if your company is suspended or unregistered."
        )
        return

    _inject_crm_css()
    st.session_state["_crm_spreadsheet_ref"] = spreadsheet
    st.session_state["_org_spreadsheet_ref"] = spreadsheet

    current_user_id = str(current_user.get("user_id", "")).strip()
    current_username = str(current_user.get("username", "")).strip()
    current_full_name = str(current_user.get("full_name") or current_username).strip()
    role = normalize_role(current_user.get("role", ROLE_USER), current_user.get("email", ""))
    is_boss = role in (ROLE_COMPANY_HEAD, ROLE_ADMIN)

    # Admin must explicitly select a company to edit; "All Companies" is strictly read-only
    active_company_id = str(current_user.get("company_id", "")).strip()
    is_read_only = False
    if role == ROLE_ADMIN:
        all_cos = fetch_all_companies(spreadsheet.id)
        co_selector_map = {"All Companies (Read-Only)": ""}
        for c in all_cos:
            co_selector_map[f"{c['company_name']} ({c.get('status', 'active').title()})"] = c["company_id"]
        chosen_co_lbl = st.selectbox(
            "Admin Company Context",
            options=list(co_selector_map.keys()),
            key="crm_admin_company_selector",
        )
        active_company_id = co_selector_map[chosen_co_lbl]
        if not active_company_id:
            is_read_only = True
            st.info(
                "**Read-Only Mode:** Select a specific company above to edit deals, reassign owners, or log interactions."
            )

    co_info = get_company_by_id(spreadsheet, active_company_id)
    co_name_banner = (
        co_info.get("company_name", "Company CRM")
        if co_info
        else "All Companies (Read-Only)"
    )

    team_members = get_company_members(all_users, active_company_id, include_disabled=False)
    member_id_to_label: dict[str, str] = {"": "Unassigned"}
    for m in team_members:
        uid = str(m.get("user_id", ""))
        member_id_to_label[uid] = (
            f"{m.get('full_name') or m.get('username')} ({get_role_badge_label(m.get('role', ROLE_EMPLOYEE))})"
        )

    opted_out_keys = get_scoped_opt_outs(spreadsheet, active_company_id, current_user_id)

    with st.container(border=True):
        hdr_c1, hdr_c2, hdr_c3 = st.columns([3.4, 1.0, 1.4])
        with hdr_c1:
            st.subheader(f"CRM Workspace — {co_name_banner}")
            st.caption(
                f"Signed in as **{current_full_name}** ({get_role_badge_label(role)})"
            )
        with hdr_c2:
            if st.button("Refresh CRM", use_container_width=True, key="btn_crm_refresh"):
                _fetch_pipeline_rows.clear()
                _fetch_activity_rows.clear()
                st.rerun()

        scoped_cards_df = all_records_df.copy()
        if role == ROLE_ADMIN and active_company_id:
            scoped_cards_df = scoped_cards_df[
                scoped_cards_df["Company ID"].astype(str).str.strip() == active_company_id
            ]

        if scoped_cards_df.empty:
            st.info("No visiting cards available in this company scope yet.")
            return

        scope_key = f"{role}:{active_company_id}:{current_user_id}"
        pipeline_map = _fetch_pipeline_rows(
            spreadsheet.id, scope_key, active_company_id, current_user_id, role
        )
        all_activities = _fetch_activity_rows(
            spreadsheet.id, scope_key, active_company_id, current_user_id, role
        )
        today_str = date.today().strftime("%Y-%m-%d")

        crm_rows: list[dict[str, Any]] = []
        for _, r in scoped_cards_df.iterrows():
            rid = str(r["Record ID"])
            meta = pipeline_map.get(rid, {})
            assigned_uid = str(meta.get("assigned_to") or r.get("Assigned To") or "").strip()

            # Strict employee scope: only leads currently assigned to this employee
            if role == ROLE_EMPLOYEE and assigned_uid != current_user_id:
                continue

            stage = meta.get("lead_stage") if meta.get("lead_stage") in CRM_STAGES else "New Lead"
            prio = meta.get("priority") if meta.get("priority") in CRM_PRIORITIES else "Warm"
            val = _parse_deal_value(meta.get("deal_value", 0))
            fu_date = str(meta.get("next_followup", "")).strip()
            exp_close = str(meta.get("expected_close", "")).strip()
            lost_reason = str(meta.get("lost_reason", "")).strip()
            stage_dt = str(meta.get("stage_changed_at") or r.get("Saved On", ""))[:10]
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
            co_key = _normalize_company_key(co_name)
            crm_rows.append(
                {
                    "Record ID": rid,
                    "Account ID": _stable_account_id(co_key),
                    "Company Name": co_name,
                    "Company Key": co_key,
                    "Contact Person": str(r["Contact Person"]),
                    "WhatsApp No.": str(r["WhatsApp No."]),
                    "Contact No.": str(r["Contact No."]),
                    "Email": str(r["Email"]),
                    "City": str(r["City"]),
                    "Product / Services": str(r["Product / Services"]),
                    "Address": str(r["Address"]),
                    "Notes": str(r["Notes"]),
                    "Assigned To": assigned_uid,
                    "Owner Name": member_id_to_label.get(assigned_uid, "Unassigned"),
                    "Stage": stage,
                    "Days in Stage": _days_since(stage_dt),
                    "Priority": prio,
                    "Deal Value": val,
                    "Weighted Value": val * prob,
                    "Next Follow-Up": fu_date,
                    "Expected Close": exp_close,
                    "Lost Reason": lost_reason,
                    "Due Status": due_status,
                    "Lead Source": source,
                }
            )

        if not crm_rows:
            st.info("No deals assigned to you yet.")
            return

        crm_df = pd.DataFrame(crm_rows)
        visible_rids = set(crm_df["Record ID"].astype(str).tolist())

        # Phase 1 Fix #1: Scope activities strictly to visible/assigned records for Employees
        activities = (
            [a for a in all_activities if a.get("record_id", "") in visible_rids]
            if role == ROLE_EMPLOYEE
            else all_activities
        )

        # Grouped Company Accounts with stable Account ID
        account_rows: list[dict[str, Any]] = []
        valid_co_df = crm_df[crm_df["Company Key"] != ""]
        for _, grp in valid_co_df.groupby("Company Key", sort=False):
            open_grp = grp[~grp["Stage"].isin(["Won", "Lost"])]
            won_grp = grp[grp["Stage"] == "Won"]
            account_rows.append(
                {
                    "Account ID": grp["Account ID"].iloc[0],
                    "Company Account": grp["Company Name"].iloc[0],
                    "Contacts": len(grp),
                    "Open Deals": len(open_grp),
                    "Open Pipeline": float(open_grp["Deal Value"].sum()),
                    "Won Revenue": float(won_grp["Deal Value"].sum()),
                }
            )
        accounts_df = (
            pd.DataFrame(account_rows).sort_values(by=["Open Pipeline", "Contacts"], ascending=[False, False])
            if account_rows
            else pd.DataFrame()
        )

        with hdr_c3:
            exp_deals = crm_df[
                [
                    "Account ID", "Company Name", "Contact Person", "Owner Name",
                    "Stage", "Days in Stage", "Priority", "Deal Value",
                    "Next Follow-Up", "Lost Reason", "Lead Source", "City",
                ]
            ].copy()
            exp_deals["Deal Value (INR)"] = exp_deals["Deal Value"].map(format_inr)
            exp_deals = exp_deals.drop(columns=["Deal Value"])

            sheets_to_export: dict[str, pd.DataFrame] = {"Pipeline Deals": exp_deals}
            if not accounts_df.empty:
                exp_accts = accounts_df.copy()
                exp_accts["Open Pipeline (INR)"] = exp_accts["Open Pipeline"].map(format_inr)
                exp_accts["Won Revenue (INR)"] = exp_accts["Won Revenue"].map(format_inr)
                sheets_to_export["Company Accounts"] = exp_accts.drop(columns=["Open Pipeline", "Won Revenue"])

            id_to_co = {str(r["Record ID"]): str(r["Company Name"]) for _, r in crm_df.iterrows()}
            sheets_to_export["Activity History"] = pd.DataFrame(
                [
                    {
                        "Timestamp": a.get("created_at", ""),
                        "Logged By": a.get("logged_by_name", ""),
                        "Company": id_to_co.get(a.get("record_id", ""), "Company Card"),
                        "Activity": a.get("activity_type", ""),
                        "Summary": a.get("summary", ""),
                        "Stage": a.get("stage_after", ""),
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
        win_rate = round((len(won_df) / len(closed_df)) * 100) if len(closed_df) > 0 else 0
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
            "360° Lead Workspace",
            f"Accounts ({len(accounts_df)})",
            "CRM Reports",
        ]
        tabs = st.tabs(tab_names)
        tab_action, tab_board, tab_workspace, tab_accounts, tab_reports = tabs

        # ---- TAB 1: Action Queue ----
        with tab_action:
            if due_df.empty:
                st.success("No overdue or due-today follow-ups.")
            else:
                for _, item in due_df.iterrows():
                    rid = item["Record ID"]
                    border_col = "#dc2626" if item["Due Status"] == "Overdue" else "#f59e0b"
                    msg_text = (
                        f"Hello {item['Contact Person'] if item['Contact Person'] != 'N/A' else 'Sir/Madam'}, "
                        f"following up regarding {item['Company Name']}."
                    )
                    links = _build_quick_action_links(
                        item, msg_text, f"Follow-up: {item['Company Name']}", opted_out_keys
                    )
                    c_card, c_a1, c_a2 = st.columns([3.8, 1.0, 1.0])
                    with c_card:
                        st.markdown(
                            f"""
                            <div class="crm-card" style="border-left: 4px solid {border_col};">
                                <span class="crm-pill" style="background:{PRIORITY_COLORS.get(item['Priority'], '#d97706')};">{html.escape(item['Priority'])}</span>
                                <strong>{html.escape(item['Company Name'])}</strong> · {html.escape(item['Contact Person'])}
                                <span class="crm-owner-pill">{html.escape(item['Owner Name'])}</span>
                                <span style="color:{border_col};font-weight:600;font-size:0.82rem;">[{html.escape(item['Due Status'])}: {html.escape(item['Next Follow-Up'])}]</span><br/>
                                <span style="opacity:0.82;font-size:0.85rem;">Stage: <strong>{html.escape(item['Stage'])}</strong> ({item['Days in Stage']}d) · Value: <strong>{format_inr(item['Deal Value'])}</strong></span><br/>
                                {links}
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )
                    with c_a1:
                        if st.button("Snooze +3d", use_container_width=True, disabled=is_read_only, key=f"crm_snz_{rid}"):
                            next_3d = (date.today() + timedelta(days=3)).strftime("%Y-%m-%d")
                            ok, msg = save_crm_deal_coordinated(
                                spreadsheet=spreadsheet, user_id=current_user_id, company_id=active_company_id,
                                assigned_to=item["Assigned To"], prev_assigned_to=item["Assigned To"],
                                logged_by_name=current_full_name, record_id=rid,
                                lead_stage=item["Stage"], prev_stage=item["Stage"],
                                priority=item["Priority"], deal_value=item["Deal Value"], prev_value=item["Deal Value"],
                                next_followup=next_3d, prev_followup=item["Next Follow-Up"],
                                lead_source=item["Lead Source"], expected_close=item["Expected Close"],
                                lost_reason=item["Lost Reason"],
                            )
                            if ok:
                                st.session_state["flash_success"] = f"Snoozed '{item['Company Name']}' to {next_3d}."
                                st.rerun()
                            else:
                                st.error(msg)
                    with c_a2:
                        if st.button("Done ✓", type="primary", use_container_width=True, disabled=is_read_only, key=f"crm_dn_{rid}"):
                            nxt_stg = "Contacted" if item["Stage"] == "New Lead" else item["Stage"]
                            ok, msg = save_crm_deal_coordinated(
                                spreadsheet=spreadsheet, user_id=current_user_id, company_id=active_company_id,
                                assigned_to=item["Assigned To"], prev_assigned_to=item["Assigned To"],
                                logged_by_name=current_full_name, record_id=rid,
                                lead_stage=nxt_stg, prev_stage=item["Stage"],
                                priority=item["Priority"], deal_value=item["Deal Value"], prev_value=item["Deal Value"],
                                next_followup="", prev_followup=item["Next Follow-Up"],
                                lead_source=item["Lead Source"], expected_close=item["Expected Close"],
                                lost_reason=item["Lost Reason"],
                                custom_activity=("Phone Call", "Completed scheduled follow-up."),
                            )
                            if ok:
                                st.session_state["flash_success"] = f"Completed follow-up for '{item['Company Name']}'."
                                st.rerun()
                            else:
                                st.error(msg)

        # ---- TAB 2: Pipeline Board ----
        with tab_board:
            b1, b2 = st.columns([1.5, 2.5])
            with b1:
                board_mode = st.radio("View", ["Visual Board", "Pipeline Table"], horizontal=True, key="crm_bm")
            with b2:
                b_search = st.text_input("Search", placeholder="Filter company, contact, or city...", key="crm_bs")

            f_crm = crm_df.copy()
            if b_search.strip():
                q = b_search.strip()
                f_crm = f_crm[
                    f_crm["Company Name"].str.contains(q, case=False, na=False, regex=False)
                    | f_crm["Contact Person"].str.contains(q, case=False, na=False, regex=False)
                    | f_crm["City"].str.contains(q, case=False, na=False, regex=False)
                ]

            if board_mode == "Visual Board":
                active_stages = ["New Lead", "Contacted", "Follow-Up Needed", "Quote Sent", "Negotiation", "Won"]
                scols = st.columns(len(active_stages))
                for s_idx, stg in enumerate(active_stages):
                    stg_df = f_crm[f_crm["Stage"] == stg]
                    with scols[s_idx]:
                        st.markdown(
                            f'<div class="crm-stage-header" style="background:{STAGE_COLORS[stg]};">{html.escape(stg)} ({len(stg_df)})</div>'
                            f'<div style="font-size:0.78rem;opacity:0.75;margin:-0.3rem 0 0.5rem 0.1rem;">{format_inr(stg_df["Deal Value"].sum())}</div>',
                            unsafe_allow_html=True,
                        )
                        for _, deal in stg_df.head(8).iterrows():
                            st.markdown(
                                f'<div class="crm-board-item"><strong>{html.escape(deal["Company Name"])}</strong><br/>'
                                f'<span style="opacity:0.78;font-size:0.8rem;">{html.escape(deal["Contact Person"])} · {deal["Days in Stage"]}d</span><br/>'
                                f'<span style="font-weight:600;font-size:0.82rem;">{format_inr(deal["Deal Value"])}</span></div>',
                                unsafe_allow_html=True,
                            )
                            if s_idx < len(active_stages) - 1 and not is_read_only:
                                next_stg = active_stages[s_idx + 1]
                                if st.button(f"→ {next_stg}", use_container_width=True, key=f"kb_{deal['Record ID']}_{stg}"):
                                    ok, msg = save_crm_deal_coordinated(
                                        spreadsheet=spreadsheet, user_id=current_user_id, company_id=active_company_id,
                                        assigned_to=deal["Assigned To"], prev_assigned_to=deal["Assigned To"],
                                        logged_by_name=current_full_name, record_id=deal["Record ID"],
                                        lead_stage=next_stg, prev_stage=deal["Stage"],
                                        priority=deal["Priority"], deal_value=deal["Deal Value"], prev_value=deal["Deal Value"],
                                        next_followup=deal["Next Follow-Up"], prev_followup=deal["Next Follow-Up"],
                                        lead_source=deal["Lead Source"], expected_close=deal["Expected Close"],
                                        lost_reason=deal["Lost Reason"],
                                    )
                                    if ok:
                                        st.rerun()
                                    else:
                                        st.error(msg)
            else:
                tbl = f_crm[
                    ["Company Name", "Contact Person", "Owner Name", "Stage", "Days in Stage", "Priority", "Deal Value", "Next Follow-Up"]
                ].copy()
                tbl["Deal Value"] = tbl["Deal Value"].map(format_inr)
                st.dataframe(tbl, use_container_width=True, hide_index=True)

        # ---- TAB 3: 360° Lead Workspace ----
        with tab_workspace:
            lead_lookup = {
                f"{r['Company Name']} — {r['Contact Person']} ({r['Stage']}) [{r['Record ID'][:8]}]": r
                for _, r in crm_df.iterrows()
            }
            sel_lbl = st.selectbox("Select Lead / Deal", options=list(lead_lookup.keys()), key="crm_360_sel")
            lead = lead_lookup[sel_lbl]
            rid = lead["Record ID"]

            quick_links = _build_quick_action_links(
                lead,
                f"Hello {lead['Contact Person'] if lead['Contact Person'] != 'N/A' else 'Sir/Madam'}, connecting regarding {lead['Company Name']}.",
                f"Regarding {lead['Company Name']}",
                opted_out_keys,
            )
            st.markdown(
                f"""
                <div class="crm-card">
                    <span class="crm-pill" style="background:{STAGE_COLORS.get(lead['Stage'], '#6366f1')};">{html.escape(lead['Stage'])}</span>
                    <span class="crm-pill" style="background:{PRIORITY_COLORS.get(lead['Priority'], '#d97706')};">{html.escape(lead['Priority'])}</span>
                    <strong>{html.escape(lead['Company Name'])}</strong> · {html.escape(lead['Contact Person'])}
                    <span class="crm-owner-pill">Owner: {html.escape(lead['Owner Name'])}</span><br/>
                    <span style="opacity:0.82;font-size:0.85rem;">Account ID: {html.escape(lead['Account ID'] or 'N/A')} · Days in Stage: {lead['Days in Stage']}d · Value: <strong>{format_inr(lead['Deal Value'])}</strong></span><br/>
                    {quick_links}
                </div>
                """,
                unsafe_allow_html=True,
            )

            left_f, right_l = st.columns(2)
            with left_f:
                st.markdown("#### Update Deal & Assignment")
                with st.form(key=f"crm_deal_f_{rid}"):
                    f1, f2 = st.columns(2)
                    with f1:
                        upd_stg = st.selectbox("Stage", CRM_STAGES, index=CRM_STAGES.index(lead["Stage"]))
                        upd_val = st.number_input("Deal Value (₹)", min_value=0, step=1000, value=int(round(lead["Deal Value"])))
                    with f2:
                        upd_prio = st.selectbox("Priority", CRM_PRIORITIES, index=CRM_PRIORITIES.index(lead["Priority"]))
                        upd_src = st.selectbox("Lead Source", CRM_SOURCES, index=CRM_SOURCES.index(lead["Lead Source"]) if lead["Lead Source"] in CRM_SOURCES else 0)

                    upd_lost = st.selectbox(
                        "Lost Reason (required if Stage = Lost)",
                        options=LOST_REASONS,
                        index=LOST_REASONS.index(lead["Lost Reason"]) if lead["Lost Reason"] in LOST_REASONS else 0,
                    )

                    if is_boss and not is_read_only:
                        owner_choices = list(member_id_to_label.keys())
                        cur_idx = owner_choices.index(lead["Assigned To"]) if lead["Assigned To"] in owner_choices else 0
                        upd_owner = st.selectbox(
                            "Assign Deal To",
                            options=owner_choices,
                            format_func=lambda u: member_id_to_label.get(u, u),
                            index=cur_idx,
                        )
                    else:
                        upd_owner = lead["Assigned To"]

                    has_fu = st.checkbox("Schedule Next Follow-Up", value=bool(lead["Next Follow-Up"]))
                    try:
                        fu_init = datetime.strptime(lead["Next Follow-Up"], "%Y-%m-%d").date() if lead["Next Follow-Up"] else date.today()
                    except ValueError:
                        fu_init = date.today()
                    fu_dt = st.date_input("Follow-Up Date", value=fu_init)

                    if st.form_submit_button("Save Deal Settings", type="primary", use_container_width=True, disabled=is_read_only):
                        if upd_stg == "Lost" and not upd_lost:
                            st.error("Please select a Lost Reason when marking a deal as Lost.")
                        else:
                            ok, msg = save_crm_deal_coordinated(
                                spreadsheet=spreadsheet, user_id=current_user_id, company_id=active_company_id,
                                assigned_to=upd_owner, prev_assigned_to=lead["Assigned To"],
                                logged_by_name=current_full_name, record_id=rid,
                                lead_stage=upd_stg, prev_stage=lead["Stage"],
                                priority=upd_prio, deal_value=float(upd_val), prev_value=lead["Deal Value"],
                                next_followup=fu_dt.strftime("%Y-%m-%d") if has_fu else "",
                                prev_followup=lead["Next Follow-Up"],
                                lead_source=upd_src, expected_close=lead["Expected Close"],
                                lost_reason=upd_lost, assign_card_owner_fn=assign_card_owner_fn,
                            )
                            if ok:
                                st.session_state["flash_success"] = msg
                                st.rerun()
                            else:
                                st.error(msg)

            with right_l:
                st.markdown("#### Log Interaction")
                with st.form(key=f"crm_act_f_{rid}"):
                    act_type = st.selectbox("Type", ACTIVITY_TYPES)
                    act_stg = st.selectbox("Stage After", CRM_STAGES, index=CRM_STAGES.index(lead["Stage"]))
                    act_note = st.text_area("Summary", placeholder="e.g., Shared quotation via WhatsApp.", height=90)
                    act_sched = st.checkbox("Update Follow-Up", value=True)
                    act_fu_dt = st.date_input("Next Follow-Up", value=date.today() + timedelta(days=2))
                    if st.form_submit_button("Log Interaction", type="primary", use_container_width=True, disabled=is_read_only):
                        if not act_note.strip():
                            st.error("Enter a brief summary.")
                        else:
                            ok, msg = save_crm_deal_coordinated(
                                spreadsheet=spreadsheet, user_id=current_user_id, company_id=active_company_id,
                                assigned_to=lead["Assigned To"], prev_assigned_to=lead["Assigned To"],
                                logged_by_name=current_full_name, record_id=rid,
                                lead_stage=act_stg, prev_stage=lead["Stage"],
                                priority=lead["Priority"], deal_value=lead["Deal Value"], prev_value=lead["Deal Value"],
                                next_followup=act_fu_dt.strftime("%Y-%m-%d") if act_sched else lead["Next Follow-Up"],
                                prev_followup=lead["Next Follow-Up"],
                                lead_source=lead["Lead Source"], expected_close=lead["Expected Close"],
                                lost_reason=lead["Lost Reason"],
                                custom_activity=(act_type, act_note),
                            )
                            if ok:
                                st.session_state["flash_success"] = f"Logged {act_type}."
                                st.rerun()
                            else:
                                st.error(msg)

            st.divider()
            st.markdown(f"#### Activity Timeline — {lead['Company Name']}")
            lead_acts = [a for a in activities if a.get("record_id") == rid]
            if not lead_acts:
                st.info("No interactions logged for this lead yet.")
            else:
                for act in lead_acts[:25]:
                    st.markdown(
                        f'<div class="crm-timeline-item"><strong>{html.escape(act.get("activity_type", "Note"))}</strong> '
                        f'by <strong>{html.escape(act.get("logged_by_name") or "Team")}</strong> · {html.escape(act.get("created_at", ""))}<br/>'
                        f'<span style="font-size:0.88rem;">{html.escape(act.get("summary", ""))}</span></div>',
                        unsafe_allow_html=True,
                    )

        # ---- TAB 4: Accounts ----
        with tab_accounts:
            if accounts_df.empty:
                st.info("No named company accounts yet.")
            else:
                disp_a = accounts_df.copy()
                disp_a["Open Pipeline"] = disp_a["Open Pipeline"].map(format_inr)
                disp_a["Won Revenue"] = disp_a["Won Revenue"].map(format_inr)
                st.dataframe(disp_a, use_container_width=True, hide_index=True)

        # ---- TAB 5: CRM Reports (Stage Aging, Lead Source Conversion & Lost Reasons) ----
        with tab_reports:
            r1, r2 = st.columns(2)
            with r1:
                st.markdown("#### Lead-Source Conversion")
                src_rows = []
                for src_name, grp in crm_df.groupby("Lead Source"):
                    won_cnt = int((grp["Stage"] == "Won").sum())
                    src_rows.append(
                        {
                            "Lead Source": src_name,
                            "Total Leads": len(grp),
                            "Won": won_cnt,
                            "Conversion (%)": round((won_cnt / len(grp)) * 100, 1),
                            "Won Revenue": format_inr(grp.loc[grp["Stage"] == "Won", "Deal Value"].sum()),
                        }
                    )
                st.dataframe(pd.DataFrame(src_rows), use_container_width=True, hide_index=True)

            with r2:
                st.markdown("#### Average Stage Aging (Days)")
                age_df = (
                    open_df.groupby("Stage", as_index=False)["Days in Stage"]
                    .mean()
                    .rename(columns={"Days in Stage": "Avg Days in Stage"})
                )
                if not age_df.empty:
                    age_df["Avg Days in Stage"] = age_df["Avg Days in Stage"].round(1)
                    st.dataframe(age_df, use_container_width=True, hide_index=True)
                else:
                    st.info("No open deals to measure stage aging.")

            lost_df = crm_df[crm_df["Stage"] == "Lost"]
            if not lost_df.empty:
                st.markdown("#### Lost-Deal Reasons")
                lr_counts = lost_df["Lost Reason"].replace("", "Unspecified").value_counts().reset_index()
                lr_counts.columns = ["Lost Reason", "Deals Lost"]
                st.dataframe(lr_counts, use_container_width=True, hide_index=True)