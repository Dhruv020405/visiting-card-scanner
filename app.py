import io
import os
import re
import sqlite3
import time
from datetime import datetime
from typing import Optional, Tuple

import pandas as pd
import streamlit as st
from google import genai
from google.genai import errors as genai_errors
from google.genai import types
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DB_PATH = "company_records.db"
MODEL_NAME = "gemini-3.5-flash-lite"
FALLBACK_MODELS = ["gemini-3.6-flash", "gemini-3.8-flash"]

st.set_page_config(
    page_title="Company Visiting Card Scanner",
    page_icon="📇",
    layout="wide",
)


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
# SQLite Database Helpers
# ---------------------------------------------------------------------------
def init_db() -> None:
    """Create the SQLite database and records table if they do not exist."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS visiting_cards (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                company_name TEXT NOT NULL,
                contact_person TEXT NOT NULL,
                phone TEXT NOT NULL,
                email TEXT NOT NULL,
                address TEXT NOT NULL,
                products_services TEXT NOT NULL,
                notes TEXT DEFAULT '',
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()


def save_record(
    company_name: str,
    contact_person: str,
    phone: str,
    email: str,
    address: str,
    products_services: str,
    notes: str,
) -> None:
    """Insert a verified visiting card record with the current timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO visiting_cards (
                company_name, contact_person, phone, email,
                address, products_services, notes, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                company_name.strip() or "N/A",
                contact_person.strip() or "N/A",
                phone.strip() or "N/A",
                email.strip() or "N/A",
                address.strip() or "N/A",
                products_services.strip() or "N/A",
                notes.strip(),
                timestamp,
            ),
        )
        conn.commit()


def fetch_all_records() -> pd.DataFrame:
    """Return all saved records as a pandas DataFrame, newest first."""
    with sqlite3.connect(DB_PATH) as conn:
        df = pd.read_sql_query(
            """
            SELECT
                id AS "ID",
                company_name AS "Company Name",
                contact_person AS "Contact Person",
                phone AS "Phone",
                email AS "Email",
                products_services AS "Products / Services",
                address AS "Address",
                notes AS "Notes",
                created_at AS "Saved On"
            FROM visiting_cards
            ORDER BY id DESC
            """,
            conn,
        )
    return df


def delete_record(record_id: int) -> None:
    """Delete a record by its ID."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM visiting_cards WHERE id = ?", (record_id,))
        conn.commit()


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
            "Gemini API key is missing. Please add it in the sidebar Settings."
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
                # Retry briefly on temporary overload (503) or rate limit (429)
                if api_err.code in (429, 503):
                    time.sleep(2 * (attempt + 1))
                    continue
                # If a model is unavailable (404), skip straight to the next fallback
                if api_err.code == 404:
                    break
                raise

    if last_error:
        raise last_error
    raise RuntimeError("All Gemini models failed to process the visiting card.")


def run_scan(image_file, api_key: str) -> None:
    """Process an UploadedFile from either file_uploader or camera_input."""
    if not api_key:
        st.error("Please enter your Gemini API key in the sidebar before scanning.")
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
# Main Application
# ---------------------------------------------------------------------------
def main() -> None:
    init_db()

    # Initialize session state variables
    if "extracted_card" not in st.session_state:
        st.session_state["extracted_card"] = None
    if "scan_counter" not in st.session_state:
        st.session_state["scan_counter"] = 0
    if "flash_success" not in st.session_state:
        st.session_state["flash_success"] = None
    if "scan_notice" not in st.session_state:
        st.session_state["scan_notice"] = None

    # ---- Sidebar: Settings & API Key ----
    with st.sidebar:
        st.header("Settings")

        env_api_key = os.getenv("GEMINI_API_KEY", "")
        user_api_key = st.text_input(
            "Gemini API Key",
            value=env_api_key,
            type="password",
            placeholder="AIza... or AQ...",
            help="Reads GEMINI_API_KEY from your environment if already set.",
        )
        active_api_key: Optional[str] = (user_api_key or env_api_key).strip()

        if active_api_key:
            st.success("API key configured")
        else:
            st.warning("Enter your Gemini API key to start scanning.")

        st.divider()
        st.caption(f"Primary model: `{MODEL_NAME}`")
        st.caption(f"Fallbacks: `{', '.join(FALLBACK_MODELS)}`")
        st.caption(f"Database: `{DB_PATH}`")

    # ---- Page Header ----
    st.title("Company Visiting Card Scanner")
    st.caption(
        "Scan visiting cards with AI, verify the details, save locally, and export to Excel."
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
                submitted = st.form_submit_button("Save Record", type="primary")
            with btn_col2:
                discarded = st.form_submit_button("Discard")

            if submitted:
                try:
                    save_record(
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
                        f"Saved '{company_name}' to {DB_PATH}."
                    )
                    st.rerun()
                except sqlite3.Error as db_err:
                    st.error(f"Database error while saving: {db_err}")

            if discarded:
                st.session_state["extracted_card"] = None
                st.rerun()

    # ---- Step 3: Saved Records, Search & Excel Export ----
    st.divider()
    st.subheader("3. Saved Visiting Cards")

    try:
        all_records_df = fetch_all_records()
    except sqlite3.Error as db_err:
        st.error(f"Failed to load records from database: {db_err}")
        return

    search_col, export_col = st.columns([3, 1])

    with search_col:
        search_query = st.text_input(
            "Search records",
            placeholder="Filter by company name, products/services, or address...",
            label_visibility="collapsed",
        )

    with export_col:
        if not all_records_df.empty:
            excel_bytes = build_excel_bytes(all_records_df)
            filename = f"company_visiting_cards_{datetime.now().strftime('%Y%m%d')}.xlsx"
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
        st.info("No visiting cards saved yet. Scan your first card above!")
        return

    # Filter records by company name, products/services, or address
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

    # Compact utility to remove accidental entries
    with st.expander("Delete a record"):
        record_options = {
            f"ID {row['ID']} — {row['Company Name']} ({row['Contact Person']})": int(
                row["ID"]
            )
            for _, row in all_records_df.iterrows()
        }
        selected_label = st.selectbox(
            "Select record to delete", options=list(record_options.keys())
        )
        if st.button("Delete Selected Record", type="secondary"):
            try:
                delete_record(record_options[selected_label])
                st.session_state["flash_success"] = "Record deleted."
                st.rerun()
            except sqlite3.Error as db_err:
                st.error(f"Could not delete record: {db_err}")


if __name__ == "__main__":
    main() #aa