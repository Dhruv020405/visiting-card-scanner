# Fuva — Visiting Card Scanner & Company CRM

A multi-user Streamlit visiting card scanner and company-level CRM backed by Google Sheets and optional Google Gemini AI extraction.

## Features
- **Card Capture:** Front/back image upload, mobile camera capture, manual entry, and bounded Excel/CSV merge (up to 500 rows, 40 columns) with multi-WhatsApp and multi-email single-column parsing.
- **Role-Based Access Control (`rbac_org.py`):**
  - **Platform Admin (`admin`):** Registers companies, issues verified 7-day Boss invites, suspends/reactivates companies, views platform audit logs, and runs operational retention cleanups.
  - **Company Head / Boss (`company_head`):** Invites employees via single-use invite codes (employees set their own passwords), manages company-wide CRM deals, reassigns open deals when disabling employees, and views team performance.
  - **Employee (`employee`):** Views and manages only leads/deals assigned to them, logs calls/WhatsApp/meetings, and exports strictly scoped activity history.
  - **Normal User (`user`):** Full visiting card scanner, Excel merge, search, and export—no CRM access. Supports self-service permanent account deletion or upgrading via a company invite code.
- **CRM Workspace (`crm_module.py`):** Action Queue (Overdue/Due Today), Visual Pipeline Board, 360° Lead Workspace with automatic activity logging, grouped Company Accounts (`account_id`), Stage Aging, Lead-Source Conversion, and Lost-Deal Reasons.

## Local Setup & Secrets
Create `.streamlit/secrets.toml` (never commit this file to Git):
```toml
SESSION_SECRET = "replace-with-a-64-character-random-secret"
GSHEET_URL = "[https://docs.google.com/spreadsheets/d/YOUR_SHEET_ID/edit](https://docs.google.com/spreadsheets/d/YOUR_SHEET_ID/edit)"
ADMIN_EMAILS = "your_admin_email@gmail.com"
GEMINI_API_KEY = "YOUR_GEMINI_API_KEY"
GEMINI_PAID_BILLING_CONFIRMED = "true"  # Set to "true" ONLY when active paid billing is confirmed in Google Cloud

SMTP_EMAIL = "your_sender@gmail.com"
SMTP_APP_PASSWORD = "your_gmail_app_password"

[gcp_service_account]
type = "service_account"
project_id = "..."
private_key_id = "..."
private_key = "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
client_email = "..."
client_id = "..."