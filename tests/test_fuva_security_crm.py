import os
import unittest
from unittest.mock import patch

from rbac_org import (
    ROLE_ADMIN,
    ROLE_COMPANY_HEAD,
    ROLE_EMPLOYEE,
    ROLE_USER,
    can_access_crm,
)
from security_utils import (
    is_paid_gemini_billing_confirmed,
    parse_rate_limit_row_fail_closed,
    verify_ai_execution_allowed,
)


class TestSecurityAndRoleBoundaries(unittest.TestCase):
    def test_normal_user_cannot_access_crm(self) -> None:
        normal_user = {"user_id": "u1", "role": ROLE_USER, "company_id": "", "email": "a@b.com"}
        self.assertFalse(can_access_crm(normal_user))

    def test_company_employee_without_company_id_cannot_access_crm(self) -> None:
        orphan_emp = {"user_id": "u2", "role": ROLE_EMPLOYEE, "company_id": "", "email": "e@b.com"}
        self.assertFalse(can_access_crm(orphan_emp))

    def test_company_head_and_employee_with_company_can_access_crm(self) -> None:
        boss = {"user_id": "u3", "role": ROLE_COMPANY_HEAD, "company_id": "comp_1", "email": "b@b.com"}
        emp = {"user_id": "u4", "role": ROLE_EMPLOYEE, "company_id": "comp_1", "email": "e@b.com"}
        self.assertTrue(can_access_crm(boss))
        self.assertTrue(can_access_crm(emp))

    def test_rate_limit_parser_fails_closed_on_malformed_rows(self) -> None:
        attempts, _ws, locked_until, malformed = parse_rate_limit_row_fail_closed(
            ["login:test", "not_a_number", "bad", "bad"], now=1000
        )
        self.assertTrue(malformed)
        self.assertGreater(locked_until, 1000)
        self.assertGreaterEqual(attempts, 999)

    def test_rate_limit_parser_accepts_valid_row(self) -> None:
        attempts, ws, locked_until, malformed = parse_rate_limit_row_fail_closed(
            ["login:test", "2", "900", "0"], now=1000
        )
        self.assertFalse(malformed)
        self.assertEqual(attempts, 2)
        self.assertEqual(ws, 900)
        self.assertEqual(locked_until, 0)

    def test_ai_gate_blocks_when_billing_unconfirmed(self) -> None:
        with patch.dict(os.environ, {"GEMINI_PAID_BILLING_CONFIRMED": "false"}):
            self.assertFalse(is_paid_gemini_billing_confirmed())
            ok, msg = verify_ai_execution_allowed("card_scan_extraction", consent_granted=True)
            self.assertFalse(ok)
            self.assertIn("GEMINI_PAID_BILLING_CONFIRMED", msg)

    def test_ai_gate_blocks_when_consent_not_granted(self) -> None:
        with patch.dict(os.environ, {"GEMINI_PAID_BILLING_CONFIRMED": "true"}):
            ok, msg = verify_ai_execution_allowed("card_scan_extraction", consent_granted=False)
            self.assertFalse(ok)
            self.assertIn("Consent is required", msg)

    def test_ai_gate_allows_when_billing_and_consent_confirmed(self) -> None:
        with patch.dict(os.environ, {"GEMINI_PAID_BILLING_CONFIRMED": "true"}):
            ok, _ = verify_ai_execution_allowed("marketing_ai_generation", consent_granted=True)
            self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()