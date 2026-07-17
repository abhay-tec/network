import hashlib
import unittest
from unittest import mock

import app as app_module


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class BaseCase(unittest.TestCase):
    def setUp(self):
        app_module.app.testing = True
        self.client = app_module.app.test_client()
        with app_module._DB_LOCK:
            app_module._USERS.clear()
            app_module._USER_ID_SEQ = 0
        with app_module._SESSION_LOCK:
            app_module._AUTH_SESSIONS.clear()
        with app_module._DASHBOARD_SESSION_LOCK:
            app_module._DASHBOARD_SESSIONS.clear()

    def _signup(self, username="alice", email="alice@example.com", password="hunter2secret"):
        ph = _hash(password)
        resp = self.client.post(
            "/api/auth/signup",
            json={
                "username": username,
                "email": email,
                "password_hash": ph,
                "confirm_password_hash": ph,
            },
        )
        return resp


class SignupSyncTokenTests(BaseCase):
    def test_signup_returns_sync_token(self):
        resp = self._signup()
        self.assertEqual(resp.status_code, 201)
        body = resp.get_json()
        self.assertIn("sync_token", body)
        self.assertTrue(body["sync_token"])
        self.assertIn(".", body["sync_token"])

    def test_sync_token_roundtrip_verifies(self):
        self._signup()
        token = app_module._sync_token_for_user("alice")
        payload = app_module._verify_sync_token(token)
        self.assertIsNotNone(payload)
        self.assertEqual(payload["username"], "alice")
        self.assertEqual(payload["email"], "alice@example.com")

    def test_tampered_token_rejected(self):
        self._signup()
        token = app_module._sync_token_for_user("alice")
        encoded, signature = token.split(".", 1)
        tampered = f"{encoded}.{'0' * len(signature)}"
        self.assertIsNone(app_module._verify_sync_token(tampered))

    def test_tampered_payload_rejected(self):
        self._signup()
        token = app_module._sync_token_for_user("alice")
        _, signature = token.split(".", 1)
        import base64
        import json

        forged = base64.urlsafe_b64encode(
            json.dumps({"username": "attacker"}).encode("utf-8")
        ).decode("ascii")
        self.assertIsNone(app_module._verify_sync_token(f"{forged}.{signature}"))


class SyncRestoreTests(BaseCase):
    def test_restore_repopulates_empty_store(self):
        self._signup()
        token = app_module._sync_token_for_user("alice")
        # Simulate serverless cold start wiping RAM.
        with app_module._DB_LOCK:
            app_module._USERS.clear()
            app_module._USER_ID_SEQ = 0
        self.assertIsNone(app_module._query_user("alice"))

        resp = self.client.post("/api/auth/sync-restore", json={"sync_token": token})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["status"], "restored")
        self.assertIsNotNone(app_module._query_user("alice"))

    def test_restore_existing_user_is_noop(self):
        self._signup()
        token = app_module._sync_token_for_user("alice")
        resp = self.client.post("/api/auth/sync-restore", json={"sync_token": token})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["status"], "exists")

    def test_restore_rejects_tampered_token(self):
        self._signup()
        token = app_module._sync_token_for_user("alice")
        encoded, signature = token.split(".", 1)
        tampered = f"{encoded}.{'0' * len(signature)}"
        resp = self.client.post("/api/auth/sync-restore", json={"sync_token": tampered})
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.get_json()["code"], "invalid_sync_token")

    def test_restore_missing_token(self):
        resp = self.client.post("/api/auth/sync-restore", json={})
        self.assertEqual(resp.status_code, 400)


class Step1SMTPTests(BaseCase):
    def test_missing_smtp_returns_clean_503_without_otp(self):
        self._signup()
        with mock.patch.dict(app_module.os.environ, {}, clear=True):
            resp = self.client.post(
                "/api/auth/step1",
                json={"username": "alice", "password_hash": _hash("hunter2secret")},
            )
        self.assertEqual(resp.status_code, 503)
        body = resp.get_json()
        self.assertEqual(body["code"], "email_unconfigured")
        self.assertNotIn("debug_otp", body)
        self.assertNotIn("otp", body)
        self.assertNotIn("tx_token", body)

    def test_successful_smtp_sends_and_hides_otp(self):
        self._signup()
        env = {"SMTP_EMAIL": "sender@gmail.com", "SMTP_PASSWORD": "app-password"}
        with mock.patch.dict(app_module.os.environ, env, clear=True):
            with mock.patch.object(app_module.smtplib, "SMTP") as smtp_cls:
                smtp_instance = smtp_cls.return_value.__enter__.return_value
                resp = self.client.post(
                    "/api/auth/step1",
                    json={"username": "alice", "password_hash": _hash("hunter2secret")},
                )
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertEqual(body["status"], "handshake_started")
        self.assertIn("tx_token", body)
        self.assertNotIn("debug_otp", body)
        self.assertNotIn("otp", body)
        smtp_instance.starttls.assert_called_once()
        smtp_instance.login.assert_called_once_with("sender@gmail.com", "app-password")
        smtp_instance.send_message.assert_called_once()

    def test_smtp_uses_gmail_host_and_tls_port(self):
        self._signup()
        env = {"SMTP_EMAIL": "sender@gmail.com", "SMTP_PASSWORD": "app-password"}
        with mock.patch.dict(app_module.os.environ, env, clear=True):
            with mock.patch.object(app_module.smtplib, "SMTP") as smtp_cls:
                self.client.post(
                    "/api/auth/step1",
                    json={"username": "alice", "password_hash": _hash("hunter2secret")},
                )
        args, kwargs = smtp_cls.call_args
        self.assertEqual(args[0], "smtp.gmail.com")
        self.assertEqual(args[1], 587)

    def test_delivery_failure_returns_503(self):
        self._signup()
        env = {"SMTP_EMAIL": "sender@gmail.com", "SMTP_PASSWORD": "app-password"}
        with mock.patch.dict(app_module.os.environ, env, clear=True):
            with mock.patch.object(
                app_module.smtplib, "SMTP", side_effect=OSError("network down")
            ):
                resp = self.client.post(
                    "/api/auth/step1",
                    json={"username": "alice", "password_hash": _hash("hunter2secret")},
                )
        self.assertEqual(resp.status_code, 503)
        body = resp.get_json()
        self.assertEqual(body["code"], "email_delivery_failed")
        self.assertNotIn("debug_otp", body)


class VerifyFlowTests(BaseCase):
    def _login(self):
        env = {"SMTP_EMAIL": "sender@gmail.com", "SMTP_PASSWORD": "app-password"}
        with mock.patch.dict(app_module.os.environ, env, clear=True):
            with mock.patch.object(app_module.smtplib, "SMTP"):
                resp = self.client.post(
                    "/api/auth/step1",
                    json={"username": "alice", "password_hash": _hash("hunter2secret")},
                )
        return resp.get_json()["tx_token"]

    def test_manual_otp_verification_reaches_dashboard(self):
        self._signup()
        tx_token = self._login()
        # OTP is only in the server session, never in the response payload.
        otp_code = app_module._AUTH_SESSIONS[tx_token].otp_code
        self.assertTrue(otp_code)
        resp = self.client.post(
            "/api/auth/verify", json={"tx_token": tx_token, "otp_code": otp_code}
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["status"], "verified")
        self.assertIn("dashboard_token", resp.get_json()["dashboard_payload"])

    def test_wrong_otp_rejected(self):
        self._signup()
        tx_token = self._login()
        resp = self.client.post(
            "/api/auth/verify", json={"tx_token": tx_token, "otp_code": "000000"}
        )
        self.assertEqual(resp.status_code, 401)

    def test_resend_no_debug_otp(self):
        self._signup()
        tx_token = self._login()
        env = {"SMTP_EMAIL": "sender@gmail.com", "SMTP_PASSWORD": "app-password"}
        with mock.patch.dict(app_module.os.environ, env, clear=True):
            with mock.patch.object(app_module.smtplib, "SMTP"):
                resp = self.client.post("/api/auth/resend-otp", json={"tx_token": tx_token})
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn("debug_otp", resp.get_json())


class PrivacyModeTests(BaseCase):
    def _dashboard_token(self):
        self._signup()
        env = {"SMTP_EMAIL": "sender@gmail.com", "SMTP_PASSWORD": "app-password"}
        with mock.patch.dict(app_module.os.environ, env, clear=True):
            with mock.patch.object(app_module.smtplib, "SMTP"):
                tx_token = self.client.post(
                    "/api/auth/step1",
                    json={"username": "alice", "password_hash": _hash("hunter2secret")},
                ).get_json()["tx_token"]
        otp_code = app_module._AUTH_SESSIONS[tx_token].otp_code
        verify = self.client.post(
            "/api/auth/verify", json={"tx_token": tx_token, "otp_code": otp_code}
        )
        return verify.get_json()["dashboard_payload"]["dashboard_token"]

    def test_save_mode_persists_and_returns_sync_token(self):
        dash = self._dashboard_token()
        for mode in ("ghost", "semi-private", "public"):
            resp = self.client.post(
                "/api/auth/save-mode", json={"dashboard_token": dash, "mode": mode}
            )
            self.assertEqual(resp.status_code, 200)
            body = resp.get_json()
            self.assertEqual(body["privacy_mode"], mode)
            self.assertTrue(body["sync_token"])

    def test_user_details_reflects_saved_mode(self):
        dash = self._dashboard_token()
        self.client.post(
            "/api/auth/save-mode", json={"dashboard_token": dash, "mode": "ghost"}
        )
        resp = self.client.post("/api/auth/user-details", json={"dashboard_token": dash})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["privacy_mode"], "ghost")


if __name__ == "__main__":
    unittest.main()
