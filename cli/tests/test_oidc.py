import json
import unittest
from unittest.mock import patch

from tdxguard import http, oidc
from tdxguard.errors import LoginError

ENDPOINTS = oidc.Endpoints(device_authorization="https://sso/device", token="https://sso/token")


def response(status, payload):
    return http.Response(status, json.dumps(payload).encode(), {})


class FakeClock:
    """sleep() advances the clock, so the polling loop runs without waiting."""

    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds

    def clock(self):
        return self.now


class FakeTokenEndpoint:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, url, fields):
        self.calls.append((url, dict(fields)))
        return self.responses.pop(0)


def authorization(interval=5, expires_in=600):
    return oidc.DeviceAuthorization(
        device_code="dev-code",
        user_code="ABCD1234",
        verification_uri="https://sso/device",
        verification_uri_complete="https://sso/device?user_code=ABCD1234",
        expires_in=expires_in,
        interval=interval,
    )


class TestPoll(unittest.TestCase):
    def poll(self, endpoint, auth=None):
        clock = FakeClock()
        result = oidc.poll(
            ENDPOINTS, "client", auth or authorization(), post_form=endpoint, sleep=clock.sleep, clock=clock.clock
        )
        return result, clock

    def test_pending_then_success(self):
        endpoint = FakeTokenEndpoint(
            response(400, {"error": "authorization_pending"}),
            response(400, {"error": "authorization_pending"}),
            response(200, {"id_token": "id", "access_token": "at"}),
        )
        result, clock = self.poll(endpoint)

        self.assertEqual("id", result["id_token"])
        self.assertEqual([5, 5, 5], clock.sleeps)
        url, fields = endpoint.calls[0]
        self.assertEqual("https://sso/token", url)
        self.assertEqual(
            {"grant_type": oidc.DEVICE_CODE_GRANT, "device_code": "dev-code", "client_id": "client"}, fields
        )

    def test_slow_down_increases_the_interval(self):
        endpoint = FakeTokenEndpoint(
            response(400, {"error": "slow_down"}),
            response(400, {"error": "authorization_pending"}),
            response(400, {"error": "slow_down"}),
            response(200, {"id_token": "id"}),
        )
        _, clock = self.poll(endpoint)
        self.assertEqual([5, 10, 10, 15], clock.sleeps)

    def test_expired_token(self):
        endpoint = FakeTokenEndpoint(response(400, {"error": "expired_token"}))
        with self.assertRaises(LoginError) as cm:
            self.poll(endpoint)
        self.assertIn("expired", cm.exception.message)

    def test_access_denied(self):
        endpoint = FakeTokenEndpoint(response(400, {"error": "access_denied"}))
        with self.assertRaises(LoginError) as cm:
            self.poll(endpoint)
        self.assertIn("declined", cm.exception.message)

    def test_deadline(self):
        endpoint = FakeTokenEndpoint(*[response(400, {"error": "authorization_pending"})] * 10)
        with self.assertRaises(LoginError) as cm:
            self.poll(endpoint, authorization(interval=5, expires_in=12))
        self.assertIn("expired", cm.exception.message)
        self.assertEqual(3, len(endpoint.calls))

    def test_unknown_error(self):
        endpoint = FakeTokenEndpoint(response(400, {"error": "invalid_client", "error_description": "no such client"}))
        with self.assertRaises(LoginError) as cm:
            self.poll(endpoint)
        self.assertIn("invalid_client: no such client", cm.exception.message)

    def test_error_code_only_in_a_message(self):
        endpoint = FakeTokenEndpoint(
            response(400, {"error": "Authorization is pending (authorization_pending)"}),
            response(200, {"id_token": "id"}),
        )
        result, _ = self.poll(endpoint)
        self.assertEqual("id", result["id_token"])

    def test_non_json_error(self):
        endpoint = FakeTokenEndpoint(http.Response(502, b"<html>Bad gateway</html>", {}))
        with self.assertRaises(LoginError) as cm:
            self.poll(endpoint)
        self.assertIn("HTTP 502", cm.exception.message)


class TestDiscoverAndStart(unittest.TestCase):
    @patch("tdxguard.oidc.http.get")
    def test_discover(self, get_mock):
        get_mock.return_value = response(
            200,
            {
                "device_authorization_endpoint": "https://sso/api/oidc/device/authorize",
                "token_endpoint": "https://sso/api/oidc/token",
            },
        )
        endpoints = oidc.discover("https://sso/")
        get_mock.assert_called_with("https://sso/.well-known/openid-configuration")
        self.assertEqual("https://sso/api/oidc/device/authorize", endpoints.device_authorization)

    @patch("tdxguard.oidc.http.get")
    def test_discover_without_device_flow(self, get_mock):
        get_mock.return_value = response(200, {"token_endpoint": "https://sso/token"})
        with self.assertRaises(LoginError):
            oidc.discover("https://sso")

    @patch("tdxguard.oidc.http.post_form")
    def test_start(self, post_mock):
        # The shape TDxSSO (Pocket ID) answers with.
        post_mock.return_value = response(
            200,
            {
                "device_code": "d",
                "user_code": "EB74MH1N",
                "verification_uri": "https://sso/device",
                "verification_uri_complete": "https://sso/device?user_code=EB74MH1N",
                "expires_in": 899,
                "interval": 5,
            },
        )
        auth = oidc.start(ENDPOINTS, "client", "openid profile")
        post_mock.assert_called_with("https://sso/device", {"client_id": "client", "scope": "openid profile"})
        self.assertEqual("EB74MH1N", auth.user_code)
        self.assertEqual(899, auth.expires_in)

    @patch("tdxguard.oidc.http.post_form")
    def test_start_refused(self, post_mock):
        post_mock.return_value = response(400, {"error": "unauthorized_client"})
        with self.assertRaises(LoginError) as cm:
            oidc.start(ENDPOINTS, "client", "openid")
        self.assertIn("unauthorized_client", cm.exception.message)


if __name__ == "__main__":
    unittest.main()
