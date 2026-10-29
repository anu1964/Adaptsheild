import unittest
from unittest.mock import patch

import requests
from fastapi.testclient import TestClient

import server


class ModelEndpointTests(unittest.TestCase):
    def setUp(self):
        server._models_cache.update(ts=0.0, models=[], error=None)
        self.client = TestClient(server.app)

    def test_models_endpoint_reports_missing_key(self):
        with patch.object(server, "load_groq_key", return_value=""):
            response = self.client.get("/models")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "models": [],
                "groq_key_set": False,
                "error": "missing_api_key",
            },
        )

    def test_models_endpoint_reports_rejected_key(self):
        provider_response = requests.Response()
        provider_response.status_code = 401

        class RejectedResponse:
            def raise_for_status(self):
                raise requests.HTTPError(response=provider_response)

        with (
            patch.object(server, "load_groq_key", return_value="test-key"),
            patch.object(server.requests, "get", return_value=RejectedResponse()),
        ):
            response = self.client.get("/models")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["error"], "invalid_api_key")
        self.assertTrue(response.json()["groq_key_set"])

    def test_models_endpoint_lists_available_chat_models(self):
        captured = {}

        class ProviderResponse:
            def raise_for_status(self):
                pass

            def json(self):
                return {
                    "data": [
                        {"id": "llama-3.3-70b-versatile", "active": True},
                        {"id": "whisper-large-v3", "active": True},
                        {"id": "llama-inactive", "active": False},
                    ]
                }

        def fake_get(url, headers, timeout):
            captured.update(url=url, headers=headers, timeout=timeout)
            return ProviderResponse()

        with (
            patch.object(server, "load_groq_key", return_value="test-key"),
            patch.object(server.requests, "get", side_effect=fake_get),
        ):
            response = self.client.get("/models")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["models"], ["llama-3.3-70b-versatile"])
        self.assertIsNone(response.json()["error"])
        self.assertEqual(captured["headers"]["Authorization"], "Bearer test-key")


if __name__ == "__main__":
    unittest.main()
