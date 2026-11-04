"""Tests for agent loop (E42)."""

import http.server
import json
import os
import threading

import pytest

from airlock.agent import AgentLoop


class TestAgent:
    """Test agent loop checks."""

    @pytest.mark.smoke
    def test_e42_vultr_inference_smoke(self):
        """E42: Agent loop works against live Vultr Inference."""
        api_key = os.environ.get("VULTR_INFERENCE_API_KEY")

        if not api_key:
            pytest.skip("VULTR_INFERENCE_API_KEY not set - smoke test skipped")

        try:
            with AgentLoop(api_key=api_key) as agent:
                messages = [{"role": "user", "content": "Say 'test' and nothing else"}]

                response = agent.chat(messages, tools=False)

                assert response is not None
                assert "choices" in response
                assert len(response["choices"]) > 0

        except Exception as e:
            pytest.fail(f"Vultr Inference API call failed: {e}")

    def test_agent_429_retry_with_fake_server(self):
        """Agent retries on 429 with Retry-After using fake HTTP server."""

        class FakeInferenceHandler(http.server.BaseHTTPRequestHandler):
            """Fake OpenAI-compatible server that returns 429 then succeeds."""

            request_count = 0

            def do_POST(self):
                FakeInferenceHandler.request_count += 1

                if FakeInferenceHandler.request_count == 1:
                    # First request: return 429 with Retry-After
                    self.send_response(429)
                    self.send_header("Retry-After", "1")
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"error": "Rate limit exceeded"}')
                else:
                    # Second request: succeed
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    response = {
                        "choices": [{"message": {"content": "test"}}],
                        "model": "test",
                    }
                    self.wfile.write(json.dumps(response).encode())

            def log_message(self, fmt, *args):
                pass  # Suppress logs

        # Start fake server
        server = http.server.HTTPServer(("127.0.0.1", 0), FakeInferenceHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            # Create agent with fake server URL
            agent = AgentLoop(
                api_key="fake_key",
                base_url=f"http://127.0.0.1:{port}",
                allow_custom_base_url=True,
            )

            messages = [{"role": "user", "content": "test"}]
            response = agent.chat(messages, tools=False)

            # Should have succeeded after retry
            assert response is not None
            assert "choices" in response
            # Should have made 2 requests (1 failed, 1 succeeded)
            assert FakeInferenceHandler.request_count == 2

        finally:
            server.shutdown()

    def test_agent_rejects_non_vultr_url(self):
        """Agent rejects non-Vultr base URLs."""
        api_key = "test_key"

        with pytest.raises(ValueError, match="Only Vultr Serverless Inference is allowed"):
            AgentLoop(api_key=api_key, base_url="https://api.openai.com/v1")

    def test_agent_requires_key(self):
        """Agent requires VULTR_INFERENCE_API_KEY."""
        saved_key = os.environ.pop("VULTR_INFERENCE_API_KEY", None)

        try:
            with pytest.raises(ValueError, match="VULTR_INFERENCE_API_KEY"):
                AgentLoop()
        finally:
            if saved_key:
                os.environ["VULTR_INFERENCE_API_KEY"] = saved_key

    def test_agent_default_base_url(self):
        """Agent defaults to Vultr Inference base URL."""
        api_key = "test_key"
        agent = AgentLoop(api_key=api_key)
        assert agent.base_url == "https://api.vultrinference.com/v1"

    def test_agent_default_model(self):
        """Agent defaults to qwen3.8-27b model."""
        api_key = "test_key"
        agent = AgentLoop(api_key=api_key)
        assert agent.model == "qwen3.8-27b"
