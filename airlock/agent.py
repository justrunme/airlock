"""Agent loop using Vultr Serverless Inference."""

import os
import time
from typing import Any

import httpx

from airlock.schemas import ActionRequest


class AgentLoop:
    """Agent loop that interacts with Vultr Serverless Inference."""

    VULTR_BASE_URL = "https://api.vultrinference.com/v1"

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str = "qwen3.8-27b",
        allow_custom_base_url: bool = False,
    ):
        """Initialize agent loop."""
        self.api_key = api_key or os.environ.get("VULTR_INFERENCE_API_KEY")
        if not self.api_key:
            raise ValueError("VULTR_INFERENCE_API_KEY environment variable must be set")

        # Enforce Vultr base URL unless explicitly allowed for testing
        if base_url is None:
            self.base_url = self.VULTR_BASE_URL
        elif base_url != self.VULTR_BASE_URL and not allow_custom_base_url:
            raise ValueError(
                f"Only Vultr Serverless Inference is allowed. "
                f"Expected {self.VULTR_BASE_URL}, got {base_url}"
            )
        else:
            self.base_url = base_url

        self.model = model
        self.client = httpx.Client(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=60.0,
        )
        self.max_retries = 3

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.client.close()

    def _get_tool_schema(self) -> list[dict[str, Any]]:
        """Get tool schema for function calling."""
        return [
            {
                "type": "function",
                "function": {
                    "name": "run_code",
                    "description": "Execute code in a secure sandbox",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "lang": {
                                "type": "string",
                                "enum": ["python", "shell"],
                                "description": "Programming language",
                            },
                            "code": {
                                "type": "string",
                                "description": "Code to execute",
                            },
                            "network": {
                                "type": "string",
                                "enum": ["none", "allowlist"],
                                "description": "Network access level",
                            },
                        },
                        "required": ["lang", "code"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "read_artifact",
                    "description": "Read an artifact from previous execution",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "description": "Artifact name"},
                        },
                        "required": ["name"],
                    },
                },
            },
        ]

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: bool = True,
        max_tokens: int = 4096,
    ) -> dict[str, Any] | None:
        """Send chat request with retries.

        The default model is a reasoning model: it spends part of max_tokens on
        reasoning before the answer, so keep max_tokens >= 2048.
        """
        request_data: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
        }

        if tools:
            request_data["tools"] = self._get_tool_schema()

        for attempt in range(self.max_retries):
            try:
                response = self.client.post("/chat/completions", json=request_data)

                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", "5"))
                    if attempt < self.max_retries - 1:
                        time.sleep(retry_after)
                        continue
                    return None

                response.raise_for_status()
                return response.json()

            except httpx.HTTPError:
                if attempt == self.max_retries - 1:
                    raise
                time.sleep(2**attempt)

        return None

    def parse_tool_call(self, response: dict[str, Any]) -> ActionRequest | None:
        """Parse tool call from response into ActionRequest."""
        if not response:
            return None

        choices = response.get("choices", [])
        if not choices:
            return None

        message = choices[0].get("message", {})
        tool_calls = message.get("tool_calls", [])

        if not tool_calls:
            return None

        tool_call = tool_calls[0]
        function = tool_call.get("function", {})
        tool_name = function.get("name")

        if tool_name not in {"run_code", "read_artifact"}:
            return None

        import json

        args = json.loads(function.get("arguments", "{}"))

        return ActionRequest(
            id=tool_call.get("id", "unknown"),
            task_id="default",
            tool=tool_name,
            lang=args.get("lang"),
            code=args.get("code"),
            network=args.get("network", "none"),
            requested={},
        )

    def run_task(self, task_description: str) -> list[dict[str, Any]]:
        """Run a task through the agent loop."""
        messages = [{"role": "user", "content": task_description}]

        iterations = []
        max_iterations = 5

        for i in range(max_iterations):
            response = self.chat(messages)
            if not response:
                break

            iterations.append({"iteration": i + 1, "response": response})

            action = self.parse_tool_call(response)
            if action:
                return iterations

            choices = response.get("choices", [])
            if choices:
                message = choices[0].get("message", {})
                if message.get("content"):
                    break

        return iterations
