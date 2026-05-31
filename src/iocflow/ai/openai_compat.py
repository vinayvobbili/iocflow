"""An OpenAI-compatible chat-model adapter (the bundled ``CommentaryModel``).

Works against any endpoint that speaks the OpenAI ``/chat/completions`` API:
OpenAI, Azure OpenAI, and local/self-hosted servers (vLLM, Ollama, LM Studio,
gateways). Uses ``requests`` directly — no provider SDK.
"""
from __future__ import annotations

from typing import Optional

try:
    import requests
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise ImportError(
        "iocflow AI commentary needs the 'ai' extra: pip install 'iocflow[ai]'"
    ) from exc


class OpenAIChatModel:
    """Chat-completions adapter for any OpenAI-compatible endpoint."""

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        base_url: str = "https://api.openai.com/v1",
        model: str = "gpt-4o-mini",
        session: "requests.Session | None" = None,
        timeout: float = 60.0,
        temperature: float = 0.2,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.temperature = temperature
        self._session = session or requests.Session()

    @property
    def name(self) -> str:
        return f"openai:{self.model}"

    def complete(self, system: str, user: str, *, json: bool = False) -> str:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": self.temperature,
        }
        if json:
            payload["response_format"] = {"type": "json_object"}

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        resp = self._session.post(
            f"{self.base_url}/chat/completions",
            headers=headers,
            json=payload,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"] or ""
