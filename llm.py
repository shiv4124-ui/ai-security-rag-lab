"""
Talks to a language model over HTTP using only the standard library.

Backends:
  ollama  - free, runs on your machine (https://ollama.com). Default.
  openai  - any OpenAI-compatible API: OpenAI, Groq, Together, LM Studio,
            vLLM, llama.cpp server, etc. Set --base-url and OPENAI_API_KEY.
"""
import json
import os
import urllib.error
import urllib.request


class LLM:
    def __init__(self, backend="ollama", model=None, base_url=None, api_key=None, temperature=0.2):
        self.backend = backend
        self.temperature = temperature
        if backend == "ollama":
            self.model = model or "llama3.2:3b"
            self.base_url = (base_url or os.environ.get("OLLAMA_HOST") or "http://localhost:11434").rstrip("/")
        elif backend == "openai":
            self.model = model or "gpt-4o-mini"
            self.base_url = (base_url or os.environ.get("OPENAI_BASE_URL") or "https://api.openai.com/v1").rstrip("/")
            self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        else:
            raise ValueError(f"Unknown backend: {backend}")

    def _request(self, url, payload=None, headers=None, timeout=300):
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(url, data=data, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"LLM API error {e.code}: {e.read().decode(errors='replace')[:500]}")
        except urllib.error.URLError as e:
            hint = " Is Ollama running? Try: ollama serve" if self.backend == "ollama" else ""
            raise RuntimeError(f"Could not reach {url}: {e.reason}.{hint}")

    def chat(self, messages, max_tokens=None):
        """messages: list of {"role": "system"|"user"|"assistant", "content": str}"""
        if self.backend == "ollama":
            options = {"temperature": self.temperature}
            if max_tokens:
                options["num_predict"] = max_tokens
            data = self._request(
                f"{self.base_url}/api/chat",
                {"model": self.model, "messages": messages, "stream": False, "options": options},
                {"Content-Type": "application/json"},
            )
            return data["message"]["content"]

        payload = {"model": self.model, "messages": messages, "temperature": self.temperature}
        if max_tokens:
            payload["max_tokens"] = max_tokens
        data = self._request(
            f"{self.base_url}/chat/completions",
            payload,
            {"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"},
        )
        return data["choices"][0]["message"]["content"]

    def model_digest(self):
        """Ollama only: the digest of the installed model build, or None."""
        if self.backend != "ollama":
            return None
        try:
            tags = self._request(f"{self.base_url}/api/tags", timeout=10)
        except RuntimeError:
            return None
        for m in tags.get("models", []):
            if m.get("name") == self.model or m.get("model") == self.model:
                return m.get("digest")
        return None
