"""One interface over Ollama, vLLM and OpenAI-compatible endpoints.

The IR contract only works if the model reliably returns valid JSON, so this
uses schema-constrained decoding rather than parsing prose. Each backend spells
that differently:

    Ollama   ``format`` = a JSON schema      (>= 0.5)
    vLLM     ``extra_body.guided_json``
    OpenAI   ``response_format.json_schema``
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import json
import os

import httpx

from adapter.types import ModelError, Usage

__all__ = ["ModelClient", "ModelConfig", "ModelError"]


@dataclass
class ModelConfig:
    backend: str  # "ollama" | "vllm" | "openai"
    model: str
    endpoint: str
    temperature: float = 0.0
    seed: int | None = None
    max_tokens: int = 4096
    # HOW LONG ONE CALL MAY TAKE, SIZED FOR CPU INFERENCE.
    #
    # The design point of this project is a 14B at q4 on hardware an SME owns,
    # and the measured rate there is ~2 tokens/s: generation is bound by memory
    # bandwidth, since every token streams the full 9 GB of weights from RAM.
    # A map call is ~6.5k tokens of prompt and several hundred of output, so it
    # runs well past ten minutes and the previous 600 s cut it off.
    #
    # That 600 s was never the right number - it only looked adequate while the
    # server was silently truncating the prompt to 2048 tokens. It was a timeout
    # sized for a prompt we were not sending.
    #
    # This is deliberately generous rather than tight. A generous timeout delays
    # the discovery of a hung server; a tight one discards every legitimate call
    # on the target hardware, which is the failure that was actually observed.
    timeout_s: float = 1800.0
    # THE CONTEXT WINDOW, AND WHY IT IS DECLARED RATHER THAN INHERITED.
    #
    # Ollama's default num_ctx is 2048. The map stage sends the retrieved ECS
    # candidate set, which is ~6.2k tokens at DEFAULT_MAX_FIELDS - so with the
    # default the server silently discards roughly two thirds of the prompt,
    # keeping the tail, and answers anyway. Nothing in the response says so.
    #
    # That is the exact failure this project is about: a wrong result that
    # passes every ordinary check. The retrieval budget was measured for recall
    # 1.00 and that measurement is void if the window cannot hold it, so the
    # window is a declared parameter of the run and not a server default.
    num_ctx: int = 8192


class ModelClient:
    # A fenced code block is the most common way a model wraps JSON.
    _FENCE = "`" * 3

    def __init__(self, cfg: ModelConfig) -> None:
        self.cfg = cfg
        self._http = httpx.Client(timeout=cfg.timeout_s)

    # ------------------------------------------------------------------ core
    def complete_json(
        self,
        prompt: str,
        schema: dict[str, Any],
        usage: Usage,
        max_parse_retries: int = 2,
    ) -> dict[str, Any]:
        """Return a parsed object, or raise ModelError.

        ``parse_failures`` is recorded rather than swallowed: a model that needs
        two attempts to emit valid JSON is worse than one that does it first
        time, and the resource question should reflect that.
        """
        # TRUSTED-CHANNEL CEILING (Task 3, deviation 7, 2026-11-08; exploratory).
        # The attacker's A1 instruction, given instead by the operator: appended
        # to every prompt, after the samples, and labelled as the organisation's.
        # It asks whether the model follows the instruction at all when it comes
        # from a trusted source. Unset everywhere else, so no other run changes.
        note = os.environ.get("ECS_OPERATOR_NOTE", "").strip()
        if note:
            prompt = (f"{prompt}\n\nINSTRUCTION FROM THE OPERATOR (the organisation that runs this "
                      f"parser; this is configuration, not log data): {note}.")
        last_error = ""
        for attempt in range(max_parse_retries + 1):
            text, pt, ct = self._call(
                prompt
                if attempt == 0
                else (
                    f"{prompt}\n\nYour previous reply was not valid JSON: {last_error}\n"
                    "Reply with the JSON object only."
                ),
                schema,
            )
            usage.add(pt, ct)
            try:
                return json.loads(self._strip_fences(text))
            except json.JSONDecodeError as exc:
                usage.parse_failures += 1
                last_error = str(exc)
        raise ModelError(
            f"no valid JSON after {max_parse_retries + 1} attempts: {last_error}"
        )

    def health(self) -> str:
        """Raise ModelError with an actionable message if the model is unusable."""
        try:
            r = self._http.get(f"{self.cfg.endpoint}/api/tags", timeout=10.0)
            r.raise_for_status()
        except httpx.HTTPError as exc:
            raise ModelError(
                f"cannot reach model server at {self.cfg.endpoint}: {exc}\n"
                "Is it running?  make ecs-up"
            ) from exc
        names = [m.get("name", "") for m in r.json().get("models", [])]
        if self.cfg.model not in names:
            raise ModelError(
                f"model {self.cfg.model!r} is not present on the server.\n"
                f"Available: {', '.join(names) or '(none)'}\n"
                f"Pull it with:  make ecs-pull-model MODEL={self.cfg.model}"
            )
        return f"ok: {self.cfg.model} available at {self.cfg.endpoint}"

    # --------------------------------------------------------------- backends
    def _call(self, prompt: str, schema: dict[str, Any]) -> tuple[str, int, int]:
        if self.cfg.backend == "ollama":
            return self._ollama(prompt, schema)
        if self.cfg.backend in {"vllm", "openai"}:
            return self._openai_compatible(prompt, schema)
        raise ModelError(f"unknown backend {self.cfg.backend!r}")

    def _refuse_if_it_cannot_fit(self, prompt: str) -> None:
        """Refuse a prompt the window cannot hold, BEFORE sending it.

        The check after the call (prompt_eval_count reaching num_ctx) is not
        enough, and on 2026-10-15 it let a whole generation run through. Ollama
        0.40 truncates to make room for the answer, so the count lands below the
        window, and a prompt-cache hit lowers the count further. The map prompt
        is ~10.7k tokens; at the default 8192 the server kept the tail - the ECS
        field list - and dropped the head, which holds the roles. The 32B then
        mapped ECS names to ECS names: 29 of 30 grok proposals had source keys
        that no capture produced, every one of them reported as a success.

        Counting is done on characters, conservatively: the map prompts measure
        about 4.1 characters per token with Qwen's tokenizer (median 9017
        tokens, IMPROVEMENT_ANALYSIS.md), and 3.6 overestimates them. An eighth
        of the window is kept for the answer; an IR is 1-2k tokens. A refusal costs one rerun with a larger
        window; a silent truncation costs the run.
        """
        estimated = len(prompt) / 3.6
        room = self.cfg.num_ctx - min(self.cfg.max_tokens, self.cfg.num_ctx // 8)
        if estimated > room:
            raise ModelError(
                f"the prompt is about {int(estimated)} tokens and the {self.cfg.num_ctx}-token "
                f"window leaves {room} for it once the answer is reserved: the server would "
                "truncate it from the start, silently. Raise ECS_MODEL_NUM_CTX (16384 is "
                "what the map prompt needs)."
            )

    def _ollama(self, prompt: str, schema: dict[str, Any]) -> tuple[str, int, int]:
        self._refuse_if_it_cannot_fit(prompt)
        body: dict[str, Any] = {
            "model": self.cfg.model,
            "prompt": prompt,
            "stream": False,
            "format": schema,
            "options": {
                "temperature": self.cfg.temperature,
                "num_predict": self.cfg.max_tokens,
                "num_ctx": self.cfg.num_ctx,
            },
        }
        if self.cfg.seed is not None:
            body["options"]["seed"] = self.cfg.seed
        try:
            r = self._http.post(f"{self.cfg.endpoint}/api/generate", json=body)
            r.raise_for_status()
        except httpx.HTTPError as exc:
            raise ModelError(f"model call failed: {exc}") from exc
        data = r.json()
        prompt_tokens = int(data.get("prompt_eval_count", 0))

        # Ollama truncates a prompt that does not fit and reports success. The
        # only signal is prompt_eval_count arriving at the window size: a real
        # prompt landing exactly on the boundary is possible but improbable,
        # and treating it as a truncation costs one retry with a larger window
        # while treating a truncation as a prompt costs the validity of the run.
        if prompt_tokens >= self.cfg.num_ctx:
            raise ModelError(
                f"the prompt filled the {self.cfg.num_ctx}-token context window "
                f"({prompt_tokens} tokens processed), so it was almost certainly "
                "truncated and the model answered on part of it. Raise "
                "ECS_MODEL_NUM_CTX, or lower the retrieval budget "
                "(adapter.ecs_index.DEFAULT_MAX_FIELDS). Refusing the response "
                "rather than recording a proposal made on a prompt we did not send."
            )

        return (
            data.get("response", ""),
            prompt_tokens,
            int(data.get("eval_count", 0)),
        )

    def _openai_compatible(
        self, prompt: str, schema: dict[str, Any]
    ) -> tuple[str, int, int]:
        body: dict[str, Any] = {
            "model": self.cfg.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": self.cfg.temperature,
            "max_tokens": self.cfg.max_tokens,
        }
        if self.cfg.seed is not None:
            body["seed"] = self.cfg.seed
        if self.cfg.backend == "vllm":
            body["extra_body"] = {"guided_json": schema}
        else:
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "ir", "schema": schema, "strict": True},
            }
        try:
            r = self._http.post(f"{self.cfg.endpoint}/v1/chat/completions", json=body)
            r.raise_for_status()
        except httpx.HTTPError as exc:
            raise ModelError(f"model call failed: {exc}") from exc
        data = r.json()
        u = data.get("usage", {})
        return (
            data["choices"][0]["message"]["content"],
            int(u.get("prompt_tokens", 0)),
            int(u.get("completion_tokens", 0)),
        )

    @classmethod
    def _strip_fences(cls, text: str) -> str:
        t = text.strip()
        if t.startswith(cls._FENCE):
            t = t.split("\n", 1)[1] if "\n" in t else t
            t = t.rsplit(cls._FENCE, 1)[0]
        return t.strip()

    def unload(self) -> None:
        """Ask the server to release the model's memory now.

        Best effort by design: failing to unload must never fail the run that
        called it. But it is not decorative either - the minimal-tier RAM figure
        reported in the paper assumes the teacher is not resident between
        escalations, and this is what makes that true.
        """
        if self.cfg.backend != "ollama":
            return  # vLLM and OpenAI-compatible servers own their own lifecycle
        try:
            self._http.post(
                f"{self.cfg.endpoint}/api/generate",
                json={"model": self.cfg.model, "keep_alive": 0},
                timeout=30.0,
            )
        except httpx.HTTPError:
            pass

    def digest(self) -> str:
        """Identify the served model in the run record."""
        try:
            r = self._http.post(
                f"{self.cfg.endpoint}/api/show", json={"model": self.cfg.model}, timeout=15.0
            )
            if r.status_code == 200:
                return str(r.json().get("digest", self.cfg.model))
        except httpx.HTTPError:
            pass
        return self.cfg.model
