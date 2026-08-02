from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Protocol, Sequence

from .domain import CandidateGeneratorKind


@dataclass(frozen=True, slots=True)
class RepairRequest:
    target_id: str
    function_name: str
    module_name: str
    original_source: str
    incident_summary: str
    traceback_summary: str
    state_summary: str
    policy_summary: str
    registered_cases_summary: str
    logs_summary: str = "No correlated logs."
    guard_summary: str = "No Guard evidence."
    maximum_candidates: int = 1


@dataclass(frozen=True, slots=True)
class CandidateProposal:
    source: str
    explanation: str
    assumptions: tuple[str, ...] = ()
    generated_tests: tuple[str, ...] = ()
    generator_kind: CandidateGeneratorKind = CandidateGeneratorKind.LLM
    generator_name: str = "provider"


@dataclass(frozen=True, slots=True)
class CandidateBatch:
    provider_name: str
    model_name: str | None
    prompt_version: str
    prompt_text: str
    candidates: tuple[CandidateProposal, ...]
    input_tokens: int | None = None
    output_tokens: int | None = None
    raw_response_hash: str | None = None


class RepairProvider(Protocol):
    name: str
    model_name: str | None
    supports_synthesis: bool

    def generate(self, request: RepairRequest) -> CandidateBatch: ...

    def synthesize(
        self,
        request: RepairRequest,
        candidates: Sequence[tuple[CandidateProposal, dict[str, Any]]],
    ) -> CandidateBatch: ...


class StaticRepairProvider:
    """Deterministic provider used by tests and demonstrations."""

    name = "static"
    model_name = None

    def __init__(
        self,
        candidates: Sequence[CandidateProposal],
        *,
        synthesized: CandidateProposal | None = None,
    ) -> None:
        self._candidates = tuple(candidates)
        self._synthesized = synthesized
        self.supports_synthesis = synthesized is not None

    def generate(self, request: RepairRequest) -> CandidateBatch:
        return CandidateBatch(
            provider_name=self.name,
            model_name=None,
            prompt_version="static-v1",
            prompt_text="static provider",
            candidates=self._candidates[: request.maximum_candidates],
        )

    def synthesize(
        self,
        request: RepairRequest,
        candidates: Sequence[tuple[CandidateProposal, dict[str, Any]]],
    ) -> CandidateBatch:
        if self._synthesized is None:
            raise NotImplementedError("No synthesized candidate configured")
        return CandidateBatch(
            provider_name=self.name,
            model_name=None,
            prompt_version="static-synthesis-v1",
            prompt_text="static synthesis provider",
            candidates=(self._synthesized,),
        )


class OllamaRepairProvider:
    """Minimal dependency-free Ollama /api/chat client."""

    name = "ollama"
    supports_synthesis = True

    def __init__(
        self,
        model: str,
        *,
        base_url: str = "http://localhost:11434",
        timeout_seconds: float = 300.0,
        keep_alive: str | int = "30m",
    ) -> None:
        self.model_name = model
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.keep_alive = keep_alive

    def generate(self, request: RepairRequest) -> CandidateBatch:
        prompt = _repair_prompt(request)
        payload = self._chat(prompt)
        candidates = _parse_candidate_response(payload["message"]["content"])
        return CandidateBatch(
            provider_name=self.name,
            model_name=self.model_name,
            prompt_version="function-repair-v1",
            prompt_text=prompt,
            candidates=tuple(candidates[: request.maximum_candidates]),
            input_tokens=payload.get("prompt_eval_count"),
            output_tokens=payload.get("eval_count"),
            raw_response_hash=hashlib.sha256(
                payload["message"]["content"].encode("utf-8")
            ).hexdigest(),
        )

    def synthesize(
        self,
        request: RepairRequest,
        candidates: Sequence[tuple[CandidateProposal, dict[str, Any]]],
    ) -> CandidateBatch:
        prompt = _synthesis_prompt(request, candidates)
        payload = self._chat(prompt)
        proposals = _parse_candidate_response(payload["message"]["content"])
        return CandidateBatch(
            provider_name=self.name,
            model_name=self.model_name,
            prompt_version="candidate-synthesis-v1",
            prompt_text=prompt,
            candidates=tuple(proposals[:1]),
            input_tokens=payload.get("prompt_eval_count"),
            output_tokens=payload.get("eval_count"),
            raw_response_hash=hashlib.sha256(
                payload["message"]["content"].encode("utf-8")
            ).hexdigest(),
        )

    def _chat(self, prompt: str) -> dict[str, Any]:
        body = json.dumps(
            {
                "model": self.model_name,
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "You repair Python functions. Return strict JSON only. "
                            "Do not include markdown fences."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                "stream": False,
                "keep_alive": self.keep_alive,
                "format": "json",
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}/api/chat",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Ollama request failed: {exc}") from exc


def _repair_prompt(request: RepairRequest) -> str:
    return f"""
Repair the Python function below.

Requirements:
- Return JSON with a top-level `candidates` array.
- Each candidate must have `source`, `explanation`, `assumptions`, and `generated_tests`.
- Each generated test is Python source that may call the replacement as `candidate(...)`; do not import modules.
- `source` must contain exactly one complete replacement function definition.
- Preserve the function name and signature.
- Do not include imports, decorators, classes, assignments, or executable top-level statements.
- Generate at most {request.maximum_candidates} candidates.

Target: {request.target_id}
Module: {request.module_name}
Function: {request.function_name}

Effective policy:
{request.policy_summary}

Incident:
{request.incident_summary}

Traceback:
{request.traceback_summary}

State changes:
{request.state_summary}

Registered validation cases and regression corpus:
{request.registered_cases_summary}

Correlated logs:
{request.logs_summary}

Guard behavior evidence and constraints:
{request.guard_summary}

Original source:
{request.original_source}
""".strip()


def _synthesis_prompt(
    request: RepairRequest,
    candidates: Sequence[tuple[CandidateProposal, dict[str, Any]]],
) -> str:
    rendered: list[str] = []
    for index, (candidate, evaluation) in enumerate(candidates, start=1):
        rendered.append(
            f"""
Candidate {index}
Source:
{candidate.source}
Explanation:
{candidate.explanation}
Evaluation:
{json.dumps(evaluation, sort_keys=True)}
""".strip()
        )
    return f"""
Create one consolidated replacement for {request.target_id} using the strongest ideas
from the candidates and their validation evidence. Do not merely concatenate code.
Return the same strict JSON schema used for normal candidate generation, with exactly
one candidate. The consolidated candidate will be independently revalidated.

Original source:
{request.original_source}

Incident:
{request.incident_summary}

{chr(10).join(rendered)}
""".strip()


def _parse_candidate_response(content: str) -> list[CandidateProposal]:
    try:
        payload = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Provider response was not valid JSON: {exc}") from exc
    raw_candidates = payload.get("candidates")
    if not isinstance(raw_candidates, list):
        if isinstance(payload.get("source"), str):
            raw_candidates = [payload]
        else:
            raise ValueError("Provider response does not contain a candidates array")
    proposals: list[CandidateProposal] = []
    for index, item in enumerate(raw_candidates):
        if not isinstance(item, dict) or not isinstance(item.get("source"), str):
            raise ValueError(f"Candidate {index} does not contain source text")
        proposals.append(
            CandidateProposal(
                source=item["source"],
                explanation=str(item.get("explanation", "")),
                assumptions=tuple(str(value) for value in item.get("assumptions", [])),
                generated_tests=tuple(str(value) for value in item.get("generated_tests", [])),
                generator_kind=CandidateGeneratorKind.LLM,
                generator_name="ollama",
            )
        )
    return proposals
