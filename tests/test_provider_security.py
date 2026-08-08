import pytest

from caretaker import OllamaBehaviorAssessmentProvider, OllamaRepairProvider, OllamaRootCauseProvider


def test_ollama_providers_default_to_loopback_only() -> None:
    OllamaRepairProvider("model", base_url="http://127.0.0.1:11434")
    OllamaBehaviorAssessmentProvider("model", base_url="http://localhost:11434")
    OllamaRootCauseProvider(model="model", endpoint="http://[::1]:11434/api/generate")

    with pytest.raises(ValueError, match="allow_remote_endpoint"):
        OllamaRepairProvider("model", base_url="http://ollama:11434")

    OllamaRepairProvider(
        "model", base_url="http://ollama:11434", allow_remote_endpoint=True
    )
