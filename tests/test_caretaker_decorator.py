import caretaker as package
import caretaker.decorators.api as api
from caretaker.decorators import caretaker as decorator_caretaker


def test_caretaker_is_public():
    assert package.caretaker is decorator_caretaker


def test_caretaker_delegates_directly_to_repair(monkeypatch):
    calls = {}
    sentinel = object()

    def fake_repair(function=None, **kwargs):
        calls["function"] = function
        calls["kwargs"] = kwargs
        return sentinel

    monkeypatch.setattr(api, "repair", fake_repair)

    def sample(value):
        return value

    result = api.caretaker(
        sample,
        target_id="test.sample",
        tags=frozenset({"test"}),
    )

    assert result is sentinel
    assert calls["function"] is sample
    assert calls["kwargs"]["target_id"] == "test.sample"
    assert calls["kwargs"]["tags"] == frozenset({"test"})


def test_caretaker_decorator_form_delegates_to_repair(monkeypatch):
    calls = {}
    sentinel = object()

    def fake_repair(function=None, **kwargs):
        calls["function"] = function
        calls["kwargs"] = kwargs
        return sentinel

    monkeypatch.setattr(api, "repair", fake_repair)

    result = api.caretaker(target_id="test.decorator")

    assert result is sentinel
    assert calls["function"] is None
    assert calls["kwargs"]["target_id"] == "test.decorator"
