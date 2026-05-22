"""Tests for the local LLM setup module. All external calls are mocked."""
import pytest

from nyuwaymcpscanner.setup import local_llm as setup_mod
from nyuwaymcpscanner.setup.local_llm import (
    run_setup, SetupError, list_installed_models,
)


class FakeResponse:
    def __init__(self, payload, status=200, raise_status=None):
        self._payload = payload
        self.status_code = status
        self._raise = raise_status

    def raise_for_status(self):
        if self._raise:
            raise self._raise

    def json(self):
        return self._payload


def test_run_setup_raises_when_ollama_not_installed(monkeypatch):
    monkeypatch.setattr(setup_mod, "is_ollama_installed", lambda: False)
    with pytest.raises(SetupError) as exc:
        run_setup()
    assert "not installed" in str(exc.value).lower()


def test_run_setup_raises_when_service_not_running(monkeypatch):
    monkeypatch.setattr(setup_mod, "is_ollama_installed", lambda: True)
    monkeypatch.setattr(setup_mod, "is_ollama_running", lambda: False)
    with pytest.raises(SetupError) as exc:
        run_setup()
    assert "not running" in str(exc.value).lower()


def test_run_setup_succeeds_when_everything_present(monkeypatch):
    monkeypatch.setattr(setup_mod, "is_ollama_installed", lambda: True)
    monkeypatch.setattr(setup_mod, "is_ollama_running", lambda: True)
    monkeypatch.setattr(setup_mod, "list_installed_models", lambda: ["llama3.1:8b"])
    # pull_model should not be called when model is already present.
    monkeypatch.setattr(setup_mod, "pull_model", lambda model=None: (_ for _ in ()).throw(
        AssertionError("pull_model should not run when model is already installed")))
    status = run_setup()
    assert status["ollama_installed"] is True
    assert status["ollama_running"] is True
    assert status["model_present"] is True


def test_run_setup_pulls_model_when_missing(monkeypatch):
    monkeypatch.setattr(setup_mod, "is_ollama_installed", lambda: True)
    monkeypatch.setattr(setup_mod, "is_ollama_running", lambda: True)
    monkeypatch.setattr(setup_mod, "list_installed_models", lambda: [])
    pulled = {"model": None}
    def fake_pull(model=setup_mod.RECOMMENDED_MODEL):
        pulled["model"] = model
        return 0
    monkeypatch.setattr(setup_mod, "pull_model", fake_pull)
    status = run_setup()
    assert pulled["model"] == setup_mod.RECOMMENDED_MODEL
    assert status["model_present"] is True


def test_run_setup_raises_when_pull_fails(monkeypatch):
    monkeypatch.setattr(setup_mod, "is_ollama_installed", lambda: True)
    monkeypatch.setattr(setup_mod, "is_ollama_running", lambda: True)
    monkeypatch.setattr(setup_mod, "list_installed_models", lambda: [])
    monkeypatch.setattr(setup_mod, "pull_model", lambda model=None: 7)
    with pytest.raises(SetupError) as exc:
        run_setup()
    assert "exited with code 7" in str(exc.value)


def test_list_installed_models_returns_empty_on_network_error(monkeypatch):
    import requests as real_requests
    def boom(*a, **kw):
        raise real_requests.ConnectionError("nope")
    monkeypatch.setattr(setup_mod.requests, "get", boom)
    assert list_installed_models() == []


def test_list_installed_models_parses_ollama_response(monkeypatch):
    payload = {"models": [{"name": "llama3.1:8b"}, {"name": "qwen2.5:7b"}]}
    monkeypatch.setattr(setup_mod.requests, "get", lambda *a, **kw: FakeResponse(payload))
    models = list_installed_models()
    assert "llama3.1:8b" in models
    assert "qwen2.5:7b" in models


def test_list_installed_models_handles_garbage_response(monkeypatch):
    monkeypatch.setattr(setup_mod.requests, "get",
                        lambda *a, **kw: FakeResponse({"unexpected": "shape"}))
    models = list_installed_models()
    assert models == []
