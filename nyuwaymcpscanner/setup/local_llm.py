"""Ollama setup and model management for the Baseline local LLM layer."""

from __future__ import annotations

import shutil
import subprocess

import requests

OLLAMA_HOST = "http://127.0.0.1:11434"
OLLAMA_TAGS_URL = f"{OLLAMA_HOST}/api/tags"
RECOMMENDED_MODEL = "llama3.1:8b"
CHECK_TIMEOUT = 5


class SetupError(Exception):
    """Setup precondition failed in a way the user must address."""


def is_ollama_installed() -> bool:
    """Return True if the `ollama` binary is on PATH."""
    return shutil.which("ollama") is not None


def is_ollama_running() -> bool:
    """Return True if the Ollama HTTP service responds on localhost."""
    try:
        resp = requests.get(OLLAMA_TAGS_URL, timeout=CHECK_TIMEOUT)
        return resp.status_code == 200
    except requests.RequestException:
        return False


def list_installed_models() -> list[str]:
    """Return the list of model tags currently available in the local Ollama."""
    try:
        resp = requests.get(OLLAMA_TAGS_URL, timeout=CHECK_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError):
        return []
    models = data.get("models") or []
    return [str(m.get("name", "")) for m in models if isinstance(m, dict)]


def pull_model(model: str = RECOMMENDED_MODEL) -> int:
    """Run `ollama pull <model>` and return the process exit code.

    Streams output to the caller's stdout/stderr so the user sees progress.
    Raises SetupError if the `ollama` binary is missing.
    """
    if not is_ollama_installed():
        raise SetupError(
            "Ollama is not installed. Install it from https://ollama.com/download "
            "then re-run `nyuwaymcpscanner setup`."
        )
    completed = subprocess.run(["ollama", "pull", model], check=False)
    return completed.returncode


def run_setup(model: str = RECOMMENDED_MODEL) -> dict:
    """End-to-end setup check. Returns a status dict; raises SetupError on hard failure."""
    status = {
        "ollama_installed": is_ollama_installed(),
        "ollama_running": is_ollama_running(),
        "model": model,
        "model_present": False,
    }

    if not status["ollama_installed"]:
        raise SetupError(
            "Ollama is not installed.\n"
            "Install it from https://ollama.com/download, then re-run setup."
        )

    if not status["ollama_running"]:
        raise SetupError(
            "Ollama is installed but the service is not running.\n"
            "Start it with `ollama serve` (or your platform's service manager), then re-run setup."
        )

    installed = list_installed_models()
    status["model_present"] = any(
        name == model or name.startswith(model + ":") for name in installed
    )

    if not status["model_present"]:
        rc = pull_model(model)
        if rc != 0:
            raise SetupError(f"`ollama pull {model}` exited with code {rc}.")
        status["model_present"] = True

    return status
