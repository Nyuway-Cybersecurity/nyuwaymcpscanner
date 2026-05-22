"""Source dispatch. Maps a target spec like ``github:owner/repo`` to a context
manager yielding a local path."""

from .local import fetch_local
from .github import fetch_github, GitHubFetchError
from .npm import fetch_npm, NpmFetchError
from .pypi import fetch_pypi, PyPIFetchError


class UnsupportedSource(Exception):
    """Source prefix is not recognised."""


def resolve(spec: str):
    """Return a context manager that yields a local Path for the given spec."""
    if spec.startswith("github:"):
        return fetch_github(spec)
    if spec.startswith("npm:"):
        return fetch_npm(spec)
    if spec.startswith("pypi:"):
        return fetch_pypi(spec)
    if ":" in spec and not _looks_like_windows_path(spec):
        prefix = spec.split(":", 1)[0]
        raise UnsupportedSource(
            f"Unknown source prefix: {prefix!r}. "
            f"Supported: github:, npm:, pypi:, or a local path."
        )
    return fetch_local(spec)


def _looks_like_windows_path(spec: str) -> bool:
    """Heuristic: 'C:\\foo' is a local path, not an unsupported source."""
    return len(spec) >= 2 and spec[1] == ":" and spec[0].isalpha()


__all__ = [
    "resolve",
    "UnsupportedSource",
    "GitHubFetchError",
    "NpmFetchError",
    "PyPIFetchError",
]
