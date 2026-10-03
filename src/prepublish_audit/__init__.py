"""prepublish-audit: stop secrets and internal information from leaving.

Run it before you open-source a repository, publish a site or share a bundle.
It checks file contents, file names, binary strings, media and document
metadata, archives and (optionally) the full git history against a private
denylist, built-in secret patterns and leak heuristics.
"""

__version__ = "0.1.0"

REPO_URL = "https://github.com/deegitech/prepublish-audit"


def doc_url(path: str) -> str:
    """Link to *path* in this repository at the installed version.

    A pipx or pip install ships the package only, so messages link to the
    documentation instead of naming files such as docs/troubleshooting.md,
    which a user would look for in their own repository.
    """
    return f"{REPO_URL}/blob/v{__version__}/{path}"


__all__ = ["REPO_URL", "__version__", "doc_url"]
