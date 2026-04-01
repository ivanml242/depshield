"""Package downloader for npm and PyPI packages.

Downloads source tarballs/sdists from npm and PyPI registries,
extracts them into temporary directories for analysis, and provides
cleanup utilities to remove temporary files when done.
"""

import io
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path

import requests


# ---------------------------------------------------------------------------
# npm registry helpers
# ---------------------------------------------------------------------------

_NPM_REGISTRY = "https://registry.npmjs.org"


def _get_npm_tarball_url(name: str, version: str) -> str:
    """Get the tarball download URL for an npm package version.

    Queries ``registry.npmjs.org/{name}`` and extracts
    ``versions[version].dist.tarball``.
    """
    url = f"{_NPM_REGISTRY}/{name}"
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    version_data = data.get("versions", {}).get(version)
    if not version_data:
        raise ValueError(f"Version {version} not found for npm package {name}")

    tarball_url = version_data.get("dist", {}).get("tarball")
    if not tarball_url:
        raise ValueError(f"No tarball URL found for {name}@{version}")

    return tarball_url


# ---------------------------------------------------------------------------
# PyPI helpers
# ---------------------------------------------------------------------------

_PYPI_BASE = "https://pypi.org/pypi"


def _get_pypi_sdist_url(name: str, version: str) -> str | None:
    """Get the sdist (.tar.gz or .zip) download URL for a PyPI package version.

    Queries ``pypi.org/pypi/{name}/{version}/json`` and looks for an sdist
    in the ``urls`` field.  Falls back to a wheel (.whl) if no sdist is
    available.
    """
    url = f"{_PYPI_BASE}/{name}/{version}/json"
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    urls = data.get("urls", [])

    # Prefer sdist (.tar.gz)
    for entry in urls:
        if entry.get("packagetype") == "sdist":
            return entry["url"]

    # Fallback: any .tar.gz or .zip
    for entry in urls:
        filename = entry.get("filename", "")
        if filename.endswith(".tar.gz") or filename.endswith(".zip"):
            return entry["url"]

    # Last resort: wheel
    for entry in urls:
        if entry.get("packagetype") == "bdist_wheel":
            return entry["url"]

    return None


# ---------------------------------------------------------------------------
# Download & extract
# ---------------------------------------------------------------------------

def _download_and_extract(download_url: str, dest_dir: str) -> Path:
    """Download an archive from *download_url* and extract it into *dest_dir*.

    Supports ``.tar.gz``, ``.tgz``, ``.zip``, and ``.whl`` (which are zips).
    Returns the path to the extracted directory.
    """
    resp = requests.get(download_url, timeout=60, stream=True)
    resp.raise_for_status()
    content = resp.content

    dest = Path(dest_dir)

    if download_url.endswith((".tar.gz", ".tgz")):
        with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as tar:
            # Security: filter out absolute paths and path traversal
            members = [
                m for m in tar.getmembers()
                if not m.name.startswith("/") and ".." not in m.name
            ]
            tar.extractall(path=dest, members=members, filter="data")

    elif download_url.endswith((".zip", ".whl")):
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            # Security: filter out absolute paths and path traversal
            safe_names = [
                n for n in zf.namelist()
                if not n.startswith("/") and ".." not in n
            ]
            for name in safe_names:
                zf.extract(name, path=dest)

    else:
        # Try tar.gz first, then zip
        try:
            with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as tar:
                members = [
                    m for m in tar.getmembers()
                    if not m.name.startswith("/") and ".." not in m.name
                ]
                tar.extractall(path=dest, members=members, filter="data")
        except tarfile.TarError:
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                safe_names = [
                    n for n in zf.namelist()
                    if not n.startswith("/") and ".." not in n
                ]
                for name in safe_names:
                    zf.extract(name, path=dest)

    return dest


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class PackageDownloader:
    """Downloads and extracts package source code for analysis.

    Usage
    -----
    >>> dl = PackageDownloader()
    >>> src_dir = dl.download("is-odd", "3.0.1", ecosystem="npm")
    >>> # ... analyze files in src_dir ...
    >>> dl.cleanup()
    """

    def __init__(self) -> None:
        self._temp_dirs: list[str] = []

    def download(
        self,
        name: str,
        version: str,
        *,
        ecosystem: str = "npm",
    ) -> Path:
        """Download and extract a package's source code.

        Parameters
        ----------
        name:
            Package name (e.g. ``"is-odd"`` or ``"requests"``).
        version:
            Exact resolved version string (e.g. ``"3.0.1"``).
        ecosystem:
            ``"npm"`` or ``"pypi"``.

        Returns
        -------
        Path
            Path to the temporary directory containing the extracted source.
        """
        temp_dir = tempfile.mkdtemp(prefix=f"depshield_{name}_{version}_")
        self._temp_dirs.append(temp_dir)

        if ecosystem == "npm":
            url = _get_npm_tarball_url(name, version)
        elif ecosystem == "pypi":
            url = _get_pypi_sdist_url(name, version)
            if url is None:
                raise ValueError(
                    f"No downloadable archive found for PyPI package {name}=={version}"
                )
        else:
            raise ValueError(f"Unknown ecosystem: {ecosystem!r}")

        _download_and_extract(url, temp_dir)
        return Path(temp_dir)

    def cleanup(self) -> None:
        """Remove all temporary directories created by this downloader."""
        for d in self._temp_dirs:
            shutil.rmtree(d, ignore_errors=True)
        self._temp_dirs.clear()

    def __enter__(self) -> "PackageDownloader":
        return self

    def __exit__(self, *args: object) -> None:
        self.cleanup()
