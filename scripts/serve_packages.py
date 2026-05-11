r"""Start a local PyPI server serving the dist\ wheel directory.

Usage
-----
    python scripts\serve_packages.py                    # default: 0.0.0.0:8080
    python scripts\serve_packages.py --port 9090
    python scripts\serve_packages.py --host 127.0.0.1 --port 8080

Teammates install from anywhere on the network:

    pip install --extra-index-url http://HOSTNAME:8080/simple/ secops-term

Requires pypiserver (install once):

    pip install pypiserver

Press Ctrl+C to stop.
"""

from __future__ import annotations

import argparse
import socket
import sys
from pathlib import Path


def _dist_dir() -> Path:
    repo_root = Path(__file__).parent.parent
    dist = repo_root / "dist"
    if not dist.is_dir():
        sys.exit(
            f"[error] dist\\ directory not found at {dist}\n"
            "Build the wheel first:\n"
            "    .venv\\Scripts\\python -m build --wheel"
        )
    wheels = list(dist.glob("*.whl"))
    if not wheels:
        sys.exit(
            f"[error] No .whl files found in {dist}\n"
            "Build the wheel first:\n"
            "    .venv\\Scripts\\python -m build --wheel"
        )
    return dist


def _local_ip() -> str:
    """Best-effort: return the machine's LAN IP for display purposes."""
    try:
        with socket.create_connection(("8.8.8.8", 80), timeout=1) as s:
            return s.getsockname()[0]
    except OSError:
        return "localhost"


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve dist\\ as a local PyPI server.")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")  # noqa: S104
    parser.add_argument("--port", type=int, default=8080, help="Port (default: 8080)")
    args = parser.parse_args()

    try:
        import pypiserver  # type: ignore[import-not-found,import-untyped]
    except ImportError:
        sys.exit("[error] pypiserver is not installed.\nInstall it with:  pip install pypiserver")

    dist = _dist_dir()
    wheels = list(dist.glob("*.whl"))
    ip = _local_ip()

    print(f"[serve] Serving {len(wheels)} wheel(s) from {dist}")
    print("[serve] Teammates install with:")
    print(f"[serve]   pip install --extra-index-url http://{ip}:{args.port}/simple/ secops-term")
    print("[serve] Press Ctrl+C to stop.\n")

    application = pypiserver.app(roots=[str(dist)], authenticate=[])
    pypiserver.serve(
        application,
        host=args.host,
        port=args.port,
    )


if __name__ == "__main__":
    main()
