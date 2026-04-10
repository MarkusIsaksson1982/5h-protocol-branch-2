"""
main.py – Docker entry point shim

Branch 1's docker-compose.yml calls `uvicorn main:app`.
This shim re-exports the real FastAPI application from five_h_proxy.proxy
so the compose service command needs no change.

Do not add business logic here. All implementation lives in five_h_proxy/.

Authors: Claude (Anthropic)
"""

from five_h_proxy.proxy import app  # noqa: F401 – re-exported for uvicorn discovery

__all__ = ["app"]
