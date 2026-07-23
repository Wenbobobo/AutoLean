"""The supported Dashboard API launcher with a loopback-safe default."""

from __future__ import annotations

import os
from dataclasses import dataclass

import uvicorn

from .app import create_app


@dataclass(frozen=True, slots=True)
class ServerConfig:
    host: str
    port: int
    remote_mode: bool

    @classmethod
    def from_environment(cls) -> ServerConfig:
        remote_mode = os.environ.get("AUTOLEAN_DASHBOARD_REMOTE") == "1"
        host = os.environ.get("AUTOLEAN_DASHBOARD_HOST", "127.0.0.1")
        port_text = os.environ.get("AUTOLEAN_DASHBOARD_PORT", "8765")
        if not host.strip() or host.strip() != host:
            raise RuntimeError("AUTOLEAN_DASHBOARD_HOST must be a non-empty trimmed host")
        try:
            port = int(port_text)
        except ValueError as error:
            raise RuntimeError("AUTOLEAN_DASHBOARD_PORT must be an integer") from error
        if not 1 <= port <= 65535:
            raise RuntimeError("AUTOLEAN_DASHBOARD_PORT must be between 1 and 65535")
        if not remote_mode and host != "127.0.0.1":
            raise RuntimeError(
                "local dashboard mode only permits AUTOLEAN_DASHBOARD_HOST=127.0.0.1"
            )
        return cls(host=host, port=port, remote_mode=remote_mode)


def main() -> None:
    config = ServerConfig.from_environment()
    # create_app applies the matching bearer-token requirement in remote mode.
    uvicorn.run(create_app(), host=config.host, port=config.port, log_level="info")


if __name__ == "__main__":
    main()
