"""Materialize a pending, source-free iFEM local-use request."""

from autolean_builder.ifem_local_use_request import main

__all__ = ["main"]

if __name__ == "__main__":
    raise SystemExit(main())
