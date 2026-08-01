"""Short entry point for the receipt-bound iFEM census OCI worker."""

from autolean_builder.ifem_prerequisite_census_oci import main

__all__ = ["main"]

if __name__ == "__main__":
    raise SystemExit(main())
