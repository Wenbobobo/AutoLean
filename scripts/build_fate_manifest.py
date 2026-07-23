"""Create a strict FATE source manifest from an operator-provided pinned checkout."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def main() -> None:
    from benchmarks.fate_adapter import build_fate_manifest

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", required=True, type=Path, help="clean FATE v4.28.0 checkout")
    parser.add_argument("--output", required=True, type=Path, help="output manifest path")
    args = parser.parse_args()

    manifest = build_fate_manifest(args.checkout, args.output)
    print(
        json.dumps(
            {
                "schema_version": manifest.schema_version,
                "tasks": len(manifest.tasks),
                "manifest_sha256": manifest.content_hash,
                "output": str(args.output),
            },
            ensure_ascii=True,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
