from __future__ import annotations

import argparse
import json
from pathlib import Path

from macos_inspector.core.detection_validation import DEFAULT_SCENARIOS, validate_detections
from macos_inspector.reporters.common import secure_write_text


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate synthetic, read-only detection regression scenarios")
    parser.add_argument("--scenarios", type=Path, default=DEFAULT_SCENARIOS)
    parser.add_argument("--output", type=Path, help="Optional owner-only JSON validation report")
    args = parser.parse_args()
    result = validate_detections(args.scenarios)
    encoded = json.dumps(result, indent=2) + "\n"
    if args.output:
        secure_write_text(args.output, encoded)
    print(encoded, end="")
    return 1 if result["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
