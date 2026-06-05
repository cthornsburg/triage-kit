#!/usr/bin/env python3
import json
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "shared" / "schema"
SAMPLE_DIR = ROOT / "samples" / "collector-output" / "batch-2026-05-09-01"


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def main() -> int:
    artifact_schema_path = SCHEMA_DIR / "artifact-record.schema.json"
    bundle_schema_path = SCHEMA_DIR / "collector-bundle-manifest.schema.json"
    batch_schema_path = SCHEMA_DIR / "batch-manifest.schema.json"

    artifact_schema = load_json(artifact_schema_path)
    bundle_schema = load_json(bundle_schema_path)
    batch_schema = load_json(batch_schema_path)

    artifact_resource = Resource.from_contents(
        artifact_schema,
        default_specification=DRAFT202012,
    )
    registry = Registry().with_resources(
        [
            ("./artifact-record.schema.json", artifact_resource),
            (artifact_schema["$id"], artifact_resource),
        ]
    )

    bundle_validator = Draft202012Validator(bundle_schema, registry=registry)
    batch_validator = Draft202012Validator(batch_schema, registry=registry)

    batch_manifest = SAMPLE_DIR / "batch-manifest.json"
    batch_validator.validate(load_json(batch_manifest))
    print(f"OK {batch_manifest.relative_to(ROOT)}")

    for manifest in sorted(SAMPLE_DIR.glob("case-*/manifest.json")):
        bundle_validator.validate(load_json(manifest))
        print(f"OK {manifest.relative_to(ROOT)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
