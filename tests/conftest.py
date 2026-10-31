from pathlib import Path

import pytest

from sbom_reporting.documents import Document, write

PARENT = "7e0368f9-4655-4de9-91fb-cdba489c6703"
COMMIT = "a" * 40


def inventory(name: str = "source") -> Document:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": name,
                "version": "1",
                "bom-ref": "root",
            }
        },
        "components": [
            {
                "type": "library",
                "name": "example",
                "version": "1.0",
                "purl": "pkg:npm/example@1.0",
                "bom-ref": "lib",
            }
        ],
        "dependencies": [{"ref": "root", "dependsOn": ["lib"]}],
    }


@pytest.fixture
def manifest_path(tmp_path: Path) -> Path:
    write(tmp_path / "source.json", inventory())
    manifest = {
        "schema_version": 1,
        "product": "example",
        "version": "v1.0.0",
        "kind": "release",
        "repository": "https://github.com/example/app",
        "source_commit": COMMIT,
        "ci_run": "https://github.com/example/app/actions/runs/123/attempts/1",
        "parent_uuid": PARENT,
        "inputs": [{"id": "source", "role": "source", "sbom": "source.json"}],
    }
    path = tmp_path / "manifest.json"
    write(path, manifest)
    return path
