import copy
import json
import subprocess
from pathlib import Path

import pytest
from conftest import inventory

from sbom_reporting.cli import main
from sbom_reporting.documents import (
    CONTAINS,
    IDENTITY,
    ORIGINS,
    SCANNER_PROPERTIES,
    digest,
    load,
    properties,
    write,
)


def test_cli_merges_nested_graphs_platforms_and_origins(manifest_path: Path) -> None:
    base = manifest_path.parent
    second = inventory("container")
    second["specVersion"] = "1.7"
    second["metadata"]["component"]["type"] = "container"
    nested = copy.deepcopy(second["components"][0])
    nested.update({"bom-ref": "nested", "purl": "pkg:npm/example@1.0?arch=arm64"})
    second["components"][0]["components"] = [nested]
    second["dependencies"].append({"ref": "lib", "dependsOn": ["nested"]})
    write(base / "container.json", second)
    manifest = load(manifest_path)
    manifest["inputs"].append(
        {
            "id": "container",
            "role": "artifact",
            "sbom": "container.json",
            "artifact": {
                "name": "example",
                "platform": "linux/arm64",
                "image": "registry.example/app@sha256:" + "b" * 64,
            },
        }
    )
    write(manifest_path, manifest)
    first, second_path = base / "first", base / "second"
    assert main(["merge", str(manifest_path), "--output", str(first)]) == 0
    assert main(["merge", str(manifest_path), "--output", str(second_path)]) == 0
    output = load(first / "combined.cdx.json")
    assert output == load(second_path / "combined.cdx.json")
    assert output["specVersion"] == "1.7"
    assert len(output["components"]) == 4  # two roots, two package/platform identities
    package = next(
        c for c in output["components"] if c.get("purl") == "pkg:npm/example@1.0"
    )
    assert {o["input"] for o in json.loads(properties(package)[ORIGINS])} == {
        "source",
        "container",
    }
    assert len(json.loads(properties(package)[CONTAINS])) == 1
    edges = {e["ref"]: e["dependsOn"] for e in output["dependencies"]}
    assert edges[package["bom-ref"]] == json.loads(properties(package)[CONTAINS])
    assert main(["verify", str(first)]) == 0
    assert main(["merge", str(manifest_path), "--output", str(first)]) == 1


@pytest.mark.parametrize(
    "case",
    [
        "missing",
        "duplicate",
        "dangling",
        "schema",
        "provenance",
        "references",
    ],
)
def test_rejects_incomplete_or_ambiguous_inputs(manifest_path: Path, case: str) -> None:
    manifest = load(manifest_path)
    source = manifest_path.parent / "source.json"
    document = load(source)
    match case:
        case "missing":
            manifest["inputs"][0]["sbom"] = "missing.json"
        case "duplicate":
            manifest["inputs"].append(manifest["inputs"][0])
        case "dangling":
            document["dependencies"][0]["dependsOn"] = ["absent"]
        case "schema":
            document["components"][0]["type"] = "invalid"
        case "provenance":
            document["metadata"]["properties"] = [
                {"name": "a3m:source:commit", "value": "b" * 40}
            ]
        case "references":
            document["components"][0]["pedigree"] = {"ancestors": []}
    write(source, document)
    write(manifest_path, manifest)
    destination = manifest_path.parent / "bad"
    assert main(["merge", str(manifest_path), "--output", str(destination)]) == 1
    assert not destination.exists()


def test_merge_metadata_conflicts_fail(manifest_path: Path) -> None:
    document = load(manifest_path.parent / "source.json")
    duplicate = copy.deepcopy(document["components"][0])
    duplicate.update({"bom-ref": "duplicate", "name": "inconsistent"})
    document["components"].append(duplicate)
    write(manifest_path.parent / "source.json", document)
    assert (
        main(
            ["merge", str(manifest_path), "--output", str(manifest_path.parent / "bad")]
        )
        == 1
    )


@pytest.mark.parametrize("case", ["input", "combined", "manifest", "missing", "record"])
def test_saved_snapshot_cannot_silently_change(manifest_path: Path, case: str) -> None:
    destination = manifest_path.parent / "snapshot"
    assert main(["merge", str(manifest_path), "--output", str(destination)]) == 0
    match case:
        case "input":
            (destination / "inputs/source.cdx.json").write_text("{}")
        case "combined":
            document = load(destination / "combined.cdx.json")
            document["components"].pop()
            write(destination / "combined.cdx.json", document)
        case "manifest":
            document = load(destination / "manifest.json")
            document["version"] = "v2"
            write(destination / "manifest.json", document)
        case "record":
            document = load(destination / "snapshot.json")
            document["inputs"] = "not records"
            write(destination / "snapshot.json", document)
        case "missing":
            (destination / "snapshot.json").unlink()
    assert main(["verify", str(destination)]) == 1


def test_available_artifact_hash_is_verified(manifest_path: Path) -> None:
    artifact = manifest_path.parent / "binary"
    artifact.write_bytes(b"release binary")
    manifest = load(manifest_path)
    manifest["inputs"][0].update(
        role="artifact",
        artifact={
            "name": "binary",
            "platform": "linux/amd64",
            "path": "binary",
            "sha256": digest(artifact.read_bytes()),
        },
    )
    write(manifest_path, manifest)
    destination = manifest_path.parent / "snapshot"
    assert main(["merge", str(manifest_path), "--output", str(destination)]) == 0
    result = load(destination / "snapshot.json")
    assert result["inputs"][0]["artifact_check"] == "verified-local-file"
    artifact.write_bytes(b"changed")
    assert (
        main(
            ["merge", str(manifest_path), "--output", str(manifest_path.parent / "bad")]
        )
        == 1
    )
    # Retrying a saved snapshot does not need or rebuild the original artifact.
    artifact.unlink()
    assert main(["verify", str(destination)]) == 0


def test_occurrences_without_purls_remain_distinct(manifest_path: Path) -> None:
    source = manifest_path.parent / "source.json"
    document = load(source)
    document["components"][0].pop("purl")
    other = copy.deepcopy(document["components"][0])
    other["bom-ref"] = "other"
    document["components"].append(other)
    write(source, document)
    destination = manifest_path.parent / "snapshot"
    assert main(["merge", str(manifest_path), "--output", str(destination)]) == 0
    components = load(destination / "combined.cdx.json")["components"]
    assert len({properties(c)[IDENTITY] for c in components}) == 3


def test_manifest_schema_and_installed_entrypoint(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["manifest-schema"]) == 0
    assert (
        json.loads(capsys.readouterr().out)["properties"]["schema_version"]["const"]
        == 1
    )
    result = subprocess.run(
        ["sbom-reporting", "--version"], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == "0.1.0"


def test_duplicate_json_keys_fail(manifest_path: Path) -> None:
    manifest_path.write_text('{"product":"a", "product":"b"}')
    assert (
        main(
            ["merge", str(manifest_path), "--output", str(manifest_path.parent / "bad")]
        )
        == 1
    )


def test_scanner_multivalued_properties_are_preserved(manifest_path: Path) -> None:
    source = manifest_path.parent / "source.json"
    document = load(source)
    document["vulnerabilities"] = []
    document["components"][0]["properties"] = [
        {"name": "aquasecurity:trivy:DiffID", "value": value}
        for value in ("layer-a", "layer-b", "layer-a")
    ]
    other = copy.deepcopy(document["components"][0])
    other["bom-ref"] = "duplicate"
    other["properties"] = [{"name": "aquasecurity:trivy:DiffID", "value": "layer-c"}]
    document["components"].append(other)
    write(source, document)
    destination = manifest_path.parent / "snapshot"
    assert main(["merge", str(manifest_path), "--output", str(destination)]) == 0
    output = load(destination / "combined.cdx.json")
    component = next(c for c in output["components"] if c.get("purl"))
    assert json.loads(properties(component)[SCANNER_PROPERTIES]) == {
        "aquasecurity:trivy:DiffID": ["layer-a", "layer-b", "layer-c"]
    }


def test_pypi_spelling_is_normalized_without_losing_names(manifest_path: Path) -> None:
    source = manifest_path.parent / "source.json"
    document = load(source)
    first = document["components"][0]
    first.update(name="Friendly_Package", purl="pkg:pypi/friendly-package@1.0")
    second = copy.deepcopy(first)
    second.update({"bom-ref": "other", "name": "friendly-package"})
    document["components"].append(second)
    write(source, document)
    destination = manifest_path.parent / "snapshot"
    assert main(["merge", str(manifest_path), "--output", str(destination)]) == 0
    output = load(destination / "combined.cdx.json")
    packages = [c for c in output["components"] if c.get("purl")]
    assert len(packages) == 1
    assert packages[0]["name"] == "friendly-package"
    assert json.loads(properties(packages[0])["sbom-reporting:scanner-names:v1"]) == [
        "Friendly_Package",
        "friendly-package",
    ]
