"""Retain immutable input bytes and verify a complete snapshot before each upload."""

import shutil
import tempfile
from pathlib import Path

from . import __version__
from .documents import Document, canonical, digest, file_digest, load, require, write
from .merge import merge
from .models import Manifest, SnapshotRecord


def fingerprint(manifest: Manifest, records: list[Document]) -> str:
    return digest(
        canonical(
            {"manifest": manifest.model_dump(mode="json"), "inputs": records}
        ).encode()
    )


def create(manifest_path: Path, destination: Path) -> Document:
    manifest = Manifest.model_validate(load(manifest_path))
    require(
        not destination.exists(),
        "Output directory already exists; choose a new snapshot path",
    )
    base = manifest_path.resolve().parent
    documents: dict[str, Document] = {}
    records: list[Document] = []
    normalized = manifest.model_dump(mode="json")
    for index, item in enumerate(manifest.inputs):
        path = base / item.sbom
        documents[item.id] = load(path)
        raw = path.read_bytes()
        record: Document = {
            "id": item.id,
            "sha256": digest(raw),
            "artifact_check": "not-applicable",
        }
        if item.artifact:
            record["artifact_check"] = "asserted"
            if item.artifact.path is not None:
                require(
                    file_digest(base / item.artifact.path) == item.artifact.sha256,
                    f"Artifact hash mismatch: {item.id}",
                )
                record["artifact_check"] = "verified-local-file"
            normalized["inputs"][index]["artifact"]["path"] = None
        normalized["inputs"][index]["sbom"] = f"inputs/{item.id}.cdx.json"
        records.append(record)
    saved = Manifest.model_validate(normalized)
    identity = fingerprint(saved, records)
    output = merge(saved, documents, identity)
    result: Document = {
        "schema_version": 1,
        "tool_version": __version__,
        "snapshot": identity,
        "inputs": records,
        "combined_sha256": digest(canonical(output).encode()),
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent) as temp:
        staging = Path(temp) / "snapshot"
        (staging / "inputs").mkdir(parents=True)
        for item in manifest.inputs:
            shutil.copyfile(base / item.sbom, staging / f"inputs/{item.id}.cdx.json")
        write(staging / "manifest.json", saved.model_dump(mode="json"))
        write(staging / "combined.cdx.json", output)
        write(staging / "snapshot.json", result)
        # Validate the copied bytes too; fail if a scanner changed them mid-read.
        verify(staging)
        require(
            not destination.exists(), "Output appeared while preparing the snapshot"
        )
        staging.rename(destination)
    return result


def verify(directory: Path) -> tuple[Manifest, Document, Document]:
    manifest = Manifest.model_validate(load(directory / "manifest.json"))
    result = SnapshotRecord.model_validate(
        load(directory / "snapshot.json")
    ).model_dump(mode="json")
    require(result.get("schema_version") == 1, "Unsupported snapshot contract")
    require(
        result.get("tool_version") == __version__,
        "Retry with the tool version recorded in the snapshot",
    )
    records = result.get("inputs", [])
    require(
        [r["id"] for r in records] == [i.id for i in manifest.inputs],
        "Incomplete snapshot input records",
    )
    documents: dict[str, Document] = {}
    for item, record in zip(manifest.inputs, records, strict=True):
        expected = Path(f"inputs/{item.id}.cdx.json")
        require(item.sbom == expected, "Saved snapshot input path is not canonical")
        path = directory / expected
        require(
            not path.is_symlink(), "Snapshot inputs must be regular files, not symlinks"
        )
        require(
            digest(path.read_bytes()) == record["sha256"],
            "Retained input checksum mismatch",
        )
        documents[item.id] = load(path)
    identity = fingerprint(manifest, records)
    require(result.get("snapshot") == identity, "Snapshot provenance checksum mismatch")
    output = load(directory / "combined.cdx.json")
    require(
        result.get("combined_sha256") == digest(canonical(output).encode()),
        "Combined checksum mismatch",
    )
    require(
        output == merge(manifest, documents, identity),
        "Combined inventory differs from retained inputs",
    )
    return manifest, output, result
