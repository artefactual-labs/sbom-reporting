"""Strict JSON/schema boundaries around scanner-owned CycloneDX structures."""

import hashlib
import json
from pathlib import Path
from typing import Any, cast

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from packageurl import PackageURL

# CycloneDX is an extensible external document, validated before processing.
# Typed models cover the caller contract; arbitrary component metadata stays JSON.
type Document = dict[str, Any]
PREFIX = "sbom-reporting:"
ORIGINS = PREFIX + "origins:v1"
IDENTITY = PREFIX + "identity"
CONTAINS = PREFIX + "contains:v1"
SCANNER_PROPERTIES = PREFIX + "scanner-properties:v1"
ROOT = "urn:sbom-reporting:application"
VERSIONS = {"1.6": SchemaVersion.V1_6, "1.7": SchemaVersion.V1_7}


class ReportingError(Exception):
    """An actionable reporting failure, safe to show without a traceback."""


def require(condition: object, message: str) -> None:
    if not condition:
        raise ReportingError(message)


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def unique_object(pairs: list[tuple[str, Any]]) -> Document:
    result: Document = {}
    for key, value in pairs:
        require(key not in result, f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def load(path: Path) -> Document:
    value = json.loads(path.read_bytes(), object_pairs_hook=unique_object)
    require(isinstance(value, dict), f"Expected a JSON object: {path.name}")
    return cast(Document, value)


def write(path: Path, document: object) -> None:
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")


def properties(component: Document) -> dict[str, str]:
    result: dict[str, str] = {}
    for prop in component.get("properties", []):
        name, value = prop["name"], prop["value"]
        require(name not in result, f"Duplicate component property: {name}")
        result[name] = value
    return result


def scanner_properties(component: Document) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for prop in component.get("properties", []):
        values = result.setdefault(prop["name"], [])
        if prop["value"] not in values:
            values.append(prop["value"])
    return {name: sorted(values) for name, values in result.items()}


def set_properties(component: Document, values: dict[str, str]) -> None:
    component["properties"] = [
        {"name": name, "value": value} for name, value in sorted(values.items())
    ]


def purl(value: str) -> str:
    try:
        return PackageURL.from_string(value).to_string()
    except ValueError as error:
        raise ReportingError("Invalid package URL") from error


def all_components(document: Document) -> list[Document]:
    result: list[Document] = []

    def visit(component: Document) -> None:
        result.append(component)
        for child in component.get("components", []):
            visit(child)

    root = document.get("metadata", {}).get("component")
    if root is not None:
        visit(root)
    for component in document.get("components", []):
        visit(component)
    return result


def has_nested_reference(value: object) -> bool:
    if isinstance(value, dict):
        return bool({"bom-ref", "ref"} & value.keys()) or any(
            has_nested_reference(child) for child in value.values()
        )
    if isinstance(value, list):
        return any(has_nested_reference(child) for child in value)
    return False


def validate(document: Document, *, supported_shape: bool = True) -> None:
    version = document.get("specVersion")
    if not isinstance(version, str) or version not in VERSIONS:
        raise ReportingError("Supported CycloneDX JSON versions: 1.6 and 1.7")
    errors = JsonStrictValidator(VERSIONS[version]).validate_str(canonical(document))
    require(not errors, "CycloneDX schema validation failed")
    components = all_components(document)
    require(components, "Empty component inventory")
    refs = [component.get("bom-ref") for component in components]
    require(all(refs) and len(refs) == len(set(refs)), "Missing or duplicate bom-ref")
    for component in components:
        scanner_properties(component)
        if "purl" in component:
            purl(component["purl"])
    for edge in document.get("dependencies", []):
        require(set(edge) <= {"ref", "dependsOn"}, "Unsupported dependency edge fields")
        require(edge["ref"] in refs, "Dangling dependency source")
        require(
            set(edge.get("dependsOn", [])) <= set(refs), "Dangling dependency target"
        )
    if not supported_shape:
        return
    require(
        set(document)
        <= {
            "$schema",
            "bomFormat",
            "specVersion",
            "version",
            "serialNumber",
            "metadata",
            "components",
            "dependencies",
            "vulnerabilities",
        },
        "Unsupported BOM sections: provide inventory-only scanner output",
    )
    require(
        not document.get("vulnerabilities"),
        "Vulnerability records are not inventory input",
    )
    # These structures can contain references that this implementation cannot remap.
    for component in components:
        require(
            not set(component)
            & {"pedigree", "evidence", "modelCard", "data", "cryptoProperties"},
            "Unsupported reference-bearing component structure",
        )
        require(
            not has_nested_reference(
                {
                    k: v
                    for k, v in component.items()
                    if k not in {"bom-ref", "components"}
                }
            ),
            "Unsupported nested component references",
        )
    metadata = document.get("metadata", {})
    require(
        not set(metadata) & {"lifecycles", "manufacture"},
        "Unsupported metadata structure",
    )
