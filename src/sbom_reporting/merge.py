"""Conservative identity merging with graph and containment preservation."""

import copy
import json
import re
import uuid

from packageurl import PackageURL

from .documents import (
    CONTAINS,
    IDENTITY,
    ORIGINS,
    PREFIX,
    ROOT,
    SCANNER_PROPERTIES,
    Document,
    all_components,
    canonical,
    digest,
    properties,
    purl,
    require,
    scanner_properties,
    set_properties,
    validate,
)
from .models import Inventory, Manifest


def combine(target: Document, incoming: Document) -> None:
    """Keep all list evidence and reject ambiguous scalar/dictionary conflicts."""
    for key, value in incoming.items():
        if key not in target:
            target[key] = copy.deepcopy(value)
        elif isinstance(value, list) and isinstance(target[key], list):
            for item in value:
                if item not in target[key]:
                    target[key].append(copy.deepcopy(item))
        elif isinstance(value, dict) and isinstance(target[key], dict):
            combine(target[key], value)
        else:
            require(target[key] == value, f"Conflicting component metadata: {key}")


def origin(item: Inventory) -> Document:
    value: Document = {"input": item.id, "role": item.role}
    if item.artifact:
        value["artifact"] = item.artifact.model_dump(
            mode="json", exclude={"path"}, exclude_none=True
        )
    return value


def merge(
    manifest: Manifest, inputs: dict[str, Document], fingerprint: str
) -> Document:
    require(
        set(inputs) == {i.id for i in manifest.inputs},
        "Declared inventories differ from inputs",
    )
    merged: dict[str, Document] = {}
    origins: dict[str, dict[str, Document]] = {}
    containment: dict[str, set[str]] = {}
    graph: dict[str, set[str]] = {ROOT: set()}
    version = (
        "1.7" if any(b.get("specVersion") == "1.7" for b in inputs.values()) else "1.6"
    )

    for item in manifest.inputs:
        document = inputs[item.id]
        validate(document)
        metadata = document.get("metadata", {})
        for prop in metadata.get("properties", []):
            if (
                prop["name"].endswith(":source:commit")
                or prop["name"] == PREFIX + "source-commit"
            ):
                require(
                    prop["value"] == manifest.source_commit, "Conflicting source commit"
                )
            if prop["name"].endswith((":project:version", ":release:version")):
                require(
                    prop["value"] == manifest.version, "Conflicting reporting version"
                )
            if (
                prop["name"].endswith(":image:reference")
                and item.artifact
                and item.artifact.image
            ):
                require(
                    prop["value"] == item.artifact.image, "Conflicting image identity"
                )
        original_root = metadata.get("component")
        require(
            original_root is not None,
            "Each scanner inventory needs a metadata component",
        )
        components = all_components(document)
        local: dict[str, str] = {}
        # First pass establishes all identities, including nested components.
        for c in components:
            require(
                not any(n.startswith(PREFIX) for n in scanner_properties(c)),
                "Reserved reporting properties in scanner input",
            )
            identity: object = ["occurrence", item.id, c["bom-ref"]]
            if c.get("purl") and c is not original_root:
                identity = [
                    "package",
                    c["type"],
                    purl(c["purl"]),
                    c.get("version"),
                    c.get("cpe"),
                ]
            ref = "urn:sbom-reporting:component:" + digest(canonical(identity).encode())
            local[c["bom-ref"]] = ref
        for c in components:
            ref = local[c["bom-ref"]]
            incoming = copy.deepcopy(c)
            incoming["bom-ref"] = ref
            if incoming.get("purl"):
                incoming["purl"] = purl(incoming["purl"])
            children = incoming.pop("components", [])
            containment.setdefault(ref, set()).update(
                local[v["bom-ref"]] for v in children
            )
            values = {}
            if incoming.get("purl"):
                parsed = PackageURL.from_string(incoming["purl"])
                if parsed.type == "pypi":
                    normalized_name = re.sub(r"[-_.]+", "-", incoming["name"]).lower()
                    require(
                        normalized_name == parsed.name, "PyPI name disagrees with PURL"
                    )
                    values[PREFIX + "scanner-names:v1"] = canonical([incoming["name"]])
                    incoming["name"] = parsed.name
            raw_properties = scanner_properties(incoming)
            if raw_properties:
                values[SCANNER_PROPERTIES] = canonical(raw_properties)
            if c is original_root:
                values[PREFIX + "scanner-metadata"] = canonical(
                    {k: v for k, v in metadata.items() if k != "component"}
                )
            incoming.pop("properties", None)
            if ref in merged:
                existing = properties(merged[ref])
                if SCANNER_PROPERTIES in values:
                    retained = json.loads(existing.get(SCANNER_PROPERTIES, "{}"))
                    for name, observations in raw_properties.items():
                        retained[name] = sorted(
                            set(retained.get(name, [])) | set(observations)
                        )
                    values[SCANNER_PROPERTIES] = canonical(retained)
                    existing.pop(SCANNER_PROPERTIES, None)
                alias_key = PREFIX + "scanner-names:v1"
                if alias_key in values:
                    aliases = set(json.loads(existing.pop(alias_key, "[]")))
                    aliases.update(json.loads(values[alias_key]))
                    values[alias_key] = canonical(sorted(aliases))
                for name, value in values.items():
                    require(
                        name not in existing or existing[name] == value,
                        f"Conflicting property: {name}",
                    )
                existing.update(values)
                combine(merged[ref], incoming)
                set_properties(merged[ref], existing)
            else:
                merged[ref] = incoming
                set_properties(incoming, values)
            origins.setdefault(ref, {})[item.id] = origin(item)
        roots = [original_root] if original_root else document.get("components", [])
        graph[ROOT].update(local[c["bom-ref"]] for c in roots)
        for edge in document.get("dependencies", []):
            ref = local[edge["ref"]]
            graph.setdefault(ref, set()).update(
                local[v] for v in edge.get("dependsOn", []) if local[v] != ref
            )

    for ref, component in merged.items():
        values = properties(component)
        values[IDENTITY] = ref
        values[PREFIX + "snapshot"] = fingerprint
        values[PREFIX + "source-commit"] = manifest.source_commit
        values[ORIGINS] = canonical(
            sorted(origins[ref].values(), key=lambda v: v["input"])
        )
        if containment[ref]:
            values[CONTAINS] = canonical(sorted(containment[ref]))
        set_properties(component, values)
    output: Document = {
        "bomFormat": "CycloneDX",
        "specVersion": version,
        "version": 1,
        "serialNumber": "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, fingerprint)),
        "metadata": {
            "component": {
                "type": "application",
                "name": manifest.product,
                "version": manifest.version,
                "bom-ref": ROOT,
                "externalReferences": [
                    {"type": "vcs", "url": str(manifest.repository)},
                    {"type": "build-system", "url": str(manifest.ci_run)},
                ],
                "properties": [
                    {"name": PREFIX + "source-commit", "value": manifest.source_commit},
                    {"name": PREFIX + "snapshot", "value": fingerprint},
                ],
            },
        },
        "components": [merged[ref] for ref in sorted(merged)],
        "dependencies": [
            {"ref": ref, "dependsOn": sorted(targets)}
            for ref, targets in sorted(graph.items())
        ],
    }
    validate(output)
    return output
