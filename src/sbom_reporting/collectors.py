"""Collect a GoReleaser Linux/amd64 archive with an embedded Vite frontend.

This explicit profile retains the source, compiled binary, frontend attribution,
and archive checks originally implemented by the Enduro pilot.
"""

import copy
import json
import re
import subprocess
import tarfile
import tempfile
import tomllib
import urllib.parse
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from packageurl import PackageURL
from pydantic import BaseModel, ConfigDict, Field

from .documents import (
    Document,
    ReportingError,
    digest,
    load,
    properties,
    require,
    write,
)
from .models import Manifest


class CollectorConfig(BaseModel):
    """Repository-owned build expectations; paths are relative to this file."""

    model_config = ConfigDict(extra="forbid")
    product: str = Field(min_length=1)
    repository: str = Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
    property_namespace: str = Field(pattern=r"^[a-z][a-z0-9-]*$")
    binary: str = Field(pattern=r"^[A-Za-z0-9_.-]+$")
    platform: Literal["linux/amd64"] = "linux/amd64"
    dist: Path = Path("dist")
    frontend: Path = Path("frontend/.output/public")
    evidence: Path = Path("sbom-evidence")
    rolling_versions: list[str] = Field(default_factory=lambda: ["main"])


class CollectionRequest(CollectorConfig):
    version: str
    commit: str
    run: str
    parent_uuid: uuid.UUID


def json_stream(text: str) -> Iterator[Document]:
    decoder = json.JSONDecoder()
    while text.strip():
        text = text.lstrip()
        item, offset = decoder.raw_decode(text)
        require(isinstance(item, dict), "Expected Go module object")
        yield item
        text = text[offset:]


class Collector:
    def __init__(self, config: CollectionRequest) -> None:
        self.config = config

    def prop(self, name: str, value: str) -> dict[str, str]:
        return {"name": self.config.property_namespace + ":" + name, "value": value}

    def package(
        self,
        ecosystem: str,
        name: str,
        version: str,
        origin: str,
        platform: str | None = None,
    ) -> Document:
        require(name and version, "Package identity is incomplete")
        purl = (
            f"pkg:{ecosystem}/{urllib.parse.quote(name, safe='/')}"
            f"@{urllib.parse.quote(version, safe='')}"
        )
        if platform:
            purl += "?arch=amd64&os=linux"
        purl = PackageURL.from_string(purl).to_string()
        result = {
            "type": "library",
            "name": name,
            "version": version,
            "purl": purl,
            "bom-ref": purl,
            "properties": [self.prop("origins", json.dumps([origin]))],
        }
        if platform:
            result["properties"].append(self.prop("platform", platform))
        return result

    def file_component(self, name: str, data: bytes, origin: str) -> Document:
        checksum = digest(data)
        return {
            "type": "file",
            "name": name,
            "version": checksum,
            "bom-ref": "urn:sha256:"
            + checksum
            + ":"
            + urllib.parse.quote(name, safe=""),
            "hashes": [{"alg": "SHA-256", "content": checksum}],
            "properties": [
                self.prop("origins", json.dumps([origin])),
                self.prop("platform", "linux/amd64"),
            ],
        }

    def bom(
        self, components: list[Document], version: str, commit: str, run: str
    ) -> Document:
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
            "metadata": {
                "timestamp": datetime.now(UTC).isoformat(),
                "component": {
                    "type": "application",
                    "name": self.config.product,
                    "version": version,
                    "bom-ref": self.config.property_namespace,
                    "externalReferences": [
                        {
                            "type": "vcs",
                            "url": f"https://github.com/{self.config.repository}/commit/{commit}",
                        },
                        {"type": "build-system", "url": run},
                    ],
                },
                "properties": [
                    self.prop("source:commit", commit),
                    self.prop("ci:run", run),
                    self.prop("platform", "linux/amd64"),
                ],
            },
            "components": components,
        }

    def generate(self) -> Document:
        args = self.config
        out = Path(args.evidence)
        out.mkdir(parents=True, exist_ok=True)
        require(re.fullmatch("[0-9a-f]{40}", args.commit), "Full commit SHA required")
        require(
            args.version in args.rolling_versions
            or re.fullmatch("v[^\\s/]+", args.version),
            "Expected a configured rolling version or an exact v* tag",
        )
        require(
            re.fullmatch(
                f"https://github.com/{self.config.repository}/actions/runs/[0-9]+/attempts/[0-9]+",
                args.run,
            ),
            "Expected an exact CI run attempt in the configured repository",
        )
        source_go = []
        for module in json_stream((out / "go-modules.json").read_text()):
            if module.get("Main"):
                continue
            module = module.get("Replace", module)
            require(
                module.get("Version"),
                "Local Go replacements need explicit inventory support",
            )
            source_go.append(
                self.package("golang", module["Path"], module["Version"], "source-go")
            )
        lock = load(out / "package-lock.json")
        source_npm = []
        for location, module in lock["packages"].items():
            if not location:
                continue
            name = module.get("name") or location.rsplit("node_modules/", 1)[-1]
            c = self.package("npm", name, module["version"], "source-frontend")
            c["properties"].append(
                self.prop("npm:dev", str(module.get("dev", False)).lower())
            )
            source_npm.append(c)
        # A package is development-only only when every occurrence is.
        by_ref = {}
        for c in source_npm:
            previous = by_ref.get(c["bom-ref"])
            if (
                previous
                and properties(previous)[self.config.property_namespace + ":npm:dev"]
                == "false"
            ):
                c["properties"][-1]["value"] = "false"
            by_ref[c["bom-ref"]] = c
        source_npm = list(by_ref.values())
        build_artifacts = json.loads((args.dist / "artifacts.json").read_bytes())
        require(
            all(
                a["type"] in {"Metadata", "Checksum", "Binary", "Archive"}
                for a in build_artifacts
            ),
            "New delivery format needs inventory support",
        )
        for kind in ("Binary", "Archive"):
            selected = [a for a in build_artifacts if a["type"] == kind]
            require(
                len(selected) == 1
                and selected[0].get("goos") == "linux"
                and (selected[0].get("goarch") == "amd64"),
                "Unexpected release platforms or artifact count",
            )
        write(out / "goreleaser-artifacts.json", build_artifacts)
        archives = list(Path(args.dist).glob("*.tar.gz"))
        require(len(archives) == 1, "Expected exactly one release archive")
        archive = archives[0]
        checksum = (Path(args.dist) / "checksums.txt").read_text()
        require(
            f"{digest(archive.read_bytes())}  {archive.name}" in checksum.splitlines(),
            "Archive checksum mismatch",
        )
        (out / "checksums.txt").write_text(checksum)
        artifacts = [self.file_component(archive.name, archive.read_bytes(), "archive")]
        binaries = []
        with tarfile.open(archive) as tar:
            for member in tar.getmembers():
                require(
                    member.isdir() or member.isfile(),
                    "Unexpected archive link or special file",
                )
                if not member.isfile():
                    continue
                stream = tar.extractfile(member)
                require(stream is not None, "Missing archive member data")
                assert stream is not None
                data = stream.read()
                artifacts.append(
                    self.file_component(member.name, data, "archive-member")
                )
                if Path(member.name).name == self.config.binary:
                    binaries.append(data)
        require(len(binaries) == 1, "Expected one configured binary in archive")
        binary = binaries[0]
        require(
            binary[:5] == b"\x7fELF\x02" and binary[18:20] == b">\x00",
            "Expected ELF amd64 binary",
        )
        with tempfile.NamedTemporaryFile() as f:
            f.write(binary)
            f.flush()
            buildinfo = subprocess.check_output(
                ["go", "version", "-m", f.name], text=True
            )
        (out / "go-buildinfo.txt").write_text(buildinfo)
        require(
            "GOOS=linux" in buildinfo
            and "GOARCH=amd64" in buildinfo
            and ("CGO_ENABLED=0" in buildinfo),
            "Binary platform/static build differs",
        )
        require(
            f"vcs.revision={args.commit}" in buildinfo
            and "vcs.modified=false" in buildinfo,
            "Binary does not identify the clean source commit",
        )
        binary_go = []
        lines = buildinfo.splitlines()
        toolchain = lines[0].split()[-1]
        # Go vulnerability records identify the linked standard library as
        # stdlib. The complete compiler/build information is retained above.
        binary_go.append(
            self.package(
                "golang",
                "stdlib",
                toolchain.removeprefix("go"),
                "binary-stdlib",
                "linux/amd64",
            )
        )
        for i, line in enumerate(lines):
            fields = line.split()
            if fields and fields[0] == "dep":
                if i + 1 < len(lines) and lines[i + 1].split()[:1] == ["=>"]:
                    fields = lines[i + 1].split()
                require(
                    len(fields) >= 3 and fields[2] != "(devel)",
                    "Unversioned binary dependency",
                )
                binary_go.append(
                    self.package(
                        "golang", fields[1], fields[2], "binary-go", "linux/amd64"
                    )
                )
        evidence = load(out / "frontend-build.json")
        frontend = []
        frontend_build_inputs = []
        for p in evidence["packages"]:
            c = self.package("npm", p["name"], p["version"], "frontend-bundle")
            require(
                c["bom-ref"] in by_ref,
                "Frontend package absent from retained lock: " + c["bom-ref"],
            )
            require(
                p["origins"]
                and set(p["origins"]) <= {"frontend-bundle", "frontend-build-input"},
                "Unknown frontend evidence origin",
            )
            c["properties"] = [self.prop("origins", json.dumps(p["origins"]))]
            if "frontend-bundle" in p["origins"]:
                frontend.append(copy.deepcopy(c))
            if "frontend-build-input" in p["origins"]:
                frontend_build_inputs.append(copy.deepcopy(c))
        assets = {}
        for path in sorted(Path(args.frontend).rglob("*")):
            if path.is_file():
                data = path.read_bytes()
                require(
                    not data or data in binary, f"Frontend asset not embedded: {path}"
                )
                name = str(path.relative_to(args.frontend))
                assets[name] = digest(data)
                artifacts.append(
                    self.file_component("frontend/" + name, data, "embedded-frontend")
                )
        require("index.html" in assets, "Missing frontend entry point")
        for chunk in evidence["chunks"]:
            require(
                assets.get(chunk["name"]) == chunk["sha256"],
                "Bundle evidence differs from embedded frontend",
            )
        require(
            evidence["chunks"]
            and any("frontend-bundle" in p["origins"] for p in evidence["packages"]),
            "No bundled dependencies",
        )
        write(
            out / "artifact-identities.json",
            {
                "commit": args.commit,
                "version": args.version,
                "run": args.run,
                "platform": "linux/amd64",
                "files": artifacts,
            },
        )
        inputs = []
        template = self.bom([], args.version, args.commit, args.run)
        archive_identity = {
            "name": archive.name,
            "platform": "linux/amd64",
            "sha256": digest(archive.read_bytes()),
            "path": str(archive.resolve()),
        }
        for label, role, components in [
            ("source-go", "source", source_go),
            ("source-frontend", "source", source_npm),
            ("binary", "artifact", binary_go),
            ("frontend-bundle", "artifact", frontend),
            ("frontend-build-input", "tooling", frontend_build_inputs),
            ("artifacts", "artifact", artifacts),
        ]:
            require(components, "Missing inventory: " + label)
            document = copy.deepcopy(template)
            # Preserve the six input scopes as distinct roots on import.
            document["metadata"]["component"].update(
                name=f"{self.config.product}:{label}", **{"bom-ref": label}
            )
            document["components"] = components
            document["dependencies"] = [
                {
                    "ref": label,
                    "dependsOn": [component["bom-ref"] for component in components],
                }
            ]
            write(out / (label + ".cdx.json"), document)
            item = {"id": label, "role": role, "sbom": label + ".cdx.json"}
            if role == "artifact":
                item["artifact"] = archive_identity
            inputs.append(item)
        manifest = {
            "schema_version": 1,
            "product": self.config.product,
            "version": args.version,
            "kind": "rolling" if args.version in args.rolling_versions else "release",
            "repository": f"https://github.com/{self.config.repository}",
            "source_commit": args.commit,
            "ci_run": args.run,
            "parent_uuid": str(args.parent_uuid),
            "parent_collection_logic": "AGGREGATE_DIRECT_CHILDREN_WITH_TAG",
            "parent_collection_tag": "report-current",
            "inputs": inputs,
        }
        Manifest.model_validate(manifest)
        write(out / "manifest.json", manifest)
        return manifest


def collect(
    config_path: Path, *, version: str, commit: str, run: str, parent_uuid: str | None
) -> Document:
    require(parent_uuid, "Configure DEPENDENCY_TRACK_PARENT_UUID")
    config = CollectorConfig.model_validate(tomllib.loads(config_path.read_text()))
    data = config.model_dump()
    for name in ("dist", "frontend", "evidence"):
        data[name] = (config_path.resolve().parent / data[name]).resolve()
    request = CollectionRequest.model_validate(
        {
            **data,
            "version": version,
            "commit": commit,
            "run": run,
            "parent_uuid": parent_uuid,
        }
    )
    try:
        return Collector(request).generate()
    except (subprocess.SubprocessError, tarfile.TarError) as error:
        raise ReportingError(
            "Cannot inspect the declared release archive/binary"
        ) from error
