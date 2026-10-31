"""Versioned caller contract. All declared inventories are required."""

from pathlib import Path
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator

Nonempty = Annotated[str, Field(min_length=1, pattern=r"\S")]
Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
Commit = Annotated[str, Field(pattern=r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$")]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Artifact(Contract):
    name: Nonempty
    platform: Annotated[str, Field(pattern=r"^[a-z0-9]+/[a-z0-9]+(?:/[a-z0-9]+)?$")]
    sha256: Digest | None = None
    image: Annotated[str, Field(pattern=r"^\S+@sha256:[a-f0-9]{64}$")] | None = None
    path: Path | None = None

    @model_validator(mode="after")
    def identity(self) -> Self:
        if (self.sha256 is None) == (self.image is None):
            raise ValueError(
                "Specify exactly one file sha256 or immutable image reference"
            )
        if self.path is not None and self.sha256 is None:
            raise ValueError("A local artifact path requires sha256")
        return self


class Inventory(Contract):
    id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]*$")]
    role: Literal["source", "artifact", "tooling"]
    sbom: Path
    artifact: Artifact | None = None

    @model_validator(mode="after")
    def artifact_required(self) -> Self:
        if self.role == "artifact" and self.artifact is None:
            raise ValueError(
                "An artifact inventory needs its exact identity and platform"
            )
        return self


class Manifest(Contract):
    schema_version: Literal[1]
    product: Nonempty
    version: Nonempty
    kind: Literal["rolling", "release"]
    repository: HttpUrl
    source_commit: Commit
    ci_run: HttpUrl
    parent_uuid: UUID
    parent_collection_logic: (
        Literal[
            "AGGREGATE_DIRECT_CHILDREN",
            "AGGREGATE_DIRECT_CHILDREN_WITH_TAG",
            "AGGREGATE_LATEST_VERSION_CHILDREN",
        ]
        | None
    ) = None
    parent_collection_tag: Nonempty | None = None
    inputs: Annotated[list[Inventory], Field(min_length=1)]

    @model_validator(mode="after")
    def unique_inputs(self) -> Self:
        if (
            self.parent_collection_tag is not None
            and self.parent_collection_logic != "AGGREGATE_DIRECT_CHILDREN_WITH_TAG"
        ):
            raise ValueError("A collection tag requires tag-filtered collection logic")
        ids = [item.id for item in self.inputs]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate inventory IDs")
        for url in (self.repository, self.ci_run):
            if url.username or url.password:
                raise ValueError("Credentials must not appear in provenance URLs")
        return self


class InputRecord(Contract):
    id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]*$")]
    sha256: Digest
    artifact_check: Literal["not-applicable", "asserted", "verified-local-file"]


class SnapshotRecord(Contract):
    schema_version: Literal[1]
    tool_version: Nonempty
    snapshot: Digest
    combined_sha256: Digest
    inputs: Annotated[list[InputRecord], Field(min_length=1)]
