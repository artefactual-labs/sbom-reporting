"""Dependency-Track upload and normalized server-side import verification."""

import base64
import time
from pathlib import Path
from uuid import UUID

import httpx
from packageurl import PackageURL

from .documents import (
    IDENTITY,
    Document,
    ReportingError,
    canonical,
    properties,
    purl,
    require,
    validate,
    write,
)
from .snapshot import verify


class Client:
    def __init__(self, url: str, key: str, *, timeout: float = 30) -> None:
        try:
            parsed = httpx.URL(url)
        except httpx.InvalidURL as error:
            raise ReportingError("Invalid Dependency-Track API URL") from error
        require(
            parsed.scheme == "https"
            or parsed.host in {"localhost", "127.0.0.1", "::1"},
            "Use HTTPS for Dependency-Track (HTTP is allowed only for loopback tests)",
        )
        require(
            not parsed.userinfo and not parsed.query and not parsed.fragment,
            "API URL must not contain credentials, a query, or a fragment",
        )
        require(key, "DEPENDENCY_TRACK_API_KEY is required")
        self.http = httpx.Client(
            base_url=url.rstrip("/") + "/api/v1/",
            headers={"X-Api-Key": key},
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
        )

    def close(self) -> None:
        self.http.close()

    def request(
        self, path: str, payload: Document | None = None, *, missing_ok: bool = False
    ) -> Document | None:
        try:
            response = self.http.request(
                "PUT" if payload is not None else "GET", path, json=payload
            )
        except httpx.HTTPError as error:
            raise ReportingError(
                "Dependency-Track transport failed; check API URL and connectivity"
            ) from error
        if missing_ok and response.status_code == 404:
            return None
        require(
            200 <= response.status_code < 300,
            f"Dependency-Track HTTP {response.status_code}; "
            "check API permissions and configuration",
        )
        try:
            value = response.json()
        except ValueError as error:
            raise ReportingError("Dependency-Track returned invalid JSON") from error
        require(
            isinstance(value, dict), "Dependency-Track returned an unexpected response"
        )
        return value


def comparison_purl(value: str) -> str:
    parsed = PackageURL.from_string(purl(value))
    if parsed.type == "golang":
        # Dependency-Track's Java PURL implementation applies the older Go
        # casing rule. This is export comparison only: source PURLs, names,
        # stable identities, versions, qualifiers and subpaths remain checked.
        parsed = PackageURL(
            type=parsed.type,
            namespace=parsed.namespace.lower() if parsed.namespace else None,
            name=parsed.name.lower(),
            version=parsed.version,
            qualifiers=parsed.qualifiers,
            subpath=parsed.subpath,
        )
    return parsed.to_string()


def signatures(document: Document) -> dict[str, str]:
    result: dict[str, str] = {}
    for component in document.get("components", []):
        require(not component.get("components"), "Unexpected nested server export")
        props = properties(component)
        identity = props.get(IDENTITY)
        require(
            identity and identity not in result,
            "Missing or duplicate imported component identity",
        )
        signature = {
            key: component.get(key)
            for key in ("type", "group", "name", "version", "cpe")
        }
        signature["purl"] = (
            comparison_purl(component["purl"]) if component.get("purl") else None
        )
        signature["properties"] = props
        signature["hashes"] = sorted(
            (h["alg"], h["content"].lower()) for h in component.get("hashes", [])
        )
        if identity is None:
            raise ReportingError("Missing imported identity")
        result[identity] = canonical(signature)
    return result


def graph_signature(document: Document) -> dict[str, set[str]]:
    root = document["metadata"]["component"]
    refs = {root["bom-ref"]: "application"}
    for component in document.get("components", []):
        require(component["bom-ref"] not in refs, "Duplicate exported bom-ref")
        refs[component["bom-ref"]] = properties(component)[IDENTITY]
    result: dict[str, set[str]] = {}
    for edge in document.get("dependencies", []):
        require(
            edge["ref"] in refs and all(r in refs for r in edge.get("dependsOn", [])),
            "Unresolved server dependency reference",
        )
        result.setdefault(refs[edge["ref"]], set()).update(
            refs[r] for r in edge.get("dependsOn", [])
        )
    return {key: value for key, value in result.items() if value}


def imported_matches(expected: Document, imported: Document) -> bool:
    try:
        validate(imported, supported_shape=False)
        root = expected["metadata"]["component"]
        actual = imported["metadata"]["component"]
        if any(actual.get(key) != root.get(key) for key in ("type", "name", "version")):
            return False
        # Project properties may not be included by Dependency-Track's exporter.
        # Bind the exact snapshot through component origins/identity and the CI URL.
        refs = {(r["type"], r["url"]) for r in actual.get("externalReferences", [])}
        if not all((r["type"], r["url"]) in refs for r in root["externalReferences"]):
            return False
        return signatures(expected) == signatures(imported) and graph_signature(
            expected
        ) == graph_signature(imported)
    except KeyError, TypeError, ValueError, ReportingError:
        return False


def upload(
    directory: Path,
    client: Client,
    *,
    allow_create: bool = False,
    expected_head: str | None = None,
    timeout: float = 300,
    interval: float = 2,
) -> Document:
    receipt_path = directory / "upload-result.json"
    receipt: Document = {"schema_version": 1, "state": "validating"}
    write(receipt_path, receipt)
    try:
        require(
            timeout > 0 and interval >= 0,
            "Upload timeout must be positive and interval nonnegative",
        )
        manifest, document, snapshot = verify(directory)
        if manifest.kind == "rolling":
            require(
                expected_head == manifest.source_commit,
                "Rolling upload requires a matching fresh --expected-head "
                "assertion from the CI wrapper",
            )
        parent_id = str(manifest.parent_uuid)
        parent = client.request("project/" + parent_id)
        # Retain only hierarchy fields, never arbitrary API response data.
        observed_parent = {
            key: parent.get(key) if parent else None
            for key in ("name", "version", "classifier", "collectionLogic")
        }
        collection_tag = parent.get("collectionTag") if parent else None
        observed_parent["collectionTag"] = (
            collection_tag.get("name") if isinstance(collection_tag, dict) else None
        )
        receipt["parent_configuration"] = observed_parent
        write(receipt_path, receipt)
        require(
            parent
            and parent.get("name") == manifest.product
            and not parent.get("version")
            and parent.get("classifier") == "APPLICATION"
            and parent.get("collectionLogic")
            in {
                "AGGREGATE_DIRECT_CHILDREN",
                "AGGREGATE_DIRECT_CHILDREN_WITH_TAG",
                "AGGREGATE_LATEST_VERSION_CHILDREN",
            },
            "Configured parent is not the expected versionless collection; observed "
            + canonical(observed_parent),
        )
        if manifest.parent_collection_logic:
            require(
                parent is not None
                and parent.get("collectionLogic") == manifest.parent_collection_logic,
                "Configured collection logic does not match the manifest; observed "
                + canonical(observed_parent),
            )
        if manifest.parent_collection_tag:
            tag = parent.get("collectionTag") if parent else None
            require(
                isinstance(tag, dict)
                and tag.get("name") == manifest.parent_collection_tag,
                "Configured collection tag does not match the manifest; observed "
                + canonical(observed_parent),
            )
        query = str(
            httpx.QueryParams({"name": manifest.product, "version": manifest.version})
        )

        def child() -> Document | None:
            project = client.request("project/lookup?" + query, missing_ok=True)
            if project:
                # Lookup responses can omit parent relations (Dependency-Track 4.x).
                # Verify hierarchy using the full record, never infer linkage.
                project_id = str(UUID(project["uuid"]))
                project = client.request("project/" + project_id)
                require(
                    project is not None and project.get("uuid") == project_id,
                    "Missing or mismatched child project record",
                )
                if project is None:
                    raise ReportingError("Missing child project record")
                parent_link = project.get("parent")
                require(isinstance(parent_link, dict), "Missing child parent linkage")
                require(
                    project.get("name") == manifest.product
                    and project.get("version") == manifest.version,
                    "Wrong inventory project identity",
                )
                require(
                    isinstance(parent_link, dict)
                    and parent_link.get("uuid") == parent_id,
                    "Existing child has a different parent; "
                    "reparent it explicitly before reporting",
                )
                require(
                    project.get("classifier") == "APPLICATION"
                    and project.get("collectionLogic", "NONE") == "NONE",
                    "Inventory child must be an APPLICATION with collectionLogic NONE",
                )
            return project

        project = child()
        require(
            project is not None or allow_create,
            "Missing child; explicitly pass --allow-create to create it",
        )
        receipt = {
            "schema_version": 1,
            "snapshot": snapshot["snapshot"],
            "product": manifest.product,
            "version": manifest.version,
            "source_commit": manifest.source_commit,
            "state": "validated",
        }
        receipt_path = directory / "upload-result.json"
        write(receipt_path, receipt)
        response = client.request(
            "bom",
            {
                "projectName": manifest.product,
                "projectVersion": manifest.version,
                "parentUUID": parent_id,
                "autoCreate": allow_create,
                "bom": base64.b64encode(canonical(document).encode()).decode(),
            },
        )
        if response is None:
            raise ReportingError("Missing upload response")
        token = str(UUID(response["token"]))
        receipt.update(state="accepted", token=token)
        write(receipt_path, receipt)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = client.request("event/token/" + token)
            require(
                status is not None and type(status.get("processing")) is bool,
                "Invalid processing-token status",
            )
            if status is None:
                raise ReportingError("Missing processing status")
            if not status["processing"]:
                receipt["state"] = "processed-unverified"
                write(receipt_path, receipt)
                project = child()
                if project:
                    project_id = str(UUID(project["uuid"]))
                    imported = client.request(
                        f"bom/cyclonedx/project/{project_id}?format=json&version={document['specVersion']}"
                    )
                    if imported is not None:
                        write(directory / "imported.cdx.json", imported)
                    if imported is not None and imported_matches(document, imported):
                        receipt.update(state="verified", project_uuid=project_id)
                        write(receipt_path, receipt)
                        return receipt
            time.sleep(min(interval, max(0, deadline - time.monotonic())))
        raise ReportingError(
            "Import not verified before timeout; acceptance/processing is not success"
        )
    except (ReportingError, KeyError, ValueError, TypeError, OSError) as error:
        receipt.update(state="failed", last_state=receipt["state"])
        write(receipt_path, receipt)
        if isinstance(error, ReportingError):
            raise
        raise ReportingError(
            "Invalid snapshot or Dependency-Track response; import unverified"
        ) from error
