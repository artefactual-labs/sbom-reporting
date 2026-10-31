import base64
import copy
import json
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from conftest import COMMIT, PARENT

from sbom_reporting.cli import main
from sbom_reporting.documents import IDENTITY, ORIGINS, Document, load, write

CHILD = "11111111-1111-4111-8111-111111111111"
TOKEN = "22222222-2222-4222-8222-222222222222"


@dataclass
class State:
    mode: str = "success"
    uploads: list[Document] = field(default_factory=list)
    document: Document | None = None


@pytest.fixture
def api(monkeypatch: pytest.MonkeyPatch) -> Iterator[State]:
    state = State()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            pass

        def reply(self, value: Document, status: int = 200) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(value).encode())

        def do_PUT(self) -> None:
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            state.uploads.append(payload)
            state.document = json.loads(base64.b64decode(payload["bom"]))
            if state.mode == "http-error":
                self.reply({"secret": "test-api-key-do-not-print"}, 403)
            elif state.mode == "bad-token":
                self.reply({"token": "invalid"})
            else:
                self.reply({"token": TOKEN})

        def do_GET(self) -> None:
            if self.path == "/api/v1/project/" + PARENT:
                self.reply(
                    {
                        "name": "wrong" if state.mode == "wrong-parent" else "example",
                        "classifier": "APPLICATION",
                        "collectionLogic": "AGGREGATE_DIRECT_CHILDREN_WITH_TAG",
                    }
                )
            elif self.path.startswith("/api/v1/project/lookup"):
                if state.mode == "missing-child" and not state.uploads:
                    self.reply({}, 404)
                else:
                    self.reply({"uuid": CHILD})
            elif self.path == "/api/v1/project/" + CHILD:
                self.reply(
                    {
                        "uuid": CHILD,
                        "name": "example",
                        "version": "v1.0.0",
                        "classifier": "APPLICATION",
                        "collectionLogic": "NONE",
                        "parent": {
                            "uuid": CHILD
                            if state.mode == "wrong-child-parent"
                            else PARENT
                        },
                    }
                )
            elif self.path.startswith("/api/v1/event/token/"):
                self.reply({"processing": state.mode == "timeout"})
            elif self.path.startswith("/api/v1/bom/cyclonedx/project/"):
                assert state.document is not None
                exported = copy.deepcopy(state.document)
                exported["metadata"].pop("properties", None)
                exported["metadata"]["component"].pop("properties", None)
                exported["metadata"]["component"]["externalReferences"][0][
                    "comment"
                ] = "server annotation"
                # Dependency-Track replaces bom-ref values on project and components.
                refs = {
                    c["bom-ref"]: f"server-{i}"
                    for i, c in enumerate(
                        [exported["metadata"]["component"], *exported["components"]]
                    )
                }
                for c in [exported["metadata"]["component"], *exported["components"]]:
                    c["bom-ref"] = refs[c["bom-ref"]]
                for edge in exported["dependencies"]:
                    edge["ref"] = refs[edge["ref"]]
                    edge["dependsOn"] = [refs[r] for r in edge["dependsOn"]]
                match state.mode:
                    case "golang-normalization" | "wrong-golang-version":
                        for c in exported["components"]:
                            if c.get("purl", "").startswith("pkg:golang/"):
                                c["purl"] = c["purl"].replace(
                                    "Example/Module", "example/module"
                                )
                                if state.mode == "wrong-golang-version":
                                    c["purl"] = c["purl"].replace("v1.2.3", "v1.2.4")
                    case "lost-component":
                        exported["components"].pop()
                    case "duplicate":
                        exported["components"].append(exported["components"][0])
                    case "lost-origin":
                        exported["components"][0]["properties"] = [
                            p
                            for p in exported["components"][0]["properties"]
                            if p["name"] != ORIGINS
                        ]
                    case "lost-identity":
                        exported["components"][0]["properties"] = [
                            p
                            for p in exported["components"][0]["properties"]
                            if p["name"] != IDENTITY
                        ]
                    case "wrong-type":
                        next(
                            c for c in exported["components"] if c["type"] == "library"
                        )["type"] = "file"
                    case "lost-hash":
                        next(c for c in exported["components"] if c.get("hashes"))[
                            "hashes"
                        ] = []
                    case "lost-graph":
                        exported["dependencies"] = []
                    case "wrong-root":
                        exported["metadata"]["component"]["name"] = "wrong"
                self.reply(exported)
            else:
                self.reply({}, 404)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(
        target=lambda: server.serve_forever(poll_interval=0.01), daemon=True
    )
    worker.start()
    monkeypatch.setenv("DEPENDENCY_TRACK_URL", f"http://127.0.0.1:{server.server_port}")
    monkeypatch.setenv("DEPENDENCY_TRACK_API_KEY", "test-api-key-do-not-print")
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        worker.join()


@pytest.mark.parametrize(
    "mode",
    [
        "success",
        "golang-normalization",
        "wrong-golang-version",
        "missing-child",
        "wrong-parent",
        "wrong-child-parent",
        "http-error",
        "bad-token",
        "timeout",
        "lost-component",
        "duplicate",
        "lost-origin",
        "lost-identity",
        "wrong-type",
        "lost-hash",
        "lost-graph",
        "wrong-root",
    ],
)
def test_real_http_import_behavior(
    manifest_path: Path, api: State, mode: str, capsys: pytest.CaptureFixture[str]
) -> None:
    source = manifest_path.parent / "source.json"
    document = load(source)
    document["components"].append(
        {
            "type": "file",
            "name": "archive.tar.gz",
            "version": "b" * 64,
            "bom-ref": "archive",
            "hashes": [{"alg": "SHA-256", "content": "b" * 64}],
        }
    )
    document["components"].append(
        {
            "type": "library",
            "name": "github.com/Example/Module",
            "version": "v1.2.3",
            "bom-ref": "go-module",
            "purl": "pkg:golang/github.com/Example/Module@v1.2.3",
        }
    )
    write(source, document)
    snapshot = manifest_path.parent / "snapshot"
    assert main(["merge", str(manifest_path), "--output", str(snapshot)]) == 0
    api.mode = mode
    result = main(["upload", str(snapshot), "--allow-create", "--timeout", "0.05"])
    assert result == (
        0 if mode in {"success", "missing-child", "golang-normalization"} else 1
    )
    if mode in {"wrong-parent", "wrong-child-parent"}:
        assert not api.uploads
        assert load(snapshot / "upload-result.json")["state"] == "failed"
    else:
        assert len(api.uploads) == 1
        assert api.uploads[0]["parentUUID"] == PARENT
        receipt = load(snapshot / "upload-result.json")
        assert receipt["state"] == ("verified" if result == 0 else "failed")
    if mode in {"success", "missing-child", "lost-component"}:
        assert load(snapshot / "imported.cdx.json")["bomFormat"] == "CycloneDX"
    captured = capsys.readouterr()
    if mode == "wrong-parent":
        assert load(snapshot / "upload-result.json")["parent_configuration"] == {
            "name": "wrong",
            "version": None,
            "classifier": "APPLICATION",
            "collectionLogic": "AGGREGATE_DIRECT_CHILDREN_WITH_TAG",
            "collectionTag": None,
        }
        assert '"name":"wrong"' in captured.err
    assert "test-api-key-do-not-print" not in captured.out + captured.err


def test_missing_child_requires_explicit_creation(
    manifest_path: Path, api: State
) -> None:
    snapshot = manifest_path.parent / "snapshot"
    assert main(["merge", str(manifest_path), "--output", str(snapshot)]) == 0
    api.mode = "missing-child"
    assert main(["upload", str(snapshot)]) == 1
    assert not api.uploads


def test_rolling_head_assertion_is_required(manifest_path: Path, api: State) -> None:
    manifest = load(manifest_path)
    manifest["kind"] = "rolling"
    write(manifest_path, manifest)
    snapshot = manifest_path.parent / "snapshot"
    assert main(["merge", str(manifest_path), "--output", str(snapshot)]) == 0
    assert main(["upload", str(snapshot)]) == 1
    assert main(["upload", str(snapshot), "--expected-head", "b" * 40]) == 1
    assert not api.uploads
    assert main(["upload", str(snapshot), "--expected-head", COMMIT]) == 0


def test_invalid_api_url_is_reported_without_echoing_credentials(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("DEPENDENCY_TRACK_URL", "http://[invalid-url-secret")
    monkeypatch.setenv("DEPENDENCY_TRACK_API_KEY", "private-api-key")
    assert main(["upload", "unused"]) == 1
    output = capsys.readouterr()
    assert "invalid-url-secret" not in output.out + output.err
    assert "private-api-key" not in output.out + output.err
    assert "Traceback" not in output.err


@pytest.mark.parametrize(
    "field,value",
    [
        ("parent_collection_logic", "AGGREGATE_DIRECT_CHILDREN"),
        ("parent_collection_tag", "report-current"),
    ],
)
def test_collection_policy_is_checked_before_upload(
    manifest_path: Path, api: State, field: str, value: str
) -> None:
    manifest = load(manifest_path)
    manifest["parent_collection_logic"] = "AGGREGATE_DIRECT_CHILDREN_WITH_TAG"
    manifest[field] = value
    write(manifest_path, manifest)
    snapshot = manifest_path.parent / "snapshot"
    assert main(["merge", str(manifest_path), "--output", str(snapshot)]) == 0
    assert main(["upload", str(snapshot), "--allow-create"]) == 1
    assert not api.uploads
