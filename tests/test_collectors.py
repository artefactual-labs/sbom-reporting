"""Exercise Enduro artifact collection and the shared CLI through their entry points."""

import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

import pytest

from sbom_reporting import documents as inventory

PARENT = "7e0368f9-4655-4de9-91fb-cdba489c6703"
RUN = "https://github.com/example/fixture/actions/runs/123/attempts/1"


class InventoryTests(unittest.TestCase):
    def test_generate_scans_actual_archive_and_embedded_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assets = root / "public"
            (assets / "_nuxt").mkdir(parents=True)
            (assets / "index.html").write_text("<html>Enduro fixture</html>")
            script = b'console.log("unique fixture bytes")'
            (assets / "_nuxt/app.js").write_bytes(script)
            (root / "go.mod").write_text("module example.com/fixture\n\ngo 1.23\n")
            (root / "main.go").write_text(
                'package main\nimport("embed"; "fmt")\n'
                "//go:embed all:public\nvar assets embed.FS\n"
                'func main(){ b,_:=assets.ReadFile("public/_nuxt/app.js"); '
                "fmt.Println(string(b)) }\n"
            )

            (root / "sbom.toml").write_text(
                'product = "Fixture App"\n'
                'repository = "example/fixture"\n'
                'property_namespace = "fixture"\n'
                'binary = "fixture-binary"\n'
                'frontend = "public"\n'
                'evidence = "evidence"\n'
            )

            def run(*args: str, env: dict[str, str] | None = None) -> str:
                return subprocess.check_output(
                    args, cwd=root, text=True, env=env
                ).strip()

            run("git", "init", "-q")
            run("git", "add", ".")
            run(
                "git",
                "-c",
                "user.name=SBOM test",
                "-c",
                "user.email=sbom@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-qm",
                "Add fixture",
            )
            commit = run("git", "rev-parse", "HEAD")
            binary_path = root.parent / (root.name + "-binary")
            self.addCleanup(binary_path.unlink, missing_ok=True)
            run(
                "go",
                "build",
                "-o",
                str(binary_path),
                env={
                    **os.environ,
                    "GOOS": "linux",
                    "GOARCH": "amd64",
                    "CGO_ENABLED": "0",
                },
            )
            binary = binary_path.read_bytes()
            dist = root / "dist"
            dist.mkdir()
            inventory.write(
                dist / "artifacts.json",
                [
                    {"type": kind, "goos": "linux", "goarch": "amd64"}
                    for kind in ("Binary", "Archive")
                ],
            )
            archive = dist / "fixture-binary.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                info = tarfile.TarInfo("fixture-binary/fixture-binary")
                info.size = len(binary)
                tar.addfile(info, io.BytesIO(binary))
            (dist / "checksums.txt").write_text(
                inventory.digest(archive.read_bytes()) + "  fixture-binary.tar.gz\n"
            )
            evidence = root / "evidence"
            evidence.mkdir()
            inventory.write(
                evidence / "frontend-build.json",
                {
                    "chunks": [
                        {"name": "_nuxt/app.js", "sha256": inventory.digest(script)}
                    ],
                    "packages": [
                        {
                            "name": "vue",
                            "version": "3.0.0",
                            "origins": ["frontend-bundle", "frontend-build-input"],
                        }
                    ],
                },
            )
            inventory.write(
                evidence / "package-lock.json",
                {
                    "packages": {
                        "node_modules/vue": {"version": "3.0.0"},
                        "node_modules/tool/node_modules/vue": {
                            "version": "3.0.0",
                            "dev": True,
                        },
                    }
                },
            )
            inventory.write(
                evidence / "go-modules.json",
                {"Path": "example.com/dependency", "Version": "v1.0.0"},
            )
            command = [
                sys.executable,
                "-m",
                "sbom_reporting",
                "collect-goreleaser",
                str(root / "sbom.toml"),
                "--parent-uuid",
                PARENT,
                "--version",
                "v1.0.0",
                "--commit",
                commit,
                "--run",
                RUN,
            ]
            subprocess.run(command, check=True)
            snapshot = evidence / "snapshot"
            shared_cli = [sys.executable, "-m", "sbom_reporting"]
            subprocess.run(
                [
                    *shared_cli,
                    "merge",
                    str(evidence / "manifest.json"),
                    "--output",
                    str(snapshot),
                ],
                check=True,
            )
            subprocess.run([*shared_cli, "verify", str(snapshot)], check=True)
            combined = inventory.load(snapshot / "combined.cdx.json")
            self.assertEqual(combined["metadata"]["component"]["name"], "Fixture App")
            self.assertEqual(combined["metadata"]["component"]["version"], "v1.0.0")
            self.assertTrue(any(c["name"] == "go" for c in combined["components"]))
            vue = next(c for c in combined["components"] if c["name"] == "vue")
            props = inventory.properties(vue)
            scanner = json.loads(props["sbom-reporting:scanner-properties:v1"])
            self.assertEqual(scanner["fixture:npm:dev"], ["false"])
            observations = json.loads(props["sbom-reporting:origins:v1"])
            self.assertEqual(
                {o["role"] for o in observations}, {"source", "artifact", "tooling"}
            )
            self.assertEqual(
                {o["input"] for o in observations},
                {"source-frontend", "frontend-bundle", "frontend-build-input"},
            )
            saved = inventory.load(snapshot / "snapshot.json")
            self.assertTrue(
                all(
                    i["artifact_check"] == "verified-local-file"
                    for i in saved["inputs"]
                    if i["id"] in {"binary", "frontend-bundle", "artifacts"}
                )
            )
            checksum = (dist / "checksums.txt").read_text()
            (dist / "checksums.txt").write_text(checksum.rstrip() + ".other\n")
            failed = subprocess.run(
                command, check=False, capture_output=True, text=True
            )
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("Archive checksum mismatch", failed.stderr)
            (dist / "checksums.txt").write_text(checksum)
            frontend_evidence = inventory.load(evidence / "frontend-build.json")
            frontend_evidence["packages"][0]["version"] = "9.0.0"
            inventory.write(evidence / "frontend-build.json", frontend_evidence)
            failed = subprocess.run(
                command, check=False, capture_output=True, text=True
            )
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("absent from retained lock", failed.stderr)
            frontend_evidence["packages"][0]["version"] = "3.0.0"
            inventory.write(evidence / "frontend-build.json", frontend_evidence)
            (assets / "_nuxt/app.js").write_text("not the embedded bytes")
            failed = subprocess.run(
                command, check=False, capture_output=True, text=True
            )
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("not embedded", failed.stderr)
            (evidence / "frontend-build.json").unlink()
            self.assertNotEqual(
                subprocess.run(command, check=False, capture_output=True).returncode, 0
            )


if __name__ == "__main__":
    unittest.main()


@pytest.mark.parametrize("extra", ['platform = "linux/arm64"', 'unexpected = "value"'])
def test_rejects_unsupported_profile_before_collection(
    tmp_path: Path, extra: str
) -> None:
    config = tmp_path / "sbom.toml"
    config.write_text(
        'product = "Other Product"\nrepository = "example/other"\n'
        'property_namespace = "other"\nbinary = "other"\n' + extra + "\n"
    )
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "sbom_reporting",
            "collect-goreleaser",
            str(config),
            "--version",
            "main",
            "--commit",
            "a" * 40,
            "--run",
            "https://github.com/example/other/actions/runs/1/attempts/1",
            "--parent-uuid",
            PARENT,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "Invalid manifest" in result.stderr
    assert not (tmp_path / "sbom-evidence").exists()


def test_packaged_frontend_plugin_entrypoint() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "sbom_reporting", "frontend-plugin"],
        check=True,
        capture_output=True,
        text=True,
    )
    plugin = Path(result.stdout.strip())
    assert plugin.is_file()
    assert "export function sbomEvidence" in plugin.read_text()
