"""Small command-line interface; keys are read only from the environment."""

import argparse
import json
import os
import sys
from pathlib import Path

from pydantic import ValidationError

from . import __version__
from .collectors import collect
from .documents import ReportingError, write
from .models import Manifest
from .snapshot import create, verify
from .upload import Client, upload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser(
        "manifest-schema", help="Print the version 1 manifest JSON schema"
    )
    commands.add_parser("frontend-plugin", help="Print the packaged Vite plugin path")
    collector = commands.add_parser(
        "collect-goreleaser", help="Inspect a Go archive with an embedded Vite frontend"
    )
    collector.add_argument("config", type=Path)
    for flag in ("version", "commit", "run"):
        collector.add_argument("--" + flag, required=True)
    collector.add_argument(
        "--parent-uuid", default=os.getenv("DEPENDENCY_TRACK_PARENT_UUID")
    )
    merge = commands.add_parser(
        "merge", help="Validate inputs and save a complete snapshot"
    )
    merge.add_argument("manifest", type=Path)
    merge.add_argument("--output", type=Path, required=True)
    check = commands.add_parser(
        "verify", help="Verify saved inputs, identities, and combined output"
    )
    check.add_argument("snapshot", type=Path)
    publish = commands.add_parser(
        "upload", help="Upload a retained snapshot and verify import"
    )
    publish.add_argument("snapshot", type=Path)
    publish.add_argument("--allow-create", action="store_true")
    publish.add_argument(
        "--expected-head",
        help="Current rolling head, obtained under the caller's upload lock",
    )
    publish.add_argument("--timeout", type=float, default=300)
    args = parser.parse_args(argv)
    try:
        if args.command == "frontend-plugin":
            print(Path(__file__).parent / "frontend" / "sbom-evidence.mjs")
            return 0
        if args.command == "collect-goreleaser":
            result = collect(
                args.config,
                version=args.version,
                commit=args.commit,
                run=args.run,
                parent_uuid=args.parent_uuid,
            )
        elif args.command == "manifest-schema":
            result = Manifest.model_json_schema()
        elif args.command == "merge":
            result = create(args.manifest, args.output)
        elif args.command == "verify":
            _, _, result = verify(args.snapshot)
        else:
            # Configuration is part of this attempt, even before an HTTP client
            # exists. Never leave a previous successful receipt on failure.
            receipt_path = args.snapshot / "upload-result.json"
            write(receipt_path, {"schema_version": 1, "state": "configuring"})
            try:
                url, key = (
                    os.getenv("DEPENDENCY_TRACK_URL"),
                    os.getenv("DEPENDENCY_TRACK_API_KEY"),
                )
                if not url or not key:
                    raise ReportingError(
                        "Configure DEPENDENCY_TRACK_URL and DEPENDENCY_TRACK_API_KEY"
                    )
                client = Client(url, key)
            except ReportingError, ValueError, OSError:
                write(
                    receipt_path,
                    {
                        "schema_version": 1,
                        "state": "failed",
                        "last_state": "configuring",
                    },
                )
                raise
            try:
                result = upload(
                    args.snapshot,
                    client,
                    allow_create=args.allow_create,
                    expected_head=args.expected_head,
                    timeout=args.timeout,
                )
            finally:
                client.close()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except ValidationError as error:
        # Do not echo arbitrary input values (which might contain credentials).
        messages = [
            f"{'.'.join(map(str, e['loc']))}: {e['msg']}"
            for e in error.errors(include_input=False, include_url=False)
        ]
        print("Invalid manifest: " + "; ".join(messages), file=sys.stderr)
    except (ReportingError, OSError, ValueError, KeyError) as error:
        message = (
            str(error)
            if isinstance(error, ReportingError)
            else "Invalid or unreadable reporting input"
        )
        print(f"SBOM reporting failed: {message}", file=sys.stderr)
    return 1
