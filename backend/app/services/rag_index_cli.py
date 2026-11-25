"""Explicit local commands for rebuilding and inspecting the RAG index."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from app.services.rag_index import (
    RagIndexError,
    build_ingested_index,
    inspect_index,
    rebuild_index,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Manage the local API-security RAG index")
    commands = parser.add_subparsers(dest="command", required=True)
    rebuild = commands.add_parser("rebuild", help="atomically rebuild the local knowledge index")
    rebuild.add_argument("--manifest", type=Path, help="bounded JSON document manifest to add")
    rebuild.add_argument("--output", type=Path, help="override RAG_INDEX_PATH")
    rebuild.add_argument(
        "--lexical-only",
        action="store_true",
        help="build without embeddings when the local embedding model is unavailable",
    )
    rebuild.add_argument(
        "--only-manifest",
        action="store_true",
        help="omit bundled OWASP guidance and index only documents in --manifest",
    )
    inspect = commands.add_parser("inspect", help="print safe metadata for the current index")
    inspect.add_argument("--path", type=Path, help="override RAG_INDEX_PATH")
    ingest = commands.add_parser(
        "ingest",
        help="extract local reference files into a new provenance-rich candidate index",
    )
    ingest.add_argument("--directory", type=Path, required=True, help="local document directory")
    ingest.add_argument(
        "--output", type=Path, required=True, help="new index path; existing paths are refused"
    )
    ingest.add_argument("--lexical-only", action="store_true", help="skip Ollama embeddings")
    ingest.add_argument(
        "--category",
        choices=("public_security_documentation", "internal_iasa_knowledge"),
        default="public_security_documentation",
        help="classify this corpus; model use still requires hash approval",
    )
    args = parser.parse_args()
    try:
        if args.command == "rebuild":
            result: dict[str, Any] = rebuild_index(
                output_path=args.output,
                manifest_path=args.manifest,
                include_bundled=not args.only_manifest,
                lexical_only=args.lexical_only,
            )
        elif args.command == "ingest":
            result = build_ingested_index(
                args.directory,
                output_path=args.output,
                lexical_only=args.lexical_only,
                source_category=args.category,
            )
        else:
            result = inspect_index(args.path)
    except RagIndexError as exc:
        parser.exit(2, f"RAG index error: {exc}\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
