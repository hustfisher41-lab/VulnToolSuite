"""Verify an extracted deployment bundle's inventory before installation."""
import hashlib
import json
from pathlib import Path
import sys


def verify(directory):
    directory = Path(directory).resolve(strict=True)
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("schema") != "vulntools/sandbox-node-bundle/v1":
        raise ValueError("Unknown deployment bundle schema")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise ValueError("Bundle inventory is empty")
    for name, expected in files.items():
        path = directory / name
        if path.is_symlink() or not path.resolve().is_relative_to(directory):
            raise ValueError("Bundle path escaped or is a symlink")
        data = path.read_bytes()
        if len(data) != expected["bytes"] or hashlib.sha256(data).hexdigest() != expected["sha256"]:
            raise ValueError("Bundle file changed: " + name)
    actual = {path.relative_to(directory).as_posix() for path in directory.rglob("*") if path.is_file()}
    if actual != set(files) | {"manifest.json"}:
        raise ValueError("Bundle has extra or missing files")
    return len(files)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python3 deployment/verify-node-bundle.py /extracted/bundle")
    print("Verified files:", verify(sys.argv[1]))
