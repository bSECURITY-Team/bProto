#!/usr/bin/env python3
"""Release artifact gate. Never prints keystore data, passwords or tool output."""
import argparse
import base64
import hashlib
import os
from pathlib import Path
import re
import subprocess


def materialize_keystore(path):
    encoded = os.environ.get("BPROTO_ANDROID_KEYSTORE_BASE64", "")
    if not encoded or len(encoded) > 512 * 1024:
        raise ValueError("missing or oversized signing keystore")
    data = base64.b64decode(encoded, validate=True)
    if not data:
        raise ValueError("empty signing keystore")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def verify(apksigner, apk, expected):
    digest = expected.replace(":", "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("expected signing certificate SHA256 is required")
    if not apk.is_file():
        raise ValueError("release APK is missing")
    result = subprocess.run([apksigner, "verify", "--verbose", "--print-certs", str(apk)],
        capture_output=True, timeout=30)
    if result.returncode != 0:
        raise ValueError("APK signature verification failed")
    certificates = re.findall(rb"^Signer #[0-9]+ certificate SHA-256 digest: ([0-9a-fA-F]{64})\s*$", result.stdout, re.MULTILINE)
    if len(certificates) != 1 or certificates[0].decode().lower() != digest:
        raise ValueError("unexpected APK signing identity")
    # Publish only a public signer fingerprint and artifact digest.
    with apk.open("rb") as stream:
        artifact = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"signer_sha256": digest, "apk_sha256": artifact}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("keystore")
    prepare.add_argument("path", type=Path)
    check = commands.add_parser("verify")
    check.add_argument("--apksigner", required=True)
    check.add_argument("--apk", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "keystore":
            materialize_keystore(args.path)
        else:
            result = verify(args.apksigner, args.apk, os.environ.get("BPROTO_ANDROID_SIGNER_SHA256", ""))
            print("Signer SHA256: " + result["signer_sha256"])
            print("APK SHA256: " + result["apk_sha256"])
    except (ValueError, OSError, subprocess.SubprocessError):
        raise SystemExit("Android release gate rejected the signing input or artifact") from None


if __name__ == "__main__":
    main()
