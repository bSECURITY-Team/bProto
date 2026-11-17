"""Release gate negative tests; subprocess fixtures are not signed-APK evidence."""
import base64
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("android_release", Path(__file__).resolve().parents[1] / "tools/android_release.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ReleaseGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.apk = self.root / "test.apk"
        self.apk.write_bytes(b"synthetic gate fixture, not an APK")
        self.digest = "12" * 32

    def signer(self, output, status=0):
        tool = self.root / "apksigner-fixture"
        tool.write_text("#!/bin/sh\nprintf '%s\\n' '" + output + "'\nexit " + str(status) + "\n")
        tool.chmod(0o700)
        return str(tool)

    def test_prepares_private_keystore_and_refuses_overwrite(self):
        path = self.root / "release.jks"
        with patch.dict(os.environ, {"BPROTO_ANDROID_KEYSTORE_BASE64": base64.b64encode(b"test-keystore").decode()}):
            module.materialize_keystore(path)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.read_bytes(), b"test-keystore")
            with self.assertRaises(FileExistsError):
                module.materialize_keystore(path)

    def test_missing_malformed_or_empty_keystore_rejected(self):
        for value in ("", "!!!", "=" * 4):
            with self.subTest(value=value), patch.dict(os.environ, {"BPROTO_ANDROID_KEYSTORE_BASE64": value}):
                with self.assertRaises(ValueError):
                    module.materialize_keystore(self.root / "missing.jks")

    def test_accepts_only_successful_matching_single_signer(self):
        tool = self.signer("Signer #1 certificate SHA-256 digest: " + self.digest)
        result = module.verify(tool, self.apk, self.digest.upper())
        self.assertEqual(result["signer_sha256"], self.digest)
        self.assertEqual(result["apk_sha256"], hashlib.sha256(self.apk.read_bytes()).hexdigest())

    def test_wrong_identity_signature_failure_and_multiple_signers_rejected(self):
        cases = [
            ("Signer #1 certificate SHA-256 digest: " + "34" * 32, 0),
            ("Signer #1 certificate SHA-256 digest: " + self.digest, 1),
            ("Signer #1 certificate SHA-256 digest: " + self.digest + "\nSigner #2 certificate SHA-256 digest: " + self.digest, 0),
        ]
        for output, status in cases:
            with self.subTest(status=status), self.assertRaises(ValueError):
                module.verify(self.signer(output, status), self.apk, self.digest)
        with self.assertRaises(ValueError):
            module.verify("unused", self.apk, "")
