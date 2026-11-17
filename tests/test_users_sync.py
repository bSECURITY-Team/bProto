"""Transactional credential adapter tests. Service commands mocked here;
real panel/mTLS/native-handshake coverage lives in test_key_sync_e2e.py.
"""
import importlib.util
import hmac
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("users_agent", Path(__file__).resolve().parents[1] / "tools/config-agent/agent.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class UsersTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.target = Path(self.tmp.name) / "server.toml"
        self.target.write_text('tag_key = "' + '22' * 32 + '"\n# operator comment\n[donor]\nsni = "localhost"\n')
        self.agent = module.Agent(dict(target=str(self.target), health=["true"], stop=["true"],
            users_sync=dict(inbound_id=1, server_binary="unused", control_socket="unused")))
        self.users = self.agent.users
        self.users.validate = lambda data: module.tomllib.loads(data.decode())
        self.calls = []
        self.users.runtime = lambda command, data: self.calls.append(command)
        self.agent.command = lambda name, candidate=None: self.calls.append(name)

    def document(self, revision, users=None, key=None, revoked=None):
        body = dict(version=2, revision=revision, inbound_id=1, owned_users=[2],
                    users=[dict(id=2, psk="11" * 32)] if users is None else users,
                    revoked=([hashlib.sha256(('2:' + '11' * 32).encode()).hexdigest()] if users == [] else []) if revoked is None else revoked)
        body["tag_proof"] = hmac.digest(key or bytes.fromhex("22" * 32),
            b"bproto users snapshot v1\0" + module.canonical(body), "sha256").hex()
        return body

    def test_preserves_operator_config_and_retries_without_reload(self):
        doc = self.document(1)
        self.assertEqual(self.users.apply(doc), dict(status="applied", revision=1))
        self.assertIn("# operator comment", self.target.read_text())
        before = self.agent.backup.read_bytes()
        self.calls.clear()
        self.assertEqual(self.users.apply(doc)["status"], "applied")
        self.assertEqual(self.calls, ["health"])
        self.assertEqual(self.agent.backup.read_bytes(), before)
        self.assertEqual(self.users.state.stat().st_mode & 0o777, 0o600)

    def test_mismatch_conflict_stale_and_unknown_schema_do_not_mutate(self):
        original = self.target.read_bytes()
        with self.assertRaises(ValueError):
            self.users.apply(self.document(1, key=b"x" * 32))
        self.assertEqual(self.target.read_bytes(), original)
        self.users.apply(self.document(2))
        for document in [self.document(1), self.document(2, []), {"version": 99}]:
            with self.assertRaises(ValueError):
                self.users.apply(document)

    def test_revoke_removes_psk_and_rejects_resurrection(self):
        self.users.apply(self.document(1))
        self.assertEqual(self.users.apply(self.document(2, []))["status"], "applied")
        self.assertNotIn("11" * 32, self.target.read_text())
        with self.assertRaises(ValueError):
            self.users.apply(self.document(3))
        with self.assertRaises(ValueError):
            self.agent.rollback()
        with self.assertRaises(ValueError):
            self.agent.apply(dict(version=1, config={}))

    def test_addition_health_failure_rolls_back(self):
        old = self.target.read_bytes()
        def health(command, data):
            if b"[[users]]" in data:
                raise ValueError("bad runtime")
        self.users.runtime = health
        self.assertEqual(self.users.apply(self.document(1))["status"], "rolled_back")
        self.assertEqual(self.target.read_bytes(), old)
        self.assertFalse(self.users.journal.exists())
        self.assertEqual(self.users.read_state()["revision"], 0)

    def test_failed_revoke_keeps_safe_file_stops_service_and_recovers(self):
        self.users.apply(self.document(1))
        good = self.users.runtime
        def fail(*args):
            raise OSError("service down")
        self.users.runtime = fail
        self.assertEqual(self.users.apply(self.document(2, []))["status"], "rollback_failed")
        self.assertNotIn("11" * 32, self.target.read_text())
        self.assertIn("stop", self.calls)
        self.assertTrue(self.users.journal.exists())
        self.users.runtime = good
        self.assertEqual(self.users.apply(self.document(2, []))["status"], "applied")
        self.assertFalse(self.users.journal.exists())

    def test_validation_failure_leaves_no_journal_or_mutation(self):
        old = self.target.read_bytes()
        def fail(data):
            raise subprocess.CalledProcessError(1, ["validate"])
        self.users.validate = fail
        with self.assertRaises(subprocess.CalledProcessError):
            self.users.apply(self.document(1))
        self.assertEqual(self.target.read_bytes(), old)
        self.assertFalse(self.users.journal.exists())

    def test_operator_user_overlap_rejected(self):
        self.target.write_text(self.target.read_text() + '\n[[users]]\nid = 2\npsk = "' + '33' * 32 + '"\n')
        with self.assertRaises(ValueError):
            self.users.apply(self.document(1))
        # Disable/revoke must not report success while a copied static PSK stays.
        with self.assertRaises(ValueError):
            self.users.apply(self.document(1, [], revoked=[]))
        with self.assertRaises(ValueError):
            self.users.apply(self.document(1, []))

    def test_crash_after_journal_rolls_forward_on_retry(self):
        good = self.users.finish
        self.users.finish = lambda journal: (_ for _ in ()).throw(RuntimeError("crash"))
        with self.assertRaises(RuntimeError):
            self.users.apply(self.document(1))
        self.assertTrue(self.users.journal.exists())
        self.users.finish = good
        self.assertEqual(self.users.apply(self.document(1))["status"], "applied")
        self.assertEqual(self.users.read_state()["revision"], 1)

    def test_disable_and_reenable_do_not_permanently_revoke(self):
        self.users.apply(self.document(1))
        self.users.apply(self.document(2, [], revoked=[]))
        self.assertEqual(self.users.apply(self.document(3))["status"], "applied")
