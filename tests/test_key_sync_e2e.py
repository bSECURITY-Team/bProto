"""Real panel -> mTLS agent -> native VPN create/apply/revoke.

Loopback, no kernel TUN. The health hook itself performs an authenticated native
handshake with an independent operator-owned probe credential. No secrets printed.
Build vpn-server, bproto and panel first. Missing binaries are test failures.
"""
import base64
import http.client
import importlib.util
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


agent_module = load("sync_agent", "tools/config-agent/agent.py")
lab = load("sync_lab", "tools/connection_lab.py")


def port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class KeySyncE2E(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="bproto-sync-e2e-", dir=os.environ.get("BPROTO_TEST_STATE_ROOT"))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        binaries = Path(os.environ.get("BPROTO_TEST_BIN_DIR", ROOT / "target/debug"))
        self.server_bin, self.client_bin = binaries / "vpn-server", binaries / "bproto"
        self.panel_bin = Path(os.environ.get("BPROTO_TEST_PANEL_BIN", ROOT / "panel/backend/target/debug/panel"))
        for binary in (self.server_bin, self.client_bin, self.panel_bin):
            self.assertTrue(binary.is_file(), "Build test binaries first")
        self.key, probe_psk = secrets.token_hex(32), secrets.token_hex(32)
        self.endpoint = os.environ.get("BPROTO_TEST_SERVER_ADDRESS", f"127.0.0.1:{port(socket.SOCK_DGRAM)}")
        self.config = self.root / "server.toml"
        self.config.write_text(lab.server_config(probe_psk, self.key, self.endpoint))
        self.config.chmod(0o600)
        self.control = self.root / "control.sock"
        command = [str(self.server_bin), "--config", str(self.config), "--control-socket", str(self.control)]
        if os.environ.get("BPROTO_TEST_DATAPATH") == "1":
            command.append("--datapath")
        self.native = self.process(command)
        self.wait(lambda: self.control.exists())
        probe = self.root / "probe.toml"
        probe.write_text(lab.client_config(probe_psk, self.key, self.endpoint, "1s"))
        probe.chmod(0o600)
        cert, key = self.root / "cert.pem", self.root / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
            "-out", str(cert), "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
            "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "extendedKeyUsage=serverAuth,clientAuth"],
            check=True, capture_output=True, timeout=15)
        identity = self.root / "identity.pem"
        identity.write_bytes(cert.read_bytes() + key.read_bytes())
        identity.chmod(0o600)
        self.agent = agent_module.Agent(dict(target=str(self.config), cert=str(cert), key=str(key), client_ca=str(cert),
            health=[str(self.client_bin), "--config", str(probe), "connect", "--seconds", "1"],
            stop=[sys.executable, "-c", "import os,signal,sys; os.kill(int(sys.argv[1]),signal.SIGTERM)", str(self.native.pid)],
            users_sync=dict(inbound_id=1, server_binary=str(self.server_bin), control_socket=str(self.control))))
        self.httpd = agent_module.HTTPServer(("127.0.0.1", 0), agent_module.handler(self.agent))
        self.httpd.socket = agent_module.tls_context(self.agent.settings).wrap_socket(self.httpd.socket, server_side=True)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_agent)
        self.panel_port = port()
        self.password = secrets.token_urlsafe(24)
        self.token = None
        self.process([str(self.panel_bin)], dict(os.environ,
            BPROTO_DB=f"sqlite://{self.root / 'panel.db'}?mode=rwc", BPROTO_LISTEN=f"127.0.0.1:{self.panel_port}",
            BPROTO_TAG_KEY=self.key, BPROTO_ADMIN_PASSWORD=self.password, BPROTO_KEY_SYNC_INBOUND="1",
            BPROTO_KEY_SYNC_AGENT_URL=f"https://localhost:{self.httpd.server_port}",
            BPROTO_CONFIG_AGENT_IDENTITY=str(identity), BPROTO_CONFIG_AGENT_CA=str(cert)))
        self.wait(self.panel_ready)
        self.token = self.api("POST", "/api/auth/login", dict(username="admin", password=self.password))["token"]
        self.inbound = self.api("POST", "/api/inbounds", dict(remark="isolated-sync-test", server=self.endpoint, donor_sni="localhost"))["id"]
        self.assertEqual(self.inbound, 1)

    def process(self, command, env=None):
        child = subprocess.Popen(command, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.stop, child)
        return child

    @staticmethod
    def stop(child):
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)

    def close_agent(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)

    def api(self, method, path, body=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.panel_port, timeout=5)
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        try:
            connection.request(method, path, None if body is None else json.dumps(body), headers)
            response = connection.getresponse()
            data = response.read()
            self.assertLess(response.status, 300, "Panel API operation failed")
            return json.loads(data) if data != b"ok" else {}
        finally:
            connection.close()

    def panel_ready(self):
        try:
            self.api("GET", "/api/health")
            return True
        except OSError:
            return False

    def wait(self, condition, timeout=30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if condition():
                return
            time.sleep(.05)
        self.fail("Isolated service/desired revision readiness timeout")

    def applied(self):
        value = self.api("GET", "/api/key-sync")
        return value["status"] == "applied" and value["desired_revision"] == value["applied_revision"]

    def client_config(self, client):
        encoded = client["config_uri"].split("/import/", 1)[1]
        profile = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        path = self.root / f'client-{client["key_id"]}.toml'
        text = lab.client_config(profile["psk"], profile["tag_key"], self.endpoint, "1s")
        path.write_text(text.replace("user_id = 1", f'user_id = {profile["uid"]}'))
        path.chmod(0o600)
        return path, profile["psk"]

    def handshake(self, path, succeeds):
        result = subprocess.run([str(self.client_bin), "--config", str(path), "connect", "--seconds", "1"],
            capture_output=True, timeout=8)
        self.assertEqual(result.returncode == 0, succeeds, "Unexpected authenticated handshake outcome")
        if succeeds:
            self.assertIn(b"tunnel up:", result.stdout)
        else:
            self.assertIn(b"handshake", (result.stdout + result.stderr).lower())

    def test_create_apply_handshake_revoke_rejects_handshake(self):
        client = self.api("POST", f"/api/inbounds/{self.inbound}/clients", dict(username="device", label="first"))
        path, psk = self.client_config(client)
        self.wait(self.applied)
        self.handshake(path, True)
        self.api("POST", f'/api/keys/{client["key_id"]}/revoke')
        self.wait(self.applied)
        self.assertNotIn(psk, self.config.read_text(), "Revoked PSK remains in live TOML")
        self.handshake(path, False)
        self.assertIsNone(self.native.poll())
        # Restart the agent object against the same durable state and retry.
        recovered = agent_module.Agent(self.agent.settings)
        self.assertEqual(recovered.users.status()["status"], "healthy")
