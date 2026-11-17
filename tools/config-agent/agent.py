#!/usr/bin/env python3
"""Single-service configuration agent. Operator-defined commands, mTLS only."""
import argparse
import base64
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import socket
import tomllib
from http.server import BaseHTTPRequestHandler, HTTPServer


def atomic_write(path, data):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".bproto-")
    try:
        with os.fdopen(fd, "wb") as stream:
            if path.exists():
                owner = path.stat()
                if os.geteuid() == 0:
                    os.fchown(stream.fileno(), owner.st_uid, owner.st_gid)
                elif owner.st_uid != os.geteuid():
                    raise PermissionError("cannot preserve configuration owner")
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class Agent:
    def __init__(self, settings):
        self.settings = settings
        self.target = Path(settings["target"])
        self.backup = self.target.with_name(self.target.name + ".previous")
        self.users = UsersSync(self) if settings.get("users_sync") else None

    def command(self, name, candidate=None):
        command = self.settings[name]
        if not isinstance(command, list) or not command or not all(isinstance(x, str) for x in command):
            raise ValueError("operator command must be an argument array")
        env = dict(os.environ)
        if candidate:
            env["BPROTO_CANDIDATE_CONFIG"] = str(candidate)
        subprocess.run(command, check=True, timeout=15, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, env=env)

    def apply(self, document):
        if self.users:
            raise ValueError("credential target requires versioned users operation")
        if not isinstance(document, dict) or document.get("version") != 1 or set(document) != {"version", "config"}:
            raise ValueError("expected schema version 1 and config")
        config = document["config"]
        if not isinstance(config, dict):
            raise ValueError("config must be an object")
        # Validate against the actual service using a private staged file.
        data = json.dumps(config, sort_keys=True).encode()
        if len(data) > 65536:
            raise ValueError("config too large")
        if not self.target.is_file():
            raise ValueError("initial configuration must be provisioned by operator")
        old = self.target.read_bytes()
        fd, staged = tempfile.mkstemp(dir=self.target.parent, prefix=".validate-")
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
            self.command("validate", staged)
        finally:
            os.unlink(staged)
        atomic_write(self.backup, old)
        atomic_write(self.target, data)
        try:
            self.command("reload")
            self.command("health")
        except (OSError, subprocess.SubprocessError):
            atomic_write(self.target, old)
            try:
                self.command("reload")
                self.command("health")
            except (OSError, subprocess.SubprocessError):
                return {"status": "rollback_failed", "error": "Previous file restored; service health failed"}
            return {"status": "rolled_back", "error": "New configuration failed health validation"}
        return {"status": "applied"}

    def rollback(self):
        if self.users:
            raise ValueError("credential rollback must not resurrect revoked keys")
        if not self.backup.is_file():
            raise ValueError("no previous configuration")
        return self.apply({"version": 1, "config": json.loads(self.backup.read_bytes())})


BEGIN_USERS = "# BEGIN bProto managed users v1\n"
END_USERS = "# END bProto managed users v1\n"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class UsersSync:
    """Credential-only adapter on the existing mTLS agent. Linux/Python >=3.11.

    Never roll back a removal to a configuration containing the removed PSK.
    A removal whose health check fails retains its recovery journal and invokes
    the operator's fixed stop hook. UI must keep it pending until acknowledged.
    """
    def __init__(self, agent):
        self.agent = agent
        self.target = agent.target
        self.settings = agent.settings["users_sync"]
        if self.target.is_symlink() or self.target.parent.stat().st_mode & 0o022:
            raise ValueError("users target requires a protected operator-owned directory")
        self.state = self.target.with_name(self.target.name + ".users-state")
        self.journal = self.target.with_name(self.target.name + ".users-journal")
        self.lock = self.target.with_name(self.target.name + ".users-lock")
        for required in ("server_binary", "control_socket", "inbound_id"):
            if required not in self.settings:
                raise ValueError("users_sync settings incomplete")
        if "stop" not in agent.settings or "health" not in agent.settings:
            raise ValueError("users sync requires fixed health and fail-closed stop hooks")

    def locked(self):
        # Lock lives in the private operator-owned config directory, not /tmp.
        fd = os.open(self.lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        stream = os.fdopen(fd, "r+")
        fcntl.flock(stream, fcntl.LOCK_EX)
        return stream

    def read_state(self):
        if not self.state.exists():
            return {"revision": 0, "proof": None, "credentials": [], "revoked": []}
        state = json.loads(self.state.read_bytes())
        if set(state) != {"revision", "proof", "credentials", "revoked"}:
            raise ValueError("invalid durable credential state")
        return state

    def local(self, command):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
            stream.settimeout(5)
            stream.connect(self.settings["control_socket"])
            stream.sendall(command.encode() + b"\n")
            response = b""
            while not response.endswith(b"\n") and len(response) < 100:
                chunk = stream.recv(100 - len(response))
                if not chunk:
                    break
                response += chunk
        if len(response) != 68 or not response.startswith(b"ok "):
            raise ValueError("runtime operation rejected")
        return response[3:-1].decode("ascii")

    def runtime(self, command, data):
        key = bytes.fromhex(tomllib.loads(data.decode())["tag_key"])
        expected = hmac.digest(key, b"bproto config receipt v1\0" + data, "sha256").hex()
        if not hmac.compare_digest(self.local(command), expected):
            raise ValueError("runtime revision differs from disk")

    def validate(self, data):
        fd, path = tempfile.mkstemp(dir=self.target.parent, prefix=".users-validate-")
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
            subprocess.run([self.settings["server_binary"], "--check-config", "--config", path],
                check=True, timeout=15, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        finally:
            os.unlink(path)

    def remove_journal(self):
        self.journal.unlink()
        fd = os.open(self.target.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def finish(self, journal):
        data = base64.b64decode(journal["candidate"], validate=True)
        atomic_write(self.target, data)
        try:
            self.runtime("reload", data)
            self.runtime("health", data)
            self.agent.command("health")
        except (ValueError, OSError, subprocess.SubprocessError):
            if journal["removed"]:
                # Persisted revocation intent is not undone to restore availability.
                try:
                    self.agent.command("stop")
                except (OSError, subprocess.SubprocessError):
                    pass
                return {"status": "rollback_failed", "revision": journal["state"]["revision"]}
            old = base64.b64decode(journal["old"], validate=True)
            atomic_write(self.target, old)
            try:
                self.runtime("reload", old)
                self.runtime("health", old)
                self.agent.command("health")
            except (ValueError, OSError, subprocess.SubprocessError):
                return {"status": "rollback_failed", "revision": journal["state"]["revision"]}
            self.remove_journal()
            return {"status": "rolled_back", "revision": journal["state"]["revision"]}
        atomic_write(self.state, canonical(journal["state"]))
        if journal["removed"]:
            # A historical backup must not retain a removed PSK or offer an
            # operator an unsafe route to resurrecting it.
            atomic_write(self.agent.backup, data)
        self.remove_journal()
        return {"status": "applied", "revision": journal["state"]["revision"]}

    def apply(self, document):
        with self.locked():
            if self.journal.exists():
                recovered = self.finish(json.loads(self.journal.read_bytes()))
                if recovered["status"] == "rollback_failed":
                    return recovered
            required = {"version", "revision", "inbound_id", "users", "owned_users", "revoked", "tag_proof"}
            if not isinstance(document, dict) or set(document) != required or type(document["version"]) is not int or document["version"] != 2:
                raise ValueError("unsupported users snapshot")
            revision = document["revision"]
            if type(revision) is not int or not 0 < revision <= 2**63 - 1:
                raise ValueError("invalid revision")
            if type(document["inbound_id"]) is not int or document["inbound_id"] != self.settings["inbound_id"]:
                raise ValueError("wrong target inbound")
            raw = self.target.read_bytes()
            config = tomllib.loads(raw.decode())
            key = bytes.fromhex(config["tag_key"])
            if len(key) != 32 or not isinstance(document["tag_proof"], str):
                raise ValueError("invalid tag proof")
            unsigned = {k: v for k, v in document.items() if k != "tag_proof"}
            proof = hmac.digest(key, b"bproto users snapshot v1\0" + canonical(unsigned), "sha256").hex()
            if not hmac.compare_digest(proof, document["tag_proof"]):
                raise ValueError("tag key mismatch")
            state = self.read_state()
            if revision == state["revision"] and proof == state["proof"]:
                self.runtime("health", raw)
                return {"status": "applied", "revision": revision}
            if revision <= state["revision"]:
                raise ValueError("stale or conflicting revision")
            users = document["users"]
            if not isinstance(users, list) or len(users) > 4096:
                raise ValueError("invalid users list")
            owned = document["owned_users"]
            if not isinstance(owned, list) or len(owned) > 4096 or any(
                    type(uid) is not int or not 0 < uid <= 2**63 - 1 for uid in owned) or len(set(owned)) != len(owned):
                raise ValueError("invalid managed ownership")
            revoked = document["revoked"]
            if not isinstance(revoked, list) or len(revoked) > 4096 or any(
                    not isinstance(token, str) or len(token) != 64 or token != token.lower()
                    or any(c not in "0123456789abcdef" for c in token) for token in revoked):
                raise ValueError("invalid revocation identities")
            revoked = set(state["revoked"]) | set(revoked)
            ids, credentials, counts = set(), [], {}
            for user in users:
                if not isinstance(user, dict) or set(user) != {"id", "psk"}:
                    raise ValueError("invalid credential")
                uid, psk = user["id"], user["psk"]
                if type(uid) is not int or not 0 < uid <= 2**63 - 1:
                    raise ValueError("invalid user id")
                if not isinstance(psk, str) or len(psk) != 64 or psk != psk.lower():
                    raise ValueError("invalid PSK encoding")
                if len(bytes.fromhex(psk)) != 32:
                    raise ValueError("invalid PSK length")
                identity = hashlib.sha256(f"{uid}:{psk}".encode()).hexdigest()
                if identity in credentials or identity in revoked:
                    raise ValueError("duplicate or previously revoked credential")
                credentials.append(identity)
                counts[uid] = counts.get(uid, 0) + 1
                if counts[uid] > 16:
                    raise ValueError("too many credentials for user")
                ids.add(uid)
            if not ids.issubset(set(owned)):
                raise ValueError("credential outside managed ownership")
            text = raw.decode()
            if BEGIN_USERS in text or END_USERS in text:
                if text.count(BEGIN_USERS) != 1 or text.count(END_USERS) != 1:
                    raise ValueError("invalid managed region")
                prefix, managed = text.split(BEGIN_USERS)
                _, tail = managed.split(END_USERS)
                if tail.strip():
                    raise ValueError("managed users region must be last")
            else:
                prefix = text
            unmanaged = tomllib.loads(prefix).get("users", [])
            if any(user["id"] in owned or hashlib.sha256(
                    f'{user["id"]}:{user["psk"].lower()}'.encode()).hexdigest() in revoked for user in unmanaged):
                raise ValueError("managed user overlaps an operator-owned user")
            block = "".join(f'[[users]]\nid = {u["id"]}\npsk = "{u["psk"]}"\n' for u in users)
            data = (prefix.rstrip() + "\n\n" + BEGIN_USERS + block + END_USERS).encode()
            self.validate(data)
            removed = set(state["credentials"]) - set(credentials)
            next_state = {"revision": revision, "proof": proof, "credentials": credentials,
                          "revoked": sorted(revoked)}
            journal = {"old": base64.b64encode(raw).decode(), "candidate": base64.b64encode(data).decode(),
                       "state": next_state, "removed": bool(removed)}
            atomic_write(self.agent.backup, raw)
            atomic_write(self.journal, canonical(journal))
            return self.finish(journal)

    def status(self):
        with self.locked():
            state = self.read_state()
            if self.journal.exists():
                return {"status": "rollback_failed", "revision": state["revision"]}
            self.runtime("health", self.target.read_bytes())
            return {"status": "healthy", "revision": state["revision"]}


def handler(agent):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def log_message(self, *_):
            pass  # Do not log request bodies, secrets, or client-controlled text.

        def do_POST(self):
            try:
                if self.headers.get("Transfer-Encoding"):
                    raise ValueError("chunked requests are not accepted")
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 <= size <= 65536:
                    raise ValueError("request too large")
                body = self.rfile.read(size)
                if len(body) != size:
                    raise ValueError("incomplete body")
                if self.path == "/users/apply" and agent.users:
                    result = agent.users.apply(json.loads(body))
                elif self.path == "/users/status" and agent.users:
                    result = agent.users.status()
                elif self.path == "/apply":
                    result = agent.apply(json.loads(body))
                elif self.path == "/rollback":
                    result = agent.rollback()
                elif self.path == "/health":
                    if agent.users:
                        result = agent.users.status()
                    else:
                        agent.command("health")
                        result = {"status": "healthy"}
                else:
                    raise ValueError("unknown action")
                code = 200 if result["status"] in ("applied", "healthy") else 409
            except (ValueError, OSError, subprocess.SubprocessError):
                code, result = 400, {"error": "Configuration rejected or service operation failed"}
            data = json.dumps(result).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)
    return Handler


def tls_context(settings):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(settings["cert"], settings["key"])
    context.load_verify_locations(settings["client_ca"])
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("settings", type=Path)
    settings = json.loads(parser.parse_args().settings.read_text())
    context = tls_context(settings)
    # Serial requests intentionally serialize mutations; no concurrent rollbacks.
    server = HTTPServer((settings.get("listen_host", "127.0.0.1"), settings["listen_port"]), handler(Agent(settings)))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
