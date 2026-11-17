-- Durable single-target outbox. Triggers participate in the caller's SQLite
-- transaction; no network request runs while a write transaction is held.
CREATE TABLE key_sync (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    desired_revision INTEGER NOT NULL DEFAULT 1,
    applied_revision INTEGER NOT NULL DEFAULT 0,
    desired_hash TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    last_error TEXT,
    updated_at INTEGER
);
INSERT INTO key_sync (id) VALUES (1);

-- Durable revoke/delete events survive removal of the original key row. The DB
-- already contains credential material; treat this table as equally private.
CREATE TABLE key_sync_revocations (
    user_id INTEGER NOT NULL,
    psk BLOB NOT NULL,
    PRIMARY KEY (user_id, psk)
);
INSERT OR IGNORE INTO key_sync_revocations SELECT user_id, psk FROM keys WHERE status = 'revoked';

CREATE TRIGGER key_sync_keys_insert AFTER INSERT ON keys BEGIN
    UPDATE key_sync SET desired_revision = desired_revision + 1, status = 'pending' WHERE id = 1;
END;
CREATE TRIGGER key_sync_keys_update AFTER UPDATE ON keys BEGIN
    INSERT OR IGNORE INTO key_sync_revocations SELECT OLD.user_id, OLD.psk WHERE NEW.status = 'revoked';
    UPDATE key_sync SET desired_revision = desired_revision + 1, status = 'pending' WHERE id = 1;
END;
CREATE TRIGGER key_sync_keys_delete AFTER DELETE ON keys BEGIN
    INSERT OR IGNORE INTO key_sync_revocations VALUES (OLD.user_id, OLD.psk);
    UPDATE key_sync SET desired_revision = desired_revision + 1, status = 'pending' WHERE id = 1;
END;
CREATE TRIGGER key_sync_users_update AFTER UPDATE OF status, expires_at, traffic_limit_bytes, traffic_used_bytes, inbound_id ON users BEGIN
    UPDATE key_sync SET desired_revision = desired_revision + 1, status = 'pending' WHERE id = 1;
END;
CREATE TRIGGER key_sync_users_delete AFTER DELETE ON users BEGIN
    UPDATE key_sync SET desired_revision = desired_revision + 1, status = 'pending' WHERE id = 1;
END;
CREATE TRIGGER key_sync_inbounds_update AFTER UPDATE ON inbounds BEGIN
    UPDATE key_sync SET desired_revision = desired_revision + 1, status = 'pending' WHERE id = 1;
END;
CREATE TRIGGER key_sync_inbounds_delete AFTER DELETE ON inbounds BEGIN
    UPDATE key_sync SET desired_revision = desired_revision + 1, status = 'pending' WHERE id = 1;
END;

CREATE TRIGGER keys_candidate_limit_insert BEFORE INSERT ON keys
WHEN NEW.status = 'active' AND (SELECT COUNT(*) FROM keys WHERE user_id = NEW.user_id AND status = 'active') >= 16
BEGIN SELECT RAISE(ABORT, 'active credential limit reached'); END;

CREATE TRIGGER keys_candidate_limit_update BEFORE UPDATE OF status, user_id ON keys
WHEN NEW.status = 'active' AND (SELECT COUNT(*) FROM keys WHERE user_id = NEW.user_id AND status = 'active' AND id != OLD.id) >= 16
BEGIN SELECT RAISE(ABORT, 'active credential limit reached'); END;
