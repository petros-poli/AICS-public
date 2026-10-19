"""Additive SWARMS-1 storage; membership is always replayed from committed leaves."""


def migrate(conn):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS swarm_bodies (
            leaf_index INTEGER PRIMARY KEY REFERENCES tlog_leaves(leaf_index),
            body BLOB, expired_policy_index INTEGER
        );
        CREATE TABLE IF NOT EXISTS swarm_secrets (
            actor_id TEXT PRIMARY KEY, secret_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS swarm_checkpoint_notes (
            note_hash TEXT PRIMARY KEY, size INTEGER NOT NULL, note BLOB NOT NULL
        );
        CREATE INDEX IF NOT EXISTS swarm_checkpoint_sizes ON swarm_checkpoint_notes(size);
    """)
