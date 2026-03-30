"""
Sprint 3 - Task 3.1: Database Integration
Async SQLite wrapper using aiosqlite.
Handles table creation, alert insertion, and querying.
"""

import aiosqlite
from datetime import datetime

DB_PATH = "alerts.db"

# ── Schema ───────────────────────────────────────────────────────────────────

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,
    src_ip      TEXT    NOT NULL,
    dst_ip      TEXT    NOT NULL,
    dst_port    INTEGER NOT NULL,
    protocol    TEXT    NOT NULL,
    size        INTEGER NOT NULL,
    prediction  TEXT    NOT NULL,
    confidence  REAL    NOT NULL
);
"""

# ── Lifecycle ────────────────────────────────────────────────────────────────

async def init_db() -> None:
    """Creates the alerts table if it doesn't exist."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(CREATE_TABLE_SQL)
        await db.commit()
    print(f"[+] Database ready at '{DB_PATH}'")


# ── Writes ───────────────────────────────────────────────────────────────────

async def insert_alert(packet_data: dict, prediction: str, confidence: float) -> int:
    """
    Persists a classified packet to the alerts table.

    Returns the new row's id so it can be broadcast over WebSocket
    without a second query.
    """
    now = datetime.utcnow().isoformat(timespec="milliseconds") + "Z"

    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            """
            INSERT INTO alerts
                (timestamp, src_ip, dst_ip, dst_port, protocol, size, prediction, confidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now,
                packet_data.get("src_ip", ""),
                packet_data.get("dst_ip", ""),
                packet_data.get("dst_port", 0),
                packet_data.get("protocol", ""),
                packet_data.get("size", 0),
                prediction,
                round(confidence, 4),
            ),
        )
        await db.commit()
        return cursor.lastrowid


# ── Reads ────────────────────────────────────────────────────────────────────

async def get_recent_alerts(limit: int = 50) -> list[dict]:
    """Returns the most recent `limit` alerts, newest first."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
        ) as cursor:
            rows = await cursor.fetchall()
    return [dict(row) for row in rows]


async def get_stats() -> dict:
    """Returns aggregate counts for the stat bar."""
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT COUNT(*) FROM alerts") as cur:
            total = (await cur.fetchone())[0]
        async with db.execute(
            "SELECT COUNT(*) FROM alerts WHERE prediction = 'Malicious'"
        ) as cur:
            malicious = (await cur.fetchone())[0]

    return {"total": total, "malicious": malicious, "benign": total - malicious}