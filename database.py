
import sqlite3
from pathlib import Path
from datetime import datetime

DB_PATH = Path(__file__).resolve().parent / "fraudshield_history.db"


def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                tool TEXT NOT NULL,
                risk TEXT NOT NULL,
                score TEXT,
                reasons TEXT,
                summary TEXT
            )
        """)
        conn.commit()


def save_scan(tool, risk, score, reasons="", summary=""):
    init_db()
    timestamp = datetime.now().astimezone().strftime(
        "%Y-%m-%d %H:%M:%S %Z"
    )

    with _connect() as conn:
        conn.execute("""
            INSERT INTO scan_history
            (timestamp, tool, risk, score, reasons, summary)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            str(timestamp), str(tool), str(risk), str(score),
            str(reasons), str(summary)
        ))
        conn.commit()


def get_history(limit=1000):
    init_db()
    with _connect() as conn:
        rows = conn.execute("""
            SELECT id, timestamp, tool, risk, score, reasons, summary
            FROM scan_history
            ORDER BY id DESC
            LIMIT ?
        """, (int(limit),)).fetchall()

    return [dict(row) for row in rows]


def clear_history():
    init_db()
    with _connect() as conn:
        conn.execute("DELETE FROM scan_history")
        conn.commit()
