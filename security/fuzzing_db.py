import sqlite3
import os
import threading
from typing import Optional, Dict, Any, List

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'exports', 'fuzzing_results.db')

class FuzzingDB:
    _lock = threading.Lock()

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or DB_PATH
        self._ensure_tables()

    def _ensure_tables(self):
        with self._get_conn() as conn:
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS device_fingerprints (
                address TEXT PRIMARY KEY,
                name TEXT,
                fingerprint TEXT,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
            c.execute('''CREATE TABLE IF NOT EXISTS fuzzing_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address TEXT,
                char_uuid TEXT,
                strategy TEXT,
                max_cases INTEGER,
                crashes_found INTEGER,
                total_cases INTEGER,
                session_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
            c.execute('''CREATE TABLE IF NOT EXISTS crash_cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER,
                char_uuid TEXT,
                payload BLOB,
                response BLOB,
                crash_type TEXT,
                FOREIGN KEY(session_id) REFERENCES fuzzing_sessions(id)
            )''')
            conn.commit()

    def _get_conn(self):
        return sqlite3.connect(self.db_path)

    def store_fingerprint(self, address: str, name: str, fingerprint: str):
        with self._lock, self._get_conn() as conn:
            c = conn.cursor()
            c.execute('''INSERT OR REPLACE INTO device_fingerprints (address, name, fingerprint, last_seen)
                         VALUES (?, ?, ?, CURRENT_TIMESTAMP)''', (address, name, fingerprint))
            conn.commit()

    def get_fingerprint(self, address: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._get_conn() as conn:
            c = conn.cursor()
            c.execute('SELECT address, name, fingerprint, last_seen FROM device_fingerprints WHERE address=?', (address,))
            row = c.fetchone()
            if row:
                return {'address': row[0], 'name': row[1], 'fingerprint': row[2], 'last_seen': row[3]}
            return None

    def log_fuzzing_session(self, address: str, char_uuid: str, strategy: str, max_cases: int, crashes_found: int, total_cases: int) -> int:
        with self._lock, self._get_conn() as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO fuzzing_sessions (address, char_uuid, strategy, max_cases, crashes_found, total_cases)
                         VALUES (?, ?, ?, ?, ?, ?)''', (address, char_uuid, strategy, max_cases, crashes_found, total_cases))
            session_id = c.lastrowid
            conn.commit()
            return session_id

    def log_crash_case(self, session_id: int, char_uuid: str, payload: bytes, response: bytes, crash_type: str):
        with self._lock, self._get_conn() as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO crash_cases (session_id, char_uuid, payload, response, crash_type)
                         VALUES (?, ?, ?, ?, ?)''', (session_id, char_uuid, payload, response, crash_type))
            conn.commit()

    def get_fuzzing_history(self, address: str) -> List[Dict[str, Any]]:
        with self._lock, self._get_conn() as conn:
            c = conn.cursor()
            c.execute('''SELECT id, char_uuid, strategy, max_cases, crashes_found, total_cases, session_time
                         FROM fuzzing_sessions WHERE address=? ORDER BY session_time DESC''', (address,))
            rows = c.fetchall()
            return [
                {'session_id': r[0], 'char_uuid': r[1], 'strategy': r[2], 'max_cases': r[3],
                 'crashes_found': r[4], 'total_cases': r[5], 'session_time': r[6]}
                for r in rows
            ]

    def get_crash_cases(self, session_id: int) -> List[Dict[str, Any]]:
        with self._lock, self._get_conn() as conn:
            c = conn.cursor()
            c.execute('''SELECT char_uuid, payload, response, crash_type FROM crash_cases WHERE session_id=?''', (session_id,))
            rows = c.fetchall()
            return [
                {'char_uuid': r[0], 'payload': r[1], 'response': r[2], 'crash_type': r[3]}
                for r in rows
            ]
