import os
import re
from pathlib import Path
from typing import Any, Iterable, List, Optional, Sequence, Tuple

try:
    import psycopg
except Exception:  # pragma: no cover - optional until postgres mode enabled
    psycopg = None


DB_BACKEND = "postgres"
POSTGRES_DSN = (os.getenv("POSTGRES_DSN", "") or "").strip()

_PLACEHOLDER_RE = re.compile(r"\?")
_INSERT_OR_IGNORE_RE = re.compile(r"^\s*INSERT\s+OR\s+IGNORE\s+INTO\s+", re.I)


def is_postgres() -> bool:
    return True


def _postgres_default_dsn() -> str:
    host = os.getenv("POSTGRES_HOST", "postgres")
    port = os.getenv("POSTGRES_PORT", "5432")
    db = os.getenv("POSTGRES_DB", "mtr")
    user = os.getenv("POSTGRES_USER", "mtr")
    pw = os.getenv("POSTGRES_PASSWORD", "change-me")
    return f"postgresql://{user}:{pw}@{host}:{port}/{db}"


def _ensure_dir(path: str) -> None:
    d = os.path.dirname(path)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)


class CompatRow:
    def __init__(self, columns: Sequence[str], values: Sequence[Any]):
        self._cols = list(columns)
        self._vals = list(values)
        self._map = {c: values[i] for i, c in enumerate(columns)}

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, int):
            return self._vals[key]
        return self._map[key]

    def __iter__(self):
        return iter(self._vals)

    def keys(self):
        return self._map.keys()

    def items(self):
        return self._map.items()

    def get(self, key: str, default: Any = None) -> Any:
        return self._map.get(key, default)


def _rewrite_sql(sql: str) -> Optional[str]:
    s = (sql or "").strip()
    if not s:
        return s
    if s.upper().startswith("PRAGMA "):
        return None
    if _INSERT_OR_IGNORE_RE.match(s):
        s = _INSERT_OR_IGNORE_RE.sub("INSERT INTO ", s)
        if re.search(r"\bON\s+CONFLICT\b", s, re.I) is None:
            s = s.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"
    s = re.sub(r"\s+COLLATE\s+NOCASE\b", "", s, flags=re.I)
    s = re.sub(r"\bIFNULL\s*\(", "COALESCE(", s, flags=re.I)
    return _PLACEHOLDER_RE.sub("%s", s)


class PgCompatCursor:
    def __init__(self, raw_cursor: Any):
        self._c = raw_cursor
        self._cols: List[str] = []
        self.rowcount = -1

    def execute(self, sql: str, params: Optional[Iterable[Any]] = None):
        rewritten = _rewrite_sql(sql)
        if rewritten is None:
            self.rowcount = 0
            return self
        self._c.execute(rewritten, tuple(params or ()))
        desc = self._c.description or []
        self._cols = [d.name for d in desc]
        self.rowcount = self._c.rowcount
        return self

    def executemany(self, sql: str, seq_of_params: Iterable[Iterable[Any]]):
        rewritten = _rewrite_sql(sql)
        if rewritten is None:
            self.rowcount = 0
            return self
        self._c.executemany(rewritten, [tuple(p or ()) for p in seq_of_params])
        desc = self._c.description or []
        self._cols = [d.name for d in desc]
        self.rowcount = self._c.rowcount
        return self

    def fetchone(self):
        row = self._c.fetchone()
        if row is None:
            return None
        return CompatRow(self._cols, row)

    def fetchall(self):
        rows = self._c.fetchall()
        return [CompatRow(self._cols, r) for r in rows]

    def __iter__(self):
        rows = self.fetchall()
        return iter(rows)


class PgCompatConnection:
    def __init__(self, raw_conn: Any):
        self._conn = raw_conn

    def cursor(self):
        return PgCompatCursor(self._conn.cursor())

    def execute(self, sql: str, params: Optional[Iterable[Any]] = None):
        cur = self.cursor()
        return cur.execute(sql, params)

    def executemany(self, sql: str, seq_of_params: Iterable[Iterable[Any]]):
        cur = self.cursor()
        return cur.executemany(sql, seq_of_params)

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()


def get_conn(logical_name: str):
    if psycopg is None:
        raise RuntimeError("PostgreSQL runtime requires psycopg dependency")
    dsn = POSTGRES_DSN or _postgres_default_dsn()
    raw = psycopg.connect(dsn, autocommit=False)
    return PgCompatConnection(raw)


def init_postgres_schema() -> None:
    conn = get_conn("postgres")
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version TEXT PRIMARY KEY,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        migrations_dir = Path(__file__).resolve().parent / "migrations" / "postgres"
        if not migrations_dir.exists():
            conn.commit()
            return
        for path in sorted(migrations_dir.glob("*.sql")):
            version = path.name
            row = conn.execute("SELECT version FROM schema_migrations WHERE version = ?", (version,)).fetchone()
            if row:
                continue
            sql_text = path.read_text(encoding="utf-8")
            # Execute SQL file statements one by one for compatibility wrapper.
            for statement in [s.strip() for s in sql_text.split(";") if s.strip()]:
                conn.execute(statement)
            conn.execute("INSERT INTO schema_migrations(version) VALUES(?)", (version,))
            conn.commit()
        required = (os.getenv("REQUIRED_SCHEMA_VERSION", "") or "").strip()
        if required:
            chk = conn.execute(
                "SELECT version FROM schema_migrations WHERE version = ?",
                (required,),
            ).fetchone()
            if not chk:
                raise RuntimeError(
                    f"Required schema version not applied: {required}"
                )
    finally:
        conn.close()
