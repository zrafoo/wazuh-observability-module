from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

import psycopg2
from psycopg2 import sql
from psycopg2.extras import Json, execute_values

USAGE_PERCENT_TO_DROP = float(os.getenv("USAGE_PERCENT_TO_DROP", "2"))

POSTGRES_HOST = os.getenv("POSTGRES_HOST", "localhost")
POSTGRES_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
POSTGRES_DB = os.getenv("POSTGRES_DB", "app_db")
POSTGRES_USER = os.getenv("POSTGRES_USER", "app_user")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "app_password")
POSTGRES_TABLE = os.getenv("POSTGRES_TABLE", "opensearch_events")
POSTGRES_SOURCE_TABLE = os.getenv("POSTGRES_SOURCE_TABLE", POSTGRES_TABLE)
POSTGRES_CLEAN_TABLE = os.getenv("POSTGRES_CLEAN_TABLE", "opensearch_events_clean")
POSTGRES_BATCH_SIZE = int(os.getenv("POSTGRES_BATCH_SIZE", "1000"))
TRUNCATE_CLEAN_TABLE = os.getenv("TRUNCATE_CLEAN_TABLE", "true")


def _parse_bool_env(value: Optional[str], name: str) -> bool:
    if value is None:
        return False
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean-like string (true/false).")


@dataclass(frozen=True)
class DropReport:
    total_rows: int
    threshold_percent: float
    threshold_rows: int
    dropped: List[str]
    kept: List[str]


@dataclass(frozen=True)
class ColumnUsage:
    column: str
    used_rows: int
    total_rows: int

    def format(self) -> str:
        return f"{self.column} - {self.used_rows}/{self.total_rows}"


def build_pg_conn() -> psycopg2.extensions.connection:
    return psycopg2.connect(
        host=POSTGRES_HOST,
        port=POSTGRES_PORT,
        dbname=POSTGRES_DB,
        user=POSTGRES_USER,
        password=POSTGRES_PASSWORD,
    )


def _ensure_source_table(conn: psycopg2.extensions.connection, table_name: str) -> None:
    with conn.cursor() as cur:
        cur.execute("SELECT to_regclass(%s)", (table_name,))
        exists = cur.fetchone()[0]
    if exists is None:
        raise ValueError(f"Source table '{table_name}' does not exist.")


def _is_used_value(value: Optional[object]) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return value.strip() != ""
    return True


def iter_source_rows(
    conn: psycopg2.extensions.connection,
    table_name: str,
    *,
    batch_size: int,
) -> Iterable[tuple[int, Optional[str], Optional[str], dict]]:
    query = sql.SQL("SELECT id, index_name, doc_id, data FROM {} ORDER BY id").format(
        sql.Identifier(table_name)
    )
    with conn.cursor(name="clear_data_cursor", withhold=True) as cur:
        cur.itersize = int(batch_size)
        cur.execute(query)
        for row in cur:
            yield row


def compute_column_usage_db(
    conn: psycopg2.extensions.connection,
    table_name: str,
    *,
    batch_size: int,
) -> List[ColumnUsage]:
    used_counts: Dict[str, int] = {}
    columns_order: List[str] = []
    seen = set()
    total_rows = 0

    for _, _, _, data in iter_source_rows(conn, table_name, batch_size=batch_size):
        total_rows += 1
        if not data:
            continue
        for key, value in data.items():
            if key not in seen:
                seen.add(key)
                columns_order.append(key)
                used_counts.setdefault(key, 0)
            if _is_used_value(value):
                used_counts[key] = used_counts.get(key, 0) + 1

    return [ColumnUsage(column=c, used_rows=used_counts.get(c, 0), total_rows=total_rows) for c in columns_order]


def drop_low_usage_columns_db(
    usages: List[ColumnUsage],
    *,
    usage_percent_to_drop: float,
) -> DropReport:
    total_rows = usages[0].total_rows if usages else 0

    if total_rows == 0:
        return DropReport(
            total_rows=0,
            threshold_percent=float(usage_percent_to_drop),
            threshold_rows=0,
            dropped=[],
            kept=[],
        )

    threshold_rows = int((usage_percent_to_drop / 100.0) * total_rows)
    dropped: List[str] = []
    kept: List[str] = []

    for u in usages:
        if (u.used_rows / total_rows) * 100.0 < float(usage_percent_to_drop):
            dropped.append(u.column)
        else:
            kept.append(u.column)

    return DropReport(
        total_rows=total_rows,
        threshold_percent=float(usage_percent_to_drop),
        threshold_rows=threshold_rows,
        dropped=dropped,
        kept=kept,
    )


def _value_to_str(value: Optional[object]) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=True, sort_keys=True)


def _update_hash(h: "hashlib._Hash", value: str) -> None:
    h.update(value.encode("utf-8"))
    h.update(b"\x1f")


def drop_duplicate_columns_db(
    conn: psycopg2.extensions.connection,
    table_name: str,
    *,
    columns: List[str],
    prefer_keep: Optional[List[str]] = None,
    batch_size: int,
) -> Dict[str, List[str]]:
    if not columns:
        return {}

    prefer = prefer_keep or []
    hashers = {c: hashlib.sha256() for c in columns}

    for _, _, _, data in iter_source_rows(conn, table_name, batch_size=batch_size):
        row_data = data or {}
        for c in columns:
            _update_hash(hashers[c], _value_to_str(row_data.get(c)))

    groups: Dict[str, List[str]] = {}
    for c in columns:
        digest = hashers[c].hexdigest()
        groups.setdefault(digest, []).append(c)

    duplicates: Dict[str, List[str]] = {}

    def _choose_canonical(cols: List[str]) -> str:
        for pcol in prefer:
            if pcol in cols:
                return pcol
        return cols[0]

    for cols in groups.values():
        if len(cols) <= 1:
            continue
        canonical = _choose_canonical(cols)
        dropped_cols = [c for c in cols if c != canonical]
        if dropped_cols:
            duplicates[canonical] = dropped_cols

    return duplicates


def ensure_clean_table(conn: psycopg2.extensions.connection, table_name: str) -> None:
    ddl = sql.SQL(
        """
        CREATE TABLE IF NOT EXISTS {table} (
            id bigserial PRIMARY KEY,
            source_id bigint,
            index_name text,
            doc_id text,
            data jsonb NOT NULL,
            inserted_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (index_name, doc_id)
        )
        """
    ).format(table=sql.Identifier(table_name))
    with conn.cursor() as cur:
        cur.execute(ddl)
    conn.commit()


def _insert_clean_batch(
    cur: psycopg2.extensions.cursor,
    table_name: str,
    rows: list[tuple[int, Optional[str], Optional[str], Json]],
    *,
    page_size: int,
) -> None:
    query = sql.SQL(
        """
        INSERT INTO {table} (source_id, index_name, doc_id, data)
        VALUES %s
        ON CONFLICT (index_name, doc_id) DO UPDATE
        SET data = EXCLUDED.data,
            source_id = EXCLUDED.source_id
        """
    ).format(table=sql.Identifier(table_name))
    execute_values(cur, query, rows, page_size=page_size)


def write_clean_table(
    conn: psycopg2.extensions.connection,
    *,
    source_table: str,
    clean_table: str,
    columns: List[str],
    batch_size: int,
) -> int:
    ensure_clean_table(conn, clean_table)
    total = 0
    with conn.cursor() as cur:
        buffer: list[tuple[int, Optional[str], Optional[str], Json]] = []
        for source_id, index_name, doc_id, data in iter_source_rows(
            conn, source_table, batch_size=batch_size
        ):
            row_data = data or {}
            if columns:
                cleaned = {k: row_data.get(k) for k in columns if k in row_data}
            else:
                cleaned = {}
            buffer.append((source_id, index_name, doc_id, Json(cleaned)))
            if len(buffer) >= int(batch_size):
                _insert_clean_batch(cur, clean_table, buffer, page_size=int(batch_size))
                conn.commit()
                total += len(buffer)
                buffer.clear()
        if buffer:
            _insert_clean_batch(cur, clean_table, buffer, page_size=int(batch_size))
            conn.commit()
            total += len(buffer)
    return total


def run_pipeline_postgres(
    *,
    source_table: str,
    clean_table: str,
    usage_percent_to_drop: float = USAGE_PERCENT_TO_DROP,
    drop_duplicates: bool = True,
    batch_size: int = POSTGRES_BATCH_SIZE,
) -> None:
    with build_pg_conn() as conn:
        _ensure_source_table(conn, source_table)
        ensure_clean_table(conn, clean_table)
        if _parse_bool_env(TRUNCATE_CLEAN_TABLE, "TRUNCATE_CLEAN_TABLE"):
            with conn.cursor() as cur:
                cur.execute(sql.SQL("TRUNCATE TABLE {}").format(sql.Identifier(clean_table)))
            conn.commit()

        usages = compute_column_usage_db(conn, source_table, batch_size=batch_size)
        report = drop_low_usage_columns_db(usages, usage_percent_to_drop=usage_percent_to_drop)
        print(
            "[step:usage] "
            f"total_rows={report.total_rows} "
            f"threshold_percent={report.threshold_percent} "
            f"dropped={len(report.dropped)} "
            f"kept={len(report.kept)}"
        )

        kept = report.kept

        if drop_duplicates and kept and report.total_rows > 0:
            dups = drop_duplicate_columns_db(
                conn,
                source_table,
                columns=kept,
                prefer_keep=[
                    "timestamp",
                    "@timestamp",
                    "_source.timestamp",
                    "_source.@timestamp",
                ],
                batch_size=batch_size,
            )
            dropped_dups = sum(len(v) for v in dups.values())
            print(f"[step:dedup] dropped={dropped_dups}")
            if dups:
                for base, cols in dups.items():
                    print(f"[step:dedup] {base} <- dropped {cols}")
            to_drop = {c for cols in dups.values() for c in cols}
            kept = [c for c in kept if c not in to_drop]

        cleaned_rows = write_clean_table(
            conn,
            source_table=source_table,
            clean_table=clean_table,
            columns=kept,
            batch_size=batch_size,
        )
        print(f"Final output: {clean_table} rows={cleaned_rows}")


def main() -> None:
    run_pipeline_postgres(
        source_table=POSTGRES_SOURCE_TABLE,
        clean_table=POSTGRES_CLEAN_TABLE,
        usage_percent_to_drop=USAGE_PERCENT_TO_DROP,
        drop_duplicates=True,
        batch_size=POSTGRES_BATCH_SIZE,
    )


if __name__ == "__main__":
    main()
