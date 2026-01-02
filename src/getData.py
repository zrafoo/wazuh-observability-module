from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

import psycopg2
from psycopg2 import sql
from psycopg2.extras import Json, execute_values
from opensearchpy import OpenSearch
from opensearchpy.helpers import scan


OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST")
OPENSEARCH_PORT = os.getenv("OPENSEARCH_PORT")
OPENSEARCH_HTTPS = os.getenv("OPENSEARCH_HTTPS")
OPENSEARCH_USER = os.getenv("OPENSEARCH_USER")
OPENSEARCH_PASSWORD = os.getenv("OPENSEARCH_PASSWORD")

VERIFY_CERTS = False
CA_CERTS: Optional[str] = None

REQUEST_TIMEOUT_S = 60

POSTGRES_HOST = os.getenv("POSTGRES_HOST", "localhost")
POSTGRES_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
POSTGRES_DB = os.getenv("POSTGRES_DB", "app_db")
POSTGRES_USER = os.getenv("POSTGRES_USER", "app_user")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "app_password")
POSTGRES_TABLE = os.getenv("POSTGRES_TABLE", "opensearch_events")
POSTGRES_BATCH_SIZE = int(os.getenv("POSTGRES_BATCH_SIZE", "1000"))
TRUNCATE_OPENSEARCH_EVENTS = os.getenv("TRUNCATE_OPENSEARCH_EVENTS", "true")
EXPORT_DAYS_FROM_OPENSEARCH = int(os.getenv("EXPORT_DAYS_FROM_OPENSEARCH", "365"))


@dataclass(frozen=True)
class ExportParams:
    index_pattern: str = "*"
    date_field: str = "@timestamp"
    page_size: int = 1000
    scroll_ttl: str = "2m"


@dataclass(frozen=True)
class PostgresParams:
    host: str = POSTGRES_HOST
    port: int = POSTGRES_PORT
    dbname: str = POSTGRES_DB
    user: str = POSTGRES_USER
    password: str = POSTGRES_PASSWORD
    table: str = POSTGRES_TABLE
    batch_size: int = POSTGRES_BATCH_SIZE


def now_iso_utc() -> str:
    """Current time in ISO8601 UTC."""
    return datetime.now(timezone.utc).isoformat()


def _parse_bool_env(value: Optional[str], name: str) -> bool:
    if value is None:
        raise ValueError(f"{name} is required.")
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean-like string (true/false).")


def build_client() -> OpenSearch:
    if not OPENSEARCH_HOST:
        raise ValueError("OPENSEARCH_HOST is required.")
    if not OPENSEARCH_PORT:
        raise ValueError("OPENSEARCH_PORT is required.")
    if not OPENSEARCH_USER:
        raise ValueError("OPENSEARCH_USER is required.")
    if OPENSEARCH_PASSWORD is None:
        raise ValueError("OPENSEARCH_PASSWORD is required.")
    https = _parse_bool_env(OPENSEARCH_HTTPS, "OPENSEARCH_HTTPS")
    port = int(OPENSEARCH_PORT)
    scheme = "https" if https else "http"
    return OpenSearch(
        hosts=[{"host": OPENSEARCH_HOST, "port": port, "scheme": scheme}],
        http_auth=(OPENSEARCH_USER, OPENSEARCH_PASSWORD),
        use_ssl=https,
        verify_certs=VERIFY_CERTS,
        ca_certs=CA_CERTS,
        ssl_assert_hostname=VERIFY_CERTS,
        ssl_show_warn=not VERIFY_CERTS,
        timeout=REQUEST_TIMEOUT_S,
        max_retries=3,
        retry_on_timeout=True,
    )


def list_indices(client: OpenSearch, pattern: str = "*") -> List[str]:
    rows = client.cat.indices(index=pattern, format="json")
    out: List[str] = []
    for row in rows:
        idx = row.get("index")
        if idx:
            out.append(idx)
    return out


def date_range_query(date_field: str, date_from: str, date_to: str) -> Dict[str, Any]:
    return {
        "query": {
            "range": {
                date_field: {
                    "gte": date_from,
                    "lt": date_to,
                }
            }
        }
    }


def iter_docs(
    client: OpenSearch,
    index: str,
    query: Dict[str, Any],
    *,
    page_size: int,
    scroll_ttl: str,
) -> Iterable[Dict[str, Any]]:
    yield from scan(
        client=client,
        index=index,
        query=query,
        size=page_size,
        scroll=scroll_ttl,
        preserve_order=False,
        request_timeout=REQUEST_TIMEOUT_S,
    )


def build_pg_conn(params: PostgresParams) -> psycopg2.extensions.connection:
    return psycopg2.connect(
        host=params.host,
        port=params.port,
        dbname=params.dbname,
        user=params.user,
        password=params.password,
    )


def ensure_events_table(conn: psycopg2.extensions.connection, table_name: str) -> None:
    ddl = sql.SQL(
        """
        CREATE TABLE IF NOT EXISTS {table} (
            id bigserial PRIMARY KEY,
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


def _insert_batch(
    cur: psycopg2.extensions.cursor,
    table_name: str,
    rows: list[tuple[str, Optional[str], Json]],
    *,
    page_size: int,
) -> None:
    query = sql.SQL(
        """
        INSERT INTO {table} (index_name, doc_id, data)
        VALUES %s
        ON CONFLICT (index_name, doc_id) DO UPDATE
        SET data = EXCLUDED.data
        """
    ).format(table=sql.Identifier(table_name))
    execute_values(cur, query, rows, page_size=page_size)


def flatten_json(
    obj: Any, parent_key: str = "", sep: str = "."
) -> dict[str, Any]:
    """
    Flatten nested dicts into dotted keys.
    Lists of scalars joined with semicolon, lists of non-scalars JSON-dumped.
    Non-scalar values JSON-dumped.
    Scalars preserved as-is.
    """
    out: dict[str, Any] = {}

    def is_scalar(val: Any) -> bool:
        return isinstance(val, (str, int, float, bool)) or val is None

    def flatten(item: Any, key_prefix: str) -> None:
        if isinstance(item, dict):
            for k, v in item.items():
                new_key = f"{key_prefix}{sep}{k}" if key_prefix else k
                flatten(v, new_key)
        elif isinstance(item, list):
            if all(is_scalar(x) for x in item):
                # join scalars with ;
                joined = ";".join("" if x is None else str(x) for x in item)
                out[key_prefix] = joined
            else:
                # complex list, JSON dump
                out[key_prefix] = json.dumps(item, ensure_ascii=False)
        elif is_scalar(item):
            out[key_prefix] = item
        else:
            # non scalar, JSON dump
            out[key_prefix] = json.dumps(item, ensure_ascii=False)

    flatten(obj, parent_key)
    return out


def export_date_range_to_postgres(
    *,
    date_from: str,
    date_to: Optional[str] = None,
    params: ExportParams = ExportParams(),
    client: Optional[OpenSearch] = None,
    pg_params: PostgresParams = PostgresParams(),
) -> int:
    date_to_final = date_to or now_iso_utc()
    client_local = client or build_client()
    client_local.info()

    indices = list_indices(client_local, params.index_pattern)
    if not indices:
        return 0

    query = date_range_query(params.date_field, date_from, date_to_final)
    total = 0
    with build_pg_conn(pg_params) as conn:
        ensure_events_table(conn, pg_params.table)
        if _parse_bool_env(TRUNCATE_OPENSEARCH_EVENTS, "TRUNCATE_OPENSEARCH_EVENTS"):
            with conn.cursor() as cur:
                cur.execute(sql.SQL("TRUNCATE TABLE {}").format(sql.Identifier(pg_params.table)))
            conn.commit()
        with conn.cursor() as cur:
            buffer: list[tuple[str, Optional[str], Json]] = []
            for idx in indices:
                for hit in iter_docs(
                    client_local,
                    idx,
                    query,
                    page_size=params.page_size,
                    scroll_ttl=params.scroll_ttl,
                ):
                    src = hit.get("_source") or {}
                    index_name = hit.get("_index") or idx
                    flat = flatten_json(src)
                    buffer.append((index_name, hit.get("_id"), Json(flat)))
                    if len(buffer) >= int(pg_params.batch_size):
                        _insert_batch(cur, pg_params.table, buffer, page_size=int(pg_params.batch_size))
                        conn.commit()
                        total += len(buffer)
                        buffer.clear()
            if buffer:
                _insert_batch(cur, pg_params.table, buffer, page_size=int(pg_params.batch_size))
                conn.commit()
                total += len(buffer)
    return total


def main() -> int:
    from datetime import timedelta

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=int(EXPORT_DAYS_FROM_OPENSEARCH))

    exported = export_date_range_to_postgres(
        date_from=start.isoformat(),
        date_to=end.isoformat(),
        params=ExportParams(index_pattern="*", date_field="@timestamp"),
    )

    print(f"Exported: {exported} docs -> {POSTGRES_DB}.{POSTGRES_TABLE}")
    return exported


if __name__ == "__main__":
    main()
