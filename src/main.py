from __future__ import annotations

import os

import psycopg2
from psycopg2 import sql

from clearData import main as clear_data_main
from event import main as event_main
from getData import main as get_data_main
from graphics import main as graphics_main


POSTGRES_HOST = os.getenv("POSTGRES_HOST", "localhost")
POSTGRES_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
POSTGRES_DB = os.getenv("POSTGRES_DB", "app_db")
POSTGRES_USER = os.getenv("POSTGRES_USER", "app_user")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "app_password")
POSTGRES_TABLE = os.getenv("POSTGRES_TABLE", "opensearch_events")
POSTGRES_SOURCE_TABLE = os.getenv("POSTGRES_SOURCE_TABLE", POSTGRES_TABLE)
POSTGRES_CLEAN_TABLE = os.getenv("POSTGRES_CLEAN_TABLE", "opensearch_events_clean")


def _build_pg_conn() -> psycopg2.extensions.connection:
    return psycopg2.connect(
        host=POSTGRES_HOST,
        port=POSTGRES_PORT,
        dbname=POSTGRES_DB,
        user=POSTGRES_USER,
        password=POSTGRES_PASSWORD,
    )


def _table_has_rows(conn: psycopg2.extensions.connection, table_name: str) -> bool:
    with conn.cursor() as cur:
        cur.execute("SELECT to_regclass(%s)", (table_name,))
        exists = cur.fetchone()[0] is not None
        if not exists:
            return False
        cur.execute(sql.SQL("SELECT 1 FROM {} LIMIT 1").format(sql.Identifier(table_name)))
        return cur.fetchone() is not None


def main() -> None:
    with _build_pg_conn() as conn:
        raw_ready = _table_has_rows(conn, POSTGRES_SOURCE_TABLE)
        clean_ready = _table_has_rows(conn, POSTGRES_CLEAN_TABLE)
    if not raw_ready:
        get_data_main()
        clear_data_main()
    elif not clean_ready:
        clear_data_main()
    event_main()
    graphics_main()


if __name__ == "__main__":
    main()
