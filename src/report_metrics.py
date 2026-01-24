from __future__ import annotations

import argparse
import math
import os
import re
import time
from difflib import SequenceMatcher
from typing import Iterable, Optional

import pandas as pd
import psycopg2
from psycopg2 import sql

from models import (
    DEFAULT_ALERT_LEVEL_THRESHOLD,
    DEFAULT_BURST_WINDOW_SECONDS,
    DEFAULT_LINK_DT_MAX_SECONDS,
    DEFAULT_LINK_TAU_SECONDS,
    HOST_CANDIDATES,
    MITRE_TACTIC_CANDIDATES,
    MITRE_TECHNIQUE_CANDIDATES,
    OBJECT_CANDIDATES,
    SUBJECT_CANDIDATES,
    _parse_ts_series,
    choose_object_columns,
    choose_subject_columns,
    compute_burst_max,
    compute_transition_probs,
)


POSTGRES_HOST = os.getenv("POSTGRES_HOST", "localhost")
POSTGRES_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
POSTGRES_DB = os.getenv("POSTGRES_DB", "models_db")
POSTGRES_USER = os.getenv("POSTGRES_USER", "models_user")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "models_password")
POSTGRES_TABLE = os.getenv("POSTGRES_TABLE", "opensearch_events")
POSTGRES_SOURCE_TABLE = os.getenv("POSTGRES_SOURCE_TABLE", POSTGRES_TABLE)
POSTGRES_CLEAN_TABLE = os.getenv("POSTGRES_CLEAN_TABLE", "opensearch_events_clean")
POSTGRES_METRICS_TABLE = os.getenv("POSTGRES_METRICS_TABLE")
POSTGRES_EVENT_TABLE = os.getenv("POSTGRES_EVENT_TABLE", "event_links")
POSTGRES_EVENT_SOURCE_TABLE = os.getenv("POSTGRES_EVENT_SOURCE_TABLE", POSTGRES_CLEAN_TABLE)
POSTGRES_BATCH_SIZE = int(os.getenv("POSTGRES_BATCH_SIZE", "1000"))

LINK_TIME_SCALE_SECONDS = float(os.getenv("LINK_TIME_SCALE_SECONDS", str(DEFAULT_LINK_TAU_SECONDS)))
LINK_DT_MAX_SECONDS = float(os.getenv("LINK_DT_MAX_SECONDS", str(DEFAULT_LINK_DT_MAX_SECONDS)))
LINK_OBJECT_SIM_EPS = float(os.getenv("LINK_OBJECT_SIM_EPS", "0.85"))
LINK_WEIGHT_TIME = float(os.getenv("LINK_WEIGHT_TIME", "0.25"))
LINK_WEIGHT_SUBJECT = float(os.getenv("LINK_WEIGHT_SUBJECT", "0.25"))
LINK_WEIGHT_OBJECT = float(os.getenv("LINK_WEIGHT_OBJECT", "0.25"))
LINK_WEIGHT_SEMANTIC = float(os.getenv("LINK_WEIGHT_SEMANTIC", "0.25"))


def _normalize_weights(alpha: float, beta: float, gamma: float, delta: float) -> tuple[float, float, float, float]:
    if any(w < 0.0 for w in (alpha, beta, gamma, delta)):
        raise ValueError("LINK_WEIGHT_* must be non-negative.")
    total = alpha + beta + gamma + delta
    if total <= 0.0:
        raise ValueError("LINK_WEIGHT_* sum must be > 0.")
    return alpha / total, beta / total, gamma / total, delta / total


LINK_WEIGHT_TIME, LINK_WEIGHT_SUBJECT, LINK_WEIGHT_OBJECT, LINK_WEIGHT_SEMANTIC = _normalize_weights(
    LINK_WEIGHT_TIME,
    LINK_WEIGHT_SUBJECT,
    LINK_WEIGHT_OBJECT,
    LINK_WEIGHT_SEMANTIC,
)

if LINK_TIME_SCALE_SECONDS <= 0.0:
    raise ValueError("LINK_TIME_SCALE_SECONDS must be > 0.")
if LINK_DT_MAX_SECONDS <= 0.0:
    raise ValueError("LINK_DT_MAX_SECONDS must be > 0.")
if not 0.0 <= LINK_OBJECT_SIM_EPS <= 1.0:
    raise ValueError("LINK_OBJECT_SIM_EPS must be in [0, 1].")

TIMESTAMP_CANDIDATES = [
    "@timestamp",
    "timestamp",
    "time",
    "event.created",
    "event.ingested",
    "event.start",
    "_source.@timestamp",
    "_source.timestamp",
    "_source.@timestamp.keyword",
    "_source.timestamp.keyword",
    "_source.event.created",
    "_source.event.ingested",
    "_source.event.start",
]

EVENT_TYPE_CANDIDATES = [
    "data.win.system.eventID",
    "data.win.system.eventId",
    "winlog.event_id",
    "event.code",
    "syscheck.event",
    "rule.id",
    "rule.description",
    "_source.data.win.system.eventID",
    "_source.rule.id",
    "_source.rule.description",
]

SEVERITY_CANDIDATES = ["rule.level", "_source.rule.level"]

_MULTI_SPLIT_RE = re.compile(r"[;,]")

SESSION_ID_COLUMNS = [
    "data.win.eventdata.logonId",
    "data.win.eventdata.logonGuid",
    "_source.data.win.eventdata.logonId",
    "_source.data.win.eventdata.logonGuid",
]

PROCESS_ID_COLUMNS = [
    "data.win.eventdata.processId",
    "data.win.eventdata.processGuid",
    "data.win.eventdata.parentProcessId",
    "data.win.eventdata.parentProcessGuid",
    "_source.data.win.eventdata.processId",
    "_source.data.win.eventdata.processGuid",
    "_source.data.win.eventdata.parentProcessId",
    "_source.data.win.eventdata.parentProcessGuid",
    "process.pid",
    "process.entity_id",
    "process.parent.pid",
    "process.parent.entity_id",
]

SUBJECT_SIMILARITY_COLS = [
    c for c in SUBJECT_CANDIDATES if c not in SESSION_ID_COLUMNS and c not in PROCESS_ID_COLUMNS
]


def build_pg_conn() -> psycopg2.extensions.connection:
    return psycopg2.connect(
        host=POSTGRES_HOST,
        port=POSTGRES_PORT,
        dbname=POSTGRES_DB,
        user=POSTGRES_USER,
        password=POSTGRES_PASSWORD,
    )


def _table_exists(conn: psycopg2.extensions.connection, table_name: str) -> bool:
    with conn.cursor() as cur:
        cur.execute("SELECT to_regclass(%s)", (table_name,))
        return cur.fetchone()[0] is not None


def _table_has_rows(conn: psycopg2.extensions.connection, table_name: str) -> bool:
    if not _table_exists(conn, table_name):
        return False
    with conn.cursor() as cur:
        cur.execute(sql.SQL("SELECT 1 FROM {} LIMIT 1").format(sql.Identifier(table_name)))
        return cur.fetchone() is not None


def _row_count(conn: psycopg2.extensions.connection, table_name: str) -> int:
    with conn.cursor() as cur:
        cur.execute(sql.SQL("SELECT COUNT(*) FROM {}").format(sql.Identifier(table_name)))
        return int(cur.fetchone()[0] or 0)


def _resolve_source_table(conn: psycopg2.extensions.connection, override: Optional[str]) -> str:
    if override:
        if not _table_exists(conn, override):
            raise ValueError(f"Table '{override}' does not exist.")
        return override
    if POSTGRES_METRICS_TABLE:
        if not _table_exists(conn, POSTGRES_METRICS_TABLE):
            raise ValueError(f"Table '{POSTGRES_METRICS_TABLE}' does not exist.")
        return POSTGRES_METRICS_TABLE
    if _table_has_rows(conn, POSTGRES_CLEAN_TABLE):
        return POSTGRES_CLEAN_TABLE
    if _table_has_rows(conn, POSTGRES_SOURCE_TABLE):
        return POSTGRES_SOURCE_TABLE
    raise ValueError("No suitable source table found (clean or source).")


def _clean_text_series(s: pd.Series) -> pd.Series:
    if s.dtype == object:
        s = s.astype(str).str.strip()
        s = s.mask(s.str.lower().isin({"", "nan", "none", "null"}))
    return s


def _valid_coverage(df: pd.DataFrame, col: str) -> float:
    if col not in df.columns or len(df) == 0:
        return 0.0
    s = df[col]
    if s.dtype == object:
        s = _clean_text_series(s)
        return float(s.notna().mean())
    return float(s.notna().mean())


def _pick_best_column(
    df: pd.DataFrame,
    candidates: Iterable[str],
    *,
    min_coverage: float = 0.01,
) -> Optional[str]:
    best_col = None
    best_cov = -1.0
    for c in candidates:
        if c not in df.columns:
            continue
        cov = _valid_coverage(df, c)
        if cov > best_cov:
            best_cov = cov
            best_col = c
    if best_col is None:
        return None
    return best_col if best_cov >= float(min_coverage) else None


def _iter_rows(
    conn: psycopg2.extensions.connection,
    table_name: str,
    *,
    batch_size: int,
    limit: Optional[int],
) -> Iterable[dict]:
    query = sql.SQL("SELECT data FROM {} ORDER BY id").format(sql.Identifier(table_name))
    with conn.cursor(name="metrics_cursor") as cur:
        cur.itersize = int(batch_size)
        cur.execute(query)
        for idx, (data,) in enumerate(cur):
            if limit is not None and idx >= int(limit):
                break
            yield data or {}


def _load_metrics_frame(
    conn: psycopg2.extensions.connection,
    table_name: str,
    *,
    keys: set[str],
    batch_size: int,
    limit: Optional[int],
) -> pd.DataFrame:
    rows: list[dict] = []
    for data in _iter_rows(conn, table_name, batch_size=batch_size, limit=limit):
        rows.append({k: data.get(k) for k in keys})
    return pd.DataFrame(rows)


def _resolve_links_table(conn: psycopg2.extensions.connection, override: Optional[str]) -> Optional[str]:
    table_name = override or POSTGRES_EVENT_TABLE
    if not table_name:
        return None
    if not _table_exists(conn, table_name):
        return None
    return table_name


def _iter_link_rows(
    conn: psycopg2.extensions.connection,
    table_name: str,
    *,
    batch_size: int,
    limit: Optional[int],
) -> Iterable[tuple]:
    query = sql.SQL(
        """
        SELECT group_id, role, event_id, link_to, c, dt, ent, k_sem, p
        FROM {}
        ORDER BY id
        """
    ).format(sql.Identifier(table_name))
    with conn.cursor(name="metrics_links_cursor") as cur:
        cur.itersize = int(batch_size)
        cur.execute(query)
        for idx, row in enumerate(cur):
            if limit is not None and idx >= int(limit):
                break
            yield row


def _load_link_frame(
    conn: psycopg2.extensions.connection,
    table_name: str,
    *,
    batch_size: int,
    limit: Optional[int],
) -> pd.DataFrame:
    rows: list[dict] = []
    for group_id, role, event_id, link_to, c, dt, ent, k_sem, p in _iter_link_rows(
        conn,
        table_name,
        batch_size=batch_size,
        limit=limit,
    ):
        rows.append(
            {
                "group_id": group_id,
                "role": role,
                "event_id": event_id,
                "link_to": link_to,
                "c": c,
                "dt": dt,
                "ent": ent,
                "k_sem": k_sem,
                "p": p,
            }
        )
    return pd.DataFrame(rows)


def _iter_chunks(items: list[str], size: int) -> Iterable[list[str]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _fetch_event_data_map(
    conn: psycopg2.extensions.connection,
    table_name: str,
    ids: set[str],
    *,
    chunk_size: int = 1000,
) -> dict[str, dict]:
    if not ids:
        return {}
    data_map: dict[str, dict] = {}
    ids_list = list(ids)
    query = sql.SQL(
        """
        SELECT doc_id, data
        FROM {table}
        WHERE doc_id = ANY(%s)
           OR data->>'_source.id' = ANY(%s)
           OR data->>'id' = ANY(%s)
        """
    ).format(table=sql.Identifier(table_name))
    with conn.cursor() as cur:
        for chunk in _iter_chunks(ids_list, int(chunk_size)):
            cur.execute(query, (chunk, chunk, chunk))
            for doc_id, data in cur.fetchall():
                row = data or {}
                candidates = (
                    _normalize_event_id(doc_id),
                    _normalize_event_id(row.get("_source.id")),
                    _normalize_event_id(row.get("id")),
                )
                for cid in candidates:
                    if cid is None or cid not in ids:
                        continue
                    if cid not in data_map:
                        data_map[cid] = row
    return data_map


def _link_metrics_summary(link_df: pd.DataFrame) -> pd.DataFrame:
    metrics = [
        ("c", "C(e_i,e_j)"),
        ("dt", "dt_seconds"),
        ("ent", "object_similarity"),
        ("subject_similarity", "subject_similarity"),
        ("k_sem", "semantic_transition"),
        ("p", "transition_prob"),
    ]
    rows: list[dict] = []
    for col, label in metrics:
        if col not in link_df.columns:
            continue
        s = pd.to_numeric(link_df[col], errors="coerce").dropna()
        if len(s) == 0:
            continue
        rows.append(
            {
                "metric": label,
                "count": int(s.count()),
                "mean": float(s.mean()),
                "median": float(s.median()),
                "p90": float(s.quantile(0.90)),
                "p99": float(s.quantile(0.99)),
                "min": float(s.min()),
                "max": float(s.max()),
            }
        )
    return pd.DataFrame(rows)


def _link_top_table(link_df: pd.DataFrame, metric_col: str, top_n: int) -> pd.DataFrame:
    if metric_col not in link_df.columns:
        return pd.DataFrame()
    sub = link_df.copy()
    sub[metric_col] = pd.to_numeric(sub[metric_col], errors="coerce")
    sub = sub[sub[metric_col].notna()].copy()
    if len(sub) == 0:
        return pd.DataFrame()
    sub = sub.sort_values(metric_col, ascending=False).head(int(top_n))
    cols = ["event_id", "link_to", "role", "group_id", "c", "dt", "ent", "k_sem", "p"]
    cols = [c for c in cols if c in sub.columns]
    out = sub[cols].copy()
    return out.rename(columns={"group_id": "group"})


def _build_sem_probs(
    df: pd.DataFrame,
    *,
    event_type_col: str,
    host_col: Optional[str],
) -> dict[tuple[str, str], float]:
    if event_type_col not in df.columns:
        return {}
    work = df.copy()
    work[event_type_col] = _clean_text_series(work[event_type_col].astype(str))
    work = work[work[event_type_col].notna()].copy()
    if host_col and host_col in work.columns:
        work[host_col] = _clean_text_series(work[host_col]).fillna("unknown")
        subject_key = host_col
    else:
        work["__all_subject"] = "all"
        subject_key = "__all_subject"
    trans = compute_transition_probs(work, subject_key, "_ts", event_type_col)
    return {(r["Ei"], r["Ej"]): float(r["P(Ej|Ei)"]) for _, r in trans.iterrows()}


def _compute_raw_link_edges(
    df: pd.DataFrame,
    *,
    ts_col: str,
    subject_cols: list[str],
    object_cols: list[str],
    host_col: Optional[str],
    event_type_col: Optional[str],
) -> pd.DataFrame:
    if ts_col not in df.columns:
        return pd.DataFrame()
    work = df.copy()
    work["_ts"] = _parse_ts_series(work[ts_col])
    work = work[work["_ts"].notna()].copy()
    if len(work) == 0:
        return pd.DataFrame()

    type_col = None
    if event_type_col and event_type_col in work.columns:
        work["_event_type"] = _clean_text_series(work[event_type_col].astype(str))
        type_col = "_event_type"

    sem_probs: dict[tuple[str, str], float] = {}
    if type_col is not None:
        sem_probs = _build_sem_probs(work, event_type_col=type_col, host_col=host_col)

    session_cols = [c for c in SESSION_ID_COLUMNS if c in work.columns]
    process_cols = [c for c in PROCESS_ID_COLUMNS if c in work.columns]
    subject_cols_filtered = [c for c in subject_cols if c in work.columns and c not in session_cols and c not in process_cols]
    object_cols_filtered = [c for c in object_cols if c in work.columns]

    work = work.sort_values("_ts").reset_index(drop=True)
    rows = work.to_dict(orient="records")
    ts_vals = [r["_ts"] for r in rows]
    type_vals = [_valid_value(r.get(type_col)) if type_col else None for r in rows]
    features = [
        _build_link_features_row(
            r,
            subject_cols=subject_cols_filtered,
            session_cols=session_cols,
            process_cols=process_cols,
            object_cols=object_cols_filtered,
        )
        for r in rows
    ]

    edges: list[dict] = []
    n = len(rows)
    for i in range(n):
        ts_i = ts_vals[i]
        edges_i: list[tuple[float, float, float, float, float]] = []
        for j in range(i + 1, n):
            dt = (ts_vals[j] - ts_i).total_seconds()
            if dt <= 0:
                continue
            if dt > float(LINK_DT_MAX_SECONDS):
                break
            subj_sim = _subject_similarity(
                features[i][:3],
                features[j][:3],
            )
            subj_val = float(subj_sim) if subj_sim is not None else 0.0
            obj_sim = _object_similarity(features[i][3], features[j][3])
            k_sem = 0.0
            if sem_probs and type_vals[i] is not None and type_vals[j] is not None:
                k_sem = float(sem_probs.get((str(type_vals[i]), str(type_vals[j])), 0.0))
            ct = math.exp(-abs(dt) / float(LINK_TIME_SCALE_SECONDS))
            co = 1.0 if obj_sim >= float(LINK_OBJECT_SIM_EPS) else 0.0
            c_score = (
                (LINK_WEIGHT_TIME * ct)
                + (LINK_WEIGHT_SUBJECT * subj_val)
                + (LINK_WEIGHT_OBJECT * co)
                + (LINK_WEIGHT_SEMANTIC * k_sem)
            )
            edges_i.append((c_score, dt, obj_sim, subj_val, k_sem))
        if not edges_i:
            continue
        total_c = sum(e[0] for e in edges_i)
        for c_score, dt, obj_sim, subj_val, k_sem in edges_i:
            p = (c_score / total_c) if total_c > 0.0 else 0.0
            edges.append(
                {
                    "c": c_score,
                    "dt": dt,
                    "ent": obj_sim,
                    "subject_similarity": subj_val,
                    "k_sem": k_sem,
                    "p": p,
                }
            )

    if not edges:
        return pd.DataFrame()
    return pd.DataFrame(edges)


def _raw_link_summary_from_df(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame()
    raw_ts_col = _pick_best_column(df, TIMESTAMP_CANDIDATES)
    raw_event_type_col = _pick_best_column(df, EVENT_TYPE_CANDIDATES)
    raw_host_col = _pick_best_column(df, HOST_CANDIDATES)
    if raw_ts_col is None or raw_ts_col not in df.columns:
        return pd.DataFrame()
    subject_cols_raw = choose_subject_columns(df)
    object_cols_raw = choose_object_columns(df)
    if not subject_cols_raw or not object_cols_raw:
        return pd.DataFrame()
    raw_edges = _compute_raw_link_edges(
        df,
        ts_col=raw_ts_col,
        subject_cols=subject_cols_raw,
        object_cols=object_cols_raw,
        host_col=raw_host_col,
        event_type_col=raw_event_type_col,
    )
    if raw_edges.empty:
        return pd.DataFrame()
    return _link_metrics_summary(raw_edges)

def _top_counts(series: pd.Series, top_n: int) -> pd.Series:
    s = _clean_text_series(series).dropna()
    if len(s) == 0:
        return pd.Series(dtype=int)
    return s.value_counts().head(int(top_n))


def _explode_multi_values(series: pd.Series) -> pd.Series:
    values: list[str] = []
    for v in _clean_text_series(series).dropna():
        s = str(v).strip()
        parts = [p.strip() for p in _MULTI_SPLIT_RE.split(s) if p.strip()]
        if parts:
            values.extend(parts)
        else:
            values.append(s)
    return pd.Series(values)


def _format_value(val: object) -> str:
    if val is None:
        return "-"
    if isinstance(val, float):
        if pd.isna(val):
            return "-"
        return f"{val:.3f}"
    if isinstance(val, pd.Timestamp):
        if pd.isna(val):
            return "-"
        return val.isoformat()
    text = str(val)
    return text if text else "-"


def _truncate(value: str, max_len: int = 80) -> str:
    if len(value) <= max_len:
        return value
    return value[: max_len - 3] + "..."


def _normalize_event_id(v: object) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    if not s or s.lower() == "nan":
        return None
    return s


def _valid_value(v: object) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    if not s or s.lower() == "nan":
        return None
    return s


def _normalize_simple(value: str) -> str:
    return value.strip().lower()


def _collect_values_from_row(row: dict, cols: list[str]) -> list[str]:
    out: list[str] = []
    for c in cols:
        v = _valid_value(row.get(c))
        if v is not None:
            out.append(v)
    return out


def _build_subject_features(row: dict) -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    subjects = frozenset(_normalize_simple(v) for v in _collect_values_from_row(row, SUBJECT_SIMILARITY_COLS))
    sessions = frozenset(_normalize_simple(v) for v in _collect_values_from_row(row, SESSION_ID_COLUMNS))
    processes = frozenset(_normalize_simple(v) for v in _collect_values_from_row(row, PROCESS_ID_COLUMNS))
    return subjects, sessions, processes


def _subject_similarity(
    a: Optional[tuple[frozenset[str], frozenset[str], frozenset[str]]],
    b: Optional[tuple[frozenset[str], frozenset[str], frozenset[str]]],
) -> Optional[float]:
    if a is None or b is None:
        return None
    subj_a, sess_a, proc_a = a
    subj_b, sess_b, proc_b = b
    if subj_a and subj_b and not subj_a.isdisjoint(subj_b):
        return 1.0
    if sess_a and sess_b and not sess_a.isdisjoint(sess_b):
        return 1.0
    if proc_a and proc_b and not proc_a.isdisjoint(proc_b):
        return 1.0
    return 0.0


_OBJ_TOKEN_SPLIT_RE = re.compile(r"[^\w]+")
_OBJ_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_OBJ_NUM_RE = re.compile(r"^\d+$")


def _normalize_object(value: str) -> str:
    s = value.strip().lower()
    s = s.replace("\\", "/")
    return " ".join(s.split())


def _tokenize_object(value: str) -> set[str]:
    return {t for t in _OBJ_TOKEN_SPLIT_RE.split(value) if t}


def _is_numeric_or_ip(value: str) -> bool:
    return _OBJ_NUM_RE.fullmatch(value) is not None or _OBJ_IP_RE.fullmatch(value) is not None


def _string_similarity(a: str, b: str) -> float:
    a_norm = _normalize_object(a)
    b_norm = _normalize_object(b)
    if not a_norm or not b_norm:
        return 0.0
    if a_norm == b_norm:
        return 1.0
    if _is_numeric_or_ip(a_norm) or _is_numeric_or_ip(b_norm):
        return 0.0
    ratio = SequenceMatcher(None, a_norm, b_norm).ratio()
    tokens_a = _tokenize_object(a_norm)
    tokens_b = _tokenize_object(b_norm)
    if tokens_a and tokens_b:
        jacc = len(tokens_a & tokens_b) / float(len(tokens_a | tokens_b))
    else:
        jacc = 0.0
    return max(ratio, jacc)


def _object_similarity(a_vals: frozenset[str], b_vals: frozenset[str]) -> float:
    if not a_vals or not b_vals:
        return 0.0
    if not a_vals.isdisjoint(b_vals):
        return 1.0
    best = 0.0
    for a in a_vals:
        for b in b_vals:
            sim = _string_similarity(a, b)
            if sim > best:
                best = sim
                if best >= 1.0:
                    return 1.0
    return best


def _build_link_features_row(
    row: dict,
    *,
    subject_cols: list[str],
    session_cols: list[str],
    process_cols: list[str],
    object_cols: list[str],
) -> tuple[frozenset[str], frozenset[str], frozenset[str], frozenset[str]]:
    subjects = frozenset(_normalize_simple(v) for v in _collect_values_from_row(row, subject_cols))
    sessions = frozenset(_normalize_simple(v) for v in _collect_values_from_row(row, session_cols))
    processes = frozenset(_normalize_simple(v) for v in _collect_values_from_row(row, process_cols))
    objects = frozenset(_normalize_object(v) for v in _collect_values_from_row(row, object_cols))
    return subjects, sessions, processes, objects


def _slugify_title(title: str) -> str:
    s = title.strip().lower()
    s = re.sub(r"[^a-z0-9]+", "_", s)
    s = s.strip("_")
    return s or "table"


def _write_csv_tables(tables: list[tuple[str, pd.DataFrame]], out_dir: str) -> list[str]:
    os.makedirs(out_dir, exist_ok=True)
    written: list[str] = []
    seen: set[str] = set()
    for title, df in tables:
        if df is None or df.empty:
            continue
        base = _slugify_title(title)
        name = base
        idx = 2
        while name in seen:
            name = f"{base}_{idx}"
            idx += 1
        seen.add(name)
        path = os.path.join(out_dir, f"{name}.csv")
        df.to_csv(path, index=False)
        written.append(path)
    return written


def _markdown_table(df: pd.DataFrame) -> str:
    if df is None or df.empty:
        return "_no data_"
    headers = [str(h) for h in df.columns]
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for row in df.itertuples(index=False, name=None):
        row_vals = []
        for v in row:
            cell = _format_value(v)
            row_vals.append(_truncate(cell))
        lines.append("| " + " | ".join(row_vals) + " |")
    return "\n".join(lines)


def _counts_table(series: pd.Series, label: str, top_n: int) -> pd.DataFrame:
    counts = _top_counts(series, top_n)
    if counts.empty:
        return pd.DataFrame(columns=[label, "events", "percent"])
    total = int(counts.sum())
    df = pd.DataFrame({label: counts.index, "events": counts.values})
    df["percent"] = (df["events"] / float(total) * 100.0).round(2)
    return df


def _severity_table(series: pd.Series) -> pd.DataFrame:
    s = pd.to_numeric(series, errors="coerce").dropna().astype(int)
    if len(s) == 0:
        return pd.DataFrame(columns=["severity", "events", "percent"])
    counts = s.value_counts().sort_index()
    total = int(counts.sum())
    df = pd.DataFrame({"severity": counts.index, "events": counts.values})
    df["percent"] = (df["events"] / float(total) * 100.0).round(2)
    return df


def _subject_metrics(
    df: pd.DataFrame,
    *,
    subject_col: str,
    ts_col: Optional[str],
    top_n: int,
    burst_window_seconds: int,
) -> pd.DataFrame:
    s = _clean_text_series(df[subject_col]).dropna()
    if len(s) == 0:
        return pd.DataFrame(columns=["subject", "events"])
    counts = s.value_counts()
    top_subjects = counts.head(int(top_n)).index
    out = pd.DataFrame({"subject": top_subjects, "events": counts.loc[top_subjects].astype(int).values})
    if ts_col is None or ts_col not in df.columns:
        return out
    tmp = df[[subject_col, ts_col]].copy()
    tmp[subject_col] = _clean_text_series(tmp[subject_col])
    tmp = tmp[tmp[subject_col].notna()].copy()
    tmp[ts_col] = _parse_ts_series(tmp[ts_col])
    tmp = tmp[tmp[ts_col].notna()].copy()
    if len(tmp) == 0:
        return out
    burst = compute_burst_max(tmp, subject_col, ts_col, window_seconds=burst_window_seconds)
    out[f"burst_rate_max_per_s_{burst_window_seconds}s"] = burst.reindex(top_subjects).fillna(0.0).round(3).values
    return out


def _object_metrics(
    df: pd.DataFrame,
    *,
    object_col: str,
    event_type_col: Optional[str],
    top_n: int,
) -> pd.DataFrame:
    s = _clean_text_series(df[object_col]).dropna()
    if len(s) == 0:
        return pd.DataFrame(columns=["object", "events"])
    counts = s.value_counts()
    top_objects = counts.head(int(top_n)).index
    out = pd.DataFrame({"object": top_objects, "events": counts.loc[top_objects].astype(int).values})
    if event_type_col is None or event_type_col not in df.columns:
        return out
    tmp = df[[object_col, event_type_col]].copy()
    tmp[object_col] = _clean_text_series(tmp[object_col])
    tmp[event_type_col] = _clean_text_series(tmp[event_type_col])
    tmp = tmp[tmp[object_col].notna() & tmp[event_type_col].notna()].copy()
    if len(tmp) == 0:
        return out
    tmp[event_type_col] = tmp[event_type_col].astype(str)
    diversity = tmp[tmp[object_col].isin(top_objects)].groupby(object_col)[event_type_col].nunique()
    out["event_type_diversity"] = diversity.reindex(top_objects).fillna(0).astype(int).values
    return out


def _shared_objects(
    df: pd.DataFrame,
    *,
    subject_col: str,
    object_col: str,
    top_n: int,
) -> pd.DataFrame:
    base = df[[subject_col, object_col]].copy()
    base[subject_col] = _clean_text_series(base[subject_col])
    base[object_col] = _clean_text_series(base[object_col])
    base = base[base[subject_col].notna() & base[object_col].notna()].copy()
    if len(base) == 0:
        return pd.DataFrame(columns=["object", "subjects", "events"])
    g = base.groupby(object_col)
    out = pd.DataFrame({"subjects": g[subject_col].nunique(), "events": g.size()})
    out = out.sort_values(["subjects", "events"], ascending=[False, False]).reset_index()
    out = out.rename(columns={object_col: "object"})
    return out.head(int(top_n))


def _subject_object_pairs(
    df: pd.DataFrame,
    *,
    subject_col: str,
    object_col: str,
    top_n: int,
) -> pd.DataFrame:
    base = df[[subject_col, object_col]].copy()
    base[subject_col] = _clean_text_series(base[subject_col])
    base[object_col] = _clean_text_series(base[object_col])
    base = base[base[subject_col].notna() & base[object_col].notna()].copy()
    if len(base) == 0:
        return pd.DataFrame(columns=["subject", "object", "events"])
    g = base.groupby([subject_col, object_col]).size().reset_index(name="events")
    g = g.sort_values("events", ascending=False)
    g = g.rename(columns={subject_col: "subject", object_col: "object"})
    return g.head(int(top_n))


def _daily_volume(ts_series: pd.Series, top_n: int) -> pd.DataFrame:
    ts = _parse_ts_series(ts_series).dropna()
    if len(ts) == 0:
        return pd.DataFrame(columns=["date", "events"])
    days = ts.dt.floor("D")
    counts = days.value_counts().sort_index()
    out = pd.DataFrame({"date": counts.index.astype(str), "events": counts.values})
    return out.sort_values("events", ascending=False).head(int(top_n))


def _render_markdown(
    *,
    table_name: str,
    total_rows: int,
    analyzed_rows: int,
    ts_col: Optional[str],
    subject_col: Optional[str],
    object_col: Optional[str],
    host_col: Optional[str],
    severity_col: Optional[str],
    event_type_col: Optional[str],
    tactic_col: Optional[str],
    technique_col: Optional[str],
    time_range: Optional[tuple[pd.Timestamp, pd.Timestamp]],
    unique_subjects: Optional[int],
    unique_objects: Optional[int],
    unique_hosts: Optional[int],
    alert_rate: Optional[float],
    severity_table: pd.DataFrame,
    event_type_table: pd.DataFrame,
    host_table: pd.DataFrame,
    subject_table: pd.DataFrame,
    object_table: pd.DataFrame,
    shared_objects_table: pd.DataFrame,
    pairs_table: pd.DataFrame,
    tactic_table: pd.DataFrame,
    technique_table: pd.DataFrame,
    daily_table: pd.DataFrame,
    link_table_name: Optional[str],
    link_total_rows: int,
    link_rows_loaded: int,
    link_rows_used: int,
    link_summary_table: pd.DataFrame,
    link_top_c_table: pd.DataFrame,
    link_top_p_table: pd.DataFrame,
    link_limit: Optional[int],
    limit: Optional[int],
) -> str:
    lines: list[str] = []
    lines.append("# Metrics Report")
    lines.append("")
    lines.append("## Dataset Summary")
    lines.append(f"- source_table: {table_name}")
    lines.append(f"- total_rows: {total_rows}")
    if limit is not None and analyzed_rows != total_rows:
        lines.append(f"- rows_analyzed: {analyzed_rows} (limit={limit})")
    else:
        lines.append(f"- rows_analyzed: {analyzed_rows}")
    lines.append(f"- timestamp_column: {ts_col or '-'}")
    lines.append(f"- severity_column: {severity_col or '-'}")
    lines.append(f"- event_type_column: {event_type_col or '-'}")
    lines.append(f"- subject_column: {subject_col or '-'}")
    lines.append(f"- object_column: {object_col or '-'}")
    lines.append(f"- host_column: {host_col or '-'}")
    lines.append(f"- mitre_tactic_column: {tactic_col or '-'}")
    lines.append(f"- mitre_technique_column: {technique_col or '-'}")
    if time_range is not None:
        start, end = time_range
        lines.append(f"- time_range: {start.isoformat()} -> {end.isoformat()}")
        span_days = (end - start).total_seconds() / 86400.0
        lines.append(f"- span_days: {span_days:.2f}")
    if unique_subjects is not None:
        lines.append(f"- unique_subjects: {unique_subjects}")
    if unique_objects is not None:
        lines.append(f"- unique_objects: {unique_objects}")
    if unique_hosts is not None:
        lines.append(f"- unique_hosts: {unique_hosts}")
    if alert_rate is not None:
        lines.append(f"- alert_rate: {alert_rate:.2f}%")

    if not severity_table.empty:
        lines.append("")
        lines.append("## Severity Distribution")
        lines.append(_markdown_table(severity_table))

    if not event_type_table.empty:
        lines.append("")
        lines.append("## Top Event Types")
        lines.append(_markdown_table(event_type_table))

    if not host_table.empty:
        lines.append("")
        lines.append("## Top Hosts")
        lines.append(_markdown_table(host_table))

    if not subject_table.empty:
        lines.append("")
        lines.append("## Top Subjects")
        lines.append(_markdown_table(subject_table))

    if not object_table.empty:
        lines.append("")
        lines.append("## Top Objects")
        lines.append(_markdown_table(object_table))

    if not shared_objects_table.empty:
        lines.append("")
        lines.append("## Objects Shared Across Subjects")
        lines.append(_markdown_table(shared_objects_table))

    if not pairs_table.empty:
        lines.append("")
        lines.append("## Top Subject/Object Pairs")
        lines.append(_markdown_table(pairs_table))

    if not tactic_table.empty:
        lines.append("")
        lines.append("## MITRE Tactics")
        lines.append(_markdown_table(tactic_table))

    if not technique_table.empty:
        lines.append("")
        lines.append("## MITRE Techniques")
        lines.append(_markdown_table(technique_table))

    if not daily_table.empty:
        lines.append("")
        lines.append("## Busiest Days")
        lines.append(_markdown_table(daily_table))

    if link_table_name is not None:
        lines.append("")
        lines.append("## Event Link Metrics")
        lines.append(f"- link_table: {link_table_name}")
        lines.append(f"- link_rows_total: {link_total_rows}")
        if link_limit is not None and link_rows_loaded != link_total_rows:
            lines.append(f"- link_rows_loaded: {link_rows_loaded} (limit={link_limit})")
        else:
            lines.append(f"- link_rows_loaded: {link_rows_loaded}")
        lines.append(f"- link_rows_used: {link_rows_used}")
        if not link_summary_table.empty:
            lines.append(_markdown_table(link_summary_table))
        if not link_top_c_table.empty:
            lines.append("")
            lines.append("### Top Links by C(e_i,e_j)")
            lines.append(_markdown_table(link_top_c_table))
        if not link_top_p_table.empty:
            lines.append("")
            lines.append("### Top Links by P")
            lines.append(_markdown_table(link_top_p_table))

    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate metrics report from Postgres events.")
    parser.add_argument("--source-table", default=None, help="Source table for metrics (overrides defaults).")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of rows for faster runs.")
    parser.add_argument("--top", type=int, default=10, help="Top N rows for each metric table.")
    parser.add_argument("--burst-window", type=int, default=DEFAULT_BURST_WINDOW_SECONDS, help="Burst window in seconds.")
    parser.add_argument("--alert-level", type=int, default=DEFAULT_ALERT_LEVEL_THRESHOLD, help="Alert threshold for rule.level.")
    parser.add_argument("--links-table", default=None, help="Event links table for link metrics.")
    parser.add_argument("--links-limit", type=int, default=None, help="Limit number of link rows for faster runs.")
    parser.add_argument("--csv-dir", default="results", help="Directory for CSV table exports.")
    parser.add_argument("--out", default=None, help="Optional output path for markdown report.")
    args = parser.parse_args()

    metric_keys = (
        set(SUBJECT_CANDIDATES)
        | set(OBJECT_CANDIDATES)
        | set(HOST_CANDIDATES)
        | set(MITRE_TACTIC_CANDIDATES)
        | set(MITRE_TECHNIQUE_CANDIDATES)
        | set(TIMESTAMP_CANDIDATES)
        | set(EVENT_TYPE_CANDIDATES)
        | set(SEVERITY_CANDIDATES)
    )

    link_limit = args.links_limit if args.links_limit is not None else args.limit
    link_table_name = None
    link_total_rows = 0
    link_rows_loaded = 0
    link_rows_used = 0
    link_summary_table = pd.DataFrame()
    link_top_c_table = pd.DataFrame()
    link_top_p_table = pd.DataFrame()
    summary_duration = None
    raw_duration = None
    preclean_duration = None
    clean_df = pd.DataFrame()
    preclean_df = pd.DataFrame()

    with build_pg_conn() as conn:
        table_name = _resolve_source_table(conn, args.source_table)
        total_rows = _row_count(conn, table_name)
        df = _load_metrics_frame(
            conn,
            table_name,
            keys=metric_keys,
            batch_size=POSTGRES_BATCH_SIZE,
            limit=args.limit,
        )
        if POSTGRES_CLEAN_TABLE and _table_has_rows(conn, POSTGRES_CLEAN_TABLE):
            clean_df = df if table_name == POSTGRES_CLEAN_TABLE else _load_metrics_frame(
                conn,
                POSTGRES_CLEAN_TABLE,
                keys=metric_keys,
                batch_size=POSTGRES_BATCH_SIZE,
                limit=args.limit,
            )
        if POSTGRES_SOURCE_TABLE and _table_has_rows(conn, POSTGRES_SOURCE_TABLE):
            preclean_df = df if table_name == POSTGRES_SOURCE_TABLE else _load_metrics_frame(
                conn,
                POSTGRES_SOURCE_TABLE,
                keys=metric_keys,
                batch_size=POSTGRES_BATCH_SIZE,
                limit=args.limit,
            )
        link_table_name = _resolve_links_table(conn, args.links_table)
        if link_table_name is not None:
            summary_start = time.perf_counter()
            link_total_rows = _row_count(conn, link_table_name)
            links_df = _load_link_frame(
                conn,
                link_table_name,
                batch_size=POSTGRES_BATCH_SIZE,
                limit=link_limit,
            )
            link_rows_loaded = len(links_df)
            links_metrics = links_df.copy()
            if "role" in links_metrics.columns:
                links_metrics = links_metrics[links_metrics["role"].fillna("").astype(str) != "target"].copy()
            links_metrics = links_metrics.dropna(subset=["c", "dt", "ent", "k_sem", "p"], how="all")
            event_source_table = POSTGRES_EVENT_SOURCE_TABLE
            if event_source_table and _table_exists(conn, event_source_table):
                event_ids = links_metrics["event_id"].map(_normalize_event_id)
                link_ids = links_metrics["link_to"].map(_normalize_event_id)
                ids_set = {i for i in pd.concat([event_ids, link_ids]).dropna().astype(str)}
                event_data = _fetch_event_data_map(conn, event_source_table, ids_set)
                if event_data:
                    features_map = {eid: _build_subject_features(row) for eid, row in event_data.items()}
                    subj_sim = [
                        _subject_similarity(features_map.get(eid), features_map.get(lid))
                        for eid, lid in zip(event_ids, link_ids)
                    ]
                    links_metrics["subject_similarity"] = subj_sim
            link_rows_used = len(links_metrics)
            link_summary_table = _link_metrics_summary(links_metrics)
            link_top_c_table = _link_top_table(links_metrics, "c", args.top)
            link_top_p_table = _link_top_table(links_metrics, "p", args.top)
            summary_duration = time.perf_counter() - summary_start

    analyzed_rows = len(df)
    ts_col = _pick_best_column(df, TIMESTAMP_CANDIDATES)
    severity_col = _pick_best_column(df, SEVERITY_CANDIDATES)
    subject_col = _pick_best_column(df, SUBJECT_CANDIDATES)
    object_col = _pick_best_column(df, OBJECT_CANDIDATES)
    host_col = _pick_best_column(df, HOST_CANDIDATES)
    event_type_col = _pick_best_column(df, EVENT_TYPE_CANDIDATES)
    tactic_col = _pick_best_column(df, MITRE_TACTIC_CANDIDATES)
    technique_col = _pick_best_column(df, MITRE_TECHNIQUE_CANDIDATES)

    time_range = None
    if ts_col and ts_col in df.columns:
        ts = _parse_ts_series(df[ts_col]).dropna()
        if len(ts) > 0:
            time_range = (ts.min(), ts.max())

    unique_subjects = None
    if subject_col and subject_col in df.columns:
        unique_subjects = int(_clean_text_series(df[subject_col]).nunique(dropna=True))

    unique_objects = None
    if object_col and object_col in df.columns:
        unique_objects = int(_clean_text_series(df[object_col]).nunique(dropna=True))

    unique_hosts = None
    if host_col and host_col in df.columns:
        unique_hosts = int(_clean_text_series(df[host_col]).nunique(dropna=True))

    alert_rate = None
    severity_table = pd.DataFrame()
    if severity_col and severity_col in df.columns:
        severity_table = _severity_table(df[severity_col])
        if not severity_table.empty:
            s = pd.to_numeric(df[severity_col], errors="coerce").dropna().astype(int)
            if len(s) > 0:
                alert_rate = (s >= int(args.alert_level)).mean() * 100.0

    event_type_table = pd.DataFrame()
    if event_type_col and event_type_col in df.columns:
        event_type_table = _counts_table(df[event_type_col].astype(str), "event_type", args.top)

    host_table = pd.DataFrame()
    if host_col and host_col in df.columns:
        host_table = _counts_table(df[host_col], "host", args.top)

    subject_table = pd.DataFrame()
    if subject_col and subject_col in df.columns:
        subject_table = _subject_metrics(
            df,
            subject_col=subject_col,
            ts_col=ts_col,
            top_n=args.top,
            burst_window_seconds=args.burst_window,
        )

    object_table = pd.DataFrame()
    if object_col and object_col in df.columns:
        object_table = _object_metrics(
            df,
            object_col=object_col,
            event_type_col=event_type_col,
            top_n=args.top,
        )

    shared_objects_table = pd.DataFrame()
    pairs_table = pd.DataFrame()
    if subject_col and object_col and subject_col in df.columns and object_col in df.columns:
        shared_objects_table = _shared_objects(
            df,
            subject_col=subject_col,
            object_col=object_col,
            top_n=args.top,
        )
        pairs_table = _subject_object_pairs(
            df,
            subject_col=subject_col,
            object_col=object_col,
            top_n=args.top,
        )

    tactic_table = pd.DataFrame()
    if tactic_col and tactic_col in df.columns:
        tactic_vals = _explode_multi_values(df[tactic_col])
        tactic_table = _counts_table(tactic_vals, "tactic", args.top)

    technique_table = pd.DataFrame()
    if technique_col and technique_col in df.columns:
        technique_vals = _explode_multi_values(df[technique_col])
        technique_table = _counts_table(technique_vals, "technique", args.top)

    daily_table = pd.DataFrame()
    if ts_col and ts_col in df.columns:
        daily_table = _daily_volume(df[ts_col], args.top)

    raw_link_summary_table = pd.DataFrame()
    if not clean_df.empty:
        raw_start = time.perf_counter()
        raw_link_summary_table = _raw_link_summary_from_df(clean_df)
        raw_duration = time.perf_counter() - raw_start
    preclean_link_summary_table = pd.DataFrame()
    if not preclean_df.empty:
        preclean_start = time.perf_counter()
        preclean_link_summary_table = _raw_link_summary_from_df(preclean_df)
        preclean_duration = time.perf_counter() - preclean_start

    report = _render_markdown(
        table_name=table_name,
        total_rows=total_rows,
        analyzed_rows=analyzed_rows,
        ts_col=ts_col,
        subject_col=subject_col,
        object_col=object_col,
        host_col=host_col,
        severity_col=severity_col,
        event_type_col=event_type_col,
        tactic_col=tactic_col,
        technique_col=technique_col,
        time_range=time_range,
        unique_subjects=unique_subjects,
        unique_objects=unique_objects,
        unique_hosts=unique_hosts,
        alert_rate=alert_rate,
        severity_table=severity_table,
        event_type_table=event_type_table,
        host_table=host_table,
        subject_table=subject_table,
        object_table=object_table,
        shared_objects_table=shared_objects_table,
        pairs_table=pairs_table,
        tactic_table=tactic_table,
        technique_table=technique_table,
        daily_table=daily_table,
        link_table_name=link_table_name,
        link_total_rows=link_total_rows,
        link_rows_loaded=link_rows_loaded,
        link_rows_used=link_rows_used,
        link_summary_table=link_summary_table,
        link_top_c_table=link_top_c_table,
        link_top_p_table=link_top_p_table,
        link_limit=link_limit,
        limit=args.limit,
    )

    csv_tables: list[tuple[str, pd.DataFrame]] = [
        ("Severity Distribution", severity_table),
        ("Top Event Types", event_type_table),
        ("Top Hosts", host_table),
        ("Top Subjects", subject_table),
        ("Top Objects", object_table),
        ("Objects Shared Across Subjects", shared_objects_table),
        ("Top Subject/Object Pairs", pairs_table),
        ("MITRE Tactics", tactic_table),
        ("MITRE Techniques", technique_table),
        ("Busiest Days", daily_table),
    ]
    if link_table_name is not None and not link_summary_table.empty:
        csv_tables.append(("Event Link Metrics Summary", link_summary_table))
    if link_table_name is not None and not link_top_c_table.empty:
        csv_tables.append(("Top Links by C(e_i,e_j)", link_top_c_table))
    if link_table_name is not None and not link_top_p_table.empty:
        csv_tables.append(("Top Links by P", link_top_p_table))
    if not raw_link_summary_table.empty:
        csv_tables.append(("Event Link Metrics Raw", raw_link_summary_table))
    if not preclean_link_summary_table.empty:
        csv_tables.append(("Event Link Metrics Preclean", preclean_link_summary_table))

    if summary_duration is not None:
        print(f"Computed event_link_metrics_summary in {summary_duration:.2f}s")
    if raw_duration is not None:
        print(f"Computed event_link_metrics_raw in {raw_duration:.2f}s")
    if preclean_duration is not None:
        print(f"Computed event_link_metrics_preclean in {preclean_duration:.2f}s")

    if args.csv_dir:
        written = _write_csv_tables(csv_tables, args.csv_dir)
        if written:
            print(f"Wrote {len(written)} CSV tables to {args.csv_dir}")

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"Wrote report to {args.out}")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
