from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Optional

import pandas as pd
import psycopg2
from psycopg2 import sql
from psycopg2.extras import execute_values

from models import (
    DEFAULT_LINK_DT_MAX_SECONDS,
    DEFAULT_LINK_TAU_SECONDS,
    _parse_ts_series,
    choose_description_column,
    choose_host_column,
    choose_object_columns,
    choose_subject_columns,
    choose_timestamp_column,
    compute_transition_probs,
    pick_event_type_column,
)


def _normalize_weights(alpha: float, beta: float, gamma: float, delta: float) -> tuple[float, float, float, float]:
    if any(w < 0.0 for w in (alpha, beta, gamma, delta)):
        raise ValueError("LINK_WEIGHT_* must be non-negative.")
    total = alpha + beta + gamma + delta
    if total <= 0.0:
        raise ValueError("LINK_WEIGHT_* sum must be > 0.")
    return alpha / total, beta / total, gamma / total, delta / total


DEFAULT_TOP_K = int(os.getenv("DEFAULT_TOP_K", "10"))
DEFAULT_TARGET_SEVERITY = int(os.getenv("DEFAULT_TARGET_SEVERITY", "15"))
DEFAULT_TARGET_LIMIT = int(os.getenv("DEFAULT_TARGET_LIMIT", "100"))

POSTGRES_HOST = os.getenv("POSTGRES_HOST", "localhost")
POSTGRES_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
POSTGRES_DB = os.getenv("POSTGRES_DB", "app_db")
POSTGRES_USER = os.getenv("POSTGRES_USER", "app_user")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "app_password")
POSTGRES_CLEAN_TABLE = os.getenv("POSTGRES_CLEAN_TABLE", "opensearch_events_clean")
POSTGRES_EVENT_SOURCE_TABLE = os.getenv("POSTGRES_EVENT_SOURCE_TABLE", POSTGRES_CLEAN_TABLE)
POSTGRES_EVENT_TABLE = os.getenv("POSTGRES_EVENT_TABLE", "event_links")
POSTGRES_BATCH_SIZE = int(os.getenv("POSTGRES_BATCH_SIZE", "1000"))
TRUNCATE_EVENT_TABLE = os.getenv("TRUNCATE_EVENT_TABLE", "true")
MIN_TRANSITION_THETA = float(os.getenv("MIN_TRANSITION_THETA", "0.1"))
LINK_TIME_SCALE_SECONDS = float(os.getenv("LINK_TIME_SCALE_SECONDS", str(DEFAULT_LINK_TAU_SECONDS)))
LINK_DT_MAX_SECONDS = float(os.getenv("LINK_DT_MAX_SECONDS", str(DEFAULT_LINK_DT_MAX_SECONDS)))
LINK_OBJECT_SIM_EPS = float(os.getenv("LINK_OBJECT_SIM_EPS", "0.85"))
LINK_WEIGHT_TIME = float(os.getenv("LINK_WEIGHT_TIME", "0.25"))
LINK_WEIGHT_SUBJECT = float(os.getenv("LINK_WEIGHT_SUBJECT", "0.25"))
LINK_WEIGHT_OBJECT = float(os.getenv("LINK_WEIGHT_OBJECT", "0.25"))
LINK_WEIGHT_SEMANTIC = float(os.getenv("LINK_WEIGHT_SEMANTIC", "0.25"))
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


def _parse_bool_env(value: Optional[str], name: str) -> bool:
    if value is None:
        return False
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean-like string (true/false).")


@dataclass
class LinkedEvent:
    event_id: Optional[str]
    source_doc_id: Optional[str]
    ts: pd.Timestamp
    c: float
    dt_seconds: float
    ent_sim: float
    k_sem: float
    prob: float
    link_to: str
    order: int
    subjects: str
    objects: str
    desc: str


@dataclass(frozen=True)
class LinkFeatures:
    subjects: frozenset[str]
    sessions: frozenset[str]
    processes: frozenset[str]
    objects: frozenset[str]


def _valid_value(v: object) -> Optional[str]:
    if v is None or (isinstance(v, float) and pd.isna(v)):
        return None
    s = str(v).strip()
    if s == "" or s.lower() == "nan":
        return None
    return s


def _pick_event_id(row: pd.Series) -> str:
    for key in ("_source.id", "id", "_id"):
        val = row.get(key)
        if val is None or (isinstance(val, float) and pd.isna(val)):
            continue
        s = str(val)
        if s and s.lower() != "nan":
            return s
    return "-"


def _collect_values(row: pd.Series, cols: list[str]) -> list[str]:
    out = []
    for c in cols:
        v = _valid_value(row.get(c))
        if v is not None:
            out.append(v)
    return out


def _format_vals(values: list[str]) -> str:
    return ", ".join(values) if values else "-"


_TOKEN_SPLIT_RE = re.compile(r"[^\w]+")
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_NUM_RE = re.compile(r"^\d+$")


def _normalize_simple(value: str) -> str:
    return value.strip().lower()


def _normalize_object(value: str) -> str:
    s = value.strip().lower()
    s = s.replace("\\", "/")
    return " ".join(s.split())


def _tokenize(value: str) -> set[str]:
    return {t for t in _TOKEN_SPLIT_RE.split(value) if t}


def _is_numeric_or_ip(value: str) -> bool:
    return _NUM_RE.fullmatch(value) is not None or _IP_RE.fullmatch(value) is not None


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
    tokens_a = _tokenize(a_norm)
    tokens_b = _tokenize(b_norm)
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


def _subject_consistency(src: LinkFeatures, dst: LinkFeatures) -> float:
    if src.subjects and dst.subjects and not src.subjects.isdisjoint(dst.subjects):
        return 1.0
    if src.sessions and dst.sessions and not src.sessions.isdisjoint(dst.sessions):
        return 1.0
    if src.processes and dst.processes and not src.processes.isdisjoint(dst.processes):
        return 1.0
    return 0.0


def _build_link_features(
    row: pd.Series,
    subject_cols: list[str],
    session_cols: list[str],
    process_cols: list[str],
    object_cols: list[str],
) -> LinkFeatures:
    subjects = frozenset(_normalize_simple(v) for v in _collect_values(row, subject_cols))
    sessions = frozenset(_normalize_simple(v) for v in _collect_values(row, session_cols))
    processes = frozenset(_normalize_simple(v) for v in _collect_values(row, process_cols))
    objects = frozenset(_normalize_object(v) for v in _collect_values(row, object_cols))
    return LinkFeatures(subjects=subjects, sessions=sessions, processes=processes, objects=objects)


def _select_target_events(
    df: pd.DataFrame,
    ts_col: str,
    *,
    severity: Optional[int],
    limit: int,
) -> list[pd.Series]:
    level_col = "rule.level" if "rule.level" in df.columns else "_source.rule.level"
    if level_col not in df.columns:
        raise ValueError("Severity column not found; expected 'rule.level' or '_source.rule.level'.")
    df = df.copy()
    df["_severity"] = pd.to_numeric(df[level_col], errors="coerce").fillna(0).astype(int)
    if severity is None:
        severity = int(df["_severity"].max())
    df = df[df["_severity"] == int(severity)].copy()
    if len(df) == 0:
        raise ValueError(f"No events with severity={severity} found.")
    df = df.sort_values(ts_col).tail(int(limit))
    return [row for _, row in df.iterrows()]


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


def load_events_from_postgres(table_name: str, *, batch_size: int) -> pd.DataFrame:
    rows: list[dict] = []
    with build_pg_conn() as conn:
        _ensure_source_table(conn, table_name)
        query = sql.SQL("SELECT index_name, doc_id, data FROM {} ORDER BY id").format(
            sql.Identifier(table_name)
        )
        with conn.cursor(name="event_source_cursor") as cur:
            cur.itersize = int(batch_size)
            cur.execute(query)
            for index_name, doc_id, data in cur:
                row = dict(data or {})
                row["_id"] = doc_id
                row["_index"] = index_name
                rows.append(row)
    return pd.DataFrame(rows)


def _fetch_table_columns(conn: psycopg2.extensions.connection, table_name: str) -> set[str]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = %s
              AND table_schema = current_schema()
            """,
            (table_name,),
        )
        return {row[0] for row in cur.fetchall()}


def ensure_event_table(conn: psycopg2.extensions.connection, table_name: str) -> None:
    ddl = sql.SQL(
        """
        CREATE TABLE IF NOT EXISTS {table} (
            id bigserial PRIMARY KEY,
            group_id text,
            role text,
            order_num int,
            event_id text,
            source_doc_id text,
            ts timestamptz,
            c double precision,
            dt double precision,
            ent double precision,
            k_sem double precision,
            p double precision,
            link_to text,
            inserted_at timestamptz NOT NULL DEFAULT now()
        )
        """
    ).format(table=sql.Identifier(table_name))
    with conn.cursor() as cur:
        cur.execute(ddl)
        cur.execute(
            sql.SQL("ALTER TABLE {table} ADD COLUMN IF NOT EXISTS p double precision").format(
                table=sql.Identifier(table_name)
            )
        )
        cur.execute(
            sql.SQL("ALTER TABLE {table} ADD COLUMN IF NOT EXISTS source_doc_id text").format(
                table=sql.Identifier(table_name)
            )
        )
    conn.commit()
    cols = _fetch_table_columns(conn, table_name)
    with conn.cursor() as cur:
        if "w" in cols and "c" not in cols:
            cur.execute(sql.SQL("ALTER TABLE {table} RENAME COLUMN w TO c").format(table=sql.Identifier(table_name)))
            cols.remove("w")
            cols.add("c")
        if "c" not in cols:
            cur.execute(
                sql.SQL("ALTER TABLE {table} ADD COLUMN IF NOT EXISTS c double precision").format(
                    table=sql.Identifier(table_name)
                )
            )
    conn.commit()


def truncate_event_table(table_name: str) -> None:
    with build_pg_conn() as conn:
        ensure_event_table(conn, table_name)
        with conn.cursor() as cur:
            cur.execute(sql.SQL("TRUNCATE TABLE {}").format(sql.Identifier(table_name)))
        conn.commit()


def _normalize_ts(value: object) -> object:
    if isinstance(value, pd.Timestamp):
        return value.to_pydatetime()
    return value


def write_event_rows_to_postgres(
    rows: list[dict],
    *,
    table_name: str,
    batch_size: int,
) -> int:
    if not rows:
        return 0
    with build_pg_conn() as conn:
        ensure_event_table(conn, table_name)
        insert_sql = sql.SQL(
            """
            INSERT INTO {table} (
                group_id, role, order_num, event_id, source_doc_id, ts, c, dt, ent, k_sem, p, link_to
            ) VALUES %s
            """
        ).format(table=sql.Identifier(table_name))
        with conn.cursor() as cur:
            buffer: list[tuple] = []
            for row in rows:
                buffer.append(
                    (
                        row.get("group"),
                        row.get("role"),
                        row.get("order"),
                        row.get("id"),
                        row.get("source_doc_id"),
                        _normalize_ts(row.get("ts")),
                        row.get("c"),
                        row.get("dt"),
                        row.get("ent"),
                        row.get("k_sem"),
                        row.get("p"),
                        row.get("link_to"),
                    )
                )
                if len(buffer) >= int(batch_size):
                    execute_values(cur, insert_sql, buffer, page_size=int(batch_size))
                    conn.commit()
                    buffer.clear()
            if buffer:
                execute_values(cur, insert_sql, buffer, page_size=int(batch_size))
                conn.commit()
    return len(rows)


def _build_sem_probs(df: pd.DataFrame, event_type_col: Optional[str], subject_col: Optional[str], ts_col: str) -> dict:
    if event_type_col is None:
        return {}
    if subject_col is not None and subject_col in df.columns:
        trans = compute_transition_probs(df, subject_col, ts_col, event_type_col)
    else:
        tmp = df.copy()
        tmp["__all_subject"] = "all"
        trans = compute_transition_probs(tmp, "__all_subject", ts_col, event_type_col)
    return {(r["Ei"], r["Ej"]): float(r["P(Ej|Ei)"]) for _, r in trans.iterrows()}


def _link_score(
    *,
    src: pd.Series,
    dst: pd.Series,
    feat_src: LinkFeatures,
    feat_dst: LinkFeatures,
    event_type_col: Optional[str],
    sem_probs: dict,
    ts_col: str,
) -> tuple[float, float, float, float]:
    dt = (dst[ts_col] - src[ts_col]).total_seconds()
    if dt <= 0 or dt > float(LINK_DT_MAX_SECONDS):
        return 0.0, 0.0, 0.0, 0.0
    ct = math.exp(-abs(dt) / float(LINK_TIME_SCALE_SECONDS))
    cu = _subject_consistency(feat_src, feat_dst)
    obj_sim = _object_similarity(feat_src.objects, feat_dst.objects)
    co = 1.0 if obj_sim >= float(LINK_OBJECT_SIM_EPS) else 0.0
    k_sem = 0.0
    if event_type_col is not None and sem_probs:
        type_src = str(src.get(event_type_col))
        type_dst = str(dst.get(event_type_col))
        k_sem = float(sem_probs.get((type_src, type_dst), 0.0))
    c_score = (
        (LINK_WEIGHT_TIME * ct)
        + (LINK_WEIGHT_SUBJECT * cu)
        + (LINK_WEIGHT_OBJECT * co)
        + (LINK_WEIGHT_SEMANTIC * k_sem)
    )
    return c_score, dt, obj_sim, k_sem


def _best_prev(
    target: pd.Series,
    candidates: list[pd.Series],
    feat_target: LinkFeatures,
    feat_candidates: dict,
    event_type_col: Optional[str],
    sem_probs: dict,
    ts_col: str,
) -> Optional[tuple[pd.Series, float, float, float, float]]:
    best = None
    best_c = 0.0
    for row in candidates:
        if row[ts_col] >= target[ts_col]:
            continue
        c_score, dt, obj_sim, k_sem = _link_score(
            src=row,
            dst=target,
            feat_src=feat_candidates[row.name],
            feat_dst=feat_target,
            event_type_col=event_type_col,
            sem_probs=sem_probs,
            ts_col=ts_col,
        )
        if c_score > best_c:
            best_c = c_score
            best = (row, c_score, dt, obj_sim, k_sem)
    return best


def _best_next(
    target: pd.Series,
    candidates: list[pd.Series],
    feat_target: LinkFeatures,
    feat_candidates: dict,
    event_type_col: Optional[str],
    sem_probs: dict,
    ts_col: str,
) -> Optional[tuple[pd.Series, float, float, float, float]]:
    best = None
    best_c = 0.0
    for row in candidates:
        if row[ts_col] <= target[ts_col]:
            continue
        c_score, dt, obj_sim, k_sem = _link_score(
            src=target,
            dst=row,
            feat_src=feat_target,
            feat_dst=feat_candidates[row.name],
            event_type_col=event_type_col,
            sem_probs=sem_probs,
            ts_col=ts_col,
        )
        if c_score > best_c:
            best_c = c_score
            best = (row, c_score, dt, obj_sim, k_sem)
    return best


def _collect_top_links(
    target: pd.Series,
    candidates: list[pd.Series],
    feat_target: LinkFeatures,
    feat_candidates: dict,
    event_type_col: Optional[str],
    sem_probs: dict,
    ts_col: str,
    *,
    direction: str,
    top_k: int,
) -> list[tuple[pd.Series, float, float, float, float]]:
    rows: list[tuple[pd.Series, float, float, float, float]] = []
    for row in candidates:
        if direction == "prev":
            if row[ts_col] >= target[ts_col]:
                continue
            c_score, dt, obj_sim, k_sem = _link_score(
                src=row,
                dst=target,
                feat_src=feat_candidates[row.name],
                feat_dst=feat_target,
                event_type_col=event_type_col,
                sem_probs=sem_probs,
                ts_col=ts_col,
            )
        else:
            if row[ts_col] <= target[ts_col]:
                continue
            c_score, dt, obj_sim, k_sem = _link_score(
                src=target,
                dst=row,
                feat_src=feat_target,
                feat_dst=feat_candidates[row.name],
                event_type_col=event_type_col,
                sem_probs=sem_probs,
                ts_col=ts_col,
            )
        if c_score <= 0.0:
            continue
        rows.append((row, c_score, dt, obj_sim, k_sem))
    rows.sort(key=lambda x: x[1], reverse=True)
    if int(top_k) > 0:
        rows = rows[: int(top_k)]
    return rows


def analyze_related_events(
    df: pd.DataFrame,
    *,
    ts_col: str,
    subject_cols: list[str],
    object_cols: list[str],
    host_col: Optional[str],
    top_k: int,
    target_severity: Optional[int],
    target_limit: int,
    out_csv: Optional[str],
    out_table: Optional[str],
) -> None:
    df = df.copy()
    df["_ts"] = _parse_ts_series(df[ts_col])
    df = df[df["_ts"].notna()].copy()
    if len(df) == 0:
        raise ValueError("No events with parseable timestamps.")

    desc_col = choose_description_column(df)
    event_type_col = pick_event_type_column(df)
    sem_probs = _build_sem_probs(df, event_type_col, host_col, ts_col)
    session_cols = [c for c in SESSION_ID_COLUMNS if c in df.columns]
    process_cols = [c for c in PROCESS_ID_COLUMNS if c in df.columns]
    subject_cols_filtered = [c for c in subject_cols if c not in session_cols and c not in process_cols]

    targets = _select_target_events(
        df,
        "_ts",
        severity=target_severity,
        limit=target_limit,
    )

    all_rows: list[dict] = []
    for target in targets:
        branch_k = max(1, min(3, int(top_k)))
        target_ts = target["_ts"]
        target_id = _pick_event_id(target)
        group_id = target_id or "-"

        feat_target = _build_link_features(
            target,
            subject_cols_filtered,
            session_cols,
            process_cols,
            object_cols,
        )

        window = df[
            (df["_ts"] >= target_ts - pd.Timedelta(seconds=LINK_DT_MAX_SECONDS))
            & (df["_ts"] <= target_ts + pd.Timedelta(seconds=LINK_DT_MAX_SECONDS))
        ].copy()

        window = window.sort_values("_ts")
        feat_cache = {
            row.name: _build_link_features(
                row,
                subject_cols_filtered,
                session_cols,
                process_cols,
                object_cols,
            )
            for _, row in window.iterrows()
        }
        base_candidates = [row for _, row in window.iterrows() if row.name != target.name]

        backbone_prev: list[tuple[pd.Series, float, float, float, float]] = []
        backbone_next: list[tuple[pd.Series, float, float, float, float]] = []

        candidates = list(base_candidates)
        current = target
        for _ in range(int(top_k)):
            best = _best_prev(
                current,
                candidates,
                feat_target if current is target else feat_cache[current.name],
                feat_cache,
                event_type_col,
                sem_probs,
                "_ts",
            )
            if best is None:
                break
            row, c_score, dt, obj_sim, k_sem = best
            backbone_prev.append((row, c_score, dt, obj_sim, k_sem))
            candidates = [c for c in candidates if c.name != row.name]
            current = row

        candidates = list(base_candidates)
        current = target
        for _ in range(int(top_k)):
            best = _best_next(
                current,
                candidates,
                feat_target if current is target else feat_cache[current.name],
                feat_cache,
                event_type_col,
                sem_probs,
                "_ts",
            )
            if best is None:
                break
            row, c_score, dt, obj_sim, k_sem = best
            backbone_next.append((row, c_score, dt, obj_sim, k_sem))
            candidates = [c for c in candidates if c.name != row.name]
            current = row

        depth_map: dict[str, int] = {str(target_id): 0}
        for i, (row, _, _, _, _) in enumerate(backbone_prev, 1):
            depth_map[_pick_event_id(row)] = i
        for i, (row, _, _, _, _) in enumerate(backbone_next, 1):
            depth_map[_pick_event_id(row)] = i

        prev_link: dict[str, pd.Series] = {}
        if backbone_prev:
            prev_link[str(target_id)] = backbone_prev[0][0]
            for i in range(len(backbone_prev) - 1):
                prev_link[_pick_event_id(backbone_prev[i][0])] = backbone_prev[i + 1][0]

        next_link: dict[str, pd.Series] = {}
        if backbone_next:
            next_link[str(target_id)] = backbone_next[0][0]
            for i in range(len(backbone_next) - 1):
                next_link[_pick_event_id(backbone_next[i][0])] = backbone_next[i + 1][0]

        used_ids = {str(target_id)}
        used_ids.update(_pick_event_id(row) for row, _, _, _, _ in backbone_prev)
        used_ids.update(_pick_event_id(row) for row, _, _, _, _ in backbone_next)

        predecessors: list[LinkedEvent] = []
        successors: list[LinkedEvent] = []

        chain_nodes: list[pd.Series] = [target]
        chain_nodes.extend([row for row, _, _, _, _ in backbone_prev])
        chain_nodes.extend([row for row, _, _, _, _ in backbone_next])

        for node in chain_nodes:
            node_id = _pick_event_id(node)
            node_feat = feat_target if node is target else feat_cache[node.name]
            node_depth = depth_map.get(node_id, 0)

            prev_neighbor = prev_link.get(node_id)
            prev_items: list[tuple[pd.Series, float, float, float, float]] = []
            if prev_neighbor is not None:
                c_score, dt, obj_sim, k_sem = _link_score(
                    src=prev_neighbor,
                    dst=node,
                    feat_src=feat_cache[prev_neighbor.name],
                    feat_dst=node_feat,
                    event_type_col=event_type_col,
                    sem_probs=sem_probs,
                    ts_col="_ts",
                )
                if c_score > 0.0:
                    prev_items.append((prev_neighbor, c_score, dt, obj_sim, k_sem))

            prev_candidates = [c for c in base_candidates if _pick_event_id(c) not in used_ids]
            prev_items.extend(
                _collect_top_links(
                    node,
                    prev_candidates,
                    node_feat,
                    feat_cache,
                    event_type_col,
                    sem_probs,
                    "_ts",
                    direction="prev",
                    top_k=branch_k,
                )
            )
            if prev_items:
                total_c = sum(c_score for _, c_score, _, _, _ in prev_items)
                for row, c_score, dt, obj_sim, k_sem in prev_items:
                    p = (c_score / total_c) if total_c > 0.0 else 0.0
                    if p < float(MIN_TRANSITION_THETA):
                        continue
                    used_ids.add(_pick_event_id(row))
                    predecessors.append(
                        LinkedEvent(
                            event_id=_pick_event_id(row),
                            source_doc_id=_valid_value(row.get("_id")),
                            ts=row["_ts"],
                            c=c_score,
                            dt_seconds=dt,
                            ent_sim=obj_sim,
                            k_sem=k_sem,
                            prob=p,
                            link_to=node_id,
                            order=node_depth + 1,
                            subjects=_format_vals(_collect_values(row, subject_cols)),
                            objects=_format_vals(_collect_values(row, object_cols)),
                            desc=_valid_value(row.get(desc_col)) if desc_col else "-",
                        )
                    )

            next_neighbor = next_link.get(node_id)
            next_items: list[tuple[pd.Series, float, float, float, float]] = []
            if next_neighbor is not None:
                c_score, dt, obj_sim, k_sem = _link_score(
                    src=node,
                    dst=next_neighbor,
                    feat_src=node_feat,
                    feat_dst=feat_cache[next_neighbor.name],
                    event_type_col=event_type_col,
                    sem_probs=sem_probs,
                    ts_col="_ts",
                )
                if c_score > 0.0:
                    next_items.append((next_neighbor, c_score, dt, obj_sim, k_sem))

            next_candidates = [c for c in base_candidates if _pick_event_id(c) not in used_ids]
            next_items.extend(
                _collect_top_links(
                    node,
                    next_candidates,
                    node_feat,
                    feat_cache,
                    event_type_col,
                    sem_probs,
                    "_ts",
                    direction="next",
                    top_k=branch_k,
                )
            )
            if next_items:
                total_c = sum(c_score for _, c_score, _, _, _ in next_items)
                for row, c_score, dt, obj_sim, k_sem in next_items:
                    p = (c_score / total_c) if total_c > 0.0 else 0.0
                    if p < float(MIN_TRANSITION_THETA):
                        continue
                    used_ids.add(_pick_event_id(row))
                    successors.append(
                        LinkedEvent(
                            event_id=_pick_event_id(row),
                            source_doc_id=_valid_value(row.get("_id")),
                            ts=row["_ts"],
                            c=c_score,
                            dt_seconds=dt,
                            ent_sim=obj_sim,
                            k_sem=k_sem,
                            prob=p,
                            link_to=node_id,
                            order=node_depth + 1,
                            subjects=_format_vals(_collect_values(row, subject_cols)),
                            objects=_format_vals(_collect_values(row, object_cols)),
                            desc=_valid_value(row.get(desc_col)) if desc_col else "-",
                        )
                    )

        print(f"[event] target id={target_id} ts={target_ts}")

        rows = [
            {
                "group": group_id,
                "role": "target",
                "order": 0,
                "id": target_id,
                "source_doc_id": _valid_value(target.get("_id")),
                "ts": target_ts,
                "link_to": "",
            }
        ]
        for ev in predecessors:
            rows.append(
                {
                    "group": group_id,
                    "role": "predecessor",
                    "order": ev.order,
                    "id": ev.event_id,
                    "source_doc_id": ev.source_doc_id,
                    "ts": ev.ts,
                    "c": ev.c,
                    "dt": ev.dt_seconds,
                    "ent": ev.ent_sim,
                    "k_sem": ev.k_sem,
                    "p": ev.prob,
                    "link_to": ev.link_to,
                }
            )
        for ev in successors:
            rows.append(
                {
                    "group": group_id,
                    "role": "successor",
                    "order": ev.order,
                    "id": ev.event_id,
                    "source_doc_id": ev.source_doc_id,
                    "ts": ev.ts,
                    "c": ev.c,
                    "dt": ev.dt_seconds,
                    "ent": ev.ent_sim,
                    "k_sem": ev.k_sem,
                    "p": ev.prob,
                    "link_to": ev.link_to,
                }
            )
        all_rows.extend(rows)

    if out_csv is not None:
        out_df = pd.DataFrame(all_rows)
        out_df.to_csv(out_csv, index=False)
        print(f"[event] wrote {len(out_df)} rows to {out_csv}")
    if out_table is not None:
        written = write_event_rows_to_postgres(
            all_rows,
            table_name=out_table,
            batch_size=int(POSTGRES_BATCH_SIZE),
        )
        print(f"[event] wrote {written} rows to {out_table}")


def main() -> None:
    import argparse

    p = argparse.ArgumentParser(description="Анализ связанных событий для набора целей по severity.")
    p.add_argument("--top", type=int, default=DEFAULT_TOP_K, help="Сколько пред/след событий выводить")
    p.add_argument("--severity", type=int, default=DEFAULT_TARGET_SEVERITY, help="Severity для выбора целей")
    p.add_argument("--limit", type=int, default=DEFAULT_TARGET_LIMIT, help="Сколько целей анализировать")
    p.add_argument("--source-table", default=POSTGRES_EVENT_SOURCE_TABLE, help="Таблица с очищенными событиями")
    p.add_argument("--out-table", default=POSTGRES_EVENT_TABLE, help="Таблица для записи результата")
    p.add_argument("--out-csv", default=None, help="Опционально: путь для event.csv")
    args = p.parse_args()

    if args.out_table and _parse_bool_env(TRUNCATE_EVENT_TABLE, "TRUNCATE_EVENT_TABLE"):
        truncate_event_table(args.out_table)
    df = load_events_from_postgres(args.source_table, batch_size=int(POSTGRES_BATCH_SIZE))
    if len(df) == 0:
        raise ValueError(f"No events found in table '{args.source_table}'.")
    ts_col = choose_timestamp_column(df)
    subject_cols = choose_subject_columns(df)
    object_cols = choose_object_columns(df)
    host_col = choose_host_column(df)
    if not subject_cols or not object_cols:
        raise ValueError("Cannot find subject/object columns with values.")
    analyze_related_events(
        df,
        ts_col=ts_col,
        subject_cols=subject_cols,
        object_cols=object_cols,
        host_col=host_col,
        top_k=int(args.top),
        target_severity=int(args.severity),
        target_limit=int(args.limit),
        out_csv=args.out_csv or None,
        out_table=args.out_table or None,
    )


if __name__ == "__main__":
    main()
