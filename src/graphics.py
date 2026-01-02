from __future__ import annotations

import math
import os
from datetime import datetime
from dataclasses import dataclass
from typing import Dict, List, Optional

import psycopg2
from psycopg2 import sql

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse


POSTGRES_HOST = os.getenv("POSTGRES_HOST", "localhost")
POSTGRES_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
POSTGRES_DB = os.getenv("POSTGRES_DB", "app_db")
POSTGRES_USER = os.getenv("POSTGRES_USER", "app_user")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "app_password")
POSTGRES_EVENT_TABLE = os.getenv("POSTGRES_EVENT_TABLE", "event_links")
POSTGRES_EVENT_SOURCE_TABLE = os.getenv(
    "POSTGRES_EVENT_SOURCE_TABLE",
    os.getenv("POSTGRES_CLEAN_TABLE", "opensearch_events_clean"),
)
POSTGRES_BATCH_SIZE = int(os.getenv("POSTGRES_BATCH_SIZE", "1000"))
HOST = os.getenv("GRAPHICS_HOST", "0.0.0.0")
PORT = int(os.getenv("GRAPHICS_PORT", "3000"))
SHOW_DECISION_METRICS = os.getenv("SHOW_DECISION_METRICS", "true").strip().lower() == "true"
METRIC_LABELS_RU = {
    "c": "C(e_i,e_j)",
    "dt": "временной разрыв Δt, сек",
    "ent": "сходство объектов C_o",
    "k_sem": "семантика перехода K_sem",
    "p": "вероятность перехода P",
}


@dataclass
class EventRow:
    group: str
    role: str
    order: int
    event_id: str
    link_to: str
    ts: str
    c: Optional[float]
    dt: Optional[float]
    ent: Optional[float]
    k_sem: Optional[float]
    p: Optional[float]


@dataclass
class EventDetails:
    event_id: str
    severity: str
    subject: str
    object: str
    desc: str
    mitre: str


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


def _ts_to_str(value: object) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    if value is None:
        return ""
    return str(value)


def load_event_rows(table_name: str, *, batch_size: int) -> List[EventRow]:
    rows: List[EventRow] = []
    with build_pg_conn() as conn:
        if not _table_exists(conn, table_name):
            return rows
        cols = _fetch_table_columns(conn, table_name)
        metric_col = "c" if "c" in cols else "w" if "w" in cols else None
        if metric_col is None:
            return rows
        query = sql.SQL(
            """
            SELECT group_id, role, order_num, event_id, link_to, ts, {metric_col}, dt, ent, k_sem, p
            FROM {table}
            ORDER BY id
            """
        ).format(
            table=sql.Identifier(table_name),
            metric_col=sql.Identifier(metric_col),
        )
        with conn.cursor(name="graphics_event_cursor") as cur:
            cur.itersize = int(batch_size)
            cur.execute(query)
            for group_id, role, order_num, event_id, link_to, ts, c_val, dt, ent, k_sem, p in cur:
                group_val = str(group_id or "default").strip() or "default"
                rows.append(
                    EventRow(
                        group=group_val,
                        role=str(role or "").strip(),
                        order=int(order_num or 0),
                        event_id=str(event_id or "").strip(),
                        link_to=str(link_to or "").strip(),
                        ts=_ts_to_str(ts),
                        c=_parse_float(c_val),
                        dt=_parse_float(dt),
                        ent=_parse_float(ent),
                        k_sem=_parse_float(k_sem),
                        p=_parse_float(p),
                    )
                )
    return rows


def _valid_value(v: object) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    if s == "" or s.lower() == "nan":
        return None
    return s


def _normalize_event_id(v: object) -> Optional[str]:
    if v is None:
        return None
    s = str(v)
    if not s or s.lower() == "nan":
        return None
    return s


def _parse_float(v: object) -> Optional[float]:
    if v is None:
        return None
    s = str(v).strip()
    if s == "" or s.lower() == "nan":
        return None
    try:
        return float(s)
    except ValueError:
        return None


def _collect_values(row: Dict[str, object], cols: List[str], limit: int = 3) -> List[str]:
    out: List[str] = []
    for c in cols:
        v = _valid_value(row.get(c))
        if v is not None:
            out.append(v)
            if len(out) >= limit:
                break
    return out


def load_event_details(table_name: str, ids: List[str]) -> Dict[str, EventDetails]:
    if not ids:
        return {}
    ids_norm = [_normalize_event_id(i) for i in ids]
    ids_set = {i for i in ids_norm if i is not None}
    if not ids_set:
        return {}
    details: Dict[str, EventDetails] = {}
    subject_cols = [
        "data.win.eventdata.subjectUserName",
        "data.win.eventdata.targetUserName",
        "data.win.eventdata.user",
        "data.win.system.computer",
        "agent.name",
        "_source.data.win.eventdata.subjectUserName",
        "_source.data.win.eventdata.targetUserName",
        "_source.data.win.eventdata.user",
        "_source.data.win.system.computer",
        "_source.agent.name",
    ]
    object_cols = [
        "data.win.eventdata.targetFilename",
        "data.win.eventdata.image",
        "data.win.eventdata.parentImage",
        "data.win.eventdata.commandLine",
        "data.win.eventdata.parentCommandLine",
        "_source.data.win.eventdata.targetFilename",
        "_source.data.win.eventdata.image",
        "_source.data.win.eventdata.parentImage",
        "_source.data.win.eventdata.commandLine",
        "_source.data.win.eventdata.parentCommandLine",
    ]
    desc_cols = [
        "rule.description",
        "data.win.system.message",
        "data.win.eventdata.description",
        "data.sca.check.description",
        "_source.rule.description",
        "_source.data.win.system.message",
        "_source.data.win.eventdata.description",
        "_source.data.sca.check.description",
    ]
    mitre_cols = [
        "rule.mitre.tactic",
        "rule.mitre_tactics",
        "rule.mitre.technique",
        "rule.mitre_techniques",
        "data.sca.check.compliance.mitre_tactics",
        "data.sca.check.compliance.mitre_techniques",
        "_source.rule.mitre.tactic",
        "_source.rule.mitre_tactics",
        "_source.rule.mitre.technique",
        "_source.rule.mitre_techniques",
        "_source.data.sca.check.compliance.mitre_tactics",
        "_source.data.sca.check.compliance.mitre_techniques",
    ]
    with build_pg_conn() as conn:
        if not _table_exists(conn, table_name):
            return {}
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
            ids_list = list(ids_set)
            cur.execute(query, (ids_list, ids_list, ids_list))
            for doc_id, data in cur.fetchall():
                row = data or {}
                candidates = (
                    _normalize_event_id(doc_id),
                    _normalize_event_id(row.get("_source.id")),
                    _normalize_event_id(row.get("id")),
                )
                rid = next((c for c in candidates if c in ids_set), None)
                if rid is None:
                    continue
                sev = _valid_value(row.get("rule.level") or row.get("_source.rule.level")) or "-"
                subject = ", ".join(_collect_values(row, subject_cols)) or "-"
                obj = ", ".join(_collect_values(row, object_cols)) or "-"
                desc = None
                for c in desc_cols:
                    desc = _valid_value(row.get(c))
                    if desc:
                        break
                desc = desc or "-"
                mitre = ", ".join(_collect_values(row, mitre_cols)) or "-"
                details[rid] = EventDetails(
                    event_id=rid,
                    severity=sev,
                    subject=subject,
                    object=obj,
                    desc=desc,
                    mitre=mitre,
                )
    return details


def _format_ts(ts_val: object) -> str:
    if ts_val is None:
        return "-"
    if isinstance(ts_val, datetime):
        return ts_val.strftime("%d-%m-%Y %H:%M:%S")
    s = str(ts_val).strip()
    if not s:
        return "-"
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        return dt.strftime("%d-%m-%Y %H:%M:%S")
    except ValueError:
        return s


def _parse_ts_value(ts_val: object) -> Optional[datetime]:
    if ts_val is None:
        return None
    if isinstance(ts_val, datetime):
        return ts_val
    s = str(ts_val).strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def _escape_html(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _safe_text(s: str) -> str:
    return s.replace("\n", " ").replace("\r", " ")


def _wrap_lines(s: str, width: int) -> int:
    if not s:
        return 1
    return max(1, (len(s) + width - 1) // width)


def _fmt_metric(v: Optional[float]) -> str:
    if v is None:
        return "-"
    return f"{v:.3f}"


def _node_label_text(details: Optional[EventDetails], ts_str: str, metrics: Optional[EventRow]) -> str:
    ts = _format_ts(ts_str)
    if details is None:
        base = f"id: -    {ts}\n----------------\nseverity: -"
    else:
        base = "\n".join(
            [
                f"id: {details.event_id}    {ts}",
                "----------------",
                f"severity: {details.severity}",
                f"subject: {_safe_text(details.subject)}",
                f"object: {_safe_text(details.object)}",
                f"desc: {_safe_text(details.desc)}",
                f"mitre: {_safe_text(details.mitre)}",
            ]
        )
    if not SHOW_DECISION_METRICS:
        return base
    c_score = _fmt_metric(metrics.c if metrics else None)
    dt = _fmt_metric(metrics.dt if metrics else None)
    ent = _fmt_metric(metrics.ent if metrics else None)
    k_sem = _fmt_metric(metrics.k_sem if metrics else None)
    p = _fmt_metric(metrics.p if metrics else None)
    return base + "\n" + "\n".join(
        [
            "----------------",
            f"{METRIC_LABELS_RU['c']}: {c_score}",
            f"{METRIC_LABELS_RU['dt']}: {dt}",
            f"{METRIC_LABELS_RU['ent']}: {ent}",
            f"{METRIC_LABELS_RU['k_sem']}: {k_sem}",
            f"{METRIC_LABELS_RU['p']}: {p}",
        ]
    )


def _node_label_html(
    details: Optional[EventDetails],
    ts_str: str,
    *,
    is_target: bool,
    metrics: Optional[EventRow],
) -> str:
    ts = _escape_html(_format_ts(ts_str))
    if details is None:
        metrics_html = ""
        if SHOW_DECISION_METRICS:
            metrics_html = (
                f"<div class='field'><span class='k'>{_escape_html(METRIC_LABELS_RU['c'])}</span><span class='v'>-</span></div>"
                f"<div class='field'><span class='k'>{_escape_html(METRIC_LABELS_RU['dt'])}</span><span class='v'>-</span></div>"
                f"<div class='field'><span class='k'>{_escape_html(METRIC_LABELS_RU['ent'])}</span><span class='v'>-</span></div>"
                f"<div class='field'><span class='k'>{_escape_html(METRIC_LABELS_RU['k_sem'])}</span><span class='v'>-</span></div>"
                f"<div class='field'><span class='k'>{_escape_html(METRIC_LABELS_RU['p'])}</span><span class='v'>-</span></div>"
            )
        return (
            "<div class='card' style='--card-bg:#ffffff;'>"
            "<div class='meta'><span class='id'>id: -</span><span class='ts'>-</span></div>"
            "<div class='field'><span class='k'>severity</span><span class='v'>-</span></div>"
            f"{metrics_html}"
            "</div>"
        )
    try:
        sev_val = int(float(details.severity))
    except ValueError:
        sev_val = 0
    if is_target:
        details_bg = "#7ab8ff"
    elif sev_val >= 15:
        details_bg = "#ef5a5a"
    elif sev_val >= 6:
        details_bg = "#f1a24b"
    else:
        details_bg = "#79c98f"
    target_cls = " target" if is_target else ""
    metrics_html = ""
    if SHOW_DECISION_METRICS:
        metrics_html = (
            f"<div class='field'><span class='k'>{_escape_html(METRIC_LABELS_RU['c'])}</span><span class='v'>{_escape_html(_fmt_metric(metrics.c if metrics else None))}</span></div>"
            f"<div class='field'><span class='k'>{_escape_html(METRIC_LABELS_RU['dt'])}</span><span class='v'>{_escape_html(_fmt_metric(metrics.dt if metrics else None))}</span></div>"
            f"<div class='field'><span class='k'>{_escape_html(METRIC_LABELS_RU['ent'])}</span><span class='v'>{_escape_html(_fmt_metric(metrics.ent if metrics else None))}</span></div>"
            f"<div class='field'><span class='k'>{_escape_html(METRIC_LABELS_RU['k_sem'])}</span><span class='v'>{_escape_html(_fmt_metric(metrics.k_sem if metrics else None))}</span></div>"
            f"<div class='field'><span class='k'>{_escape_html(METRIC_LABELS_RU['p'])}</span><span class='v'>{_escape_html(_fmt_metric(metrics.p if metrics else None))}</span></div>"
        )
    return (
        f"<div class='card{target_cls}' style='--card-bg:{_escape_html(details_bg)};'>"
        f"<div class='meta'><span class='id'>id: {_escape_html(details.event_id)}</span><span class='ts'>{ts}</span></div>"
        f"<div class='field'><span class='k'>severity</span><span class='v'>{_escape_html(details.severity)}</span></div>"
        f"<div class='field'><span class='k'>subject</span><span class='v'>{_escape_html(details.subject)}</span></div>"
        f"<div class='field'><span class='k'>object</span><span class='v'>{_escape_html(details.object)}</span></div>"
        f"<div class='field'><span class='k'>desc</span><span class='v'>{_escape_html(details.desc)}</span></div>"
        f"<div class='field'><span class='k'>mitre</span><span class='v'>{_escape_html(details.mitre)}</span></div>"
        f"{metrics_html}"
        "</div>"
    )


def build_graph(rows: List[EventRow], details: Dict[str, EventDetails]) -> Dict[str, List[Dict]]:
    target = next((r for r in rows if r.role == "target"), None)
    predecessors = sorted([r for r in rows if r.role == "predecessor"], key=lambda r: r.order)
    successors = sorted([r for r in rows if r.role == "successor"], key=lambda r: r.order)

    nodes = []
    edges = []
    row_map = {r.event_id: r for r in rows if r.event_id}
    ts_map = {event_id: _parse_ts_value(row.ts) for event_id, row in row_map.items()}
    ts_sec_map = {event_id: (ts.timestamp() if ts is not None else None) for event_id, ts in ts_map.items()}
    if target is not None and target.event_id in row_map:
        target_ts = ts_map.get(target.event_id)
    else:
        target_ts = _parse_ts_value(target.ts) if target is not None else None
    target_sec = target_ts.timestamp() if target_ts is not None else None
    def _field_height(lines: int) -> int:
        return 14 + (max(1, lines) * 16)

    def _node_height(d: Optional[EventDetails]) -> int:
        height = 32  # meta row
        height += _field_height(1)  # severity
        if d is None:
            if SHOW_DECISION_METRICS:
                height += 5 * _field_height(1)
            return max(120, height)
        height += _field_height(_wrap_lines(d.subject, 36))
        height += _field_height(_wrap_lines(d.object, 36))
        height += _field_height(_wrap_lines(d.desc, 44))
        height += _field_height(_wrap_lines(d.mitre, 36))
        if SHOW_DECISION_METRICS:
            height += 5 * _field_height(1)
        return max(140, height)

    height_map = {event_id: _node_height(details.get(event_id)) for event_id in row_map}

    card_width = 320
    gap_x = 140
    gap_y = 40
    bucket_gap = 240

    secs = [sec for sec in ts_sec_map.values() if sec is not None]
    if secs:
        min_sec = min(secs)
        max_sec = max(secs)
        span = max_sec - min_sec
        approx_buckets = min(12, max(4, int(math.sqrt(max(len(row_map), 1)))))
        bucket_seconds = max(1, int(span / approx_buckets)) if span > 0 else 1
    else:
        min_sec = 0.0
        bucket_seconds = 1

    def _bucket_key(sec: Optional[float]) -> Optional[int]:
        if sec is None:
            return None
        return int((sec - min_sec) // bucket_seconds)

    target_id = target.event_id if target is not None else None
    target_bucket_key = _bucket_key(target_sec) if target_sec is not None else None

    buckets: Dict[object, List[str]] = {}
    for eid, sec in ts_sec_map.items():
        if target_id is not None and eid == target_id:
            key = "target"
        else:
            key = _bucket_key(sec)
        buckets.setdefault(key, []).append(eid)

    def _sort_bucket(eids: List[str]) -> List[str]:
        return sorted(
            eids,
            key=lambda eid: (
                ts_sec_map.get(eid) if ts_sec_map.get(eid) is not None else float("inf"),
                row_map[eid].role,
                row_map[eid].order,
            ),
        )

    time_scale = (card_width + gap_x) / float(bucket_seconds)
    positions: Dict[str, tuple[int, int]] = {}
    prev_center = None
    prev_half = 0.0

    numeric_keys = sorted([k for k in buckets.keys() if isinstance(k, int)])
    bucket_keys: list[object] = []
    if target_id is not None:
        if target_bucket_key is not None:
            left = [k for k in numeric_keys if k < target_bucket_key]
            right = [k for k in numeric_keys if k >= target_bucket_key]
            bucket_keys.extend(left)
            bucket_keys.append("target")
            bucket_keys.extend(right)
        else:
            bucket_keys.append("target")
            bucket_keys.extend(numeric_keys)
    else:
        bucket_keys.extend(numeric_keys)
    if None in buckets:
        bucket_keys.append(None)

    for key in bucket_keys:
        eids = buckets.get(key) or []
        if not eids:
            continue
        ordered = _sort_bucket(eids)
        n = len(ordered)
        cols = max(1, int(math.ceil(math.sqrt(n))))
        rows_count = int(math.ceil(n / cols))

        row_heights = [0] * rows_count
        for idx, eid in enumerate(ordered):
            r = idx // cols
            row_heights[r] = max(row_heights[r], height_map.get(eid, 120))

        row_offsets = []
        acc = 0
        for h in row_heights:
            row_offsets.append(acc)
            acc += h + gap_y
        total_height = acc - gap_y if row_heights else 0

        bucket_width = (cols * card_width) + ((cols - 1) * gap_x)
        bucket_half = bucket_width / 2.0

        if key == "target":
            desired = 0.0
        elif key is None:
            desired = (
                prev_center + prev_half + bucket_half + bucket_gap if prev_center is not None else 0.0
            )
        else:
            bucket_start = min_sec + (key * bucket_seconds)
            origin = target_sec if target_sec is not None else min_sec
            desired = (bucket_start - origin) * time_scale

        if prev_center is None:
            center = desired
        else:
            min_center = prev_center + prev_half + bucket_half + bucket_gap
            center = max(desired, min_center)

        prev_center = center
        prev_half = bucket_half

        for idx, eid in enumerate(ordered):
            r = idx // cols
            c = idx % cols
            x = center + (c - (cols - 1) / 2.0) * (card_width + gap_x)
            row_top = -total_height / 2.0 + row_offsets[r]
            y = row_top + (row_heights[r] / 2.0)
            positions[eid] = (int(x), int(y))

    if positions:
        xs = [p[0] for p in positions.values()]
        ys = [p[1] for p in positions.values()]
        shift_x = int((min(xs) + max(xs)) / 2)
        shift_y = int((min(ys) + max(ys)) / 2)
        positions = {eid: (x - shift_x, y - shift_y) for eid, (x, y) in positions.items()}

    def _add_node(event_id: str, role: str, order: int, ts_str: str, x: int, y: int) -> None:
        if not event_id:
            return
        d = details.get(event_id)
        metrics = row_map.get(event_id)
        label_text = _node_label_text(d, ts_str, metrics)
        label_html = _node_label_html(d, ts_str, is_target=(role == "target"), metrics=metrics)
        sev_val = 0
        if d is not None:
            try:
                sev_val = int(float(d.severity))
            except ValueError:
                sev_val = 0
        if role == "target":
            color = "#7ab8ff"
        elif sev_val >= 15:
            color = "#ef5a5a"
        elif sev_val >= 6:
            color = "#f1a24b"
        else:
            color = "#79c98f"
        height = height_map.get(event_id, 102)
        pos_x = x
        pos_y = y
        nodes.append(
            {
                "data": {
                    "id": event_id,
                    "label_text": label_text,
                    "label_html": label_html,
                    "role": role,
                    "order": order,
                    "severity": sev_val,
                    "color": color,
                    "height": height,
                },
                "position": {"x": pos_x, "y": pos_y},
            }
        )

    if target is not None:
        _add_node(
            target.event_id,
            "target",
            0,
            target.ts,
            positions.get(target.event_id, (0, 0))[0],
            positions.get(target.event_id, (0, 0))[1],
        )
        for p in predecessors:
            _add_node(
                p.event_id,
                "predecessor",
                p.order,
                p.ts,
                positions.get(p.event_id, (0, 0))[0],
                positions.get(p.event_id, (0, 0))[1],
            )
        for s in successors:
            _add_node(
                s.event_id,
                "successor",
                s.order,
                s.ts,
                positions.get(s.event_id, (0, 0))[0],
                positions.get(s.event_id, (0, 0))[1],
            )

    for row in rows:
        if not row.event_id:
            continue
        link_to = getattr(row, "link_to", None)
        if link_to:
            role = row.role if row.role != "target" else "successor"
            if role == "successor":
                source = link_to
                target = row.event_id
            else:
                source = row.event_id
                target = link_to
            edges.append(
                {
                    "data": {
                        "id": f"{source}->{target}",
                        "source": source,
                        "target": target,
                        "role": role,
                        "order": row.order,
                    }
                }
            )

    return {"nodes": nodes, "edges": edges}


app = FastAPI()


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    html = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Граф событий</title>
    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;600&display=swap" rel="stylesheet">
    <style>
      :root { --bg:#f7f7f9; --panel:#ffffff; --ink:#101114; --muted:#6b7280; }
      html,body { margin:0; height:100%; font-family:"Space Grotesk", sans-serif; color:var(--ink); background:radial-gradient(1200px 700px at 10% 10%, #ffffff, #f2f2f6); }
      body { overflow:hidden; }
      body.collapsed .wrap { grid-template-columns: 56px 1fr; }
      .wrap { display:grid; grid-template-columns: 320px 1fr; height:100vh; transition:grid-template-columns 180ms ease; }
      aside { padding:24px; border-right:1px solid #e6e6ee; background:linear-gradient(180deg,#ffffff,#f6f7fb); display:flex; flex-direction:column; gap:16px; overflow:hidden; }
      body.collapsed aside { padding:16px 10px; }
      h1 { margin:0 0 10px; font-size:22px; }
      p { margin:0 0 10px; color:var(--muted); }
      #cy-wrap { position:relative; width:100%; height:100vh; overflow:hidden; }
      #cy { width:100%; height:100%; }
      #labels { position:absolute; inset:0; pointer-events:none; z-index:10; }
      .node-label { pointer-events:none; transform-origin:center center; }
      .node-label { position:absolute; transform:translate(-50%, -50%); }
      .targets { display:flex; flex-direction:column; gap:10px; margin:0; overflow:auto; padding-right:6px; flex:1; min-height:0; }
      .target-btn { border:1px solid #e2e2ee; background:#ffffff; border-radius:12px; padding:10px 12px; text-align:left; cursor:pointer;
                    display:flex; flex-direction:column; gap:4px; transition:all 120ms ease; }
      .target-btn:hover { border-color:#b8b8d6; box-shadow:0 6px 18px rgba(20,20,50,0.06); }
      .target-btn.active { border-color:#3b82f6; box-shadow:0 0 0 2px rgba(59,130,246,0.2); }
      .target-id { font-weight:600; font-size:12px; word-break:break-all; }
      .target-meta { display:flex; justify-content:space-between; font-size:12px; color:var(--muted); }
      .target-sev { font-weight:600; }
      .card { width:320px; box-sizing:border-box; color:#111; border:1px solid #1f2937; border-radius:0; background: var(--card-bg); }
      .card.target { box-shadow: 0 0 25px rgba(59, 130, 246, 0.6); border-color:#3b82f6; }
      .meta { display:grid; grid-template-columns: 2fr 1fr; padding:6px 8px; border-bottom:1px solid #1f2937; font-weight:600; }
      .ts { text-align:right; }
      .field { display:grid; grid-template-columns: 1fr 3fr; gap:8px; padding:6px 8px; border-bottom:1px solid #1f2937; }
      .field:last-child { border-bottom:none; }
      .k { font-weight:600; }
      .v { font-weight:400; word-break:break-word; overflow-wrap:anywhere; }
      .aside-header { display:flex; align-items:center; gap:10px; }
      .toggle-btn { border:1px solid #e2e2ee; background:#ffffff; border-radius:10px; padding:6px 8px; cursor:pointer; }
      .toggle-btn:hover { border-color:#b8b8d6; }
      .search { display:flex; gap:8px; align-items:center; }
      .search input { flex:1; border:1px solid #e2e2ee; border-radius:10px; padding:8px 10px; font-family:inherit; }
      body.collapsed .collapse-hide { display:none; }
    </style>
  </head>
  <body>
    <div class="wrap">
      <aside>
        <div class="aside-header">
          <button class="toggle-btn" id="toggle" title="Свернуть панель">⇤</button>
          <h1 class="collapse-hide">Граф событий</h1>
        </div>
        <div class="search collapse-hide">
          <input id="search" type="text" placeholder="Поиск по ID события" />
        </div>
        <div id="targets" class="targets collapse-hide"></div>
      </aside>
      <div id="cy-wrap">
        <div id="cy"></div>
        <div id="labels"></div>
      </div>
    </div>
    <script src="https://unpkg.com/cytoscape@3.26.0/dist/cytoscape.min.js"></script>
    <script>
      async function boot() {
        const toggleBtn = document.getElementById('toggle');
        const searchInput = document.getElementById('search');
        const targetWrap = document.getElementById('targets');
        if (!window.cytoscape) {
          targetWrap.innerHTML = '<p>Не удалось загрузить движок графа. Проверьте доступ к CDN.</p>';
          return;
        }
        const cy = cytoscape({
          container: document.getElementById('cy'),
          elements: [],
          style: [
            { selector: 'node', style: { 'width':320, 'height':'data(height)', 'opacity':0 } },
            { selector: 'edge', style: { 'width':1.2, 'line-color':'#9ca3af', 'target-arrow-shape':'triangle', 'target-arrow-color':'#9ca3af',
                                         'curve-style':'straight', 'arrow-scale':0.6 } }
          ],
          layout: { name:'preset', fit:false }
        });
        const labelLayer = document.getElementById('labels');
        const labels = new Map();
        function initLabels() {
          labelLayer.innerHTML = '';
          labels.clear();
          cy.nodes().forEach((node) => {
            const el = document.createElement('div');
            el.className = 'node-label';
            el.dataset.id = node.id();
            el.innerHTML = node.data().label_html;
            el.style.visibility = 'hidden';
            labelLayer.appendChild(el);
            labels.set(node.id(), el);
          });
          updateLabels();
          labels.forEach((el) => { el.style.visibility = 'visible'; });
        }
        function updateLabels() {
          const z = cy.zoom();
          labels.forEach((el, id) => {
            const node = cy.getElementById(id);
            if (node.empty()) return;
            const pos = node.renderedPosition();
            el.style.left = `${pos.x}px`;
            el.style.top = `${pos.y}px`;
            el.style.transform = `translate(-50%, -50%) scale(${z})`;
          });
        }
        let raf = null;
        function scheduleUpdate() {
          if (raf) return;
          raf = requestAnimationFrame(() => {
            raf = null;
            updateLabels();
          });
        }
        cy.on('pan zoom drag free', scheduleUpdate);
        cy.on('render', scheduleUpdate);
        cy.ready(() => initLabels());
        cy.userPanningEnabled(true);
        cy.userZoomingEnabled(true);
        cy.minZoom(0.2);
        cy.maxZoom(2.0);
        if (typeof cy.wheelSensitivity === 'function') {
          cy.wheelSensitivity(0.2);
        }
        const wrap = document.getElementById('cy-wrap');
        wrap.addEventListener('wheel', (evt) => {
          if (evt.ctrlKey || evt.metaKey) {
            return;
          }
          evt.preventDefault();
          cy.panBy({ x: -evt.deltaX, y: -evt.deltaY });
        }, { passive: false });

        function centerOnTarget() {
          const targetNode = cy.nodes().filter(n => n.data('role') === 'target');
          if (targetNode.length > 0) {
            cy.zoom(0.8);
            cy.center(targetNode);
          }
        }

        async function loadGraph(groupId) {
          const url = groupId ? `/data?group=${encodeURIComponent(groupId)}` : '/data';
          const resp = await fetch(url);
          const graph = await resp.json();
          cy.elements().remove();
          cy.add([...graph.nodes, ...graph.edges]);
          cy.layout({ name:'preset', fit:false }).run();
          initLabels();
          centerOnTarget();
        }

        let allGroups = [];
        let activeGroupId = null;
        async function loadTargets() {
          const resp = await fetch('/groups');
          allGroups = await resp.json();
          await renderTargets(allGroups);
        }

        async function renderTargets(groups) {
          const wrap = document.getElementById('targets');
          wrap.innerHTML = '';
          if (!groups.length) {
            wrap.innerHTML = '<p>Нет событий.</p>';
            return;
          }
          let activeBtn = null;
          groups.forEach((g, idx) => {
            const btn = document.createElement('button');
            btn.type = 'button';
            const isActive = activeGroupId ? g.id === activeGroupId : idx === 0;
            btn.className = 'target-btn' + (isActive ? ' active' : '');
            btn.dataset.group = g.id;
            btn.innerHTML = `
              <div class="target-meta">
                <span class="target-sev">sev ${g.severity}</span>
                <span class="target-ts">${g.ts}</span>
              </div>
              <div class="target-id">${g.id}</div>
            `;
            btn.addEventListener('click', async () => {
              if (activeBtn) activeBtn.classList.remove('active');
              btn.classList.add('active');
              activeBtn = btn;
              activeGroupId = g.id;
              await loadGraph(g.id);
            });
            wrap.appendChild(btn);
            if (isActive) {
              activeBtn = btn;
            }
          });
          const next = activeGroupId || groups[0].id;
          activeGroupId = next;
          await loadGraph(next);
        }

        await loadGraph('');
        try {
          await loadTargets();
          if (searchInput) {
            searchInput.addEventListener('input', async () => {
              const q = searchInput.value.trim().toLowerCase();
              if (!q) {
                await renderTargets(allGroups);
                return;
              }
              const filtered = allGroups.filter(g => g.id.toLowerCase().includes(q));
              await renderTargets(filtered);
            });
          }
          if (toggleBtn) {
            toggleBtn.addEventListener('click', () => {
              const collapsed = document.body.classList.toggle('collapsed');
              toggleBtn.textContent = collapsed ? '⇥' : '⇤';
              toggleBtn.title = collapsed ? 'Развернуть панель' : 'Свернуть панель';
            });
          }
        } catch (err) {
          console.error(err);
          targetWrap.innerHTML = '<p>Не удалось загрузить список целей. Проверьте перезапуск сервера.</p>';
        }
      }
      boot();
    </script>
  </body>
</html>"""
    return HTMLResponse(html)


@app.get("/data", response_class=JSONResponse)
def data(group: Optional[str] = None) -> JSONResponse:
    rows = load_event_rows(POSTGRES_EVENT_TABLE, batch_size=POSTGRES_BATCH_SIZE)
    if group:
        rows = [r for r in rows if r.group == group]
    else:
        target = next((r for r in rows if r.role == "target"), None)
        if target is not None:
            rows = [r for r in rows if r.group == target.group]
    ids = [r.event_id for r in rows if r.event_id]
    details = load_event_details(POSTGRES_EVENT_SOURCE_TABLE, ids)
    graph = build_graph(rows, details)
    return JSONResponse(graph)


@app.get("/groups", response_class=JSONResponse)
def groups() -> JSONResponse:
    rows = load_event_rows(POSTGRES_EVENT_TABLE, batch_size=POSTGRES_BATCH_SIZE)
    targets = [r for r in rows if r.role == "target" and r.event_id]
    ids = [r.event_id for r in targets]
    details = load_event_details(POSTGRES_EVENT_SOURCE_TABLE, ids)
    items = []
    for r in targets:
        det = details.get(r.event_id)
        items.append(
            {
                "id": r.event_id,
                "ts": _format_ts(r.ts),
                "severity": det.severity if det is not None else "-",
            }
        )
    return JSONResponse(items)


def main() -> None:
    import uvicorn

    uvicorn.run("graphics:app", host=HOST, port=PORT, reload=False)


if __name__ == "__main__":
    main()
