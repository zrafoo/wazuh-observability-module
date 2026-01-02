from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional, Tuple
import warnings

import pandas as pd
import numpy as np


DEFAULT_CSV_PATH = "export.clean.csv"
DEFAULT_ALERT_LEVEL_THRESHOLD = 7
DEFAULT_BURST_WINDOW_SECONDS = 120
DEFAULT_SEVERITY_THRESHOLD = 15
DEFAULT_OUTPUT_LIMIT = 10
DEFAULT_CHAIN_GAP_SECONDS = 300
DEFAULT_CHAIN_MAX_EVENTS = 10
DEFAULT_LINK_TAU_SECONDS = 120
DEFAULT_LINK_DT_MAX_SECONDS = 300
DEFAULT_LINK_ENT_THRESHOLD = 0.2
DEFAULT_LINK_DT_EPS_SECONDS = 1.0

SUBJECT_CANDIDATES = [
    "data.win.eventdata.subjectUserName",
    "data.win.eventdata.targetUserName",
    "data.win.eventdata.logonId",
    "data.win.eventdata.user",
    "data.win.eventdata.parentUser",
    "data.win.eventdata.accountName",
    "data.win.eventdata.subjectUserSid",
    "data.win.eventdata.targetUserSid",
    "data.win.eventdata.subjectDomainName",
    "data.win.eventdata.targetDomainName",
    "data.win.eventdata.logonType",
    "data.win.eventdata.processId",
    "data.win.eventdata.processGuid",
    "data.win.eventdata.parentProcessId",
    "data.win.eventdata.parentProcessGuid",
    "_source.data.win.eventdata.subjectUserName",
    "_source.data.win.eventdata.targetUserName",
    "_source.data.win.eventdata.logonId",
    "_source.data.win.eventdata.user",
    "_source.data.win.eventdata.parentUser",
    "_source.data.win.eventdata.accountName",
    "_source.data.win.eventdata.subjectUserSid",
    "_source.data.win.eventdata.targetUserSid",
    "_source.data.win.eventdata.subjectDomainName",
    "_source.data.win.eventdata.targetDomainName",
    "_source.data.win.eventdata.logonType",
    "_source.data.win.eventdata.processId",
    "_source.data.win.eventdata.processGuid",
    "_source.data.win.eventdata.parentProcessId",
    "_source.data.win.eventdata.parentProcessGuid",
    "data.win.system.computer",
    "_source.data.win.system.computer",
    "agent.name",
    "agent.id",
    "_source.agent.name",
    "_source.agent.id",
    "_source.agent.ip",
    "_source.predecoder.hostname",
    "user.name",
    "user.id",
    "user.domain",
    "user.sid",
    "host.name",
    "data.win.eventdata.processName",
    "_source.data.win.eventdata.processName",
    "data.win.eventdata.image",
    "_source.data.win.eventdata.image",
    "process.executable",
    "process.name",
    "process.pid",
]

OBJECT_CANDIDATES = [
    "syscheck.path",
    "syscheck.file",
    "syscheck.dir",
    "_source.syscheck.path",
    "data.win.eventdata.objectName",
    "data.win.eventdata.targetFilename",
    "data.win.eventdata.commandLine",
    "data.win.eventdata.parentCommandLine",
    "data.win.eventdata.image",
    "data.win.eventdata.parentImage",
    "data.win.eventdata.keyName",
    "data.win.eventdata.valueName",
    "data.win.eventdata.ipAddress",
    "data.win.eventdata.port",
    "_source.data.win.eventdata.objectName",
    "_source.data.win.eventdata.targetFilename",
    "_source.data.win.eventdata.commandLine",
    "_source.data.win.eventdata.parentCommandLine",
    "_source.data.win.eventdata.image",
    "_source.data.win.eventdata.parentImage",
    "_source.data.win.eventdata.keyName",
    "_source.data.win.eventdata.valueName",
    "_source.data.win.eventdata.ipAddress",
    "_source.data.win.eventdata.port",
    "destination.ip",
    "destination.domain",
    "source.ip",
    "source.domain",
    "destination.port",
    "source.port",
    "url.full",
    "file.path",
    "file.name",
]

HOST_CANDIDATES = [
    "_source.agent.name",
    "agent.name",
    "_source.data.win.system.computer",
    "data.win.system.computer",
    "host.name",
]

MITRE_TACTIC_CANDIDATES = [
    "_source.rule.mitre.tactic",
    "_source.rule.mitre_tactics",
    "_source.data.sca.check.compliance.mitre_tactics",
]

MITRE_TECHNIQUE_CANDIDATES = [
    "_source.rule.mitre.technique",
    "_source.rule.mitre_techniques",
    "_source.data.sca.check.compliance.mitre_techniques",
]

DESCRIPTION_CANDIDATES = [
    "_source.rule.description",
    "_source.data.win.system.message",
    "_source.data.win.eventdata.description",
    "_source.data.sca.check.description",
]

ENTITY_KEY_COLUMNS = {
    "host": ["_source.agent.name", "_source.data.win.system.computer", "agent.name", "host.name", "data.win.system.computer"],
    "logon_id": ["_source.data.win.eventdata.logonId", "data.win.eventdata.logonId"],
    "user_sid": ["_source.data.win.eventdata.subjectUserSid", "data.win.eventdata.subjectUserSid"],
    "process_guid": ["_source.data.win.eventdata.processGuid", "data.win.eventdata.processGuid"],
    "process_id": ["_source.data.win.eventdata.processId", "data.win.eventdata.processId"],
    "image": ["_source.data.win.eventdata.image", "data.win.eventdata.image", "process.executable", "process.name"],
    "parent_image": ["_source.data.win.eventdata.parentImage", "data.win.eventdata.parentImage"],
    "target": ["_source.data.win.eventdata.targetFilename", "data.win.eventdata.targetFilename", "file.path", "file.name"],
    "command": ["_source.data.win.eventdata.commandLine", "data.win.eventdata.commandLine"],
    "ip": ["_source.data.win.eventdata.ipAddress", "data.win.eventdata.ipAddress", "source.ip", "destination.ip"],
    "port": ["_source.data.win.eventdata.port", "data.win.eventdata.port", "source.port", "destination.port"],
}

ENTITY_WEIGHTS = {
    "process_guid": 5.0,
    "logon_id": 4.0,
    "user_sid": 3.5,
    "image": 2.5,
    "parent_image": 2.0,
    "process_id": 1.5,
    "host": 1.0,
    "target": 1.5,
    "command": 1.0,
    "ip": 1.0,
    "port": 0.5,
}


@dataclass
class ColumnChoice:
    timestamp_col: str
    subject_col: str
    object_col: str


def load_events_csv(path: str) -> pd.DataFrame:
    df = pd.read_csv(path, keep_default_na=True)
    return df


def _pick_first_existing(
    df: pd.DataFrame,
    candidates: Iterable[str],
    *,
    min_coverage: float = 0.01,
) -> Optional[str]:
    best_col: Optional[str] = None
    best_cov: float = -1.0
    n = float(len(df)) if len(df) else 0.0

    for c in candidates:
        if c not in df.columns:
            continue
        if n == 0.0:
            return c
        s = df[c]
        non_null = s.notna().sum()
        if non_null == 0:
            cov = 0.0
        else:
            if s.dtype == object:
                cov = float((s.astype(str).str.strip().str.len() > 0).sum()) / n
            else:
                cov = float(non_null) / n
        if cov > best_cov:
            best_cov = cov
            best_col = c

    if best_col is None:
        return None
    return best_col if best_cov >= float(min_coverage) else None


def _has_any_value(s: pd.Series) -> bool:
    if s.dtype == object:
        return (s.astype(str).str.strip().str.lower() != "nan").any()
    return s.notna().any()


def _valid_value(v: object) -> Optional[str]:
    if v is None or (isinstance(v, float) and pd.isna(v)):
        return None
    s = str(v).strip()
    if s == "" or s.lower() == "nan":
        return None
    return s


def choose_timestamp_column(df: pd.DataFrame) -> str:
    ts_candidates = [
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
    ts = _pick_first_existing(df, ts_candidates)
    if ts is None:
        raise ValueError(
            "Cannot find a timestamp column. Expected one of: @timestamp, timestamp, time, event.created, event.ingested, event.start, _source.@timestamp, _source.timestamp."
        )
    return ts


def choose_subject_columns(df: pd.DataFrame) -> list[str]:
    return [c for c in SUBJECT_CANDIDATES if c in df.columns and _has_any_value(df[c])]


def choose_object_columns(df: pd.DataFrame) -> list[str]:
    return [c for c in OBJECT_CANDIDATES if c in df.columns and _has_any_value(df[c])]


def choose_host_column(df: pd.DataFrame) -> Optional[str]:
    for c in HOST_CANDIDATES:
        if c in df.columns and _has_any_value(df[c]):
            return c
    return None


def choose_mitre_tactic_column(df: pd.DataFrame) -> Optional[str]:
    for c in MITRE_TACTIC_CANDIDATES:
        if c in df.columns and _has_any_value(df[c]):
            return c
    return None


def choose_mitre_technique_column(df: pd.DataFrame) -> Optional[str]:
    for c in MITRE_TECHNIQUE_CANDIDATES:
        if c in df.columns and _has_any_value(df[c]):
            return c
    return None


def choose_description_column(df: pd.DataFrame) -> Optional[str]:
    for c in DESCRIPTION_CANDIDATES:
        if c in df.columns and _has_any_value(df[c]):
            return c
    return None


def _parse_ts_series(s: pd.Series) -> pd.Series:
    fmt_kibana = "%b %d, %Y @ %H:%M:%S.%f"
    s_kib = pd.to_datetime(s, errors="coerce", utc=True, format=fmt_kibana)
    if float(s_kib.notna().mean()) >= 0.5:
        return s_kib
    fmt_kib_no_ms = "%b %d, %Y @ %H:%M:%S"
    s_kib2 = pd.to_datetime(s, errors="coerce", utc=True, format=fmt_kib_no_ms)
    if float(s_kib2.notna().mean()) >= 0.5:
        return s_kib2

    s1 = pd.to_datetime(s, errors="coerce", utc=True, format="ISO8601")
    if float(s1.notna().mean()) >= 0.5:
        return s1
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            message="Could not infer format",
            category=UserWarning,
        )
        return pd.to_datetime(s, errors="coerce", utc=True)


def choose_model_columns(df: pd.DataFrame) -> ColumnChoice:
    ts = choose_timestamp_column(df)
    subj = _pick_first_existing(df, SUBJECT_CANDIDATES)
    if subj is None:
        raise ValueError("Cannot find a subject column; dataset looks unexpected.")
    obj = _pick_first_existing(df, OBJECT_CANDIDATES)
    if obj is None:
        raise ValueError("Cannot find an object column; dataset looks unexpected.")
    return ColumnChoice(timestamp_col=ts, subject_col=subj, object_col=obj)


def prepare_events(
    df: pd.DataFrame,
    cols: ColumnChoice,
    alert_level_threshold: int = DEFAULT_ALERT_LEVEL_THRESHOLD,
) -> pd.DataFrame:
    out = df.copy()
    out[cols.timestamp_col] = _parse_ts_series(out[cols.timestamp_col])
    out = out[out[cols.timestamp_col].notna()].copy()
    if "rule.level" in out.columns:
        level = pd.to_numeric(out["rule.level"], errors="coerce").fillna(0).astype(int)
        out["_is_alert"] = level >= int(alert_level_threshold)
        out["_rule_level"] = level
    else:
        out["_is_alert"] = False
        out["_rule_level"] = 0
    out = out[out[cols.subject_col].notna()].copy()
    out[cols.subject_col] = out[cols.subject_col].astype(str).str.strip()
    out = out[out[cols.subject_col].str.len() > 0].copy()
    if cols.object_col in out.columns:
        mask = out[cols.object_col].notna()
        out.loc[mask, cols.object_col] = out.loc[mask, cols.object_col].astype(str).str.strip()
        out.loc[mask & (out[cols.object_col].str.len() == 0), cols.object_col] = pd.NA
    return out


def pick_event_type_column(df: pd.DataFrame) -> Optional[str]:
    candidates = [
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
    for c in candidates:
        if c in df.columns and df[c].notna().any():
            return c
    return None


def compute_transition_probs(
    df: pd.DataFrame,
    subject_col: str,
    ts_col: str,
    event_type_col: str,
) -> pd.DataFrame:
    tmp = df[[subject_col, ts_col, event_type_col]].dropna().copy()
    tmp[event_type_col] = tmp[event_type_col].astype(str)
    tmp = tmp.sort_values([subject_col, ts_col])
    tmp["_prev_type"] = tmp.groupby(subject_col)[event_type_col].shift(1)
    trans = tmp.dropna(subset=["_prev_type"]).groupby(["_prev_type", event_type_col]).size().rename("n").reset_index()
    totals = trans.groupby("_prev_type")["n"].sum().rename("N").reset_index()
    out = trans.merge(totals, on="_prev_type", how="left")
    out["P(Ej|Ei)"] = out["n"] / out["N"].clip(lower=1)
    out = out.rename(columns={"_prev_type": "Ei", event_type_col: "Ej"})
    return out[["Ei", "Ej", "n", "N", "P(Ej|Ei)"]].sort_values(["Ei", "P(Ej|Ei)"], ascending=[True, False])


def compute_transition_suspicion(
    transitions: pd.DataFrame,
    norm_transitions: pd.DataFrame,
) -> pd.DataFrame:
    norm = norm_transitions[["Ei", "Ej", "P(Ej|Ei)"]].rename(columns={"P(Ej|Ei)": "P_norm"})
    out = transitions.merge(norm, on=["Ei", "Ej"], how="left")
    out["P_norm"] = out["P_norm"].fillna(0.0)
    p = out["P_norm"].clip(lower=1e-12, upper=1.0)
    out["Susp(Ei->Ej)"] = (-np.log10(p)).astype(float)
    return out.sort_values(["Susp(Ei->Ej)", "n"], ascending=[False, False])


def compute_chain_score(
    df: pd.DataFrame,
    subject_col: str,
    ts_col: str,
    delta_t_seconds: int = 30,
) -> pd.Series:
    tmp = df[[subject_col, ts_col]].dropna().sort_values([subject_col, ts_col]).copy()
    tmp["_dt"] = tmp.groupby(subject_col)[ts_col].diff().dt.total_seconds()
    tmp["_corr"] = (tmp["_dt"].fillna(1e18) <= float(delta_t_seconds)).astype(int)
    return tmp.groupby(subject_col)["_corr"].sum().sort_values(ascending=False)


def compute_event_utility(
    df: pd.DataFrame,
    *,
    event_type_col: Optional[str],
    w1: float = 1.0,
    w2: float = 0.02,
    w3: float = 1.0,
) -> pd.Series:
    fields_count = df.notna().sum(axis=1).astype(float)
    if event_type_col is not None and event_type_col in df.columns:
        types = df[event_type_col].astype(str)
        freq = types.value_counts(dropna=False)
        novelty = types.map(lambda x: 1.0 / float(freq.get(x, 1))).astype(float)
    else:
        novelty = pd.Series(0.0, index=df.index)
    alert_flag = df.get("_is_alert", False)
    alert_val = alert_flag.astype(int) if hasattr(alert_flag, "astype") else pd.Series(0, index=df.index)
    utility = (w1 * alert_val) + (w2 * fields_count) + (w3 * novelty)
    return utility


def _rank01(s: pd.Series) -> pd.Series:
    if len(s) == 0:
        return s
    return s.rank(pct=True)


def compute_subject_risk_score(
    df: pd.DataFrame,
    cols: ColumnChoice,
    *,
    burst_window_seconds: int,
    chain_delta_seconds: int = 30,
    top_n: int = 15,
    w_intensity: float = 0.25,
    w_burst: float = 0.35,
    w_chain: float = 0.40,
) -> pd.DataFrame:
    intensity = compute_intensity(df, cols.subject_col).astype(float)
    burst = compute_burst_max(df, cols.subject_col, cols.timestamp_col, window_seconds=burst_window_seconds).astype(float)
    chain = compute_chain_score(df, cols.subject_col, cols.timestamp_col, delta_t_seconds=chain_delta_seconds).astype(float)
    subjects = intensity.index.union(burst.index).union(chain.index)
    intensity = intensity.reindex(subjects).fillna(0.0)
    burst = burst.reindex(subjects).fillna(0.0)
    chain = chain.reindex(subjects).fillna(0.0)
    n_int = _rank01(intensity)
    n_burst = _rank01(burst)
    n_chain = _rank01(chain)
    score = (w_intensity * n_int) + (w_burst * n_burst) + (w_chain * n_chain)
    out = pd.DataFrame(
        {
            "events": intensity.astype(int),
            f"burst_rate_max_per_s_{burst_window_seconds}s": burst.astype(float),
            f"chain_score_dt_{chain_delta_seconds}s": chain.astype(float),
            "attacker_score": score.astype(float),
        }
    )
    return out.sort_values("attacker_score", ascending=False).head(int(top_n))


def explain_subject_behavior(
    row: pd.Series,
    *,
    burst_col: str,
    chain_col: str,
) -> str:
    parts = []
    parts.append(f"events={int(row.get('events', 0))}")
    parts.append(f"burst={float(row.get(burst_col, 0.0)):.2f} ev/s")
    parts.append(f"chain={float(row.get(chain_col, 0.0)):.0f}")
    cues = []
    if float(row.get(burst_col, 0.0)) >= 2.0:
        cues.append("быстрый всплеск")
    if float(row.get(chain_col, 0.0)) >= 200:
        cues.append("плотная сессия действий")
    if cues:
        parts.append("signals=" + ", ".join(cues))
    return "; ".join(parts)


def compute_intensity(df: pd.DataFrame, subject_col: str) -> pd.Series:
    return df.groupby(subject_col).size().sort_values(ascending=False)


def compute_burst_max(
    df: pd.DataFrame,
    subject_col: str,
    ts_col: str,
    window_seconds: int = DEFAULT_BURST_WINDOW_SECONDS,
) -> pd.Series:
    tmp = df[[subject_col, ts_col]].copy()
    tmp["_sec"] = tmp[ts_col].dt.floor("s")
    per_sec = tmp.groupby([subject_col, "_sec"]).size().rename("cnt").reset_index()
    def _roll_max(s: pd.Series) -> float:
        rolled = s.rolling(f"{int(window_seconds)}s").sum()
        return float((rolled / float(window_seconds)).max()) if len(rolled) else 0.0
    out = {}
    for subj, subdf in per_sec.groupby(subject_col):
        s = subdf.set_index("_sec")["cnt"].sort_index()
        out[subj] = _roll_max(s)
    return pd.Series(out).sort_values(ascending=False)


def subject_metrics_table(
    df: pd.DataFrame,
    cols: ColumnChoice,
    top_n: int = 10,
    burst_window_seconds: int = DEFAULT_BURST_WINDOW_SECONDS,
) -> pd.DataFrame:
    intensity = compute_intensity(df, cols.subject_col)
    top_subjects = intensity.head(top_n).index
    burst = compute_burst_max(df[df[cols.subject_col].isin(top_subjects)], cols.subject_col, cols.timestamp_col, burst_window_seconds)
    table = pd.DataFrame(
        {
            "events": intensity.loc[top_subjects].astype(int),
            f"burst_rate_max_per_s_{burst_window_seconds}s": burst.reindex(top_subjects).fillna(0.0).astype(float),
        }
    )
    table = table.sort_values("events", ascending=False)
    return table


def compute_object_touch_count(df: pd.DataFrame, object_col: str) -> pd.Series:
    return df.groupby(object_col).size().sort_values(ascending=False)


def object_metrics_table(df: pd.DataFrame, cols: ColumnChoice, top_n: int = 10) -> pd.DataFrame:
    df_obj = df[df[cols.object_col].notna()].copy()
    df_obj = df_obj[df_obj[cols.object_col].astype(str).str.lower() != "nan"].copy()
    touch = compute_object_touch_count(df_obj, cols.object_col)
    top_objects = touch.head(top_n).index
    if "syscheck.event" in df_obj.columns and df_obj["syscheck.event"].notna().any():
        event_type_col = "syscheck.event"
    else:
        event_type_col = pick_event_type_column(df_obj)
    sub = df_obj[df_obj[cols.object_col].isin(top_objects)].copy()
    if event_type_col is not None:
        diversity = sub.groupby(cols.object_col)[event_type_col].nunique(dropna=True)
    else:
        diversity = sub.groupby(cols.object_col).size() * 0 + 1
    table = pd.DataFrame(
        {
            "events": touch.loc[top_objects].astype(int),
            "event_type_diversity": diversity.reindex(top_objects).fillna(0).astype(int),
        }
    ).sort_values("events", ascending=False)
    return table


def top_objects_for_subject(
    df: pd.DataFrame,
    cols: ColumnChoice,
    subject: str,
    top_n: int = 10,
) -> pd.DataFrame:
    sub = df[df[cols.subject_col] == subject]
    g = sub.groupby(cols.object_col)
    out = pd.DataFrame(
        {
            "events": g.size().astype(int),
        }
    ).sort_values("events", ascending=False)
    return out.head(top_n)


def expand_subject_object_pairs(
    df: pd.DataFrame,
    ts_col: str,
    subject_cols: list[str],
    object_cols: list[str],
) -> pd.DataFrame:
    rows: list[dict] = []
    for _, row in df.iterrows():
        subjects = []
        for c in subject_cols:
            v = _valid_value(row.get(c))
            if v is not None:
                subjects.append(v)
        objects = []
        for c in object_cols:
            v = _valid_value(row.get(c))
            if v is not None:
                objects.append(v)
        if not subjects or not objects:
            continue
        base = row.to_dict()
        for s in subjects:
            for o in objects:
                rec = dict(base)
                rec["__subject"] = s
                rec["__object"] = o
                rows.append(rec)
    if not rows:
        return pd.DataFrame(columns=list(df.columns) + ["__subject", "__object"])
    return pd.DataFrame(rows)


def _collect_values(row: pd.Series, cols: list[str]) -> list[str]:
    out = []
    for c in cols:
        v = _valid_value(row.get(c))
        if v is not None:
            out.append(v)
    return out


def _first_value(row: pd.Series, cols: list[str]) -> Optional[str]:
    for c in cols:
        v = _valid_value(row.get(c))
        if v is not None:
            return v
    return None


def extract_entity_values(row: pd.Series) -> dict:
    values = {}
    for key, cols in ENTITY_KEY_COLUMNS.items():
        v = _first_value(row, cols)
        if v is not None:
            values[key] = v
    return values


def entity_similarity(a: dict, b: dict) -> float:
    score = 0.0
    total = 0.0
    for key, w in ENTITY_WEIGHTS.items():
        va = a.get(key)
        vb = b.get(key)
        if va is None or vb is None:
            continue
        total += float(w)
        if va == vb:
            score += float(w)
    if total == 0.0:
        return 0.0
    return score / total


def time_kernel(dt_seconds: float, tau_seconds: float) -> float:
    if dt_seconds < 0:
        return 0.0
    dt_eff = max(float(dt_seconds), float(DEFAULT_LINK_DT_EPS_SECONDS))
    return float(np.exp(-dt_eff / float(tau_seconds)))


def link_weight(
    dt_seconds: float,
    ent_sim: float,
    *,
    tau_seconds: float,
) -> float:
    return time_kernel(dt_seconds, tau_seconds) * ent_sim


def build_event_graph_edges(
    df: pd.DataFrame,
    *,
    ts_col: str,
    id_col: Optional[str],
    subject_col: Optional[str],
    subject_cols: list[str],
    object_cols: list[str],
    severity_threshold: int,
    tau_seconds: int,
    dt_max_seconds: int,
    ent_threshold: float,
    top_n: int,
) -> pd.DataFrame:
    work = df.copy()
    work[ts_col] = _parse_ts_series(work[ts_col])
    work = work[work[ts_col].notna()].copy()
    if "rule.level" in work.columns:
        levels = pd.to_numeric(work["rule.level"], errors="coerce").fillna(0).astype(int)
        work = work[levels >= int(severity_threshold)].copy()
    if len(work) == 0:
        return pd.DataFrame(columns=["src_id", "dst_id", "c", "dt", "ent", "k_sem"])

    event_type_col = pick_event_type_column(work)
    sem_probs = None
    if event_type_col is not None:
        if subject_col is not None and subject_col in work.columns:
            trans = compute_transition_probs(work, subject_col, ts_col, event_type_col)
        else:
            work = work.copy()
            work["__all_subject"] = "all"
            trans = compute_transition_probs(work, "__all_subject", ts_col, event_type_col)
        sem_probs = {(r["Ei"], r["Ej"]): float(r["P(Ej|Ei)"]) for _, r in trans.iterrows()}

    rows = []
    if subject_col is not None and subject_col in work.columns:
        groups = work.groupby(subject_col)
    else:
        groups = [("all", work)]
    for _, gdf in groups:
        gdf = gdf.sort_values(ts_col)
        ent_vals = [extract_entity_values(r) for _, r in gdf.iterrows()]
        rows_list = [r for _, r in gdf.iterrows()]
        for i, row_i in enumerate(rows_list):
            ts_i = row_i[ts_col]
            ent_i = ent_vals[i]
            type_i = str(row_i.get(event_type_col)) if event_type_col else None
            for j in range(i + 1, len(rows_list)):
                row_j = rows_list[j]
                ts_j = row_j[ts_col]
                dt = (ts_j - ts_i).total_seconds()
                if dt <= 0:
                    continue
                if dt > float(dt_max_seconds):
                    break
                ent_sim = entity_similarity(ent_i, ent_vals[j])
                if ent_sim < float(ent_threshold):
                    continue
                k_sem = 1.0
                if event_type_col is not None and sem_probs is not None:
                    type_j = str(row_j.get(event_type_col))
                    k_sem = float(sem_probs.get((type_i, type_j), 0.0))
                c_score = link_weight(dt, ent_sim, tau_seconds=tau_seconds) * float(k_sem)
                rows.append(
                    {
                        "src_id": row_i.get(id_col) if id_col else None,
                        "dst_id": row_j.get(id_col) if id_col else None,
                        "c": c_score,
                        "dt": dt,
                        "ent": ent_sim,
                        "k_sem": k_sem,
                    }
                )
    out = pd.DataFrame(rows)
    if len(out) == 0:
        return out
    return out.sort_values("c", ascending=False).head(int(top_n))


def build_host_chains(
    df: pd.DataFrame,
    *,
    ts_col: str,
    id_col: Optional[str],
    host_col: str,
    subject_cols: list[str],
    object_cols: list[str],
    severity_threshold: int,
    max_gap_seconds: int,
    max_events: int,
    top_n: int,
    tau_seconds: int,
    dt_max_seconds: int,
    ent_threshold: float,
) -> list[dict]:
    work = df.copy()
    work[ts_col] = _parse_ts_series(work[ts_col])
    work = work[work[ts_col].notna()].copy()
    if "rule.level" in work.columns:
        levels = pd.to_numeric(work["rule.level"], errors="coerce").fillna(0).astype(int)
        work = work[levels >= int(severity_threshold)].copy()
    if len(work) == 0:
        return []

    desc_col = choose_description_column(work)
    event_type_col = pick_event_type_column(work)
    sem_probs = None
    if event_type_col is not None:
        trans = compute_transition_probs(work, host_col, ts_col, event_type_col)
        sem_probs = {(r["Ei"], r["Ej"]): float(r["P(Ej|Ei)"]) for _, r in trans.iterrows()}

    chains: list[dict] = []
    for host, hdf in work.groupby(host_col):
        hdf = hdf.sort_values(ts_col)
        rows = [r for _, r in hdf.iterrows()]
        if not rows:
            continue
        ent_vals = [extract_entity_values(r) for r in rows]
        events = []
        for r in rows:
            events.append(
                {
                    "ts": r[ts_col],
                    "id": r.get(id_col) if id_col else None,
                    "subjects": _collect_values(r, subject_cols),
                    "objects": _collect_values(r, object_cols),
                    "desc": _valid_value(r.get(desc_col)) if desc_col else None,
                    "event_type": str(r.get(event_type_col)) if event_type_col else None,
                }
            )
        next_idx = [-1] * len(events)
        next_w = [0.0] * len(events)
        for i in range(len(events)):
            ts_i = events[i]["ts"]
            best_j = -1
            best_w = 0.0
            for j in range(i + 1, len(events)):
                ts_j = events[j]["ts"]
                dt = (ts_j - ts_i).total_seconds()
                if dt <= 0:
                    continue
                if dt > float(dt_max_seconds):
                    break
                ent_sim = entity_similarity(ent_vals[i], ent_vals[j])
                if ent_sim < float(ent_threshold):
                    continue
                k_sem = 1.0
                if event_type_col is not None and sem_probs is not None:
                    type_i = events[i]["event_type"]
                    type_j = events[j]["event_type"]
                    if type_i is not None and type_j is not None:
                        k_sem = float(sem_probs.get((type_i, type_j), 0.0))
                w = link_weight(dt, ent_sim, tau_seconds=tau_seconds) * k_sem
                if w > best_w:
                    best_w = w
                    best_j = j
            if best_j != -1:
                next_idx[i] = best_j
                next_w[i] = best_w
        used = set()
        for i in range(len(events)):
            if i in used:
                continue
            chain = []
            score = 1.0
            k_sem_vals = []
            cur = i
            last_ts = None
            while cur != -1 and cur not in used and len(chain) < int(max_events):
                ev = events[cur]
                if last_ts is not None:
                    gap = (ev["ts"] - last_ts).total_seconds()
                    if gap > float(max_gap_seconds):
                        break
                chain.append(ev)
                used.add(cur)
                if next_idx[cur] == -1:
                    break
                score *= max(next_w[cur], 1e-9)
                if event_type_col is not None and sem_probs is not None:
                    nxt = next_idx[cur]
                    if nxt != -1:
                        t_i = events[cur]["event_type"]
                        t_j = events[nxt]["event_type"]
                        if t_i is not None and t_j is not None:
                            k_sem_vals.append(float(sem_probs.get((t_i, t_j), 0.0)))
                last_ts = ev["ts"]
                cur = next_idx[cur]
            if len(chain) >= 2:
                conformance = float(np.mean(k_sem_vals)) if k_sem_vals else 0.0
                chains.append(
                    {
                        "host": host,
                        "start": chain[0]["ts"],
                        "end": chain[-1]["ts"],
                        "events": chain,
                        "score": score,
                        "conformance": conformance,
                    }
                )
    chains = sorted(chains, key=lambda c: (len(c["events"]), c.get("score", 0.0)), reverse=True)
    return chains[: int(top_n)]


def subject_object_links(
    df: pd.DataFrame,
    cols: ColumnChoice,
    *,
    severity_threshold: int,
    top_n: int = 25,
) -> pd.DataFrame:
    if "rule.level" in df.columns:
        levels = pd.to_numeric(df["rule.level"], errors="coerce").fillna(0).astype(int)
        df = df[levels >= int(severity_threshold)].copy()
    if len(df) == 0:
        return pd.DataFrame(columns=["subject", "object", "events", "first_ts", "last_ts"])
    base = df[[cols.subject_col, cols.object_col, cols.timestamp_col]].dropna().copy()
    g = base.groupby([cols.subject_col, cols.object_col])
    out = g.size().rename("events").reset_index()
    out["first_ts"] = g[cols.timestamp_col].min().values
    out["last_ts"] = g[cols.timestamp_col].max().values
    out = out.rename(columns={cols.subject_col: "subject", cols.object_col: "object"})
    return out.sort_values(["events"], ascending=[False]).head(int(top_n))


def objects_shared_by_subjects(
    df: pd.DataFrame,
    cols: ColumnChoice,
    *,
    severity_threshold: int,
    top_n: int = 15,
) -> pd.DataFrame:
    if "rule.level" in df.columns:
        levels = pd.to_numeric(df["rule.level"], errors="coerce").fillna(0).astype(int)
        df = df[levels >= int(severity_threshold)].copy()
    base = df[[cols.subject_col, cols.object_col]].dropna().copy()
    if len(base) == 0:
        return pd.DataFrame(columns=["object", "subjects", "events"])
    g = base.groupby(cols.object_col)
    out = pd.DataFrame(
        {
            "subjects": g[cols.subject_col].nunique(dropna=True),
            "events": g.size(),
        }
    ).sort_values(["subjects", "events"], ascending=[False, False])
    out = out.reset_index().rename(columns={cols.object_col: "object"})
    return out.head(int(top_n))
