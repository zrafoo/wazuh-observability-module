# Data Exporter (OpenSearch -> Postgres -> Event Graph)

This module pulls security events from OpenSearch, stores them in Postgres,
cleans/normalizes the dataset, computes related-event links, and serves a
web UI that visualizes event chains as a graph.

## What it does

- Export raw Wazuh/OpenSearch alerts to Postgres (JSONB).
- Clean and deduplicate events into a separate table.
- Build event links (predecessor/target/successor) with probabilities.
- Serve a FastAPI UI for interactive graph visualization.

## Project flow

1) `getData.py` -> fetches events from OpenSearch into Postgres.
2) `clearData.py` -> produces a cleaned table.
3) `event.py` -> builds event links into `event_links`.
4) `graphics.py` -> serves the graph UI.

The container entrypoint runs `src/main.py`, which executes the steps above.

## Quick start

```bash
docker compose up -d --build --force-recreate
```

Open the UI at: `http://localhost:3000`

## Environment variables (docker-compose)

Key settings are configured in `docker-compose.yml`, including:

- Postgres connection (`POSTGRES_*`)
- OpenSearch connection (`OPENSEARCH_*`)
- Export range (`EXPORT_DAYS_FROM_OPENSEARCH`)
- Link threshold (`MIN_TRANSITION_THETA`)
- Link scoring weights and scales (`LINK_WEIGHT_*`, `LINK_TIME_SCALE_SECONDS`, `LINK_DT_MAX_SECONDS`, `LINK_OBJECT_SIM_EPS`)
- UI options (`SHOW_DECISION_METRICS`)

See `docker-compose.yml` for the full list.
