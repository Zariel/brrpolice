#!/usr/bin/env python3
"""Check operator-facing ownership constraints through Helm's public interface."""

import subprocess
from pathlib import Path

chart = Path(__file__).resolve().parents[1] / "charts/brrpolice"
base = [
    "helm",
    "template",
    "brrpolice",
    str(chart),
    "--set",
    "config.qbittorrent.base_url=http://qbittorrent",
]
cases = [
    ("multiple writers", ["replicaCount=2"], "replicaCount"),
    (
        "discarding an existing claim",
        ["persistence.enabled=false", "persistence.existingClaim=keep"],
        "enabled",
    ),
    (
        "database outside the data volume",
        ["config.database.path=/tmp/history.sqlite"],
        "path",
    ),
    (
        "non-string Grafana instance selector labels",
        [
            "monitoring.dashboards.grafanaOperator.matchLabels.dashboards=1",
        ],
        "matchLabels",
    ),
    (
        "non-string dashboard labels",
        ["monitoring.dashboards.labels.grafana_dashboard=1"],
        "grafana_dashboard",
    ),
]
for name, values, field in cases:
    args = [*base]
    for value in values:
        args.extend(["--set", value])
    rendered = subprocess.run(args, text=True, capture_output=True, check=False)
    assert rendered.returncode != 0 and field in rendered.stderr, (
        name,
        rendered.stdout,
        rendered.stderr,
    )
    print(f"Rejected {name}")
