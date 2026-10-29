#!/usr/bin/env python3
"""Exercise a populated database upgrade using the rendered chart's storage contract."""

import hashlib
import json
import os
import shlex
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENGINE = shlex.split(os.environ.get("CONTAINER_ENGINE", "docker"))
IMAGE = os.environ.get("TEST_IMAGE", "brrpolice-ci:test")
OFFENCES = 155_000


def command(*args, **kwargs):
    return subprocess.run(
        args, check=True, text=True, capture_output=True, **kwargs
    ).stdout


def fixture(path):
    with sqlite3.connect(path) as db:
        db.execute("""CREATE TABLE _sqlx_migrations (
            version BIGINT PRIMARY KEY, description TEXT NOT NULL,
            installed_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            success BOOLEAN NOT NULL, checksum BLOB NOT NULL,
            execution_time BIGINT NOT NULL)""")
        for migration in sorted((ROOT / "migrations").glob("*.sql"))[:7]:
            sql = migration.read_text()
            version, description = migration.stem.split("_", 1)
            db.executescript(sql)
            db.execute(
                "INSERT INTO _sqlx_migrations(version,description,success,checksum,execution_time) VALUES(?,?,1,?,0)",
                (
                    int(version),
                    description.replace("_", " "),
                    hashlib.sha384(sql.encode()).digest(),
                ),
            )
        db.execute(
            """WITH RECURSIVE seq(n) AS (
            VALUES(1) UNION ALL SELECT n + 1 FROM seq WHERE n < ?
        )
        INSERT INTO peer_offences (
            torrent_hash, peer_ip, peer_port, policy_name, offence_number,
            reason_code, observed_seconds, bad_seconds, progress_delta,
            avg_up_rate_bps, banned_at, ban_expires_at
        )
        SELECT printf('%040x', n), '10.0.0.10', 51413, 'score', 1,
            'score_based', 600, 600, 0, 0,
            '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z'
        FROM seq""",
            (OFFENCES,),
        )
    path.chmod(0o666)


def main():
    rendered = command(
        "helm",
        "template",
        "brrpolice",
        str(ROOT / "charts/brrpolice"),
        "--set",
        "config.qbittorrent.base_url=http://127.0.0.1:1",
        "--set",
        "persistence.existingClaim=fixture",
        "--set",
        "podSecurityContext.runAsUser=568",
        "--set",
        "podSecurityContext.runAsGroup=568",
        "--set",
        "podSecurityContext.fsGroup=568",
        "--set",
        "resources.limits.memory=64Mi",
    )
    resources = [
        json.loads(line)
        for line in command("yq", "-o=json", "-I=0", ".", input=rendered).splitlines()
        if line.strip()
    ]
    deployment = next(r for r in resources if r["kind"] == "Deployment")
    pod = deployment["spec"]["template"]["spec"]
    container = pod["containers"][0]
    config = next(r for r in resources if r["kind"] == "ConfigMap")["data"][
        "config.toml"
    ]
    tmp_mount = next(m for m in container["volumeMounts"] if m["mountPath"] == "/tmp")
    tmp_volume = next(v for v in pod["volumes"] if v["name"] == tmp_mount["name"])
    assert tmp_volume.get("emptyDir") == {}, (
        "SQLite spill files need disk-backed temporary storage"
    )
    assert container["securityContext"]["readOnlyRootFilesystem"]

    with tempfile.TemporaryDirectory(prefix="brrpolice-migration-") as scratch:
        scratch = Path(scratch)
        data, temporary, configuration = (
            scratch / name for name in ["data", "tmp", "config"]
        )
        for directory in [data, temporary, configuration]:
            directory.mkdir(mode=0o777)
            directory.chmod(0o777)
        database = data / "brrpolice.sqlite"
        fixture(database)
        (configuration / "config.toml").write_text(config)
        security = pod["securityContext"]
        args = [
            *ENGINE,
            "run",
            "--read-only",
            "--memory",
            "64m",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--user",
            f"{security['runAsUser']}:{security['runAsGroup']}",
            "--mount",
            f"type=bind,src={data},dst=/data",
            "--mount",
            f"type=bind,src={configuration},dst=/etc/brrpolice,readonly",
        ]
        for entry in container["env"]:
            args.extend(["--env", f"{entry['name']}={entry['value']}"])

        # This control proves the fixture actually spills to disk. A tiny fixture
        # would pass without a writable /tmp and miss the production regression.
        failed = subprocess.run(
            [*args, "--rm", IMAGE, *container["args"]],
            check=False,
            text=True,
            capture_output=True,
            timeout=90,
        )
        assert failed.returncode != 0 and "(code: 6410)" in failed.stderr, (
            failed.stdout + failed.stderr
        )
        with sqlite3.connect(database) as observer:
            assert (
                observer.execute(
                    "SELECT COUNT(*) FROM _sqlx_migrations WHERE version=8"
                ).fetchone()[0]
                == 0
            )
        print("Without /tmp: reproduced SQLITE_IOERR_GETTEMPPATH (6410)", flush=True)

        for attempt in range(2):
            running = command(
                *args,
                "--detach",
                "--mount",
                f"type=bind,src={temporary},dst=/tmp",
                IMAGE,
                *container["args"],
            ).strip()
            try:
                deadline = time.monotonic() + 60
                while True:
                    with sqlite3.connect(database, timeout=1) as observer:
                        complete = observer.execute(
                            "SELECT COUNT(*) FROM _sqlx_migrations WHERE version=8 AND success=1"
                        ).fetchone()[0]
                        metadata = observer.execute(
                            "SELECT schema_version FROM service_meta"
                        ).fetchone()
                        if complete and metadata:
                            assert (
                                observer.execute(
                                    "SELECT COUNT(*) FROM peer_offences"
                                ).fetchone()[0]
                                == OFFENCES
                            )
                            assert metadata[0] == 8
                            break
                    assert time.monotonic() < deadline, command(
                        *ENGINE, "logs", running
                    )
                    state = command(
                        *ENGINE, "inspect", "--format", "{{.State.Running}}", running
                    ).strip()
                    assert state == "true", command(*ENGINE, "logs", running)
                    time.sleep(0.1)
                print(
                    f"With /tmp, start {attempt + 1}: schema 8; {OFFENCES} offences retained",
                    flush=True,
                )
            finally:
                command(*ENGINE, "stop", "--time", "10", running)
                command(*ENGINE, "rm", running)


if __name__ == "__main__":
    main()
