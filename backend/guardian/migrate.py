import os
from pathlib import Path

import psycopg


def migrate(database_url: str) -> None:
    schema = Path(__file__).with_name("schema.sql").read_text(encoding="utf-8")
    with psycopg.connect(database_url, connect_timeout=5) as connection:
        connection.execute("SELECT pg_advisory_xact_lock(75316804)")
        connection.execute(schema)


def purge_expired(database_url: str) -> tuple[int, int]:
    with psycopg.connect(database_url, connect_timeout=5) as connection:
        scans = connection.execute("DELETE FROM guardian_scans WHERE expires_at <= now()")
        sessions = connection.execute("DELETE FROM guardian_sessions WHERE expires_at <= now()")
        connection.execute("DELETE FROM guardian_auth_limits WHERE window_start < now() - interval '1 hour'")
        return scans.rowcount, sessions.rowcount


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("migrate", "purge"))
    arguments = parser.parse_args()
    url = os.environ["GUARDIAN_DATABASE_URL"]
    if arguments.command == "migrate":
        migrate(url)
    else:
        scans, sessions = purge_expired(url)
        print(f"Deleted {scans} expired scans and {sessions} expired sessions.")
