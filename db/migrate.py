"""
Aplica las migraciones de db/migrations en orden y registra las aplicadas en schema_migrations.
Uso (desde la raíz del repo):
    .venv/bin/python db/migrate.py            # aplica las pendientes
    .venv/bin/python db/migrate.py --force 001_init.sql   # re-aplica una (son idempotentes)
"""
import sys
from pathlib import Path

import psycopg
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
MIGRATIONS = ROOT / "db" / "migrations"

load_dotenv(ROOT / ".env")


def main():
    force = set(sys.argv[sys.argv.index("--force") + 1:]) if "--force" in sys.argv else set()
    with psycopg.connect(sslmode="require", connect_timeout=15) as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS schema_migrations (
                   version    text PRIMARY KEY,
                   applied_at timestamptz NOT NULL DEFAULT now())"""
        )
        conn.commit()
        applied = {r[0] for r in conn.execute("SELECT version FROM schema_migrations")}

        for path in sorted(MIGRATIONS.glob("*.sql")):
            if path.name in applied and path.name not in force:
                print(f"[--]    {path.name} ya aplicada")
                continue
            with conn.transaction():
                conn.execute(path.read_text(encoding="utf-8"))
                conn.execute(
                    """INSERT INTO schema_migrations (version) VALUES (%s)
                       ON CONFLICT (version) DO UPDATE SET applied_at = now()""",
                    (path.name,),
                )
            print(f"[OK]    {path.name} aplicada")


if __name__ == "__main__":
    main()
