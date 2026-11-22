"""
CLI entrypoint to seed a fresh Neo4j database with canonical threat intelligence STIX entities.
Usage:
    python backend/scripts/seed_neo4j.py
or inside Docker:
    docker compose exec backend python scripts/seed_neo4j.py
"""
import sys
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.graph.seed import main

if __name__ == "__main__":
    main()
