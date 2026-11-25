# Knowledge Graph Data Sources & Provenance

This document records the canonical data sources, pinned versions, SHA-256 verification checksums, and ingestion methodology for the **Secure GraphRAG Knowledge Intelligence System**.

---

## 1. Official MITRE ATT&CK® Enterprise STIX 2.1 Bundle

| Field | Value |
| :--- | :--- |
| **Source Repository** | `mitre-attack/attack-stix-data` (GitHub) |
| **Pinned Version** | `20.1` (`2026-11-05T15:11:27.678Z`) |
| **Bundle URL** | `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-20.1.json` |
| **Bundle SHA-256** | `539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5` |
| **Compiled Graph Artifact** | `backend/app/graph/attack_enterprise_v20_1.json.gz` (5.47 MB) |
| **Active Graph Entities** | **1,827** (`ThreatActor`, `Malware`, `Tool`, `Technique`, `Mitigation`, `Campaign`) |
| **Directed STIX Relationships** | **20,957** (`USES`, `MITIGATES`, `SUBTECHNIQUE_OF`, `ATTRIBUTED_TO`) |
| **Provenance Evidence Records** | **22,299** (indexed directly from `external_references` & STIX relationship citations) |

---

## 2. Ingestion & Verification Pipeline (`scripts/ingest_attack.py`)

All graph data enters through a single reproducible pipeline:
```bash
# Download (cached in data/stix_cache/), verify SHA-256, and compile graph:
python scripts/ingest_attack.py

# Batch-ingest into Neo4j with full-text search & property indexes:
python scripts/ingest_attack.py --neo4j
```

**Data Integrity Controls:**
- **Revoked & Deprecated Exclusion**: Objects marked `revoked: true` or `x_mitre_deprecated: true` in the STIX 2.1 bundle are strictly omitted.
- **Provenance Linking**: Every node carries its canonical ATT&CK external ID (e.g., `G0007`, `S0154`, `T1055`, `M1049`) and MITRE URL; every edge carries its STIX relationship ID (`source_id`) linked to a primary evidence record.
- **Test Fixture Isolation**: Synthetic test fixtures (`PHANTOM DRAGON`, `CRIMSON WOLF`) are strictly isolated to `ENVIRONMENT=testing` or `INCLUDE_TEST_FIXTURE=true` smoke runs and never contaminate production graphs.

---

## 3. MITRE ATT&CK® Terms of Use

> MITRE ATT&CK® and ATT&CK® are registered trademarks of The MITRE Corporation. Data sourced from `mitre-attack/attack-stix-data` is distributed under the Apache License 2.0 / MITRE ATT&CK Terms of Use.
