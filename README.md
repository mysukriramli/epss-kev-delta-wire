# 🎯 EPSS & CISA KEV Delta Wire

An autonomous, zero-maintenance vulnerability weaponization wire running entirely on GitHub Actions. It joins CISA Known Exploited Vulnerabilities (KEV) with FIRST.org EPSS scores to detect and record exploitation probability surges.

## Data Feeds for Agents
Optimized for automated red teams, patch-prioritization bots, and triage agents.

- [`v1/high-risk-exploited.json`](public/v1/high-risk-exploited.json)
- [`v1/recent-cisa-kev.json`](public/v1/recent-cisa-kev.json)
- [`llms.txt`](public/llms.txt)
- `epss_kev.parquet` (Columnar database snapshot)

## Architecture
- **Upstream Sources**: CISA KEV JSON + FIRST.org EPSS REST API
- **Engine**: DuckDB + Parquet
- **Storage**: Append-only Git-committed JSONL ledger in `/data/history`
- **Edge CDN**: GitHub Pages (Fastly CDN)
