import os
import json
import hashlib
import duckdb
import requests
from datetime import datetime, timezone

DB_FILE = "data/epss_kev.db"
HISTORY_DIR = "data/history"
EXPORT_DIR = "public"
API_DIR = os.path.join(EXPORT_DIR, "v1")

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"

def compute_hash(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()

def fetch_cisa_kev():
    headers = {"User-Agent": "EPSS-KEV-Delta-Wire/1.0 (Machine-First Autonomous Knowledge Wire)"}
    resp = requests.get(CISA_KEV_URL, headers=headers, timeout=30)
    if resp.status_code != 200:
        return []
    data = resp.json()
    return data.get("vulnerabilities", [])

def fetch_epss_scores(cve_ids: list) -> dict:
    scores = {}
    chunk_size = 80
    headers = {"User-Agent": "EPSS-KEV-Delta-Wire/1.0"}
    
    for i in range(0, len(cve_ids), chunk_size):
        chunk = cve_ids[i:i + chunk_size]
        cve_param = ",".join(chunk)
        try:
            r = requests.get(f"{EPSS_API_URL}?cve={cve_param}", headers=headers, timeout=20)
            if r.status_code == 200:
                res_json = r.json()
                for item in res_json.get("data", []):
                    cve = item.get("cve")
                    epss = float(item.get("epss", 0.0))
                    pct = float(item.get("percentile", 0.0))
                    scores[cve] = (epss, pct)
        except Exception:
            pass
    return scores

def serialize_row(row: dict) -> dict:
    out = {}
    for k, v in row.items():
        if k == "cwes_json" and isinstance(v, str):
            try:
                out["cwes"] = json.loads(v)
            except Exception:
                out["cwes"] = v
        else:
            out[k] = v
    return out

def build_static_api(conn):
    os.makedirs(API_DIR, exist_ok=True)
    now_iso = datetime.now(timezone.utc).isoformat()
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # 1. Export High Exploitability / Active Threats (EPSS > 0.50 or KEV Ransomware Confirmed)
    cur = conn.execute("""
        SELECT * FROM kev_catalog 
        WHERE epss_score >= 0.50 OR known_ransomware = 'Known'
        ORDER BY epss_score DESC LIMIT 100
    """)
    cols = [desc[0] for desc in cur.description]
    high_risk = [serialize_row(dict(zip(cols, row))) for row in cur.fetchall()]
    
    with open(os.path.join(API_DIR, "high-risk-exploited.json"), "w", encoding="utf-8") as f:
        json.dump({"metadata": {"updated_at": now_iso, "count": len(high_risk)}, "vulnerabilities": high_risk}, f, indent=2)

    # 2. Export Newly Added to CISA KEV (Past 30 Days)
    cur = conn.execute("SELECT * FROM kev_catalog ORDER BY date_added DESC, cve_id DESC LIMIT 100")
    recent_kev = [serialize_row(dict(zip(cols, row))) for row in cur.fetchall()]

    with open(os.path.join(API_DIR, "recent-cisa-kev.json"), "w", encoding="utf-8") as f:
        json.dump({"metadata": {"updated_at": now_iso, "count": len(recent_kev)}, "vulnerabilities": recent_kev}, f, indent=2)

    # 3. LLM Digest (llms.txt)
    lines = [
        "# EPSS-KEV Exploit Surge Wire",
        f"> Last Sync: {now_iso} UTC",
        "> Authoritative Sources: CISA Known Exploited Vulnerabilities + FIRST.org EPSS",
        "",
        "## Top Exploitation Signals (Weaponized & High Likelihood)"
    ]
    for v in high_risk[:25]:
        ransom = " [RANSOMWARE KNOWN]" if v["known_ransomware"] == "Known" else ""
        lines.append(
            f"- **{v['cve_id']}** ({v['vendor_project']} {v['product']}): "
            f"EPSS Probability {v['epss_score']:.2%} (Percentile: {v['epss_percentile']:.1%}){ransom} - {v['vulnerability_name']}"
        )

    with open(os.path.join(EXPORT_DIR, "llms.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    # 4. Minimal Web Dashboard
    html = f"""<!DOCTYPE html><html><head><title>EPSS &amp; CISA KEV Delta Wire</title></head>
    <body style='font-family:system-ui,sans-serif;max-width:850px;margin:2rem auto;line-height:1.6;padding:0 1rem;'>
    <h1>🎯 EPSS &amp; CISA KEV Delta Wire</h1>
    <p>Machine-first temporal wire tracking real-world exploit weaponization and probability surges.</p>
    <h3>Data Feeds</h3>
    <ul>
      <li><a href='v1/high-risk-exploited.json'>/v1/high-risk-exploited.json</a> (EPSS &gt;= 0.50 or Ransomware Active)</li>
      <li><a href='v1/recent-cisa-kev.json'>/v1/recent-cisa-kev.json</a> (Latest CISA Weaponized Catalog)</li>
      <li><a href='llms.txt'>llms.txt</a> (Token-Efficient Agent Digest)</li>
      <li><a href='epss_kev.parquet'>epss_kev.parquet</a> (Full Columnar Database)</li>
    </ul></body></html>"""
    with open(os.path.join(EXPORT_DIR, "index.html"), "w", encoding="utf-8") as f:
        f.write(html)

def run():
    os.makedirs("data", exist_ok=True)
    os.makedirs(HISTORY_DIR, exist_ok=True)
    os.makedirs(EXPORT_DIR, exist_ok=True)

    conn = duckdb.connect(DB_FILE)
    with open("schema.sql", "r", encoding="utf-8") as f:
        conn.execute(f.read())

    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    date_str = now.strftime("%Y-%m-%d")
    year_str = now.strftime("%Y")
    month_str = now.strftime("%m")

    kev_entries = fetch_cisa_kev()
    if not kev_entries:
        conn.close()
        return

    # Sort to examine the most recent additions first
    kev_entries.sort(key=lambda x: x.get("dateAdded", ""), reverse=True)
    sample_pool = kev_entries[:200]
    cve_list = [item.get("cveID") for item in sample_pool if item.get("cveID")]

    epss_map = fetch_epss_scores(cve_list)

    month_dir = os.path.join(HISTORY_DIR, year_str, month_str)
    os.makedirs(month_dir, exist_ok=True)
    daily_history_file = os.path.join(month_dir, f"{date_str}.jsonl")

    conn.execute("BEGIN TRANSACTION")

    for item in sample_pool:
        cve_id = item.get("cveID")
        vendor = item.get("vendorProject", "").replace("'", "''")
        prod = item.get("product", "").replace("'", "''")
        v_name = item.get("vulnerabilityName", "").replace("'", "''")
        date_added = item.get("dateAdded", "")
        desc = item.get("shortDescription", "").replace("'", "''")
        action = item.get("requiredAction", "").replace("'", "''")
        due = item.get("dueDate", "")
        ransom = item.get("knownRansomwareCampaignUse", "Unknown")
        notes = item.get("notes", "").replace("'", "''")
        cwes_json = json.dumps(item.get("cwes", [])).replace("'", "''")

        epss_val, epss_pct = epss_map.get(cve_id, (0.0, 0.0))

        canonical_state = {
            "cve_id": cve_id,
            "date_added": date_added,
            "ransomware": ransom,
            "epss_score": epss_val
        }
        content_hash = compute_hash(canonical_state)

        existing = conn.execute(f"SELECT epss_score, content_hash FROM kev_catalog WHERE cve_id = '{cve_id}'").fetchone()

        if not existing:
            conn.execute(f"""
                INSERT INTO kev_catalog (
                    cve_id, vendor_project, product, vulnerability_name, date_added,
                    short_description, required_action, due_date, known_ransomware, notes,
                    cwes_json, epss_score, epss_percentile, content_hash, first_observed_utc, last_updated_utc
                ) VALUES (
                    '{cve_id}', '{vendor}', '{prod}', '{v_name}', '{date_added}',
                    '{desc}', '{action}', '{due}', '{ransom}', '{notes}',
                    '{cwes_json}', {epss_val}, {epss_pct}, '{content_hash}', '{now_iso}', '{now_iso}'
                )
            """)

            commit_id = conn.execute("SELECT nextval('seq_commit_id')").fetchone()[0]
            conn.execute(f"""
                INSERT INTO ledger (commit_id, timestamp_utc, operation, cve_id, epss_score, detail)
                VALUES ({commit_id}, '{now_iso}', 'KEV_INGESTED', '{cve_id}', {epss_val}, 'Added to CISA KEV')
            """)

            ledger_entry = {
                "commit_id": commit_id,
                "timestamp_utc": now_iso,
                "operation": "KEV_INGESTED",
                "cve_id": cve_id,
                "epss_score": epss_val,
                "known_ransomware": ransom
            }
            with open(daily_history_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(ledger_entry) + "\n")

        elif existing[1] != content_hash:
            old_score = existing[0]
            delta = epss_val - old_score

            conn.execute(f"""
                UPDATE kev_catalog SET
                    known_ransomware = '{ransom}',
                    epss_score = {epss_val},
                    epss_percentile = {epss_pct},
                    content_hash = '{content_hash}',
                    last_updated_utc = '{now_iso}'
                WHERE cve_id = '{cve_id}'
            """)

            commit_id = conn.execute("SELECT nextval('seq_commit_id')").fetchone()[0]
            conn.execute(f"""
                INSERT INTO ledger (commit_id, timestamp_utc, operation, cve_id, epss_score, detail)
                VALUES ({commit_id}, '{now_iso}', 'SCORE_DELTA', '{cve_id}', {epss_val}, 'Delta: {delta:+.4f}')
            """)

            ledger_entry = {
                "commit_id": commit_id,
                "timestamp_utc": now_iso,
                "operation": "SCORE_DELTA",
                "cve_id": cve_id,
                "old_score": old_score,
                "new_score": epss_val,
                "delta": delta
            }
            with open(daily_history_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(ledger_entry) + "\n")

    conn.execute("COMMIT")

    conn.execute(f"COPY (SELECT * FROM kev_catalog) TO '{EXPORT_DIR}/epss_kev.parquet' (FORMAT PARQUET)")
    build_static_api(conn)
    conn.close()

if __name__ == "__main__":
    run()
