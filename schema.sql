CREATE SEQUENCE IF NOT EXISTS seq_commit_id START 1;

CREATE TABLE IF NOT EXISTS kev_catalog (
    cve_id VARCHAR PRIMARY KEY,
    vendor_project VARCHAR,
    product VARCHAR,
    vulnerability_name VARCHAR,
    date_added VARCHAR,
    short_description VARCHAR,
    required_action VARCHAR,
    due_date VARCHAR,
    known_ransomware VARCHAR,
    notes VARCHAR,
    cwes_json VARCHAR,
    epss_score DOUBLE,
    epss_percentile DOUBLE,
    content_hash VARCHAR,
    first_observed_utc VARCHAR,
    last_updated_utc VARCHAR
);

CREATE TABLE IF NOT EXISTS ledger (
    commit_id BIGINT PRIMARY KEY,
    timestamp_utc VARCHAR,
    operation VARCHAR,
    cve_id VARCHAR,
    epss_score DOUBLE,
    detail VARCHAR
);
