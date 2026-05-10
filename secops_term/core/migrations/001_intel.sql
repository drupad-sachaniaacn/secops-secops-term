-- 001_intel.sql — IOC corpus + retro-hunt jobs (brief v3 §6.1)
--
-- Tables created here are the persistent home of the threat-intel pipeline:
--   iocs              one row per (type, value) pair, dedup-keyed.
--   ioc_sources       one row per provider observation (many per IOC).
--   retro_hunt_jobs   queue/log of Chronicle/V1 retro hunts (Phase 2 wires the worker).
--
-- All timestamps are ISO-8601 UTC strings ("YYYY-MM-DDTHH:MM:SS.ffffffZ").
-- `tags` is a JSON-encoded array of strings.
-- `confidence` is 0–100 (provider-reported or computed) or NULL.

CREATE TABLE iocs (
    id INTEGER PRIMARY KEY,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    confidence INTEGER,
    tags TEXT,
    UNIQUE(type, value)
);

CREATE INDEX idx_iocs_type ON iocs(type);
CREATE INDEX idx_iocs_last_seen ON iocs(last_seen);

CREATE TABLE ioc_sources (
    ioc_id INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    source_ref TEXT,
    context TEXT,
    fetched_at TEXT NOT NULL
);

CREATE INDEX idx_ioc_sources_ioc_id ON ioc_sources(ioc_id);
CREATE INDEX idx_ioc_sources_source ON ioc_sources(source);

CREATE TABLE retro_hunt_jobs (
    id INTEGER PRIMARY KEY,
    ioc_id INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    platform TEXT NOT NULL,
    status TEXT NOT NULL,
    query TEXT,
    hits INTEGER,
    created_at TEXT NOT NULL,
    completed_at TEXT,
    error TEXT
);

CREATE INDEX idx_retro_hunt_jobs_status ON retro_hunt_jobs(status);
CREATE INDEX idx_retro_hunt_jobs_ioc_id ON retro_hunt_jobs(ioc_id);
