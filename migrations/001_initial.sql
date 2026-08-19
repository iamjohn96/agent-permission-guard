CREATE TABLE IF NOT EXISTS tool_calls (
  id TEXT PRIMARY KEY,
  server_id TEXT NOT NULL,
  tool_name TEXT NOT NULL,
  arguments_json TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  base_decision TEXT NOT NULL CHECK (base_decision IN ('allow', 'ask', 'deny')),
  effective_decision TEXT NOT NULL CHECK (effective_decision IN ('allow', 'ask', 'deny')),
  matched_rule_id TEXT,
  reason_codes_json TEXT NOT NULL,
  risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
  risk_band TEXT NOT NULL CHECK (risk_band IN ('low', 'medium', 'high', 'critical')),
  risk_signals_json TEXT NOT NULL,
  status TEXT NOT NULL,
  started_at TEXT NOT NULL,
  completed_at TEXT,
  latency_ms INTEGER,
  result_summary_json TEXT,
  error_code TEXT
);

CREATE INDEX IF NOT EXISTS tool_calls_started_at_idx ON tool_calls(started_at DESC);
CREATE INDEX IF NOT EXISTS tool_calls_tool_name_idx ON tool_calls(tool_name);

CREATE TABLE IF NOT EXISTS audit_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,
  tool_call_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  event_json TEXT NOT NULL,
  previous_hash TEXT NOT NULL,
  event_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  FOREIGN KEY (tool_call_id) REFERENCES tool_calls(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS audit_events_tool_call_idx ON audit_events(tool_call_id, sequence);
