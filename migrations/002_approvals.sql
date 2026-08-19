CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY,
  tool_call_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'expired', 'cancelled')),
  requested_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  decided_at TEXT,
  FOREIGN KEY (tool_call_id) REFERENCES tool_calls(id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_approvals_tool_call_id
ON approvals(tool_call_id);

CREATE INDEX IF NOT EXISTS idx_approvals_pending_expires_at
ON approvals(expires_at)
WHERE status = 'pending';
