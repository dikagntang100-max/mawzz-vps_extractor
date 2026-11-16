CREATE TABLE IF NOT EXISTS connection_history (
  id BIGSERIAL PRIMARY KEY,
  ip_address INET NOT NULL,
  username TEXT NOT NULL,
  hostname TEXT,
  os_info TEXT,
  status TEXT NOT NULL CHECK (status IN ('success', 'failed')),
  error_message TEXT,
  connected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  disconnected_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE connection_history ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Service role full access"
  ON connection_history FOR ALL TO service_role
  USING (true) WITH CHECK (true);

CREATE POLICY "Deny anon access"
  ON connection_history FOR ALL TO anon
  USING (false);
