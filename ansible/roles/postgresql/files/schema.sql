-- Argus — schéma de base de données
-- Idempotent : peut être rejoué sur une instance existante.

CREATE TABLE IF NOT EXISTS scans (
    id          SERIAL PRIMARY KEY,
    tool        VARCHAR(32)  NOT NULL,   -- 'zap', 'nikto', 'nmap', 'testssl', 'nuclei', 'wpscan', 'trivy'
    target      VARCHAR(128) NOT NULL,   -- nom du site (websites.yml)
    target_url  TEXT         NOT NULL,
    started_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMPTZ,
    status      VARCHAR(16)  NOT NULL DEFAULT 'running', -- running|completed|failed
    raw_output  JSONB                                     -- sortie brute de l'outil
);

-- Causes racines détectées par l'agent IA (un cluster de findings = une cause)
CREATE TABLE IF NOT EXISTS root_causes (
    id            SERIAL PRIMARY KEY,
    target        VARCHAR(128) NOT NULL,
    summary       TEXT         NOT NULL,
    severity      VARCHAR(16)  NOT NULL,   -- CRITICAL|HIGH|MEDIUM|LOW|INFO
    suggested_fix TEXT,
    finding_count INT          NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS findings (
    id                   SERIAL PRIMARY KEY,
    scan_id              INT          REFERENCES scans(id) ON DELETE CASCADE,
    severity             VARCHAR(16)  NOT NULL,  -- CRITICAL|HIGH|MEDIUM|LOW|INFO (raw, scanner)
    title                VARCHAR(256) NOT NULL,
    description          TEXT,
    url                  TEXT,
    cvss_score           NUMERIC(3,1),
    cve_ids              TEXT[],
    remediation          TEXT,
    notified_at          TIMESTAMPTZ,            -- NULL = pas encore notifié

    -- Enrichissement par l'agent IA (NULL tant que pas triagé)
    ai_severity          VARCHAR(16),            -- sévérité réajustée selon contexte
    ai_is_false_positive BOOLEAN     DEFAULT FALSE,
    ai_remediation       TEXT,                   -- fix généré (diff, commande, config)
    ai_root_cause_id     INT REFERENCES root_causes(id) ON DELETE SET NULL,
    ai_dedup_of          INT REFERENCES findings(id) ON DELETE SET NULL,
    ai_confidence        NUMERIC(3,2),           -- 0.00 → 1.00
    ai_triaged_at        TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS reports (
    id           SERIAL PRIMARY KEY,
    generated_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    report_type  VARCHAR(16)  NOT NULL,  -- 'daily' | 'weekly' | 'on-demand'
    target       VARCHAR(128),           -- NULL = rapport global tous sites
    html_path    TEXT,
    pdf_path     TEXT
);

-- Audit log des appels LLM (coût, débogage, circuit breaker budget)
CREATE TABLE IF NOT EXISTS agent_runs (
    id            SERIAL PRIMARY KEY,
    run_type      VARCHAR(32)  NOT NULL,        -- 'triage' | 'remediate' | 'chat' | 'orchestrate'
    scan_id       INT REFERENCES scans(id) ON DELETE SET NULL,
    target        VARCHAR(128),
    provider      VARCHAR(32)  NOT NULL,        -- 'anthropic' | 'openai' | 'google' | 'ollama'
    model         VARCHAR(64)  NOT NULL,
    input_tokens  INT          NOT NULL DEFAULT 0,
    output_tokens INT          NOT NULL DEFAULT 0,
    cost_usd      NUMERIC(10,6) NOT NULL DEFAULT 0,
    duration_ms   INT,
    status        VARCHAR(16)  NOT NULL,        -- 'success' | 'failed' | 'budget_exceeded'
    error         TEXT,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Migrations idempotentes pour les instances existantes
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_severity          VARCHAR(16);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_is_false_positive BOOLEAN DEFAULT FALSE;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_remediation       TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_root_cause_id     INT REFERENCES root_causes(id) ON DELETE SET NULL;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_dedup_of          INT REFERENCES findings(id) ON DELETE SET NULL;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_confidence        NUMERIC(3,2);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_triaged_at        TIMESTAMPTZ;

-- Index pour les requêtes fréquentes
CREATE INDEX IF NOT EXISTS idx_findings_severity      ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_notified      ON findings(notified_at) WHERE notified_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_findings_ai_triaged    ON findings(ai_triaged_at);
CREATE INDEX IF NOT EXISTS idx_findings_real_issues   ON findings(scan_id, ai_severity)
    WHERE ai_is_false_positive = FALSE AND ai_dedup_of IS NULL;
CREATE INDEX IF NOT EXISTS idx_scans_target_tool      ON scans(target, tool, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_status           ON scans(status) WHERE status = 'running';
CREATE INDEX IF NOT EXISTS idx_root_causes_target     ON root_causes(target, severity);
CREATE INDEX IF NOT EXISTS idx_agent_runs_created     ON agent_runs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_runs_cost_today  ON agent_runs(created_at)
    WHERE status = 'success';
