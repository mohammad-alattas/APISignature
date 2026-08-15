-- APISignature index schema.
--
-- Built offline by etl/build_index.py and read at runtime by the C++ plugin.
-- Everything the panel displays is stored pre-rendered as HTML, so the plugin
-- never parses JSON, YAML or Markdown inside x64dbg -- it looks up a row and
-- hands the string to QTextBrowser.

PRAGMA journal_mode = OFF;
PRAGMA synchronous = OFF;

-- Provenance and attribution. Read by the panel's About section; the sdk-api and
-- capa-rules entries carry the licence text we are obliged to reproduce when
-- shipping a prebuilt index.
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- The shared compression dictionary, stored with the data it decodes. Without it
-- the text table is unreadable, so it lives in the same file rather than being
-- compiled into the plugin, where a version skew would silently corrupt output.
CREATE TABLE text_dict (
    id   INTEGER PRIMARY KEY CHECK (id = 1),
    data BLOB NOT NULL
);

-- Interned document text: every distinct HTML fragment exactly once, raw-deflate
-- compressed against text_dict. See etl/textstore.py for why both halves are
-- needed -- interning alone leaves 75 MB, compression alone leaves 55% of 63 MB,
-- and together they reach 16 MB.
CREATE TABLE text (
    id   INTEGER PRIMARY KEY,
    size INTEGER NOT NULL,   -- uncompressed bytes, so the reader allocates once
    data BLOB NOT NULL
);

-- One row per documented API. `name` is the exact spelling; `name_norm` is
-- normalize.canonical(name) and is what a folded lookup matches against.
-- doc_id and return_id reference `text`; a NULL means absent or empty.
CREATE TABLE api (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    name_norm   TEXT NOT NULL,
    dll         TEXT,
    header      TEXT,
    syntax      TEXT,
    doc_id      INTEGER REFERENCES text (id),
    return_id   INTEGER REFERENCES text (id),
    doc_url     TEXT,
    source      TEXT NOT NULL CHECK (source IN ('malapi', 'sdk-api', 'driver-ddi'))
);

CREATE INDEX api_name_norm_idx ON api (name_norm);

-- Parameters in declaration order.
CREATE TABLE api_param (
    api_id  INTEGER NOT NULL REFERENCES api (id),
    ord     INTEGER NOT NULL,
    name    TEXT NOT NULL,
    desc_id INTEGER REFERENCES text (id),
    PRIMARY KEY (api_id, ord)
) WITHOUT ROWID;

-- The malicious-intent layer, present only for the APIs MalAPI covers.
CREATE TABLE malapi (
    api_id      INTEGER PRIMARY KEY REFERENCES api (id),
    description TEXT NOT NULL,
    credits     TEXT,
    created     TEXT,
    last_update TEXT,
    source_url  TEXT
);

CREATE TABLE attack (
    id   INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE api_attack (
    api_id    INTEGER NOT NULL REFERENCES api (id),
    attack_id INTEGER NOT NULL REFERENCES attack (id),
    PRIMARY KEY (api_id, attack_id)
) WITHOUT ROWID;

CREATE INDEX api_attack_attack_idx ON api_attack (attack_id);

-- capa rules, flattened to API-only feature programs. `program` is a compact
-- binary opcode stream evaluated by src/capa_eval.cpp -- deliberately not JSON,
-- so the runtime needs no parser. `match:` references to other rules are
-- resolved transitively at build time.
CREATE TABLE capa_rule (
    id            INTEGER PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE,
    namespace     TEXT,
    description   TEXT,
    attck_json    TEXT,
    mbc_json      TEXT,
    scope_static  TEXT,
    scope_dynamic TEXT,
    program       BLOB NOT NULL,
    -- Distinct APIs the rule mentions anywhere, including inside `optional:`
    -- blocks. Drives the "what else does this combination need" display.
    api_count     INTEGER NOT NULL,
    -- Evaluable leaves in the compiled program. The ratio decides how far a rule
    -- can be trusted from an import table alone: a rule with zero unknown leaves
    -- is decided entirely by APIs, while one that also tests strings or
    -- constants has a discriminator we cannot see. Measured, not guessed --
    -- 279 non-library rules are API-only and 358 are mixed.
    api_leaves     INTEGER NOT NULL,
    unknown_leaves INTEGER NOT NULL,
    -- capa's own library rules: referenced by other rules via `match:` but never
    -- reported to the user on their own.
    is_lib        INTEGER NOT NULL DEFAULT 0,

    -- Whether the program is already satisfied with NO APIs present (treating
    -- unseen features as true). Such a rule says nothing about a target: it would
    -- fire on an empty binary. 396 of 1033 reportable rules test no API at all,
    -- and others name APIs only inside `optional:` blocks -- which a simple
    -- api_count check would not catch.
    --
    -- A fixed property of the rule, so it is settled once here rather than by
    -- evaluating every program twice on every lookup.
    fires_empty   INTEGER NOT NULL,

    -- What kind of evidence can decide this rule, measured from the compiled
    -- program. Drives the confidence tier and the panel's statement of what it
    -- cannot see:
    --   'api-only'  279  every test is an API test
    --   'mixed'     358  APIs plus strings or constants we cannot observe
    --   'no-api'    396  no API tests at all; invisible from an import table
    evidence      TEXT NOT NULL CHECK (evidence IN ('api-only', 'mixed', 'no-api')),

    refs_json     TEXT
);

-- The runtime only ever asks for reportable rules that APIs can actually decide.
CREATE INDEX capa_rule_evidence_idx ON capa_rule (evidence, is_lib, fires_empty);

-- Dictionary of every API named by any rule, normalized through
-- normalize.canonical. Feature programs reference these ids rather than strings,
-- so evaluation is integer set membership with no string hashing at runtime.
CREATE TABLE capa_api (
    id        INTEGER PRIMARY KEY,
    name_norm TEXT NOT NULL UNIQUE
);

-- Reverse index: which rules mention this API. Drives both the "appears in these
-- capabilities" section of the panel and the candidate set for import matching.
CREATE TABLE capa_rule_api (
    rule_id     INTEGER NOT NULL REFERENCES capa_rule (id),
    capa_api_id INTEGER NOT NULL REFERENCES capa_api (id),
    PRIMARY KEY (rule_id, capa_api_id)
) WITHOUT ROWID;

CREATE INDEX capa_rule_api_api_idx ON capa_rule_api (capa_api_id);

-- Full-text search over the API surface, so the panel can offer a search box
-- without a second index. Populated directly by the ETL.
CREATE VIRTUAL TABLE api_fts USING fts5 (
    name,
    description,
    tokenize = 'unicode61'
);
