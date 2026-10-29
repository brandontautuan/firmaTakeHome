# Take-home: action classifier

**Time budget: at most 2 hours of human time.** We expect you to use a coding
agent, and we are as interested in the process as in the result.

## Context

An AI agent's outbound HTTP requests are classified into *action classes*
(`payment.refund`, `repo.write`, ...). Policies then allow or deny action
classes instead of naming every provider. The classification is driven by
**mapping sets**: TOML files that say "requests to this host, method and path
are action class X". The caller denies any request the classifier does not
classify, so a wrong answer here is a security bug, not a cosmetic one.

You will build the classification core as a library. No I/O, network,
database or CLI.

## What to build

Implement the two functions in `src/lib.rs`. Their signatures are fixed;
everything else is yours to design.

```rust
pub async fn load(sets: &[&str]) -> Result<Classifier, LoadError>;
impl Classifier { pub async fn classify(&self, method: &str, host: &str, path: &str) -> Option<&str>; }
```

`load` takes the text of one or more user-provided mapping files. `classify`
returns the action class for a request, or `None` when it is unclassified.

## Mapping file format

```toml
format_version = 1
name = "Acme Payments"
description = "Acme payments API mappings"
host = "acme.com"

[[rules]]
method = "GET"
subdomain = "api"
path = "/v1/payment_intents"
action_class = "payment.read"

[[rules]]
subdomain = "api"
path = "/v1/refunds/*"
action_class = "payment.refund"

[[rules]]
path = "/pricing"
action_class = "payment.read"
```

- A rule applies to the host formed by its `subdomain` followed by the file's
  `host`. With `host = "acme.com"`:
  - `subdomain = "api"` applies to `api.acme.com`;
  - `subdomain = "*"` applies to any subdomain of `acme.com`, such as
    `a.acme.com`;
  - no `subdomain` applies to `acme.com` itself.
- `subdomain`, `method` and `path` are optional. Omitting `method` or `path`
  matches everything.
- `*` in a path is a wildcard.
- `action_class` must be one of `ACTION_CLASSES` in `src/lib.rs`.
- Unknown keys are an error, so misspelled keys fail loudly.

## Behavior

- Both functions will be called from inside an HTTP handler.
- When several rules match a request, **the most specific wins**.
- Sets are loaded together, with no precedence.
- Requests are matched as an HTTP client would send them.
- `classify` must never panic.

## Deliverables

1. The crate, building with no warnings and with `cargo test` passing.
2. Your complete AI session transcript, in the most detailed form your tool
   offers. Do not summarise, redact or `--sanitize` it. We want to see the
   instructions, skills, files and documents you gave the agent, as well as
   its tool calls. Send the raw session file, plus the readable export if
   your tool has one:
   - **Claude Code:** the raw file
     `~/.claude/projects/<project>/<session-id>.jsonl` (`<project>` is your
     working directory path with every non-alphanumeric character replaced by
     `-`; sessions older than 30 days are deleted by default), and
     optionally `/export session.txt`.
   - **Codex:** the raw file
     `~/.codex/sessions/<year>/<month>/<day>/rollout-*.jsonl`, and
     optionally `/export session.md`.
   - **opencode:** `opencode export <sessionID> > session.json` (run
     `opencode export` without an ID to pick the session; do not pass
     `--sanitize`).
   - If you used several sessions, send all of them. Also send any
     instruction files, skills or notes you wrote or installed for the agent
     (for example `CLAUDE.md`, `AGENTS.md`, or a `SKILL.md`).

We will read your code, your tests and your transcript, then spend about 45
minutes discussing them with you.
