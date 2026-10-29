AGENTS.md — Firma HTTP Action Classifier
Mission and source of truth
Build the Rust library described in README.md: parse TOML mapping sets and classify (method, host, path) into one of the existing ACTION_CLASSES, or None. This is a library, not an HTTP proxy, agent harness, policy engine, UI, network service, or LLM. Never add I/O, networking, databases, or a CLI.

Read README.md, Cargo.toml, src/lib.rs, and tests/example.rs before editing. The project design document describes our chosen implementation policies; the repository README and the fixed API take precedence if there is any disagreement. Record and surface ambiguities rather than inventing undocumented API behavior.

Public API signatures are fixed:
pub async fn load(sets: &[&str]) -> Result<Classifier, LoadError>;
impl Classifier {
    pub async fn classify(&self, method: &str, host: &str, path: &str) -> Option<&str>;
}
Keep ACTION_CLASSES unchanged. Keep all four supplied example tests passing. LoadError can be redesigned but must implement std::error::Error. No unwrap/expect on untrusted inputs; classify must never panic. The classifier must be immutable after load, Send + Sync, and fast to query.
Workflow: two parallel owners, one integrator, one reviewer
Use two concurrent implementation agents. A third agent (Integrator) works after both are ready; an optional fourth (Security Reviewer) inspects the merged result without simultaneously editing it. Do not run multiple agents with write access to the same worktree.

Prefer separate Git worktrees and branches:
# Run from the repository root; example names only.
git worktree add ../firma-config -b agent/config
git worktree add ../firma-matcher -b agent/matcher
Agent 1 — Configuration, validation, and compilation input
Owns: src/config.rs and configuration-focused tests (tests/config_validation.rs or module-local tests). Can propose—but not unilaterally edit—shared public types or src/lib.rs.

Responsibilities:
- Deserialize mapping sets and rules with Serde; #[serde(deny_unknown_fields)] on both.
- Validate format version (1), required/nonempty fields, allowed action classes, host/subdomain/method/path syntax, and empty rules as defined in the design.
- Parse all provided TOML strings, with no filesystem reads; collect source identifiers (input set index, optional name, rule index).
- Expose validated configuration records for Agent 2's compiler/matcher representation.
- Design structured load errors, including cross-set conflict diagnostics; coordinate error implementation with the Integrator.
- Ensure set order never establishes precedence.
- Do not create a separate host/path matcher or overlap algorithm in config.rs.
Deliver: exported types/functions and tests; notes for Integrator documenting validation invariants, error metadata, and unresolved interface needs.
Agent 2 — HTTP normalization, matching, and overlap primitives
Owns: src/normalize.rs, src/matcher.rs, and their focused tests. Do not edit src/config.rs; avoid modifying src/lib.rs or Cargo.toml without agreeing on an integration interface.

Responsibilities:
- Implement safe request normalization (host, method, path) and reject malformed/ambiguous requests with no panic.
- Implement compiled exact/wildcard host, method, and path matching.
- Define deterministic, documented specificity ordering independent of set order.
- Provide rule-overlap detection using the same semantics as runtime matching. Overlap must account for valid normalized request inputs, not just string equality.
- Expose a stable interface for validated rules and/or compilation; do not parse TOML.
- Write specificity, wildcard, Unicode, adversarial input, and property/fuzz-style tests where practical.
Deliver: exported types/functions and tests; notes for Integrator documenting matching semantics, overlap guarantees, and unsupported inputs.
Integrator — after both implementation branches land
Owns: src/lib.rs, integration adjustments to shared types, Cargo.toml if required, and cross-module tests (tests/classification.rs, tests/conflicts.rs, tests/security.rs). One integration owner only.

Responsibilities:
- Reconcile module interfaces (do not maintain duplicate canonicalization or matching logic).
- Implement the fixed load() function: parse -> validate -> compile -> detect conflicts -> return immutable classifier.
- Implement the fixed classify() function: normalize -> find matching compiled rules -> select highest specificity -> return static class or None.
- Use source locations from config to generate actionable LoadError variants.
- Reject equal-specificity overlapping rules with different classes; allow same-class duplicates and overlaps where one rule has greater specificity. Be conservative when exact overlap cannot be proved: reject unsupported/ambiguous patterns rather than silently accept potential conflicts.
- Ensure the same canonicalization contract is applied to rule literals and request inputs.
- Run all tests and verify Send + Sync, deterministic set-order behavior, and no warnings.
Security Reviewer — after integration (read-only first)
Independently review the completed implementation for bypasses, specificity ambiguities, normalization differences between load and classify, panic paths, excessive allocations, unsupported upstream HTTP semantics, and configuration conflicts. Produce reproducible failing tests or concrete findings before requesting targeted fixes. Do not rewrite the architecture without a demonstrated defect.
Shared behavior contract
These are chosen policies from the technical design, not all explicit README requirements. If a policy conflicts with a direct README requirement, follow README and flag the difference.

Hosts: Case-insensitive ASCII DNS hostnames; lower-case for comparison. Request host may have a valid numeric port and one trailing DNS dot; reject empty labels, malformed ports, userinfo, unsupported IP literals (including a hostname with an all-numeric final label), and ambiguous syntax. Match on label boundaries, never arbitrary suffixes. In configuration, host is the base hostname; omitted subdomain matches only the bare host; an exact subdomain = "api" matches only api.base; subdomain = "*" matches any nonempty sequence of subdomain labels but not the bare host.

Methods: HTTP tokens, folded to uppercase in rules and requests so `delete` cannot skip a `DELETE` rule; reject malformed/empty method tokens. Omitted rule method matches any valid method.

Paths: Empty request path normalizes to /; nonempty path must begin /. Drop query/fragment before matching (reject them in patterns). Reject empty segments (`//`), backslashes and non-graphic bytes. Keep trailing slashes; for a request ending in `/`, return None when its slash-stripped spelling has a different nonempty classification, because servers can strip the sent slash. Decode only escaped unreserved characters (RFC 3986 6.2.2) and upper-case other escapes, identically for rules and requests; never double-decode. Normalize dot segments; reject invalid percent encoding and encoded separators (%2F, %5C). A configured path must start with /; omission matches all valid paths; * matches zero or more characters including /, and multiple wildcards are supported. /v1/refunds/* matches /v1/refunds/ but not /v1/refunds.

Specificity: Lexicographic ranking: (1) exact subdomain over wildcard for subdomain requests (bare-host rules only match bare host), (2) exact path > wildcard path > absent path; among wildcards, more literal characters > fewer wildcards > longer literal prefix, (3) explicit method > absent method. Never use file or insertion order to break ties. If any remaining equal-specificity rules could classify the same valid request differently, reject the configuration during load.

Important security boundary: Matching URL metadata cannot reveal agent reasoning, authorization, request body, or provider-specific server decoding rules. Do not infer missing information. If normalization is ambiguous, return None for requests or reject the rule when loading. Document important limits.
Module contracts and coordination
Before writing a cross-module type, Agent 1 and Agent 2 should agree on:
1. The validated rule shape: base host, optional subdomain, optional method, optional path, action_class, and source-location metadata.
2. Which module owns compile-time canonicalization of configured host/path values. normalize.rs owns canonicalization semantics; config.rs calls shared helpers rather than duplicating them.
3. How matcher.rs accepts rule data and returns match/specificity results.
4. How it checks potential overlap with equal specificity, and how the caller gets enough context to construct errors.
5. Error behavior for invalid rules vs invalid request inputs.
Agent 1 may compile to a small validated configuration IR; Agent 2 may compile that IR to an internal matching IR. Avoid cyclic imports. A practical dependency direction is config -> normalize for shared validation helpers, then lib orchestrates config and matcher; avoid config <-> matcher cycles. Shared DTO types can live in config.rs or a small model.rs owned by the Integrator.

When an interface is unresolved, write down a proposed contract and stop at your module boundary, rather than touching the other agent's files. Communicate:
- proposed exported type and function signatures;
- invariant guaranteed at that boundary;
- test that demonstrates intended behavior;
- any uncertainty that needs a single integration decision.
Error reporting
Favor thiserror variants that identify mapping set index, mapping name when known, rule index where applicable, invalid field/value, and the reason for rejection. Since load() accepts TOML text rather than paths, do not claim a file name is known. Conflicts report both rules' source locations. No silent correction of invalid config.
Tests and completion gates
Each agent runs its focused tests before commit. Only the Integrator claims full-project success. After integration, run from Firma_take_home/:
cargo fmt --all -- --check
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
Minimum coverage: original four tests; unknown keys; missing/empty fields; version; action classes; hosts/methods/paths; nested wildcard subdomains; multiple wildcards; exact/wildcard/omitted precedence; identical and overlapping cross-set conflicts; normalization and bypass attempts; Unicode/malformed inputs; no panic; order independence; parallel requests. If a command fails due to another branch not yet integrated, report this precisely without claiming success.
Agent process and submission evidence
Preserve all raw agent session transcripts for every development session and every agent, including tool calls and instructions. Submit any AGENTS.md, CLAUDE.md, SKILL.md, and notes provided to agents, as required by README. Do not summarize, sanitize, or redact the required transcript. Never place secrets in prompts or logs; keep credentials out of the project.

At the end of each agent's work, report: changed files, exported interfaces, tests run and results, design decisions, unresolved questions, and branch/commit identifier. Do not claim work from another branch has been tested until it is merged.
