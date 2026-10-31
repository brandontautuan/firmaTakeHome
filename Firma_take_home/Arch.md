# Firma AI — HTTP Action Classifier
## End-to-End Technical Design Document

### 1. Project overview

Build a deterministic, security-focused Rust library that classifies outbound HTTP requests made by AI agents into predefined action classes.

The system receives HTTP request metadata:

- HTTP method
- Host
- URL path

It compares this metadata against user-provided TOML mapping sets and returns the action class associated with the most specific matching rule.

The classifier must remain provider-agnostic. It should not hardcode API providers, infer agent intent, or use an LLM to classify requests.

The classifier is intended to be embedded inside a larger agent governance system. It does not perform HTTP interception, policy enforcement, or authorization itself.

**Primary objective:** Given a collection of valid mapping rules and an HTTP request, consistently return the correct action class without ambiguity, panics, or unsafe fallback behavior.

### 2. Scope and constraints

#### In scope

- TOML configuration parsing
- Configuration validation
- Multi-set loading
- Structured loading errors
- Rule compilation
- Host normalization
- Method validation
- Path normalization
- Exact and wildcard matching
- Rule specificity and precedence
- Cross-set conflict detection
- Deterministic classification
- Unit, integration, and robustness testing
- Thread-safe immutable classifier state

#### Out of scope

- Agent harnesses
- LLM inference
- HTTP interception
- HTTP servers or proxies
- Policy enforcement
- User authorization
- Databases
- Network requests
- Filesystem access
- CLI tools
- Session or reasoning analysis

Do not expand beyond the Rust library described in the existing README.

### 3. Existing public API

Preserve the existing public API signatures.

```rust
pub async fn load(
    sets: &[&str]
) -> Result<Classifier, LoadError>;

impl Classifier {
    pub async fn classify(
        &self,
        method: &str,
        host: &str,
        path: &str
    ) -> Option<&str>;
}
```

`load()` receives the raw text of one or more TOML mapping sets.

`classify()` receives request metadata and returns a matching action class or `None`.

Preserve the seven existing action classes:

```rust
pub const ACTION_CLASSES: &[&str] = &[
    "payment.read",
    "payment.create",
    "payment.refund",
    "repo.read",
    "repo.write",
    "communication.external.send",
    "llm.inference",
];
```

Do not add new classes.

### 4. Architecture

The library has two distinct execution phases.

#### Phase A — Configuration loading

```text
TOML Mapping Sets
        |
        v
Configuration Parser
        |
        v
Schema Validation
        |
        v
Semantic Validation
        |
        v
Rule Compilation
        |
        v
Cross-Set Conflict Detection
        |
        v
Immutable Classifier
```

All configuration-related work should happen inside `load()`.

The loader must reject invalid or ambiguous configurations before returning a usable classifier.

#### Phase B — Request classification

```text
HTTP Request Metadata
        |
        v
Request Normalization
        |
        v
Candidate Rule Matching
        |
        v
Specificity Comparison
        |
        v
Some(action_class) / None
```

`classify()` must not parse TOML, perform I/O, or modify stored rules.

The request path should remain lightweight and deterministic.

### 5. Proposed module structure

```text
Firma_take_home/
├── Cargo.toml
├── README.md
├── src/
│   ├── lib.rs
│   ├── config.rs
│   ├── normalize.rs
│   └── matcher.rs
└── tests/
    ├── example.rs
    ├── classification.rs
    ├── conflicts.rs
    ├── robustness.rs
    └── security.rs
```

Configuration-validation tests live beside the parser in `src/config.rs`;
`tests/robustness.rs` covers generated malformed and valid request inputs.

#### `lib.rs`

Owns the public API and integration between modules.

Responsibilities:

- Preserve `ACTION_CLASSES`.
- Define and expose `Classifier`.
- Define and expose `LoadError`.
- Implement `load()`.
- Implement `classify()`.
- Connect configuration compilation with matching.

#### `config.rs`

Owns configuration parsing and validation.

Responsibilities:

- Deserialize TOML.
- Validate required fields.
- Validate rule values.
- Reject unknown fields.
- Normalize configuration fields using agreed rules.
- Prepare validated rules.
- Preserve useful source metadata for errors.

#### `normalize.rs`

Owns request normalization.

Responsibilities:

- Normalize incoming hosts.
- Validate HTTP methods.
- Normalize paths according to the documented HTTP contract.
- Reject malformed or ambiguous inputs.
- Expose normalized request representations.

#### `matcher.rs`

Owns matching semantics and specificity.

Responsibilities:

- Match hosts and subdomains.
- Match HTTP methods.
- Match exact and wildcard paths.
- Calculate rule specificity.
- Compare matching rules.
- Determine whether two rule patterns overlap.
- Provide the shared matching logic needed for load-time conflict detection.

The conflict detector must not independently reimplement matcher semantics.

### 6. Configuration schema

The TOML mapping structure is:

```toml
format_version = 1
name = "Acme Payments"
description = "Acme API"
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
```

Use Serde to deserialize the configuration into strongly typed structures.

```rust
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MappingSet {
    pub format_version: u32,
    pub name: String,
    pub description: Option<String>,
    pub host: String,
    pub rules: Vec<Rule>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub method: Option<String>,
    pub subdomain: Option<String>,
    pub path: Option<String>,
    pub action_class: String,
}
```

Both structures must reject unknown fields.

Keep the raw configuration representation separate from the validated runtime representation.

### 7. Configuration validation

Validate every mapping set before compilation.

#### Mapping-level validation

Reject:

- Invalid TOML syntax.
- Unknown or misspelled fields.
- Missing required fields.
- Empty required strings.
- Unsupported `format_version`.
- Invalid hostnames.
- Invalid rule arrays.
- Empty rule sets.

Only `format_version = 1` is supported.

An optional description may be absent or empty.

#### Rule-level validation

Reject:

- Missing `action_class`.
- Empty `action_class`.
- An action class not present in `ACTION_CLASSES`.
- Invalid method tokens.
- Invalid subdomain formats.
- Invalid path patterns.
- Malformed percent encoding.
- Unsupported wildcard syntax.
- Ambiguous or unsafe normalized patterns.

Optional rule fields:

- `method`
- `subdomain`
- `path`

Omitting a method or path means any valid method or path, respectively.

Omitting a subdomain means the bare host only.

#### Host validation

Use an explicit ASCII DNS hostname contract.

- Convert hostnames to lowercase.
- Reject empty labels.
- Reject invalid characters.
- Reject malformed leading or trailing hyphens.
- Reject embedded ports in configuration hostnames.
- Reject unsupported IP literals.
- Reject invalid wildcard placement.
- Preserve DNS label boundaries.

Configuration `host` should represent the bare domain.
It must contain at least two DNS labels; single-label public suffix-like bases
such as `com` are too broad for a wildcard rule.

Subdomain values must be either `*` or one or more valid DNS labels. Per the README, the rule host is the subdomain followed by `host`, so `subdomain = "api.eu"` with `host = "acme.com"` names `api.eu.acme.com`.
Numeric exact subdomain labels are valid when the combined hostname is valid.
A hostname whose final label is a WHATWG IPv4 number is rejected: all decimal
digits, or `0x`/`0X` followed by zero or more hex digits. Hex-looking labels in
any other position, as in `0x7f.acme.com`, are ordinary DNS labels.

#### Method validation

- Reject invalid token characters.
- Reject whitespace.
- Reject empty strings.
- Reject `method = "*"`; omitting `method` is the only spelling for any valid method.
- Fold method tokens to uppercase in both rules and requests. Rules that differ only by method case are therefore the same method. Request handling is described in §9.
- A missing method means any valid method.

#### Path validation

- Explicit path patterns must begin with `/`.
- `*` is the only supported wildcard character.
- Reject malformed percent encoding.
- Reject encoded separators that create ambiguous path interpretations.
- Apply the same canonicalization contract to configuration literals and request paths.
- Decode only escaped unreserved characters (`A-Z a-z 0-9 - . _ ~`) and upper-case remaining escapes (RFC 3986 section 6.2.2). Decode once; `%25` stays `%25`.
- Reject empty segments (`//`), backslashes, literal semicolons, and non-graphic bytes. Semicolons can be stripped as path parameters by upstream servers, so accepting them could classify a different operation.
- Reject query strings and fragments in patterns.
- Reject patterns that cannot be represented safely by the matcher.
- Reject configured `.` and `..` segments instead of silently rewriting them.

### 8. Internal compiled representation

The runtime classifier should not retain raw TOML structures as its primary matching format.

Introduce a validated internal representation.

Conceptually:

```rust
struct CompiledRule {
    host: HostMatcher,
    method: MethodMatcher,
    path: PathMatcher,
    action_class: &'static str,
    specificity: Specificity,
}
```

Possible internal matcher types:

```rust
enum HostMatcher {
    Bare(String),
    ExactSubdomain {
        base: String,
        subdomain: String,
    },
    WildcardSubdomain {
        base: String,
    },
}

enum MethodMatcher {
    Any,
    Exact(String),
}

enum PathMatcher {
    Any,
    Exact(String),
    Wildcard(CompiledPattern),
}
```

The precise types may change based on the matcher implementation, but parsing and matching must agree on one shared contract.

`Specificity` should be a structured value with an explicitly defined ordering.

Since the action classes are a fixed constant list, compiled rules retain the corresponding `ACTION_CLASSES` static string, so an unknown class cannot be returned at runtime.

Preserve mapping-set index, mapping name, and rule index during loading so errors can identify their sources.

### 9. HTTP request normalization

Normalize incoming request metadata before matching.

#### Host

- Lowercase ASCII hostnames.
- Accept valid numeric ports and remove them.
- Remove one trailing DNS dot.
- Reject empty or malformed hosts.
- Reject userinfo.
- Reject invalid domain labels.
- Reject unsupported IP literal representations.
- Reject hostnames whose final label is a WHATWG IPv4 number (all digits, or `0x`/`0X` plus zero or more hex digits), including abbreviated or noncanonical IPv4-like forms such as `127.1` and `0x7f.0x1`.
- Reject non-ASCII names; IDNs must arrive in their `xn--` form.
- Preserve subdomain boundaries.

`api.acme.com` must never match `evilapi.acme.com` unless explicitly configured to do so.

#### Method

- Validate according to HTTP token syntax.
- Reject malformed tokens.
- Reject methods longer than 32 bytes.
- Do not infer method semantics.
- Match on the uppercase form, and treat a method whose spelling folding changed as having two readings.

RFC 9110 makes methods case-sensitive, so `get` is formally not `GET`. In practice Fetch and Node upper-case common methods (Fetch leaves `patch` alone), some servers fold case, and case-sensitive routers such as Go's `ServeMux` send `get` past a `GET` route to a catch-all handler. The classifier cannot see which applies, so it supports both interpretations:

- Folded: `get` is `GET`, and every rule is eligible.
- Case-sensitive: `get` is a distinct method, and only method-less rules are eligible.

If both readings name a class and the classes differ, return `None`. Action classes have no sensitivity order, so neither reading can be preferred: `delete` must not become `payment.read` when a `DELETE` rule says `payment.refund`, and `get` must not become `payment.read` when the method-less rule it reaches on a case-sensitive server says `payment.refund`. Uppercase methods have one reading. As with the path checks below, a reading that finds no rule is not a disagreement, so `patch` still classifies under a lone `PATCH` rule.

#### Path

- Empty path becomes `/`.
- Reject a request path longer than 8 KiB after removing its query or fragment.
- Remove query strings and fragments before matching.
- Require a leading `/` for nonempty paths.
- Reject duplicate slashes (empty segments): servers disagree on whether `//` collapses.
- Reject literal semicolons: Tomcat, Jetty, and Spring-style servers may strip path parameters before routing.
- Keep trailing slashes. When a request path ends in `/`, also compare the slash-stripped spelling; if it classifies to a different action, return `None`. This protects against servers that strip a sent trailing slash while preserving the classification of a request sent without one.
- Also compare an ASCII-lowercased spelling outside percent escapes against lowercased compiled rule patterns, plus its slash-stripped spelling when applicable. If any such spelling has a different nonempty classification, return `None`. This detects disagreement with common case-insensitive routers without changing the case-sensitive match itself.
- Return `None` when equally specific rules with different classes match any spelling. Load-time conflict detection compares patterns as written, so `/v1/Refunds` and `/v1/refunds` can load together but tie once folded; denying keeps the result independent of rule order.
- Each path spelling is evaluated under each method reading above, so one request is compared under at most eight readings.
- Decode escaped unreserved characters, so `%72efunds` matches `refunds` and `%2e%2e` is a dot segment.
- Normalize dot segments.
- Reject malformed percent encoding.
- Reject encoded `/` and `\` where interpretations are ambiguous.
- Reject non-ASCII and non-graphic bytes; they must arrive percent-encoded.
- A `/`-ending path produced by dot-segment removal counts as a trailing slash: `/a/b/..` is `/a/`.
- Treat `*` in a request path as an ordinary character. Only configured patterns have wildcards, and `%2A` in a pattern is a literal escape.
- Avoid double decoding.
- Reject unsupported or ambiguous representations.

Document the normalization contract clearly.

HTTP clients and upstream servers may interpret some paths differently. The classifier cannot guarantee semantic equivalence across every upstream service using only method, host, and path. Prefer conservative rejection when interpretation is uncertain.

#### Known limits

- Some servers trim trailing dots or `%20` at the end of a segment.
- Method-override headers such as `X-HTTP-Method-Override` are not visible to this API.
- A server that decodes a path twice can interpret `%252e` differently.
- Request bodies and provider-specific routing data are outside this metadata-only classifier.
- Comparing readings cannot detect a server that behaves differently only where the other reading has no rule. `patch` under a lone `PATCH` rule classifies, although a case-sensitive server does not treat it as `PATCH`; it is the only rule that names the request.

### 10. Rule matching

#### Host matching

For `host = "acme.com"`:

- Omitted subdomain matches `acme.com`.
- `subdomain = "api"` matches `api.acme.com`.
- `subdomain = "*"` matches any nonempty subdomain.
- Wildcard subdomains may span multiple DNS label levels.
- Wildcard subdomains do not match the bare host.
- Exact subdomains take priority over wildcard subdomains when both match.

#### Method matching

- Exact methods match after both sides are folded to uppercase. A differently cased request method is also checked as a distinct method (§9).
- An omitted method matches any valid method.
- Explicit methods outrank omitted methods when higher-priority dimensions are equivalent.

#### Path matching

- Exact paths match exactly after normalization.
- `*` matches zero or more characters, including `/`.
- Multiple wildcards are permitted.
- An omitted path matches every valid normalized path.
- Explicit paths outrank omitted paths.

Example:

`/v1/refunds/*` matches:

- `/v1/refunds/re_123`
- `/v1/refunds/a/b/c`
- `/v1/refunds/`

It does not match `/v1/refunds`.

### 11. Specificity ordering

Use a deterministic lexicographic ordering.

The order is:

1. Host specificity (host kind, then base-host label depth).
2. Path specificity.
3. Method specificity.

Host specificity:

- Exact subdomain takes priority over wildcard subdomain.
- Bare-host rules match only the bare host.
- Among host matchers of the same kind, the rule with the deeper base host
  takes priority before any path or method comparison.

Path specificity:

- Exact path over wildcard path.
- Wildcard path over omitted path.
- Among wildcard patterns, prefer more literal characters.
- Then prefer fewer wildcards.
- Then prefer greater literal-prefix length.

Method specificity:

- Explicit method over omitted method.

Do not use source-file ordering or insertion ordering as a tiebreaker.

If two matching rules have identical specificity and different action classes, loading must have rejected the ambiguity beforehand.

### 12. Multiple mapping sets

`load()` must support multiple TOML mapping sets in the same call.

Example:

```rust
let classifier = load(&[
    payments_mapping,
    github_mapping,
    llm_mapping,
]).await?;
```

Requirements:

- Parse each set independently.
- Validate each set independently.
- Compile all accepted rules into a shared collection.
- Detect conflicts within and across mapping sets.
- Reject invalid combinations before exposing the classifier.
- Never give a mapping set priority because it was loaded first.
- Treat duplicate equivalent rules returning the same action class as harmless; they may be deduplicated.

A change in the ordering of mapping sets must not change classification results.

### 13. Conflict detection

Conflict detection happens during `load()`.

A conflict occurs when two rules:

1. Can match at least one identical valid HTTP request.
2. Have the same specificity for that request.
3. Return different action classes.

Example:

```toml
method = "POST"
path = "/v1/refunds/*"
action_class = "payment.refund"
```

versus:

```toml
method = "POST"
path = "/v1/refunds/*"
action_class = "payment.read"
```

Reject the combined configuration.

Conflicts are not limited to identical rule strings.

For example, two different wildcard patterns may overlap and have equal specificity.

The matcher module should provide shared primitives for:

- Checking whether two host matchers can overlap.
- Checking whether two method matchers can overlap.
- Checking whether two path patterns can overlap.
- Comparing rule specificity.

The configuration loader should call these primitives rather than implement its own matching semantics.

A conservative conflict detector must not silently accept an unresolved ambiguity. If exact overlap checking is not implemented for a supported pattern type, either restrict that pattern type during validation or reject potentially conflicting patterns with an explicit error.

Wildcard overlap analysis has one 4,000,000-state budget for the complete
load, rather than a pair-count limit. Only pairs with different action
classes, equal specificity, and overlapping methods and hosts consume that
budget. Equal patterns (including two omitted paths) are recognized as
conflicts before budgeted analysis. This keeps unrelated or same-class rules
cheap while failing closed when a configuration would require excessive work.
Pairs containing an exact path are resolved directly against that literal.
Two wildcard patterns are first compared on their literal text before the
first `*` and after the last `*`: if either end disagrees within the shorter
length, no path matches both, decided in linear time without budget. Compatible
ends already guarantee an overlap (the shared prefix, both patterns' middle
literals, then the shared suffix matches both), so the product-NFA search only
confirms a conflict and the budget acts as a safeguard rather than a limit
ordinary configurations reach. Distinct REST prefixes such as
`/v1/customers/*` and `/v1/charges/*` therefore load at any count up to the
rule limit.

Overlap is decided for patterns as written. Patterns that differ only by case are not conflicts at load, because they name different paths on a case-sensitive server; they are handled at classification (§9).

Avoid silently selecting the first encountered rule.

### 14. Structured error handling

Replace the placeholder `LoadError`.

The implemented `LoadError` variants are `InvalidSet`, `ConflictingRules`,
`ConflictAnalysisTooComplex`, and `TooManyRules`. `InvalidSet` wraps the
set-local `SetError` variants `Toml`, `UnsupportedFormatVersion`,
`InvalidField`, `InvalidRule`, and `UnknownActionClass`.

Set and rule indexes are 0-based. Every set-local error identifies the input
set and its declared name when parsing reached it. `InvalidRule` includes the
rule index, field, and Debug-quoted rejected value; diagnostic values are
bounded to 256 bytes and marked as truncated. `Toml` carries the parser's
message with the same bound, prefixed by the 1-based line and column; it does
not quote the source line, because the `toml` crate's own rendering would echo
an arbitrarily long line into logs or HTTP responses. Conflicts identify both
rule locations and their mapping sets.

For example:

```text
mapping set 0: invalid TOML: line 4, column 1: unknown field `bogus`, expected one of `format_version`, `name`, `description`, `host`, `rules`

mapping set 2 "Acme Payments": rule 3 names unsupported action class "payment.delete"

mapping set 1 "A" rule 2 and mapping set 3 "B" rule 4 overlap with equal specificity but different action classes
```

Avoid using `unwrap()` or `expect()` for user-provided configuration.

### 15. Classifier runtime behavior

`classify()` should:

1. Validate and normalize request inputs.
2. Return `None` immediately if normalization fails.
3. Compare normalized inputs against compiled rules.
4. Identify every applicable candidate or maintain the best candidate while scanning.
5. Select the highest-specificity match.
6. Compare the other method and path readings (§9), and return `None` if any names a different class or ties between classes.
7. Return the selected action class.
8. Return `None` if no rule matches.

It must not:

- Parse TOML.
- Access a database.
- Make network requests.
- Perform filesystem I/O.
- Mutate shared classifier state.
- Depend on a coding agent or LLM.
- Panic on malformed requests.

For the expected scope, an immutable vector of compiled rules with a linear scan is an acceptable initial implementation.

More elaborate indexing should only be introduced if benchmarks demonstrate a benefit.

### 16. Concurrency and performance

The library will be used inside HTTP handlers.

Requirements:

- `Classifier` must be `Send + Sync`.
- Rules remain immutable after loading.
- No locks should be necessary for ordinary classification.
- Avoid expensive preprocessing on every request.
- Precompute specificity metadata during loading.
- Normalize path patterns and precompute their case-folded copies during loading.
- Keep classification deterministic under concurrent requests.
- Avoid unnecessary allocations where practical.

Configuration limits are deliberate: a normalized path pattern is at most
1,024 bytes, a load accepts at most 10,000 rules, and wildcard conflict
analysis spends at most 4,000,000 product-NFA states across the entire load
(only pairs whose literal prefixes and suffixes agree reach that search).
The limits bound configuration-controlled memory and CPU use while preserving
the linear runtime scan.
Request inputs are also bounded: methods are at most 32 bytes and paths are
at most 8 KiB after query or fragment handling. Normalization is linear in the
input length: dot-segment removal uses a segment stack rather than shifting a
buffer, so a path of many `/..` segments costs no more than any other.
Wildcard matching is O(pattern length × path length) per eligible rule, so the
worst-case cost of one `classify` scales with those limits and the eight
readings. Mapping sets are trusted to the same degree as the policy they drive;
a request alone cannot reach this cost without such patterns being configured.

The public functions remain asynchronous because the starter API requires it, but internal parsing and matching do not require asynchronous tasks.

If practical, verify concurrent classifications through a Tokio test using a shared `Arc<Classifier>`.

### 17. Testing strategy

#### Configuration parsing tests

Cover:

- Valid mapping files.
- Invalid TOML syntax.
- Unknown top-level keys.
- Unknown rule-level keys.
- Missing required fields.
- Empty required strings.
- Unsupported format versions.
- Optional fields omitted.
- Empty rules.
- Invalid action classes.
- Malformed methods.
- Malformed hostnames.
- Invalid subdomains.
- Invalid paths.

#### Matching tests

Cover:

- Exact host matching.
- Bare hosts.
- Exact subdomains.
- Wildcard subdomains.
- Nested subdomains.
- Exact methods.
- Omitted methods.
- Exact paths.
- Wildcard paths.
- Multiple path wildcards.
- Omitted paths.
- Unmatched requests.

#### Specificity tests

Cover:

- Exact host versus wildcard host.
- Exact path versus wildcard path.
- Wildcard path specificity comparisons.
- Explicit method versus omitted method.
- Multiple simultaneously matching rules.
- Equal-specificity ties.
- Independent results when loading sets in different orders.

#### Conflict tests

Cover:

- Identical rules with different classes.
- Overlapping wildcard rules with different classes.
- Conflicts inside one set.
- Conflicts across multiple sets.
- Duplicate rules with the same class.
- Overlapping rules where one has higher specificity.
- Rules matching different hosts that should not conflict.

#### Normalization and security tests

Cover:

- Host casing.
- Host ports.
- Trailing host dots.
- Host suffix bypass attempts.
- Malformed userinfo.
- HTTP method casing.
- Invalid method tokens.
- Empty paths.
- Query strings.
- Fragments.
- Duplicate slashes.
- Trailing slashes.
- Literal dot segments.
- Encoded dot segments.
- Encoded path separators.
- Invalid percent sequences.
- Unicode paths.
- Arbitrary malformed input.

#### Robustness tests

Use property-based testing or fuzz-style generated inputs to confirm:

- `classify()` never panics.
- Classification remains deterministic.
- Rule ordering does not affect results.
- Malformed input does not unexpectedly map to a valid action class.
- Concurrent classification does not mutate shared state.

Generated request coverage must include valid matching requests as well as malformed input, and assert that a meaningful portion reaches an action class.

`tests/robustness.rs` uses a seeded generator with no extra dependency, so failures reproduce. It checks that:

- Generated methods, hosts, and paths classify when valid and return `None` under a catch-all rule set once a malformed form is introduced.
- Wildcard matching agrees with an independent reference matcher, with both outcomes represented.
- Generated rule sets give the same load outcome and classifications when rules are shuffled and split across sets.
- A classification under a non-uppercase method never contradicts the folded or the case-sensitive reading.
- Equivalent spellings of a valid request classify identically.

`src/matcher.rs` compares overlap analysis with exhaustive search over short patterns.

Maintain all four existing example tests.

### 18. Multi-agent development plan

Two coding agents are working concurrently.

#### Agent 1 — Configuration and compilation

Ownership:

- `config.rs`
- Parsing and configuration validation tests
- Configuration-related error design
- Validated rule construction
- Loader-related conflict detection integration

Responsibilities:

- Deserialize TOML.
- Reject invalid configurations.
- Verify allowed action classes.
- Build validated mapping data.
- Prepare source metadata for errors.
- Coordinate compiled rule interfaces with the matcher.

Do not independently implement request matching.

#### Agent 2 — Normalization and matching

Ownership:

- `normalize.rs`
- `matcher.rs`
- Normalization and matching unit tests

Responsibilities:

- Implement request normalization.
- Implement exact and wildcard matching.
- Implement specificity ordering.
- Implement overlap detection primitives.
- Expose interfaces for compiled rule evaluation.

Do not independently parse TOML.

#### Integration phase

After both agents finish:

- Review both module contracts.
- Establish shared compiled-rule types.
- Connect parser output to matcher input.
- Implement the public `load()` function.
- Implement the public `classify()` function.
- Connect conflict detection to loading.
- Run integration tests.
- Resolve mismatches between modules.
- Verify order independence and security assumptions.

Use separate Git worktrees or branches for parallel agents where possible, and integrate intentionally rather than allowing simultaneous edits to shared files.

### 19. Verification and acceptance criteria

The implementation is complete when:

- The original public API is unchanged.
- All valid TOML mapping sets load successfully.
- Invalid configurations produce useful errors.
- Only predefined action classes can be returned.
- Multiple mapping sets work without ordering precedence.
- Conflicting rules are rejected.
- The most specific matching rule is selected deterministically.
- Request normalization is consistent and documented.
- Malformed inputs return `None` without panicking.
- Classification requires no network, filesystem, or external services.
- `Classifier` is safe for concurrent use.
- The four starter tests pass.
- Additional unit and integration tests pass.
- The crate builds without warnings.
- Clippy reports no warnings under the selected lint configuration.

Run:

```bash
cargo fmt --check
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
```

### 20. Submission requirements

Preserve the complete raw coding-agent session transcripts for all sessions used during development.

Include all instruction files provided to the agents, including any `CLAUDE.md`, `AGENTS.md`, or skill files created for this project.

Do not sanitize, redact, or summarize the required raw transcripts.

Review the recorded sessions for unintended exposure of credentials before using any external services during development. Avoid introducing secrets into the take-home workflow.

Ensure the repository and any accompanying documentation accurately describe the implemented behavior and its limitations.

### 21. Final engineering principles

The solution should prioritize:

1. Correctness over cleverness.
2. Security over permissive matching.
3. Deterministic behavior over implicit precedence.
4. Explicit validation over silent correction.
5. Immutable state over shared mutable runtime state.
6. Clear module boundaries over unnecessary abstraction.
7. Comprehensive adversarial testing over happy-path testing alone.

The ultimate goal is a small, production-quality classification component whose behavior can be explained and defended for every supported input.

**The classifier is not expected to understand an agent's reasoning. It must reliably classify observable HTTP operations according to explicitly configured mapping rules.**
