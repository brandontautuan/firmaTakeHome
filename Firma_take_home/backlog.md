# Audit backlog

Findings from auditing each change against `README.md` (authoritative), `Arch.md`
and `agents.md`. The auditor only records findings; it does not change code.
Each entry: severity, the commit it was found in, the evidence, and a suggested
resolution. Mark resolved entries `[x]` with the fixing commit.

Severity: **HIGH** = classification/security impact or spec violation,
**MED** = code/doc drift or missing required coverage, **LOW** = hardening.

---

## Audit 1 — `e8d5871`, `04ce80a` (2026-10-29)

Gates: `cargo fmt --check` OK · `cargo build` 0 warnings · `cargo test` 46/46 ·
`cargo clippy --all-targets -D warnings` OK.

- [ ] **HIGH — Method case-folding reverted; the fall-through bypass is back and is now asserted as expected behaviour** (`04ce80a`)
  - `normalize::method` (src/normalize.rs:31) no longer upper-cases. With the
    rules in `tests/security.rs`, `classify("delete", "api.acme.com",
    "/v1/charges/ch_1")` returns `payment.read`. `DELETE` returns
    `payment.refund`. `method_matching_is_case_sensitive` now asserts
    `payment.read` for `delete`/`Delete`.
  - That contradicts the module doc at the top of `tests/security.rs`
    ("must not reach a broader, less sensitive rule"). It also contradicts
    `Arch.md:340`, `Arch.md:426`, `Arch.md:464` and `agents.md:61`, which all
    say methods are folded to uppercase.
  - Resolve by picking one policy and making code, tests and both docs agree:
    - (a) Restore folding.
    - (b) Keep case-sensitivity, revert the doc lines, and close the
      fall-through another way. For example, return `None` when the method
      is not all uppercase and a method-specific rule would have matched
      its uppercased form. Or reject non-uppercase methods outright.

    Either way, a test should not assert that `delete` gets the less sensitive
    class.

- [ ] **MED — Single-label subdomain restriction contradicts the docs** (`e8d5871`)
  - `config.rs` now rejects `subdomain = "api.eu"` (`is_dns_label`).
    `Arch.md:333` says "`*` or one or more valid DNS labels" and cites the
    README.
  - This is fail-closed, so there's no security impact. It's a deliberate
    narrowing of the README's "subdomain followed by host" wording.
  - Resolve by updating `Arch.md:333` back to a single label with a one-line
    rationale (the same host can still be written as `host = "eu.acme.com"`,
    `subdomain = "api"`), or by reverting the restriction.

- [ ] **LOW — `CompiledRule::new` still accepts dotted subdomains** (src/matcher.rs, `Some(value) => normalize::host(value)`)
  - Only `config.rs` enforces the one-label rule. `agents.md` asks for one
    canonicalization contract, not checks duplicated per module. If anything
    builds a `CompiledRule` without going through `config::parse`, the two
    disagree.
  - Resolve by enforcing the label rule in the shared helper, or by having
    `CompiledRule::new` take an already-validated subdomain.

## Audit 2 — `80ff741` (2026-10-29)

Gates: `cargo fmt --check` OK · `cargo build` 0 warnings · `cargo test` 46/46 ·
`cargo clippy --all-targets -D warnings` OK.

- [ ] **HIGH — `//` paths accepted again; the fall-through bypass is now asserted as expected** (`80ff741`)
  - `classify("POST", "api.acme.com", "/v1//refunds/x")` returns
    `payment.read`, but `/v1/refunds/x` returns `payment.refund`.
    `duplicate_path_segments_are_preserved_for_matching` asserts the
    `payment.read` result.
  - Servers that merge slashes (nginx `merge_slashes on` by default, many
    framework routers) execute the refund. The agent gets a refund
    classified as a read.
  - It contradicts `Arch.md:351`, `Arch.md:436`, `agents.md:63` and the
    `tests/security.rs` module doc. The README says "Requests are matched as
    an HTTP client would send them", and the server-side interpretation is
    what makes the action dangerous.
  - Resolve by picking a policy and syncing code, tests and docs:
    - (a) Restore rejection, i.e. return `None`. That is fail-closed, and
      real clients essentially never send `//`.
    - (b) Collapse `//` for both rules and requests.
    - (c) Keep preserving it, but apply the same disagreement check
      already used for trailing slashes: classify the collapsed spelling too
      and return `None` if the classes differ.

    Do not keep a test that asserts the less sensitive class.

- [ ] **MED — Quadratic `remove_dot_segments` reintroduced** (src/normalize.rs, `80ff741`)
  - The `String::drain(..n)` / `replace_range` loop shifts the remaining
    buffer once per segment, so cost is O(segments × length).
  - With the same algorithm at `0ea6f30`, a 64 KB path took about 21 ms
    per `classify` in release, and much longer in debug.
  - That path is attacker-controlled input to an HTTP handler. The linear
    stack version this replaced can keep empty segments: push `""`
    segments instead of rejecting them.
  - At minimum, cap the request path length (e.g. 8 KiB, then `None`) and
    test it.

- [ ] **LOW — `//` in patterns is accepted silently** (`pattern_path("/v1//x")`)
  - Under the current policy a rule `/v1//x` is legal and distinct from
    `/v1/x`. Whatever HIGH resolution is chosen, patterns should follow the
    same rule as requests: rejected or collapsed in both, not one of each.

## Baseline gaps (pre-existing, found during Audit 1)

- [ ] **MED — No generated-input robustness tests** (Arch.md §17 "Robustness
  tests", agents.md completion gates)
  - Coverage is hand-picked inputs only. Arch asks for property-based or
    fuzz-style tests that `classify` never panics, is deterministic, and is
    unaffected by rule order.
  - A dev-only `proptest` (or a seeded byte-generator loop with no new
    dependency) would satisfy it.

- [ ] **LOW — Wildcard hosts with different base depths tie on host specificity** (src/matcher.rs `specificity`)
  - `*` on `acme.com` and `*` on `api.acme.com` both score `host = 0`. For
    `x.api.acme.com`, the deeper base doesn't rank higher, so path/method
    decide, and an equal-specificity tie becomes a load-time conflict.
  - This is deterministic and safe, but probably surprising. Consider adding
    base-host label count to host specificity, and document the result in
    Arch.md §11.

- [ ] **LOW — Compiled rules store `action_class: String`** (Arch.md §8 suggests `&'static str`)
  - Store the matching `ACTION_CLASSES` entry instead. This also makes "only
    predefined classes can be returned" hold by construction rather than by
    validation order.

- [ ] **LOW — `classify` allocates per call** (method `String`, host
  `String`, path `String`, plus the stripped-slash re-scan)
  - Fine at the expected scale (Arch.md §15 allows a linear scan). Revisit
    only if benchmarks show it matters.
