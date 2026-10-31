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

- [x] **HIGH — Method case-folding reverted; the fall-through bypass is back and is now asserted as expected behaviour** (`04ce80a`) — **resolved in `fc32096`: folding restored. Superseded by Audit 15, because folding alone left the reverse case open; non-uppercase spellings that disagree now return `None`**
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

- [x] **MED — Single-label subdomain restriction contradicts the docs** (`e8d5871`) — **resolved in `8a43772`: multi-label subdomains allowed again, matching `Arch.md:333`**
  - `config.rs` now rejects `subdomain = "api.eu"` (`is_dns_label`).
    `Arch.md:333` says "`*` or one or more valid DNS labels" and cites the
    README.
  - This is fail-closed, so there's no security impact. It's a deliberate
    narrowing of the README's "subdomain followed by host" wording.
  - Resolve by updating `Arch.md:333` back to a single label with a one-line
    rationale (the same host can still be written as `host = "eu.acme.com"`,
    `subdomain = "api"`), or by reverting the restriction.

- [x] **LOW — `CompiledRule::new` still accepts dotted subdomains** (src/matcher.rs, `Some(value) => normalize::host(value)`) — **resolved in `8a43772`: config and matcher both accept DNS names again**
  - Only `config.rs` enforces the one-label rule. `agents.md` asks for one
    canonicalization contract, not checks duplicated per module. If anything
    builds a `CompiledRule` without going through `config::parse`, the two
    disagree.
  - Resolve by enforcing the label rule in the shared helper, or by having
    `CompiledRule::new` take an already-validated subdomain.

## Audit 2 — `80ff741` (2026-10-29)

Gates: `cargo fmt --check` OK · `cargo build` 0 warnings · `cargo test` 46/46 ·
`cargo clippy --all-targets -D warnings` OK.

- [x] **HIGH — `//` paths accepted again; the fall-through bypass is now asserted as expected** (`80ff741`) — **resolved in `fc32096` via option (a): `//` rejected. Re-verified in Audit 15: `empty_path_segments_are_unclassified` and `generated_paths_classify_only_when_they_are_unambiguous`**
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

- [x] **MED — Quadratic `remove_dot_segments` reintroduced** (src/normalize.rs, `80ff741`) — **resolved in `fc32096`: linear stack version restored. Re-verified in Audit 15: `normalization_stays_linear_well_beyond_the_request_limit`**
  - The `String::drain(..n)` / `replace_range` loop shifts the remaining
    buffer once per segment, so cost is O(segments × length).
  - With the same algorithm at `0ea6f30`, a 64 KB path took about 21 ms
    per `classify` in release, and much longer in debug.
  - That path is attacker-controlled input to an HTTP handler. The linear
    stack version this replaced can keep empty segments: push `""`
    segments instead of rejecting them.
  - At minimum, cap the request path length (e.g. 8 KiB, then `None`) and
    test it.

- [x] **LOW — `//` in patterns is accepted silently** (`pattern_path("/v1//x")`) — **resolved in `fc32096`: `pattern_path("/v1//x")` is `None`. Re-verified in Audit 15: `configured_patterns_follow_the_request_path_rules`**
  - Under the current policy a rule `/v1//x` is legal and distinct from
    `/v1/x`. Whatever HIGH resolution is chosen, patterns should follow the
    same rule as requests: rejected or collapsed in both, not one of each.

## Audit 3 — `8a43772`, `fc32096` (2026-10-29)

Gates: `cargo fmt --check` OK · `cargo build` 0 warnings · `cargo test` 47/47 ·
`cargo clippy --all-targets -D warnings` OK.

These commits restore the documented policies (multi-label subdomains,
upper-case method folding, `//` rejection, linear dot-segment removal). Code,
tests, `Arch.md` and `agents.md` agree again on all Audit 1/2 items.

- [x] **LOW — Redundant assertion in `method_case_does_not_fall_through_to_method_less_rule`** (tests/security.rs) — **resolved in `09a4754`**
  - The standalone `DELETE` assertion duplicates the first iteration of the
    loop that follows. It's harmless; drop it for clarity.

- [x] **LOW — Policy churn is visible in history** (`04ce80a` → `fc32096`, `e8d5871` → `8a43772`, `80ff741` → `fc32096`) — **resolved in the working tree on top of `2907b0d` (uncommitted): Arch.md §7/§9 record the rationale for each final policy. The history itself stays visible, so be ready to discuss it**
  - Three policies were reverted and then restored within ten minutes.
    Reviewers will read the history and transcript. Be ready to explain
    the decision for each, or record the rationale in Arch.md §7/§9 so the
    final state reads as deliberate.

## Audit 4 — `61aa677` (2026-10-29)

Gates: `cargo fmt --check` OK · `cargo build` 0 warnings · **`cargo test`
FAILS: 5 failures** · `cargo clippy --all-targets -D warnings` OK.

- [x] **HIGH — Two README starter tests fail; the deliverable gate is broken** (`61aa677`, src/lib.rs `classify`) — **resolved in `c2e2283`: an unclassified alternative spelling no longer counts as disagreement; 4/4 example tests pass**
  - The trailing-slash check is now symmetric and treats "the other spelling
    is unclassified" as a disagreement. So every exact rule is denied unless
    the opposite-slash spelling is also covered by a rule with the same class.
  - Failing tests:
    - `example.rs`: `exact_rule_matches` (`GET api.acme.com
      /v1/payment_intents` → `None`, expected `payment.read`) and
      `rule_without_subdomain_applies_to_the_host_itself` (`/pricing` →
      `None`).
    - `classification.rs`: `most_specific_rule_wins` and
      `host_patterns_respect_label_boundaries`.
    - `conflicts.rs`: `same_class_duplicates_are_harmless`.
  - README deliverable 1 requires `cargo test` to pass, and `agents.md`
    says to keep the four example tests passing.

- [x] **HIGH — Specific rules under a broader wildcard become unreachable** (same change) — **resolved in `5b59802`: one-way check restored; `/v1/msg/send` and `/v1/payouts` classify again; Arch.md:437 and agents.md:63 updated**
  - Even if `None` alternatives were ignored, a symmetric check denies any
    narrower rule nested under a wildcard. With `/v1/*/send` →
    `communication.external.send` and `/v1/*` → `payment.read`, the request
    `/v1/msg/send` is denied, because `/v1/msg/send/` matches only `/v1/*`.
    The same happens to the test file's `/v1/payouts` → `payment.create`
    rule, which `trailing_slash_that_changes_the_class_is_unclassified` now
    asserts as `None`.
  - That is fail-closed, so it isn't a bypass. But it silently disables
    ordinary configurations, and README-style rule sets stop working.
  - Recommended resolution: revert to the one-directional check from
    `8a7f3ae`:
    - only when the request ends in `/`, also classify the stripped
      spelling;
    - deny only if that is `Some` and different.

    Rationale: the path as sent is authoritative. The ambiguity worth
    guarding is servers *stripping* a trailing slash, while servers adding
    one is rare (redirects aside, which go through classification again).
    If symmetric checking is wanted anyway, document it in Arch.md §9 and
    update all five affected tests. Expect to justify why README examples
    no longer classify.

## Audit 5 — `497f84f` (2026-10-29)

Gates: `cargo fmt --check` OK · `cargo build` 0 warnings · **`cargo test`
still FAILS: the same 5 failures as Audit 4** (the new tests pass) ·
`cargo clippy --all-targets -D warnings` OK.

The bounded overlap check fits Arch.md §13: "reject potentially conflicting
patterns with an explicit error" rather than accept an unresolved ambiguity.
The 1M-state cap is checked with `checked_add`/`checked_mul` before
allocating, and the flat `Vec<bool>` replaces nested vectors. Both new tests
pass.

- [x] **LOW — Identical patterns are reported as "too complex" instead of as a conflict** (src/matcher.rs `globs_overlap`) — **resolved in `98788f4`: `left == right` short-circuits before the budget**
  - Two rules with the same 1,000-`*` path and different classes are
    trivially a conflict. They get `ConflictAnalysisTooComplex`, which
    points the user at the wrong problem.
  - Short-circuit `left == right` (and `None`/`None`) to `Ok(true)` before the
    size check.

- [x] **LOW — The cap is per pair, with no total budget** (`find_conflict`) — **addressed in `b2d8402`, but it overcorrects; see Audit 6 MED**
  - Load cost is up to `n² × 1M` states when many long equal-specificity
    wildcard rules share a host and method. Config is user-supplied and
    `load` runs in an HTTP handler (README), so a large set could stall a
    worker.
  - Consider a pattern-length limit at validation (e.g. 2 KiB) or a total
    state budget across all pairs. Note it in Arch.md §16.

- [x] **LOW — New `LoadError` variant isn't documented** (Arch.md §14 lists error categories) — **resolved in `98788f4`: Arch.md §14 lists `ConflictAnalysisTooComplex` and `TooManyRules`**
  - Add "conflict analysis too complex" next to "Conflicting rules" so the
    docs match the public enum.

- Still open: both Audit 4 HIGH items. `tests/classification.rs` and the new
  `tests/robustness.rs` were being edited during this audit and will be
  audited once committed.

## Audit 6 — `c2e2283`, `b2d8402` (2026-10-29)

Gates (each commit checked separately; `c2e2283` from a clean export):
`cargo fmt --check` OK · `cargo build` 0 warnings · `cargo test` 51/51 at
`c2e2283`, 52/52 at `b2d8402` · `cargo clippy --all-targets -D warnings` OK.

- [x] **HIGH (carried from Audit 4) — Nested-wildcard rules unreachable, now asserted by a test** (src/lib.rs `classify`, tests/classification.rs `most_specific_rule_wins`) — **resolved in `5b59802`: one-way check restored; `/v1/msg/send` and `/v1/payouts` classify again; Arch.md:437 and agents.md:63 updated**
  - The check is still symmetric. `GET api.acme.com/v1/msg/send`, with
    rule `/v1/*/send` → `communication.external.send`, now returns `None`,
    and the test expects `None`. Any narrower rule under a broader wildcard
    is unreachable unless the narrow pattern also matches the slash-appended
    form.
  - It is fail-closed, so not a bypass. But a reviewer reading
    `most_specific_rule_wins` will see that "most specific wins" fails in an
    ordinary case. README: "When several rules match a request, the most
    specific wins."
  - Arch.md:437 describes only the `/x/` → `/x` direction, not appending a
    slash.
  - Resolve with the one-directional check from Audit 4 (only strip the
    slash from a request that ends in `/`). Otherwise document the
    symmetric rule and its cost in Arch.md §9 and name this trade-off in
    the test.

- [x] **MED — Pair-check cap limits every load to about 447 rules in total** (`b2d8402`, src/matcher.rs `find_conflict`) — **resolved in `98788f4`: the pair cap was replaced by a total state budget charged only to eligible pairs. See Audit 11 for a new MED in its place**
  - `checked_pairs` counts every pair before any filtering. 448 rules fail
    to load even when they are all disjoint: different hosts, same class,
    or different specificity. A realistic deployment that loads several
    provider mapping sets could reach this and get
    `ConflictAnalysisTooComplex`.
  - That error names an arbitrary pair that has nothing to do with the
    cause, which is misleading.
  - Resolve by counting only pairs that reach the expensive step (different
    class, equal specificity, overlapping method and host). Or group rules
    by host pattern and specificity first, so only same-group pairs are
    compared. Or replace both caps with one total budget of glob-overlap
    states. Document the limit in Arch.md §14/§16.

- [x] **LOW — `same_class_duplicates_are_harmless` was weakened** (`c2e2283`, tests/conflicts.rs) — **resolved in `09a4754`: `/x` restored**
  - The rule changed from `/x` to `/x*`, apparently to get past the
    trailing-slash failure that `c2e2283` itself then fixed. The test no
    longer covers exact duplicate rules.
  - Restore `/x`; it passes with the current `classify`.

- [x] **LOW — Robustness generator rarely produces valid input** (tests/robustness.rs) — **resolved in `db5a4c7`: 80% of generated requests are valid, with an assertion that at least 500 of 2,000 classify and that results are in `ACTION_CLASSES`**
  - Hosts are random strings from a 15-character alphabet, so almost none
    parse as `*.acme.com`. Nearly every iteration exits at host
    normalization, and the matcher, glob and trailing-slash code is barely
    exercised.
  - The determinism and order-independence assertions therefore mostly
    compare `None` to `None`.
  - Bias the generator: choose the host from a small valid set (e.g.
    `api.acme.com`, `x.acme.com`, `acme.com`), build the path from valid
    segments, then mutate. Also assert that the result is `None` or a
    member of `ACTION_CLASSES` (Arch.md §17).

## Audit 7 — `5b59802` (2026-10-29)

Gates (clean export): `cargo fmt --check` OK · `cargo build` 0 warnings ·
`cargo test` 52/52 · `cargo clippy --all-targets -D warnings` OK.

Code, tests, Arch.md §9 and agents.md now agree on the one-way trailing-slash
rule. No new findings. Open after this audit: MED pair-check cap (Audit 6),
plus the LOW items.

## Audit 8 — `4b49f06` (2026-10-29)

Gates (re-run from a clean export; the first run accidentally included
uncommitted `7235e08` work): `cargo fmt --check` OK · `cargo build` 0 warnings · `cargo test` 52/52 ·
`cargo clippy --all-targets -D warnings` OK. Arch.md §9 and agents.md were
updated together with the code.

Rejecting an all-numeric final label closes the IPv4 short forms (`127.1`,
`010.0.0.1`, `1.2.3.4.5`) that `Ipv4Addr::from_str` misses. This is
consistent with "Reject unsupported IP literal representations".

- [x] **LOW — Numeric exact subdomains can no longer be configured** (src/config.rs subdomain validation → `normalize::host`) — **resolved in `2907b0d`: the combined host is validated**
  - Subdomain validation reuses `normalize::host`, where a bare label is its
    own "final label". So `subdomain = "123"` and `subdomain = "api.1"` now
    fail to load, although `123.acme.com` is an ordinary DNS name.
  - Probe: `subdomain = "123"` loads → `false`. The request `123.acme.com`
    still classifies through `subdomain = "*"`, so this is only a config
    restriction (fail-closed).
  - Resolve by applying the numeric-final-label check to the *combined*
    host (`subdomain.host`), or to request and base hosts only. Validate
    subdomains with the DNS-label rules alone.

- [x] **LOW — Hex IPv4 forms still pass as hostnames** (src/normalize.rs `host`) — **incorrectly closed in `2907b0d`, which only rejected a whole name starting with lowercase `0x`; `0x7f.0x1` and `x.0X7F000001` still loaded (reproduced in Audit 15). Now resolved in the working tree on top of `2907b0d` (uncommitted): the final label is checked as this entry recommended. Tests: `hosts_ending_in_an_ipv4_number_are_rejected_in_configuration`, `normalizes_hosts_and_rejects_ambiguous_authorities`**
  - WHATWG URL parsing treats a host whose last label is `0x`-prefixed hex
    as IPv4: `0x7f000001` is `127.0.0.1`, and so is `0x7f.1`. Here
    `0x7f.1` is caught (last label `1`), but `0x7f000001` is not.
  - Probe: `host = "0x7f000001"` loads → `true`. The same request host
    would match that rule as if it were a DNS name.
  - Impact is limited: a config must name the IP-like host itself, and no
    domain-based rule matches it. Still, it contradicts the
    "unsupported IP literal" contract.
  - Resolve by extending the final-label check to WHATWG's "ends in a
    number": all digits, or `0x`/`0X` followed by hex digits (including a
    bare `0x`).

## Audit 9 — `7235e08` (2026-10-29)

Gates: `cargo fmt --check` OK · `cargo build` 0 warnings · `cargo test` 53/53
(the new `compiled_rules_only_retain_known_action_classes` runs) ·
`cargo clippy --all-targets -D warnings` OK. Arch.md §8 was updated in the
same commit.

`CompiledRule.action_class` is now the `&'static str` from `ACTION_CLASSES`,
looked up in `CompiledRule::new`. `classify` can therefore only return a
predefined class, by construction (Arch.md §19). It also checks again what
`config.rs` validates, so the guard holds even if the two drift apart. No new
findings.

## Audit 10 — `db5a4c7`, `09a4754` (2026-10-29)

Gates (each from a clean export): `cargo fmt --check` OK · `cargo build`
0 warnings · `cargo test` 53/53 at both · `cargo clippy --all-targets -D
warnings` OK. Arch.md §17 now requires generated coverage to include valid,
matching requests, and `db5a4c7` provides it.

- [x] **LOW — Valid generated requests come from a fixed pool of 320 combinations** (tests/robustness.rs `generated_request`) — **resolved in the working tree on top of `2907b0d` (uncommitted): `generated_equivalent_spellings_classify_identically` mutates valid tuples (host case, port, trailing dot, query, fragment, dot segments, escapes, trailing slash), and the method, host, and path generators produce varied valid values**
  - Valid tuples are picked from 4 methods × 4 hosts × 5 paths × 4 (the
    random branch), with no mutation. Trailing slashes, ports, host case,
    trailing dots and `//` never appear in a *valid* request.
  - So the trailing-slash comparison and host normalization are covered
    only by the hand-written tests.
  - Optional: mutate a valid tuple after choosing it (append `/`, add
    `:443`, uppercase the host, add a trailing `.`, insert `%2e`), and
    assert that classification is unchanged or `None`.

- [x] **LOW — Minimum Rust version is undeclared** (Cargo.toml) — **addressed in `2907b0d`, but with the wrong value; see Audit 14**
  - `src/` uses `if let … &&` let-chains, stable in Rust 1.88.
    `tests/robustness.rs` uses `u64::is_multiple_of`, stable in 1.87.
    `edition = "2024"` alone only implies 1.85.
  - A reviewer on Rust 1.85–1.87 gets compile errors instead of a clear
    "requires rustc 1.88" message. Builds here use 1.97.1.
  - Add `rust-version = "1.88"` to `[package]`.

## Audit 11 — `98788f4` (2026-10-29)

Gates (clean export): `cargo fmt --check` OK · `cargo build` 0 warnings ·
`cargo test` 58/58 (re-confirmed with an isolated build) · `cargo clippy --all-targets -D warnings` OK. Arch.md §13,
§14, §16 and agents.md document the new limits in the same commit.

- [x] **MED — Plain exact-path rules use up the wildcard budget; about 400 ordinary rules fail to load** (src/matcher.rs `paths_overlap` → `globs_overlap`) — **resolved in `d2d8067`: literal pairs short-circuit, and the 400-rule probe now loads. See Audit 14 for the wildcard-prefix variant**
  - Any eligible pair whose paths differ goes through the product-NFA
    search, even when neither path contains `*`. Two same-length literals,
    such as `/api/00001` and `/api/00002`, have equal specificity, so each
    pair is charged `(len+1)²` states (121 here) just to learn that the
    paths differ.
  - Probe (clean export, release build): one set on `acme.com`, rules
    `path = "/api/NNNNN"` alternating `repo.read` / `repo.write`:

    | rules | result |
    |---|---|
    | 200 | loads (6 ms) |
    | 400 | `ConflictAnalysisTooComplex` ("rule 230 and rule 363") |
    | 800 / 2,000 / 10,000 | same error |

    That is an ordinary REST mapping, well under the documented 10,000-rule
    limit.
  - The new tests miss it: `same_class_rules_do_not_consume_overlap_budget`
    uses one class, so no pair is eligible. The error also blames a pair of
    rules that cannot conflict.
  - Resolve by spending budget only on wildcard-wildcard pairs:
    - neither path contains `*` → overlap is `left == right`;
    - exactly one contains `*` → overlap is
      `glob_matches(pattern, literal)`, which is linear in practice;
    - only two wildcard patterns need `globs_overlap`.

    Add a test with hundreds of different-class exact paths.

- [x] **LOW — Pattern-length cap is enforced only in `config.rs`** (`MAX_PATTERN_BYTES`) — **resolved in `2907b0d`: `CompiledRule::new` enforces `MAX_PATTERN_BYTES`**
  - `CompiledRule::new` accepts any length. The state-budget sizing assumes
    the cap, so any future path that builds rules without `config::parse`
    breaks that assumption. This is the same drift risk as the Audit 1
    subdomain item.
  - Move the check next to `normalize::pattern_path`, or into
    `CompiledRule::new`.

- [ ] **LOW — Pairwise loop is O(n²) even when no budget is spent**
  - 10,000 single-class exact rules took 136 ms to load in release (about
    50M pair comparisons), and debug builds are much slower. `load` runs in
    an HTTP handler (README).
  - This is acceptable for the stated limits. If larger configs matter,
    bucket rules by `(host pattern, specificity)` before comparing pairs.

## Audit 12 — `11bbeb6` (H7) … `fb3adea` (H11) (2026-10-29)

Gates (each commit from a clean export, re-run with an isolated `target/`
per commit after a shared build dir was found to give stale results): fmt OK ·
build 0 warnings · tests 59 / 60 / 61 / 61 / 61, all passing · clippy OK at
every commit. The probes below were re-confirmed with isolated builds. Each commit updates
Arch.md and agents.md together with the code.

- H7 rejects literal `;` in request and pattern paths. `%3B` is kept encoded.
  Tomcat, Jetty and Spring strip `;` parameters before decoding, so that is
  consistent.
- H8 ranks wildcard hosts by base depth (resolves the baseline item) and
  requires at least two labels in a base host.
- H9 caps methods at 32 bytes and raw paths at 8 KiB. That fails closed and
  matches common server request-line limits.
- H10 rejects `method = "*"` and configured dot segments, consistent with
  "explicit validation over silent correction".
- H11 includes the rejected value in `InvalidRule`. Arch.md §5/§14 now
  describe the real test layout and error enum, and the §14 example matches
  the actual `Display` output.

- [x] **MED (carried from Audit 11, still reproduces at `fb3adea`) — 400 exact-path rules with two classes fail with `ConflictAnalysisTooComplex`** — **resolved in `d2d8067`**
  - Same probe, same result ("rule 230 and rule 363"). None of H7–H11 touch
    `paths_overlap`.

- [ ] **LOW — Two-label minimum does not stop public-suffix bases; the new test relies on one** (src/config.rs `validate_host`, tests/classification.rs `deeper_wildcard_base_host_wins_before_path_specificity`)
  - `host = "co.uk"` with `subdomain = "*"` still loads.
  - Probe: `classify("POST", "api.bank.co.uk", "/transfer")` →
    `Some("llm.inference")`. Every `.co.uk` site gets whatever class the
    broad rule names. If policy allows that class, requests to unrelated
    sites are allowed.
  - Arch.md:332 presents the two-label rule as preventing wildcards rooted
    at a public suffix. It only covers single-label suffixes such as `com`.
  - Resolve with either:
    - (a) document it as a heuristic and say that multi-label public
      suffixes (`co.uk`, `com.au`, `github.io`) are the config author's
      responsibility, ideally with the test using a non-suffix base such as
      `example.co.uk`; or
    - (b) embed a small static denylist of common multi-label suffixes for
      `*` rules. The no-I/O constraint rules out fetching the PSL.

- [x] **LOW — Error messages echo the entire rejected value** (`SetError::InvalidRule { value }`, H11) — **resolved in `2907b0d` for `InvalidRule`/`UnknownActionClass` (256-byte `diagnostic_value`). See Audit 14 for TOML errors**
  - A 1 MB invalid `path` produces a 1,000,051-byte `LoadError` message.
    Callers often log or return this from an HTTP handler, so it can bloat
    logs or responses.
  - Truncate the stored or displayed value, e.g. to 128 characters plus
    `…`, and test it.

## Audit 13 — `5d78ae8` (H12) (2026-10-29)

Gates (clean export, isolated `target/`): fmt OK · build 0 warnings ·
`cargo test` 64/64 · clippy OK. Arch.md §9 (including a new "Known limits"
list) and agents.md were updated in the same commit.

Auditor process note: Audits 10–12 originally shared one `CARGO_TARGET_DIR`
across exports, and cargo reused stale artifacts. Pass/fail results still
hold after re-running each commit in isolation; only the test counts above
were corrected. Every audit from here on uses a fresh target per commit.

- [x] **MED — Rules with uppercase literals become unreachable when a broader rule covers their lowercase spelling** (src/lib.rs `classify`, H12) — **resolved in `649bdd7`/`2907b0d`: lowercased requests are compared with precomputed `folded_path`. The Twilio-style probe classifies as configured**
  - The lowercase alternative is matched against the original,
    case-sensitive patterns. A configured route such as
    `/2010-04-01/Accounts/*/Messages.json` (Twilio's real casing) matches
    the request as sent. But its lowercased copy `/2010-04-01/accounts/…`
    matches only a broader rule, so the classes "disagree".
  - Probe (Twilio-style set with a catch-all `/*` → `repo.read`):
    - `POST /2010-04-01/Accounts/AC123/Messages.json` → **`None`**.
      Expected `communication.external.send`. The broad
      `Accounts/*` rule with no method also loses.
    - The `GET` spellings return `repo.read` only because the catch-all
      happens to share that class.
  - This is the same nested-rule failure as Audit 4/6, now for any API
    whose paths contain capitals: Twilio, Azure, many AWS services. The new
    test `/v1/IDs/*` passes only because no broader rule exists.
  - Resolve by comparing case-insensitively on both sides. Precompute a
    lowercased copy of each pattern at load, and match the lowercased
    request against those copies for the alternative. A rule that matches
    as configured then also matches its own lowercase spelling, so only a
    genuinely different case-insensitive winner causes denial. Add a test
    with an uppercase-literal rule nested under a broader rule.

- [x] **LOW — `lowercase_path_outside_escapes` indexes without bounds checks** (src/normalize.rs, `bytes[index + 1]`, `bytes[index + 2]`) — **resolved in `2907b0d`: uses `bytes.get`**
  - Safe today, because callers pass only paths already validated by
    `decode_unreserved`. But this is a panic site on the `classify` path,
    and its safety rests on a cross-function invariant. agents.md: "No
    unwrap/expect on untrusted inputs; classify must never panic."
  - Use `bytes.get(index + 1..index + 3)` and copy whatever is present, or
    make it a private helper that takes the validated type.

- Still open at `5d78ae8`, re-confirmed with isolated builds: the Audit 11
  exact-path budget MED (400 rules → `ConflictAnalysisTooComplex`), the
  Audit 12 `co.uk` wildcard LOW, and the Audit 12 unbounded-error-value LOW
  (1 MB path → 1,000,051-byte message).

## Audit 14 — `649bdd7`, `d2d8067`, `2907b0d` (2026-10-29)

Gates (each commit, clean export, isolated `target/`): fmt OK · build
0 warnings · tests 63 / 64 / 67, all passing · clippy OK. Arch.md §7, §9,
§13, §14, §16 and agents.md updated in step.

Probes at `2907b0d`, release build:

| probe | result |
|---|---|
| 400 exact paths, 2 classes | **loads** (was `TooComplex`) |
| Twilio-style `POST …/Accounts/*/Messages.json` under `/*` | `communication.external.send` |
| same, lowercased | `None` (disagreement, as intended) |

- [ ] **MED — Wildcard rules with distinct literal prefixes still exhaust the budget** (src/matcher.rs `paths_overlap` → `globs_overlap`)
  - Probe: 400 rules `path = "/api/NNNNN/*"` alternating
    `repo.read`/`repo.write` → `ConflictAnalysisTooComplex` ("rule 212 and
    rule 307"). This is the most common REST mapping shape: `/v1/customers/*`,
    `/v1/charges/*`, `/v1/refunds/*` …, with different classes.
  - Two such patterns can never overlap, because their literal prefixes
    differ before the first `*`. Yet each pair is charged about
    `(len+1)²` states.
  - Resolve with a linear pre-check before `globs_overlap`:
    - compare the literal prefixes up to each pattern's first `*`, and the
      literal suffixes after each pattern's last `*`;
    - if either pair diverges within the shorter length, return
      `Ok(false)` without spending budget.

    Add the 400-rule prefix-wildcard case as a test.

- [ ] **LOW — `rust-version = "1.85"` is too low** (Cargo.toml)
  - `src/config.rs` uses `if let … &&` let-chains (e.g. lines 60–61 and
    69–71), which were stabilised in Rust **1.88**. Edition 2024 alone
    allows them only from 1.88.
  - On 1.85–1.87, Cargo accepts the declared MSRV and rustc then fails on
    the let-chains. That is the confusing failure the field is meant to
    prevent. Changing `is_multiple_of` to `% 5 == 0` in `robustness.rs` does
    not help.
  - Set `rust-version = "1.88"`. Only 1.95 and stable are installed here, so
    this was not verified by building on 1.85.

- [ ] **LOW — TOML parse errors are still unbounded** (`SetError::Toml`)
  - `toml`'s error display quotes the offending source line. Probe: an
    invalid document with a 1 MB line gives a **2,000,160-byte** `LoadError`
    message.
  - `diagnostic_value` covers only `InvalidRule` and `UnknownActionClass`.
    Store a bounded rendering, such as the message without the snippet or
    a truncated `to_string()`, or cap the input size before parsing.

- Still open: the `co.uk` public-suffix wildcard LOW from Audit 12. It still
  loads at `2907b0d`.

## Audit 15 — final security and submission pass (2026-10-31)

Base `2907b0d` plus uncommitted working-tree changes. No fixing commit exists
yet, so entries closed here cite tests and name the working tree. Replace that
wording with the hash when this work is committed.

Gates (fresh `target/`): `cargo fmt --check` OK · `cargo build` 0 warnings ·
`cargo test --all-targets` 83/83 (67 at the base) ·
`cargo clippy --all-targets -- -D warnings` OK. Each fix below had a failing
test first: 7 tests failed against `2907b0d`.

Rechecked at the base and already fixed, with no code change needed:

- `POST /v1//refunds/x` returns `None`; `//` in a pattern fails to load.
- `remove_dot_segments` is linear. At the 8 KiB cap, `classify` took 20–62 µs
  per call in release for the worst dot-heavy paths. The new guard fails when
  the old buffer-shifting algorithm is put back.

- [x] **HIGH — Method folding could report a less sensitive class than a case-sensitive server executes** (`src/lib.rs` `classify`) — **resolved in the working tree on top of `2907b0d` (uncommitted)**
  - Rules `/x` → `payment.refund` and `GET /x` → `payment.read`: `get /x`
    returned `payment.read`. A case-sensitive router (Go's `ServeMux`) sends
    `get` to the catch-all handler, so the refund runs classified as a read.
  - A folded and a case-sensitive reading are now compared, and disagreement
    returns `None`. This changes one existing expectation:
    `method_case_does_not_fall_through_to_method_less_rule` now asserts `None`
    instead of `payment.refund` for `delete`/`Delete`. Action classes have no
    sensitivity order, so the two directions cannot be told apart.
  - Tests: `method_case_cannot_reach_a_less_sensitive_method_specific_rule`,
    `method_case_classifies_when_both_readings_agree`,
    `generated_method_case_never_selects_a_class_one_reading_contradicts`.

- [x] **HIGH — Classification depended on rule order for patterns differing only by case** (`src/lib.rs` `best_match`) — **resolved in the working tree on top of `2907b0d` (uncommitted)**
  - Rules `/v1/Refunds` → `payment.refund` and `/v1/refunds` → `payment.read`
    pass the load check but tie once folded, and `max_by` picked the last.
    `/v1/Refunds` returned `None` in one order and `payment.refund` in the other,
    against README "no precedence". A tie now denies the request.
  - Tests: `patterns_differing_only_by_case_do_not_depend_on_rule_order`,
    `generated_rule_sets_classify_identically_in_every_order`.

- [ ] **LOW — `classify` is slow at the configuration limits with adversarial patterns** (`glob_matches`, new in this audit)
  - 10,000 rules of about 1 KiB `/*a*a…b` against an 8 KiB `/`-ending path took
    0.64 s (`GET`) and 1.29 s (`get`) in release, compared with 0.4 ms for 10,000
    ordinary exact rules. It needs such patterns in the mapping files, so it
    is not reachable from requests alone. Documented in Arch.md §16.

- Rechecked and still open at this audit: Audit 14 MED (400 `/api/NNNNN/*` rules →
  `ConflictAnalysisTooComplex`; 200 load), Audit 14 LOW `rust-version`, Audit 14
  LOW TOML errors (1 MB line → 2,000,134-byte message), Audit 12 LOW `co.uk`
  (still loads), Audit 11 LOW pair loop (10,000 rules, 138 ms), Baseline LOW per-call
  allocations.

## Baseline gaps (pre-existing, found during Audit 1)

- [x] **MED — No generated-input robustness tests** (Arch.md §17 "Robustness — **started in `c2e2283` and `db5a4c7`; resolved in the working tree on top of `2907b0d` (uncommitted): `tests/robustness.rs` now has generated malformed-method, host, and path checks, a reference wildcard matcher, and rule-order, method-case, and equivalent-spelling properties**
  tests", agents.md completion gates)
  - Coverage is hand-picked inputs only. Arch asks for property-based or
    fuzz-style tests that `classify` never panics, is deterministic, and is
    unaffected by rule order.
  - A dev-only `proptest` (or a seeded byte-generator loop with no new
    dependency) would satisfy it.

- [x] **LOW — Wildcard hosts with different base depths tie on host specificity** (src/matcher.rs `specificity`) — **resolved in `f04706c`: base-host label depth ranks right after host kind**
  - `*` on `acme.com` and `*` on `api.acme.com` both score `host = 0`. For
    `x.api.acme.com`, the deeper base doesn't rank higher, so path/method
    decide, and an equal-specificity tie becomes a load-time conflict.
  - This is deterministic and safe, but probably surprising. Consider adding
    base-host label count to host specificity, and document the result in
    Arch.md §11.

- [x] **LOW — Compiled rules store `action_class: String`** (Arch.md §8 suggests `&'static str`) — **resolved in `7235e08`**
  - Store the matching `ACTION_CLASSES` entry instead. This also makes "only
    predefined classes can be returned" hold by construction rather than by
    validation order.

- [ ] **LOW — `classify` allocates per call** (method `String`, host
  `String`, path `String`, plus the stripped-slash re-scan)
  - Fine at the expected scale (Arch.md §15 allows a linear scan). Revisit
    only if benchmarks show it matters.
