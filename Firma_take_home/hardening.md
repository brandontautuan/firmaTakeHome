# HARDENING.md — steering for the coding agent

Read this after `README.md`, `agents.md` and `Arch.md`. It turns the security
audit of `b2d8402` (see `backlog.md`) into ordered, bounded work items.

Precedence stays the same: README > fixed API > `agents.md` > `Arch.md` > this
file. If an item here conflicts with the README, stop and flag it.

## Ground rules

1. **Follow the design; only extend it where a defect was demonstrated.** Every
   item below either brings the code back in line with `Arch.md` (Tier 1), or
   adds to the design to close a reproduced problem (Tier 2/3). Do not
   restructure modules, add indexing, add dependencies, or "optimize" beyond
   what an item asks for. A linear scan is the accepted design (Arch §15).
2. **One item per commit.** Each commit contains the code change, a test that
   would have failed before it, and the matching `Arch.md` / `agents.md` edit.
   Code and docs must never disagree at any commit. The commit message names
   the item number (e.g. `H6: total conflict-analysis budget`).
3. **Never weaken a test to make it pass.** Never write a test that asserts the
   *less* sensitive class for an alternate spelling of a request. If a test
   seems wrong, stop and report rather than editing the expectation.
4. **Fail closed.** When unsure, the request is unclassified (`None`) or the
   config is rejected with an explicit `LoadError`. Never pick a class by
   guessing.
5. **Don't flip-flop on policy.** The policies in `Arch.md` §7/§9/§11 are
   decided. Do not revert method folding, `//` rejection, multi-label
   subdomains, or linear dot-segment removal.
6. **Same canonicalization both sides.** Any new path or host rule goes in the
   shared helpers in `normalize.rs` and applies to both config patterns and
   requests, unless the item says otherwise.
7. **Gates on every commit**, run from `Firma_take_home/`:
   ```bash
   cargo fmt --all -- --check
   cargo build
   cargo test
   cargo clippy --all-targets -- -D warnings
   ```
   The four tests in `tests/example.rs` must pass unchanged.
8. No `unwrap`/`expect` on untrusted input. `classify` must never panic. Keep
   `Classifier` `Send + Sync` and immutable after `load`.

## Work order

Do the items in this order. Stop after each tier and report.

---

## Tier 1 — make the code match the design

### H1. Check trailing slashes in one direction only (open HIGH, Audit 4/6)

- **Problem:** `classify` also checks `/x` against `/x/`. A narrower rule under
  a broader wildcard can never match: with `/v1/*/send` →
  `communication.external.send` and `/v1/*` → `payment.read`,
  `GET api.acme.com/v1/msg/send` returns `None`. This breaks README "the most
  specific wins".
- **Change (`src/lib.rs` `classify`):** only when the normalized path ends in
  `/` and isn't `/`, classify the path without that slash as well. Return
  `None` only if that result is `Some` and differs. A path without a trailing
  slash gets no alternate check.
- **Rationale for the doc:** the risk is a server stripping a trailing slash
  and running a more sensitive handler than the one classified. A request sent
  without the slash is already classified as sent.
- **Tests:**
  - `tests/classification.rs` `most_specific_rule_wins`: `/v1/msg/send` →
    `Some("communication.external.send")`.
  - `tests/security.rs`: `POST /v1/payouts` → `Some("payment.create")`, and
    `POST /v1/payouts/` → `None`.
  - Rename the security test to match the one-directional behaviour.
- **Docs:** Arch §9 and agents.md "Paths" say the check goes one way, with the
  rationale above.

### H2. Reject IP-like hosts (Arch §7, §9)

- **Problem:** only dotted-quad IPv4 is rejected. `010.0.0.1` and `127.1` load
  as config hosts and are accepted as request hosts.
- **Change (`normalize::host`):** reject any host whose last label is all
  digits. No real TLD is all-numeric (RFC 3696 §2). Config uses the same
  helper, so both sides are covered.
- **Tests:** a config `host` of `127.1` or `010.0.0.1` is rejected. A request
  host of `127.1`, `010.0.0.1` or `1.2.3.4.5` gives `None`.

### H3. Store the action class as `&'static str` (Arch §8)

- **Change:** `CompiledRule::action_class` holds the matching `ACTION_CLASSES`
  entry, found at compile time. An unknown class is a `CompileError`, which
  `load` maps to `SetError::UnknownActionClass`. `best_match` returns the
  stored reference.
- **Why:** only the seven classes can come back, guaranteed by the type rather
  than by validation order.

### H4. Make the robustness tests reach the matcher (Arch §17)

- **Problem:** the generator's alphabet doesn't contain `c`, `m` or `e`, so no
  generated host is ever under `acme.com`. Both tests only ever compare `None`
  with `None`.
- **Change (`tests/robustness.rs`):**
  - Pick the method from {`GET`, `POST`, `DELETE`, `get`, generated junk}.
  - Pick the host from {`api.acme.com`, `x.acme.com`, `a.b.acme.com`,
    `acme.com`, generated junk}.
  - Build the path from valid segments (`v1`, `refunds`, `x`, `.`, `..`,
    `%72efunds`, an empty last segment), then randomly mutate one byte.
- **Asserts:**
  - Results are deterministic and independent of set order.
  - Every result is `None` or a member of `ACTION_CLASSES`.
  - At least 25% of iterations classify to `Some`, so the test fails if the
    generator stops reaching the matcher again.
  - Use no new dependencies.

### H5. Test cleanups

- `tests/conflicts.rs` `same_class_duplicates_are_harmless`: change the path
  back from `/x*` to `/x`.
- `tests/security.rs` `method_case_does_not_fall_through_to_method_less_rule`:
  remove the standalone `DELETE` assertion that the loop already covers.
- `tests/conflicts.rs:165`: remove the stale "Exact subdomains are one DNS
  label" comment.

---

## Tier 2 — hardening that adds to the design

### H6. Bound the cost of conflict analysis by total work, not pair count (MED)

- **Problem:**
  - The 1M-state cap per pair multiplies across up to 100k pairs. 40 wildcard
    rules (a 42 KB config) take 21.6 s to load in release.
  - The pair cap counts *every* pair, so 448 rules on unrelated hosts fail with
    a misleading `ConflictAnalysisTooComplex` that names unrelated rules.
- **Change (`src/matcher.rs`, `src/config.rs`):**
  1. **Pattern length limit:** reject config `path` patterns longer than
     1024 bytes after normalization (`SetError::InvalidRule`, field `path`).
  2. **Total budget:** replace `MAX_CONFLICT_PAIR_CHECKS` with one total
     budget of glob-overlap states for the whole load (e.g. 4,000,000).
     Charge it only for pairs that reach `globs_overlap`, i.e. different
     class, equal specificity, and overlapping method and host. Cheap pairs
     cost nothing.
  3. **Short-circuit identical patterns:** before any budget check, two equal
     patterns (or both `None`) count as overlapping, so identical rules report
     `ConflictingRules`, not "too complex".
  4. **Rule-count limit:** add an explicit limit on total rules (e.g. 10,000)
     with its own `LoadError` variant, so the n² pair loop stays bounded.
- **Tests:**
  - 1,000 rules on 1,000 different hosts load.
  - 600 same-class exact paths in one set load.
  - The 40-rule adversarial config is rejected (too complex) or loads in under
    1 s in a debug build.
  - Two identical 1,000-`*` patterns with different classes give
    `ConflictingRules`.
  - A 1,025-byte pattern is rejected.
- **Docs:** Arch §13, §14 (list every `LoadError` variant) and §16 (state the
  limits and why).

### H7. Leave paths containing `;` unclassified (HIGH)

- **Problem:** `POST /v1/refunds;jsessionid=x/re_1` gives `payment.read`.
  Tomcat, Jetty and Spring strip `;` path parameters and run the refund.
- **Change:** reject a literal `;` in `normalize_path`, which covers both
  requests and patterns. `%3B` stays an encoded literal and is still accepted.
- **Tests (`tests/security.rs`):** `/v1/refunds;x/re_1` and
  `/v1/refunds;/re_1` give `None`. A config pattern containing `;` is
  rejected.
- **Docs:** add `;` to the rejected-forms list in Arch §7/§9 and agents.md
  "Paths", with the reason (servers strip path parameters).

### H8. Wildcard host rules: deeper base wins; no single-label base hosts (MED)

- **Problem:** a set with `host = "com"`, `subdomain = "*"`, `path = "/v1/*"`
  → `llm.inference` overrides Stripe's `*` rule on `stripe.com`.
  `POST api.stripe.com/v1/refunds/x` gives `llm.inference`, which breaks
  README "no precedence".
- **Change:**
  1. **Ranking:** in `Specificity`, put host *kind* (exact/bare beats wildcard)
     first, then base-host label count, before any path field. Exact and bare
     hosts use their full label count; they only overlap when the host strings
     are equal, so it doesn't change their ordering.
  2. **Config check:** reject a config `host` with fewer than two labels
     (`InvalidField("host")`).
- **Tests:**
  - With the Stripe set and a `co.uk`-style broad set loaded together,
    Stripe's rule wins for `api.stripe.com`.
  - `host = "com"` is rejected.
  - The existing tests that two wildcard rules on bases at the same depth
    conflict still pass.
- **Docs:** Arch §11 and agents.md "Specificity" add base depth after host
  kind. Arch §7 says the base host needs at least two labels.

### H9. Cap input sizes (LOW)

- **Change:**
  - A request `path` input longer than 8 KiB, measured before stripping the
    query, gives `None`.
  - A method longer than 32 bytes gives `None`.
  - Hosts are already bounded by the DNS length check.
- **Tests:** an 8,193-byte path gives `None`. An 8,192-byte valid path still
  classifies.
- **Docs:** Arch §9 and §16.

### H10. Reject confusing config values (LOW)

- `method = "*"` gives `InvalidRule { field: "method" }`. Someone might read it
  as "any method"; omitting `method` is how to say that.
- A config path with a `.` or `..` segment is rejected, whether or not it
  contains a wildcard. Today `/v1/../admin` is silently rewritten to `/admin`,
  which Arch §7 forbids ("no silent correction").
- Docs: Arch §7.

### H11. Error detail and doc sync (LOW)

- Add the rejected value to `SetError::InvalidRule` (e.g.
  `value: String`, Debug-quoted in the message).
- Arch §14:
  - List every variant that exists, including `ConflictAnalysisTooComplex` and
    the new limits.
  - Say that set and rule indexes are 0-based, and make the example messages
    match the real `Display` output.
- Arch §5: list `tests/robustness.rs`, and say config tests live in
  `src/config.rs` rather than `tests/config_validation.rs`.

---

## Tier 3 — judgement call (owner decides; default below)

### H12. Uppercase path spellings (HIGH, behaviour depends on the server)

- **Problem:** `POST /v1/REFUNDS/re_1` gives `payment.read`. Express and
  ASP.NET Core route case-insensitively by default.
- **Default: (b), if time allows; otherwise (a).**
  - **(a) Document only:** add "case-insensitive server routing" to the
    known-limits list in Arch §9.
  - **(b) Disagreement check:**
    - Also classify the path with ASCII letters lowercased *outside*
      percent escapes, so `%3A` stays `%3A`.
    - If that result is `Some` and differs from the original, return `None`.
    - Combine this with H1: check every alternate spelling (lowercased,
      stripped trailing slash, both). Deny if any alternate that isn't `None`
      disagrees.
    - Don't lowercase the path itself or the rules; IDs can be case-sensitive.
    - Document in §9 that this only catches rules written in lowercase, which
      is the usual convention.

### Document only, no code

Add these to a "Known limits" list in Arch §9:

- Trailing dots or `%20` at the end of a segment (IIS and others trim them).
- Method-override headers (`X-HTTP-Method-Override`): the classifier never
  sees headers.
- Servers that decode a path twice (`%252e`).
- Request bodies, and any routing that depends on the provider.

---

## Out of scope — do not do

- No new action classes, public API changes, I/O, CLI, or dependencies.
- No rule indexing, caching, tries or other performance changes beyond H6/H9.
- No change to the method-folding, `//`, multi-label subdomain or dot-segment
  policies.
- Do not edit `backlog.md` entries other than marking items `[x]` with the
  fixing commit.

## Report after each tier

For each item:
- the commit hash;
- the files changed;
- the tests added (name and what they prove);
- the gate results, with exact counts (`cargo test N/N`);
- the doc sections edited;
- anything you were unsure about or deliberately left undone.

Do not claim a tier is done if any gate fails.
