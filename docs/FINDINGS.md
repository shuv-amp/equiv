# Findings

Behavioural differences found between **adjacent patch releases** of published
crates — version pairs where semver promises consumers nothing changed.

**Date:** 2026-08-16
**Method:** Phase 1 local probe path (generate → find → shrink → replay).
Every `DIVERGES` below was replayed against both unmodified artifacts before
being recorded; unconfirmed candidates are dropped, per
[`CLAIMS.md`](CLAIMS.md).

---

## Run summary

| | |
|---|---:|
| Crates scanned | 52 |
| Adjacent patch pairs with changed `src/` | 556 |
| Function pairs admissible on both sides and probeable | 26 |
| `DIVERGES`, replay-confirmed | 14 |
| — of those, behavioural | **2** |
| — of those, representation-only | 12 |
| No divergence within budget (reported `UNKNOWN`) | 6 |
| `UNKNOWN` from build or run failure | 6 |

556 pairs collapsing to 26 probeable function pairs is the eligibility
constraint from [`PHASE0.md`](../bench/probe/PHASE0.md) showing up end to end,
and it is the binding limit on this whole approach today, not the fuzzing.

The 14 confirmed divergences are **not** 14 independent findings, and reporting
them as one number would be misleading. They are four changes. Eleven of them
are one `Debug` impl in one crate, firing once per constructor.

---

## Behavioural

### `regex-syntax` 0.1.0 → 0.1.1 — `is_punct`

```
input:  c = '#'
0.1.0:  false
0.1.1:  true            witness 005a, replay-confirmed
```

`'#'` was added to the punctuation set:

```rust
 '[' | ']' | '{' | '}' | '^' | '$' => true,        // 0.1.0
 '[' | ']' | '{' | '}' | '^' | '$' | '#' => true,  // 0.1.1
```

This is the cleanest case in the run. The return type is `bool`, so no
rendering difference can be involved, and the shrinker landed on exactly the
character that was added.

### `textwrap` 0.13.2 → 0.13.3 — `indent`

```
input:  s = " ```a", prefix = " ```a"
0.13.2: " ```a ```a\n"
0.13.3: " ```a ```a"    witness 00, replay-confirmed
```

0.13.2 iterates `s.lines()` and pushes `'\n'` after every line, so it always
appends a trailing newline. 0.13.3 splits on `'\n'` and joins, preserving its
absence.

**This was intentional and documented.** The 0.13.3 changelog reads: *"Make
`indent` preserve existing newlines in the input string. Before, `indent("foo",
"")` would return `"foo\n"` by mistake."* The probe found the same case from
source alone, with no changelog and no test suite — which is the only claim
being made for it. It is a validation result, not a discovery.

---

## Representation-only

Recorded separately because they are not behavioural differences in any useful
sense. The probe's observation contract is the callee's return `Debug` output or
a panic ([`CLAIMS.md`](CLAIMS.md)), so a change to how a value prints is
indistinguishable from a change to the value.

| Crate | Pair | Functions | What changed |
|---|---|---:|---|
| `bytesize` | 0.2.1 → 0.2.2 | 11 | A custom `Debug` impl. `ByteSize { size: 0 }` now prints `0 B`. Fires once per constructor; it is one change. |
| `wildmatch` | 2.1.0 → 2.1.1 | 1 | A private field `max_questionmarks` was added, so the derived `Debug` prints an extra field. |

### What this says about the tool

Twelve of fourteen confirmed divergences being representation-only is the most
useful result in this run. The observation contract cannot currently separate
*the answer changed* from *the printing changed*, and on a real corpus that
distinction is most of the signal.

The fix is a stronger observation than `Debug`: compare structural equality
where the return type admits it, and fall back to `Debug` only when it does not.
Until that lands, any run over a real corpus has to be reported in two columns,
as above.

---

## Reproducing one case

The batch driver that produced this table is not in the tree yet — registry
discovery and the scan worker are Phase 1 roadmap items, listed as not shipped
in [`CLAIMS.md`](CLAIMS.md). A single pair reproduces with what is shipped:

1. Fetch both versions and unpack them.
2. Retag each with `project::retag_version` to `0.0.0-equiv-old` and
   `0.0.0-equiv-new`. Cargo unifies semver-compatible versions, so a patch pair
   does not otherwise resolve.
3. Build a `ProbeCrate` with the function's `HarnessSpec`, mine a `Corpus` from
   the crate's own sources, and write it out.
4. `cargo run -- --iters 40000`, then `cargo run -- --replay <hex>`.

`crates/equiv-harness/tests/e2e.rs` runs exactly this loop against a synthetic
pair and is the working reference.
