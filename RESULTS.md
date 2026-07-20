# Proof-of-Inference Cost Study — Results

**Question:** Is cryptographic proof-of-inference cheap enough to run on the
hot path of *every* LLM request, so the LENS economy can mint only against a
proof that real, useful inference happened?

**Method:** Implement three proof schemes (cheapest/weakest → most
expensive/strongest), benchmark gen time / proof size / verify time across
realistic generation sizes, and report honest numbers.

- Hardware: Apple M4, `go1.26.3 darwin/arm64`, stdlib crypto only
  (`crypto/ed25519`, `crypto/sha256`), no external dependencies.
- "Execution step" = one token-generation step. Each step emits a
  **256-byte intermediate state** that gets hashed. Cost for Schemes B and C
  scales **linearly in this state size** — see caveats.
- Numbers below are produced by `go run ./cmd/report` (uses `testing.Benchmark`).
  Reproduce the raw per-case numbers with `go test -bench=. -benchmem ./...`.

## Reproduce

```
cd ~/talyvor-research/povi-prototype
go test ./...                       # 12 correctness tests (crypto is validated)
go test -bench=. -benchmem ./...    # raw benchmark matrix
go run ./cmd/report                 # the consolidated table below
```

## The numbers

| Scheme | N | K | gen_time | proof_bytes | verify_time |
|--------|---|---|----------|-------------|-------------|
| A signed-receipt | — | — | 12.59 µs | 64 B | 27.88 µs |
| B merkle-trace | 100 | 1 | 19.57 µs | 299 B | 425 ns |
| B merkle-trace | 100 | 4 | 19.50 µs | 1.1 KB | 1.70 µs |
| B merkle-trace | 100 | 16 | 21.10 µs | 4.2 KB | 6.79 µs |
| B merkle-trace | 100 | 32 | 23.12 µs | 8.4 KB | 13.60 µs |
| B merkle-trace | 1000 | 1 | 185.93 µs | 398 B | 609 ns |
| B merkle-trace | 1000 | 4 | 186.73 µs | 1.5 KB | 2.44 µs |
| B merkle-trace | 1000 | 16 | 188.59 µs | 5.8 KB | 9.77 µs |
| B merkle-trace | 1000 | 32 | 191.39 µs | 11.5 KB | 19.65 µs |
| B merkle-trace | 10000 | 1 | 1.860 ms | 530 B | 860 ns |
| B merkle-trace | 10000 | 4 | 1.859 ms | 2.0 KB | 3.45 µs |
| B merkle-trace | 10000 | 16 | 1.863 ms | 7.8 KB | 13.80 µs |
| B merkle-trace | 10000 | 32 | 1.971 ms | 15.6 KB | 27.68 µs |
| C hash-chain | 100 | — | 11.76 µs | 32 B | 11.72 µs * |
| C hash-chain | 1000 | — | 116.62 µs | 32 B | 116.88 µs * |
| C hash-chain | 10000 | — | 1.169 ms | 32 B | 1.169 ms * |

`*` Scheme C's 32-byte commitment is **not independently verifiable**. To
verify it the gateway must replay the entire N-step chain, which requires the
**full trace** (≈ N × 256 B). At N=10000 that is ~2.4 MB of trace data and
~1.17 ms of verify work, every time.

Two structural facts the table makes obvious:

- **Scheme B gen is flat in K** (~1.86 ms at N=10000 whether K=1 or K=32). Gen
  cost is dominated by hashing all N states and building the tree — O(N). K
  only changes proof size and verify time.
- **Scheme B verify is sub-linear** in N (it is O(K·log N)): microseconds even
  at N=10000. Scheme C verify is O(N) — three orders of magnitude slower.

## 1. What does a realistic large generation (N = 10000) cost?

| Scheme | added gen latency | proof on the wire | verify | what you actually get |
|--------|-------------------|-------------------|--------|------------------------|
| **A** | **12.6 µs** | **64 B** | 27.9 µs | a node signature over the request/response metadata |
| **B** | **~1.86 ms** | 530 B – 15.6 KB (K=1→32) | 0.9 – 27.7 µs | a tamper-evident commitment to the whole trace + K audit paths |
| **C** | **1.17 ms** | 32 B *commitment* — but **~2.4 MB** to actually verify | **1.17 ms** | a full ordered commitment, not succinctly checkable |

## 2. Which schemes clear the hot-path bar (< 5 ms gen **and** < 10 KB proof)?

- **Scheme A — clears it with four orders of magnitude to spare.** 12.6 µs and
  64 bytes. Trivially viable on every request.
- **Scheme B — clears it, for K ≤ 16.** At N=10000: gen 1.86 ms (< 5 ms ✓) and
  proof 7.8 KB at K=16 (< 10 KB ✓). Only K=32 (15.6 KB) breaks the size bar.
  **This is the headline result: the realistic middle scheme is actually
  affordable on the hot path.** 1.86 ms added to a 10k-token generation (which
  on a real model takes hundreds of ms to seconds) is well under 1% overhead.
- **Scheme C — passes on paper, fails in practice.** Gen 1.17 ms and a 32-byte
  commitment both look great, but the 32 bytes are not verifiable on their own:
  verification needs the entire ~2.4 MB trace and 1.17 ms of replay *per
  request at the gateway*. As a per-request proof it does not really clear the
  bar — its "10 KB" is a mirage.

## 3. Honest verdict

**Yes — per-request proof-of-inference is cheap enough, but only for the
*attestation/tamper-evidence* class of proof, not for proof of honest
computation.** Both Scheme A and Scheme B fit comfortably on the hot path of
every request. This is a better outcome than the worst case (where only the
weak Scheme A is affordable): the Merkle-committed trace (B) is viable too, so
the economy can have a cryptographic, auditable commitment on every request —
not merely a bare signature.

**What none of these schemes prove (this is the important honesty):**

- **None prove the response actually came from the claimed model**, or that the
  GPU ran the real weights honestly. A malicious node can sign a fabricated
  response (A), or build a perfectly self-consistent Merkle tree / hash chain
  over fabricated states (B, C). Self-consistency ≠ correctness.
- Scheme A proves only *non-repudiable attestation*: "this key-holder claimed
  this." Scheme B proves the node *committed* to a specific trace and lets you
  catch **post-hoc tampering** of that trace probabilistically (and lets you
  challenge/audit it later). Scheme C proves the same binding deterministically
  for the whole trace, but buys nothing extra on the hot path for its higher
  verify cost.
- **Real proof that the computation was honest needs TEE attestation
  (e.g. confidential-compute GPU enclaves) or genuine ZKML** — both are a
  separate, much heavier question (ZKML proving is currently seconds-to-minutes
  and megabytes per inference, nowhere near hot-path viable). This prototype
  deliberately does not attempt it.
- The B/C gen numbers assume the per-step state is **256 B and already in
  memory**; cost scales linearly with state size, and the naive Scheme B
  implementation is allocation-heavy (~1.2 MB / 20k allocs at N=10000), so
  1.86 ms is an upper bound for a straightforward build — a streaming/arena
  implementation would be faster.

## Recommendation — what Talyvor's Phase 1 proof should be

**Ship Scheme A carrying a Scheme B Merkle root, on every request; verify by
random challenge; keep honest-computation proofs off the hot path.**

Concretely: as tokens are generated, hash each step's state into a Merkle leaf
and fold the tree (the ~1.86 ms at N=10000 amortizes into generation and stays
< 5 ms). On completion, the node emits a **64-byte ed25519 signed receipt whose
signed payload includes the 32-byte Merkle root** — ~96 bytes total on the
wire, ~13 µs to produce, ~28 µs to verify. **Mint LENS against this signed,
root-bound receipt.** Then make it tamper-evident without paying for it on
every request: the gateway issues **random post-hoc challenges** on a sampled
fraction of requests, demanding K sampled authentication paths (≤ 8 KB,
produced and verified in microseconds); a node that committed to a fabricated
or altered trace fails the challenge with probability rising in K and loses
stake. This gives the economy a cryptographic, auditable, non-repudiable proof
on 100% of requests at near-zero hot-path cost, with stronger probabilistic
tamper-evidence sampled cheaply — while the genuinely hard guarantee (that the
claimed model ran honestly) is pursued separately via TEE attestation or ZKML,
sampled and asynchronous, never on the hot path. **The real design constraint
to write into the economy: the per-request proof is attestation + tamper-
evidence, not proof of honest computation — token issuance must be backed by
stake and challenge, not by the receipt alone.**
