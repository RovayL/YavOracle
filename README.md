# YavOracle: Coverage-Safe Fiat–Shamir in Rust

A small Rust framework that lets you **write interactive proofs as they’re meant to run**,two programs exchanging typed messages, and then **swap the runtime** to get a correct non-interactive proof via Fiat–Shamir (FS). The core idea is **coverage safety**: every prover-controlled value that influences verification must be *bound into* the transcript **before** any challenge is sampled. If something relevant isn’t bound, your code won’t compile.

This repository contains two crates:

* **`fsr-core`** — the runtime & typed DSL:

  * `Transcript<PENDING, O>` with compile-time gating of `challenge()` using const generics.
  * Traits `Message`, `Bindable`, `CanonicalEncode`, `Absorb`, `Oracle`.
  * Two swappable runtimes:

    * **FS**: `HashOracle` (non-interactive, programmable random oracle).
    * **Interactive** (feature-gated): `InteractiveProverOracle` / `InteractiveVerifierOracle` over a simple in-memory channel (you can swap in TCP or any transport).
  * Macros: `declare_round!`, `round_mask!`.
* **`fsr-bind-derive`** — a proc-macro derive that **auto-generates coverage bindings** from your message struct:

  * `#[derive(FsrBindable)]` scans fields and emits `impl Bindable` with:

    * `const OBLIG_MASK: u128` — OR of all obligation bits you mark.
    * `fn bind(...)` — canonical absorption of every covered field.
  * Field attributes:

    * `#[bind(ob = N)]` — this field **must be bound before** sampling the next challenge (sets obligation bit `1<<N`).
    * `#[bind(skip)]` — explicitly not transcript-bound (scratch, hints, etc.).
    * `#[bind(label = "custom.label")]` — override the default label `Type.field`.
  * Struct attributes:

    * `#[bind(prefix = "TypePrefix")]` — default label prefix (defaults to the type name).
    * `#[bind(core = "fsr_core")]` — override the path to the core crate.

>  **Toolchain**: `fsr-core` uses `generic_const_exprs` for typestate arithmetic. Build with **nightly** Rust.

```bash
rustup toolchain install nightly
rustup override set nightly   # in this repo
```

---

## Why this exists

Implementers keep getting Fiat–Shamir wrong by forgetting to hash some prover-chosen input(s) that affect verification (coverage bugs). This framework encodes those dependencies **at the type level**:

* You mark verification-relevant fields with `#[bind(ob = N)]`.
* The round’s pending set of obligations is a **const bitmask** inside `Transcript<PENDING, O>`.
* **`challenge()` only exists when `PENDING == 0`**. If you forgot to absorb a relevant value, the code won’t compile.

You write your protocol *once* (prover/verifier messages, labels), and switch between:

* **Interactive** (verifier samples and sends randomness), and
* **FS** (verifier replaced by a hash-based oracle)
  by changing only the **oracle type**.

---

## Repository Layout

```
fsr-core/
  Cargo.toml
  src/lib.rs
  examples/
    schnorr.rs               # FS runtime example (HashOracle)
    schnorr_interactive.rs   # Interactive runtime + toy group verification
fsr-bind-derive/
  Cargo.toml
  src/lib.rs                 # #[derive(FsrBindable)] with #[bind(...)] attributes
```

---

## Building & Running

### 1) Build everything

```bash
cargo +nightly build
```

### 2) Run the **FS** example (non-interactive, HashOracle)

```bash
cargo +nightly run --example schnorr
```

### 3) Run the **Interactive** example (verifier↔prover channel)

Enable the `interactive` feature (pulls in `rand` and the interactive oracles):

```bash
cargo +nightly run --features interactive --example schnorr_interactive
```

This runs a Schnorr proof in a tiny **toy additive group** (integers mod a prime) and checks the equation:

> `z·G = T + e·Y` (mod p), where `Y = x·G`, `T = r·G`, `z = r + e·x`.

You’ll see printed values and `verification: true`.

---

## Swapping runtimes (Interactive ↔ FS)

Your protocol code (messages, absorption, round declarations) is **identical**. The only change is which `Oracle` you plug into `Transcript`.

**FS (HashOracle):**

```rust
let oracle = HashOracle::new(b"my-protocol");
let tr: MyRound<HashOracle> = Transcript::new(oracle);
```

**Interactive:**

```rust
// feature = "interactive"
let (p_chan, v_chan) = mem_duplex_pair();
let prover_oracle   = InteractiveProverOracle::new(p_chan, b"my-protocol");
let verifier_oracle = InteractiveVerifierOracle::new(v_chan, StdRng::from_entropy(), b"my-protocol");

let tr_p: MyRound<_> = Transcript::new(prover_oracle);
let tr_v: MyRound<_> = Transcript::new(verifier_oracle);
```

> You can implement `Channel` for any transport (TCP, QUIC, WebSocket) to carry challenges; the *application* layer still sends the actual messages you define.

---

## How binding & obligations work

### Field-level annotations

In `examples/schnorr_interactive.rs`:

```rust
#[derive(Clone, Debug, FsrBindable)]
#[bind(prefix = "Commit")]
pub struct Commit {
    #[bind(ob = 0)]     // <-- this field must be bound pre-challenge
    pub T: G1,          // verification-relevant commitment (affects the check)
}
```

* `#[derive(FsrBindable)]` generates:

  * `impl Bindable for Commit { const OBLIG_MASK: u128 = 1 << 0; fn bind(..) { absorb("Commit.T", self.T) } }`
* In the round declaration, that bit becomes **pending** until you call `absorb`:

  ```rust
  declare_round!(R1 = [Commit]);              // type R1<O> = Transcript<{Commit::OBLIG_MASK}, O>
  let tr: R1<HashOracle> = Transcript::new(...);
  let tr = tr.absorb::<{ Commit::OBLIG_MASK }, _>(Commit::LABEL, &commit);
  let (e, tr) = tr.challenge::<Scalar>("e");  // ok only after absorb clears the bit
  ```
* If you *forget* to absorb `Commit` before `challenge()`, the type is `Transcript<1, _>` and `challenge()` simply doesn’t exist — compile-time error, not a test failure.

### Labels & coverage

* By default, each bound field uses the label **`TypeName.field_name`** (configurable via `#[bind(prefix="...")]` and/or `#[bind(label="...")]`). These labels give **domain separation** inside the oracle.
* `#[bind(skip)]` must be used to **explicitly** omit a field (e.g., temporary scratch), which prevents accidental omissions.

### Multi-round protocols

For round k:

* Give each **pre-challenge** prover→verifier field a unique `#[bind(ob = N)]` bit within that boundary.
* Declare the mask with `declare_round!(Rk = [MsgA, MsgB, ...])`.
* Start each boundary with the appropriate `Transcript` type and repeat the absorb→challenge flow.

---

## Creating your own protocol (step-by-step)

1. **Model your domain types** and implement `CanonicalEncode` for each value that will be absorbed into the transcript (e.g., group elements, scalars, vectors).

2. **Define message structs** and mark which fields must be bound before the challenge:

   ```rust
   #[derive(FsrBindable)]
   #[bind(prefix = "Round1Msg")]
   struct Round1Msg {
       #[bind(ob = 0)] pub a: G1,           // verification-relevant (pre-challenge)
       #[bind(ob = 1)] pub b: Vec<u8>,      // another relevant input (pre-challenge)
       #[bind(skip)]   pub scratch: usize,  // not part of the transcript
   }
   impl Message for Round1Msg {
       const DIR: Direction = Direction::ProverToVerifier;
       const LABEL: &'static str = "Round1Msg";
   }
   ```

3. **Declare the round’s pending set**:

   ```rust
   declare_round!(R1 = [Round1Msg]);   // PENDING = (1<<0) | (1<<1)
   ```

4. **Write the flow** (prover or verifier):

   ```rust
   let tr: R1<HashOracle> = Transcript::new(HashOracle::new(b"protocol"));
   let m = Round1Msg { a, b, scratch: 0 };
   let tr = tr.absorb::<{ Round1Msg::OBLIG_MASK }, _>(Round1Msg::LABEL, &m);
   let (e, tr) = tr.challenge::<FieldElem>("challenge");  // only enabled after absorb
   // ... respond, absorb post-challenge messages, final decision ...
   ```

5. **Swap runtimes at will** (FS ↔ Interactive) by changing the oracle type, not your protocol.

---

## Notes & Recommendations

* Replace the demo challenge reducer with a **real hash-to-field** for your curve/field type.
* Use structured labels with a stable **domain separation tag** (DST) per protocol/version.
* The interactive example’s channel is an in-process `mpsc` duplex; implement `Channel` for sockets to run across processes/machines.
* If you must stay on **stable** Rust, we can port the typestate bitmasks to a type-level integers approach (e.g., `typenum`). The ergonomics are slightly noisier; ask if you want the stable variant.

---

## TL;DR

* Declare messages with `#[derive(FsrBindable)]` and mark pre-challenge fields using `#[bind(ob = N)]`.
* Use `declare_round!` to set a round’s pending obligations.
* The compiler enforces that **all** obligations are bound before `challenge()` can be called.
* Run with either:

  * `HashOracle` (FS mode), or
  * `InteractiveProverOracle` / `InteractiveVerifierOracle` (interactive mode, `--features interactive`).

This way, you get **correct-by-construction** Fiat–Shamir conversions and sharply reduced room for coverage bugs like the ones seen in the wild.
