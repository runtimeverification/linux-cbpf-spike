# linux-cbpf spike

Verification spike on the classic-BPF (cBPF) validators of the Linux kernel,
for an AI-agent sandboxing threat model. Two consumers of the same validator
family: seccomp (`kernel/seccomp.c`, `net/core/filter.c`) and io_uring
(`io_uring/bpf_filter.c`, new since 7.0).

Primary goal: find a real security defect (out-of-bounds load or store, policy
bypass, divergence between the two validators) and prepare an upstream fix.
Secondary goal: Lean 4 theorems over the validators.

Method: C -> faithful Rust reimplementation -> differential fuzzing against the
real C -> Charon/Aeneas -> Lean 4.

Phases: 0 inventory and hypotheses, 1 Rust reimplementation, 2 differential
harness and hypothesis testing, 3 specification, 4 Lean proofs.

## Environment

- Kernel sources: `~/linux-cbpf`, branch `cbpf-spike`, at
  `v7.3-rc6-63-g0c2669a9f4a1`. Do not modify it unless the user asks for a
  patch; patches go on this branch only.
- Builds: `~/build-cbpf` (x86_64, `make O=`). Never build in-tree.
- Do not touch: `~/linux-full`, `~/linux-uidmap-patch`, `~/linux-isolation`,
  `~/linux`. Read `~/linux-isolation` and `~/kernel-c-to-rust-spike` for
  reusable scripts and layout only.
- **The host kernel is not the target kernel.** The host runs
  6.8.0-138-generic. Label every measurement with the kernel it came from.
- Charon: `~/charon/bin/charon`, `909ff09`, emits LLBC v0.1.220.
- Aeneas: **use `~/aeneas-project/aeneas/bin/aeneas`** (`c2015b86`). Do not
  use `~/aeneas/bin/aeneas` (wrong LLBC version, uncommitted local change).
- Lean: toolchain `v4.31.0`, mathlib matching. Never run bare
  `lean --version`; always run inside a project with a `lean-toolchain`.
- rustc stable 1.94.0. LibAFL 0.15.
- Proof idioms that worked with this Aeneas pin: see the "Lemma index"
  section of `~/linux-isolation/CLAUDE.md` before starting any Lean proof.

## Git rules

- Never run `git commit`, `git push`, `git stash`, `git clean`, `git reset`.
  The user commits. Say when a commit point is reached.

## Calibration rule

Any claim reached by following logic across more than one source file must be
either empirically checked or explicitly marked `[NEEDS EMPIRICAL CHECK]`.
Do not present such a claim as settled. In the previous spike the hit rate
for multi-file reasoning was poor: four confident wrong claims, each caught
only by running the kernel.

Corollary: when a measurement and the source disagree, first ask whether they
are the same kernel, the same build flags, or the same branch.

## Security findings

- If anything looks like a security bug (OOB access, policy bypass, privilege
  gain, filter accepted by one validator and rejected by the other): stop,
  write it to `FINDINGS.md` with a minimal reproducer, mark it
  `[UNCONFIRMED]` until it reproduces against the compiled C, then say so.
- Do not post, mail, or publish anything. Disclosure goes through
  security@kernel.org and is the user's decision.

## Honesty constraints

- Never call a `sorry`-carrying result proved. Never write "verified" about
  anything not yet proved.
- Never claim a vulnerability without a reproducing witness, and describe it
  as a spec violation in our reimplementation until confirmed against the C.
- Assumptions appear as explicit hypotheses in theorem statements; the
  theorem-by-assumption matrix goes into `VERIFY-REPORT.md` beside the
  `#print axioms` output.
- Concurrency and barrier discipline are outside every proof here; they go
  first on the exclusion list.
- If the pipeline blocks on a mechanical limitation (unions, `dyn` trait
  objects, raw casts, function pointers), record it in `OPEN_CHALLENGES.md`
  and stop, rather than working around it with an unfaithful model.
- Equivalence claims are against the C as this tree compiles it, and nothing
  stronger.

## Artifacts

`INVENTORY.md`, `DIFF.md`, `HYPOTHESES.md`, `FINDINGS.md`, `SPEC.md`,
`OPEN_CHALLENGES.md`, `VERIFY-REPORT.md`. Every statement in them is tagged
`[VERIFIED: how]` or `[UNVERIFIED]`.

## Build commands (to be filled in as phases complete)

```sh
# 1. Rust reimplementation and its tests
cd rust && cargo build --release && cargo test --release

# 2. Charon: Rust -> LLBC
cd rust && PATH=$HOME/charon/bin:$PATH charon cargo --preset=aeneas

# 3. Aeneas: LLBC -> Lean
~/aeneas-project/aeneas/bin/aeneas -backend lean <llbc> -dest verify/lean/

# 4. Lean. Copy setup-local.sh and axioms.sh from
#    ~/linux-isolation/verify/lean/ rather than writing new ones.
cd verify/lean && ./setup-local.sh && lake build && ./axioms.sh
```
