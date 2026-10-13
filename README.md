# linux-cbpf-spike

Verification spike on the classic-BPF (cBPF) validators of the Linux kernel:
the code that decides whether a seccomp or io_uring filter program is safe to
install. Second target in Runtime Verification's work on the kernel's isolation
layer, after the user-namespace ID map
([linux-isolation-spike](https://github.com/runtimeverification/linux-isolation-spike)).

Method: inventory the C, state what each function is responsible for, compare
the two consumers (seccomp and io_uring), test hypotheses by execution in a VM,
then reimplement in Rust and prove properties in Lean 4 via Charon/Aeneas.

## Result so far

While inventorying what the io_uring CONNECT filter is allowed to see, we found
a policy bypass: the populate hook filled the IPv6 port and address only for a
28-byte `sockaddr_in6`, while the IPv6 stack accepts 24. A filter denying an
IPv6 destination could be sidestepped by submitting the connect with
`addr_len = 24`.

- Reproduced in a VM on the target kernel, 2x2 filter/length matrix.
- One-line fix, regression-tested with the same reproducer.
- Reported 2026-10-09, applied by the io_uring maintainer the same day,
  commit `aa5d5f8e5023` in mainline, queued for 7.2 stable.
- Thread: https://lore.kernel.org/io-uring/20261009133807.730724-1-natalie.klaus@runtimeverification.com/

## Files

- `INVENTORY.md`: every function on the cBPF admission path for both consumers, with file:line and the property it is responsible for.
- `DIFF.md`: line-by-line comparison of the seccomp and io_uring validators.
- `HYPOTHESES.md`: ranked bug hypotheses and their verdicts.
- `FINDINGS.md`: the confirmed finding, evidence, fix and disclosure timeline.
- `repro/`: reproducers, VM run scripts and logs. `f1_connect_v6.c` is the bypass witness; `h3_*` is the differential fuzz of seccomp's constant-allow emulator (refuted, 1.5e9 cases).
- `disclosure/`: the report, commit message and formatted patch as sent.
- `CLAUDE.md`: environment, calibration rules and honesty constraints for the AI-assisted parts of the work.

Every claim in these files is tagged VERIFIED (ran it) or UNVERIFIED (read
it). Claims reached by reasoning across source files stay UNVERIFIED until a
VM witness confirms them.

## Status

Phase 0 (inventory, hypotheses) and Phase 2 (execution) done for the finding
above. Rust reimplementation and Lean proofs of the validators are next. No
theorem is proved yet.
