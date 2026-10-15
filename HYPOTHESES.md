# HYPOTHESES.md — bug hypotheses for Phase 2 execution

Tree `~/linux-cbpf` at `v7.3-rc6-63-g0c2669a9f4a1`. Tags as in INVENTORY.md.
L = likelihood that a real defect exists at this commit; I = impact if it does.
All execution in Phase 2 targets the built kernel (`~/build-cbpf/arch/x86/boot/bzImage`
under virtme-ng, which is installed: `vng`, `qemu-system-x86_64` [VERIFIED: which]),
never the 6.8 host kernel, which lacks io_uring BPF filters entirely.

Ranked by L x I. Items 1-4 are where a real finding is plausible; 5-12 are the
properties the proofs must cover and where a bug would be surprising; 13-18 are
spec notes and boundary tests.

## 1. H1 — io_uring CONNECT filter blind to IPv6 port/address for 24 <= addr_len < 28  (L: high, I: high)

`io_connect_bpf_populate` fills `connect.port` and `connect.v6_addr` only when
`conn->addr_len >= sizeof(struct sockaddr_in6)` = 28 (io_uring/net.c:1744), but every
IPv6 connect path accepts `SIN6_LEN_RFC2133` = 24 (include/net/ipv6.h:26; net/ipv6/tcp_ipv6.c:125,
:150; net/ipv6/datagram.c:162; net/ipv6/udp.c:1300; net/ipv6/raw.c:227; net/sctp/socket.c:347),
and `io_connect` passes the user's `addr_len` straight to `__sys_connect_file` (net.c:1847).
Port and address occupy bytes 2..8 and 8..24 of `sockaddr_in6` (include/uapi/linux/in6.h:50-56),
so both are present in a 24-byte address; only `sin6_scope_id` (bytes 24..28) is missing.
Consequence: with `addr_len = 24` the filter sees `family = AF_INET6, port = 0, v6_addr = ::`
(the union was zeroed by the memset at net/bpf_filter.c:35-36) while the kernel connects to the
real destination. Any CONNECT filter that denies by IPv6 port or address is bypassed.
The IPv4 thresholds agree (populate 16 = `sizeof(sockaddr_in)`; net/ipv4/tcp_ipv4.c:212,
net/ipv4/datagram.c:30, net/ipv4/raw.c:719) so IPv4 is not affected.
[NEEDS EMPIRICAL CHECK: spans io_uring/net.c and net/ipv6/*]. Recorded as FINDINGS.md F-1.
**CONFIRMED in Phase 2** (2026-10-08) against `7.3.0-rc6-00063-g0c2669a9f4a1` in a
virtme-ng VM; reproducer `repro/f1_connect_v6.c`. See FINDINGS.md F-1 "Confirmation".

## 2. H2 — context-semantics footguns in the io_uring populate hooks  (L: medium, I: medium)

Not kernel bugs by themselves, but each lets a plausible filter be bypassed:
- (a) `AF_INET6` sockets accept v4-mapped addresses; the hook copies whatever family the
  sockaddr carries (net.c:1730-1749). A filter keyed on `family == AF_INET` and `v4_addr`
  does not see `::ffff:a.b.c.d` connects. [VERIFIED: read]
- (b) SOCKET: `type` is stored raw from `sqe->off` (net.c:1765) so the filter's `socket.type`
  carries `SOCK_NONBLOCK | SOCK_CLOEXEC`; the header comment says "load + mask". Exact-match
  deny filters miss. [VERIFIED: read]
- (c) OPENAT2: `__io_openat_prep` ORs `O_LARGEFILE` into `how.flags` at prep time
  (io_uring/openclose.c:65-66) and prep runs inside `io_init_req` before the filters
  (io_uring.c:1882 vs :1887); the filter sees the modified flags. OPENAT shows flags
  normalised by `build_open_how` (openclose.c:100). [NEEDS EMPIRICAL CHECK: two files]
Outcome feeds SPEC.md as documented semantics rather than FINDINGS.md unless the behaviour
contradicts the UAPI header.

## 3. H3 — seccomp allow-cache emulator disagrees with real execution  (L: low, I: high)

`seccomp_is_const_allow` (kernel/seccomp.c:770-845) re-interprets the original program on
`(arch, nr)` with `A` modelled by `reg_value`, over the subset {`LD|W|ABS` at `k` = 0 or 4,
`RET|K`, `JA`, `J{EQ,GE,GT,SET}|K`, `ALU|AND|K`}; anything else returns "not cacheable",
which is the safe direction. A divergence would mean a syscall the filter would not allow
is allowed from the cache (`seccomp_run_filters` :416). It runs on `orig_prog`, the bytes
saved before the rewrite (filter.c:1453 before :1464) [NEEDS EMPIRICAL CHECK: two files].
Test: Phase 1 Rust models of both the emulator and the cBPF interpreter; differential fuzz
(random programs in the subset plus random noise insns); then the C emulator extracted into
a userspace harness; then VM confirmation of the resulting syscall behaviour.

### H3 VERDICT: REFUTED — no over-allow beyond the intentional uprobe passthrough  [VERIFIED: fuzz + VM]

Method (`repro/h3_const_allow_fuzz.c`, built by `repro/h3_build.sh`): the kernel's own
`seccomp_is_const_allow`, `seccomp_uprobe_exception`, `seccomp_check_filter`,
`bpf_check_classic`, `chk_code_allowed`, `check_load_and_stores` and `bpf_anc_helper` are
extracted VERBATIM from `~/linux-cbpf` at build time and compiled in userspace. Programs are
admitted exactly as the kernel admits them (classic check, then the seccomp rewrite on a
copy); the emulator runs on the original bytes and a reference cBPF interpreter runs the
rewritten bytes, as `bpf_prog_create_from_user()` does. Oracle: for every (program, arch, nr)
the emulator marks constant-allow, the interpreter must return action `SECCOMP_RET_ALLOW`
for every `seccomp_data` with that (arch, nr) (random args and ip). Pure userspace, no
kernel interaction. Self-tests include a positive control (a deny-everything filter) that
the oracle must flag for exactly nr 335/336 on x86_64.

| run | seed | programs admitted | (prog,arch,nr) emulated | reference runs | REAL divergences | intentional (uprobe) | anomalies / WARN_ON |
|---|---|---|---|---|---|---|---|
| 1 (T=32) | 1 | 196,469 | 201,184,256 | 1,323,149,109 | 0 | 250,954 | 0 / 0 |
| 2 (T=16) | 2 | 982,580 | 1,006,161,920 | 3,329,956,848 | 0 | 1,255,595 | 0 / 0 |
| 3 (T=64) | 3 | 294,773 | 301,847,552 | 3,949,308,318 | 0 | 377,178 | 0 / 0 |

Program mix: 50% filter-like (arch check, nr allowlists with JEQ/JGE/JGT/JSET, AND masks,
JA, optional args-dependent branch, RET variants incl. ALLOW|data) and 50% random soup over
the full admitted opcode set (ALU K/X, scratch ST/LD, TAX/TXA, RET A, LEN). Rejection rate
about 1.7%. The emulator also under-caches in the safe direction (about 20% of sampled
non-cached (arch, nr) were in fact always-allow): incompleteness, not a bug.

The single divergence class is `seccomp_uprobe_exception()` (kernel/seccomp.c:744-762,
commit 89d1d8434d24 "seccomp: passthrough uprobe systemcall without filtering"): for
x86_64 nr 335 (uretprobe) and 336 (uprobe) the emulator returns true without reading the
filter, so the cache allows them whatever the filter says. Intentional and public; not a
finding.

VM confirmation (`repro/h3_uprobe_passthrough.c` via `repro/h3_run.sh`; log
`repro/h3_run.log`), kernel `7.3.0-rc6-00063-g0c2669a9f4a1-dirty` = build #2 of 2026-10-08
15:42 (0c2669a9f4a1 plus the then-uncommitted F-1 fix to io_uring/net.c; kernel/seccomp.c
and net/core/filter.c unmodified), host 6.8 as hypervisor only:
- T1  filter denies uprobe(336) with ERRNO(EPERM): `syscall(336) -> -1 errno=71 (EPROTO)`.
  The syscall executed (sys_uprobe's own out-of-trampoline error): bypassed by the cache.
  [VERIFIED: run]
- T1b filter denies uretprobe(335): child killed by SIGILL (sys_uretprobe's own
  out-of-trampoline path): bypassed. [VERIFIED: run]
- T2  filter denies getpid(39): `syscall(39) -> -1 errno=1 (EPERM)`: enforced; the cache
  did not over-allow an ordinary syscall. [VERIFIED: run]
- T3  same filter, getppid(110) on the constant-allow path: returned 252. [VERIFIED: run]

Why no divergence is expected (proof target for Phase 4; UNVERIFIED as a proof): the
emulated path depends only on nr, arch and constants; each modelled instruction has the
same semantics as the converted program (32-bit unsigned compares; `pc += jt|jf|k` then
`pc++` equals `pc + 1 + off`; AND|K; exact `RET|K == SECCOMP_RET_ALLOW`); A starts at 0 as
the eBPF prologue guarantees; the emulator reads orig_prog saved before the rewrite; the
runtime lookup consults the bitmap only for the same (arch, nr) with `0 <= nr < NR_syscalls`.
Bounded fuzzing cannot prove absence; the Lean theorem is what closes H3.

Threat-model note: on x86_64 a seccomp filter cannot deny uprobe/uretprobe; direct calls
outside a trampoline yield EPROTO / SIGILL and confer no capability. Documented upstream
behaviour, recorded for the sandbox spec.

## 4. H4 — check_load_and_stores admits a read of a never-written scratch cell  (L: low, I: high)

filter.c:935-986. The converted load reads the eBPF stack slot `FP-(4k+4)` (filter.c:855-858);
the interpreter's stack frame is uninitialised (kernel/bpf/core.c:2416-2426), so an admitted
read-before-write would surface a stale stack value in `A`, observable through `RET|A`: 16 bits
per syscall via `SECCOMP_RET_DATA` with `SECCOMP_RET_ERRNO` (seccomp.c:1280-1286, capped at
`MAX_ERRNO`), one allow/deny bit per submission in io_uring. The analysis is a forward
meet-over-paths that relies on all jumps being forward (`jt`, `jf` are u8 and `JA k` is
unsigned) and on `k < 16` and targets `< flen` having been checked first (filter.c:1106-1133
run before :1151). This is a long-standing shared check; the interest here is proving it, not
expecting a break. Test: Rust model plus an independent all-paths oracle; differential fuzz
against the C; Lean theorem in Phase 4.

### H4 VERDICT: REFUTED — no admitted program reads an unwritten scratch cell  [VERIFIED: fuzz + VM]

Method (`repro/h4_mem_init_fuzz.c`, built by `repro/h4_build.sh` from the same verbatim
extract as H3): three oracles per generated program. (A) An independent exact must-write
dataflow with reachability over the forward-jump DAG: SAFE iff every reachable `LD|MEM` /
`LDX|MEM` reads a cell written on every path from entry. (B) An execution oracle that runs
the admitted, rewritten program on random `seccomp_data` with per-cell initialised tracking
and poison values; any read of an uninitialised cell on an executed path is a real leak.
(C) Incompleteness in the safe direction (kernel rejects, reference SAFE). Programs are
memory-dense and deliberately NOT write-tracked at generation (75% random soup, 25%
diamonds with stores on one/both/neither branch, dead stores after RET, loads at the
join), all structurally valid so `check_load_and_stores` can be called directly and its
verdict cross-checked against `bpf_check_classic`. Pure userspace.

| run | seed | programs | kernel accepted | reference safe / unsafe | (A) accepted-but-unsafe | (B) uninit read in execution | executions | (C) rejected-but-safe |
|---|---|---|---|---|---|---|---|---|
| 1 (T=64) | 11 | 500,000 | 104,149 | 173,394 / 326,606 | 0 | 0 | 6,665,536 | 69,245 |
| 2 (T=64) | 12 | 20,000,000 | 4,180,801 | 6,948,622 / 13,051,378 | 0 | 0 | 267,571,264 | 2,767,821 |
| 3 (T=256) | 13 | 10,000,000 | 2,089,761 | 3,472,226 / 6,527,774 | 0 | 0 | 534,978,816 | 1,382,465 |
| total | | 30,500,000 | 6,374,711 | 10,594,242 / 19,905,758 | **0** | **0** | 809,215,616 | 4,219,531 |

Consistency: every reference-unsafe program (19,905,758) was rejected by the kernel; every
kernel-accepted program is reference-safe (accepted + rejected-but-safe = reference safe,
exactly); `bpf_check_classic` and a direct `check_load_and_stores` call never disagreed;
zero interpreter anomalies and zero `WARN_ON` hits. Self-tests pass, including the unsafe
diamond and dead-store cases (rejected by both) and the safe both-branch store (accepted).

Incompleteness (safe direction, ~40% of safe programs in this adversarial mix): after a
`RET` the kernel carries that path's `memvalid` into the next instruction as if it fell
through (filter.c:948-981 has no RET case), so (i) a join reached only by jumps from
stores but textually preceded by a poorer RET path is rejected, and (ii) dead loads after
a RET are rejected. Conservative, never unsafe. Witness: `repro/h4_vm_witness.c` W3.

VM confirmation (`repro/h4_vm_witness.c` via `repro/h4_run.sh`, log `repro/h4_run.log`),
kernel `7.3.0-rc6-00063-g0c2669a9f4a1-dirty` (build #2 of 2026-10-08 15:42; seccomp.c and
net/core/filter.c identical to the pinned commit), host 6.8 as hypervisor only:
- W1 unsafe diamond (store on one branch, load at join): `seccomp(2)` -> `EINVAL`. [VERIFIED: run]
- W2 safe, both branches store distinct `ERRNO|data` values, `RET A`: accepted; `getpid`
  -> `errno=291 (0x123)`, `getppid` -> `errno=1110 (0x456)`. The `RET A` channel does carry
  scratch contents to userspace, deterministically: this is the channel a leak would use.
  [VERIFIED: run]
- W3 safe but phantom-after-RET: `EINVAL` (kernel conservative; matches the extract). [VERIFIED: run]
- W4 store only in dead code, load after: `EINVAL`. [VERIFIED: run]

Why no divergence is expected (proof target for Phase 4; UNVERIFIED as a proof): the
analysis is a forward meet-over-paths on a DAG; at every pc it ANDs the fall-through
contribution with `masks[pc]`, the AND of `memvalid` at every jump that targets pc; every
real predecessor edge is included (jumps record into `masks`, fall-through carries
`memvalid`, and a jump's own fall-through is replaced by `~0` because a jump never falls
through), so the computed set is a subset of the cells written on every real path; stores
add exactly the stored cell; `k < 16` and target bounds are enforced earlier in
`bpf_check_classic`. The phantom RET fall-through only shrinks the set. Bounded fuzzing
cannot prove absence; the Lean theorem closes it.

Harness note: the first VM run's W2 filter had no ALLOW default, so the child's own
`write`/`exit_group` were answered with `-ERRNO` and glibc's `_exit` abort trap killed it
before reporting (kernel behaviour correct; witness bug). Fixed by routing only
getpid/getppid through `RET A`; re-run is the record above.

## 5. H5 — context-load bound arithmetic  (L: none at this commit, I: high)

`k < sizeof && (k & 3) == 0` implies `k + 4 <= sizeof` only if `sizeof % 4 == 0`. Holds:
64 and 40 [VERIFIED: objdump]. Both structs contain `__u64` members, so their size is a
multiple of 8 by construction; no `static_assert` says so (INVENTORY.md). Boundary tests:
io_uring `k = 36` accepted, `k = 40` rejected, `k = 2` rejected; seccomp `k = 60` / `64` / `2`.
Lean: `k < 40 -> k &&& 3 = 0 -> k + 4 <= 40` and the same for 64.

## 6. H6 — a packet-only opcode survives the consumer check and reaches the converter  (L: none, I: high)

If an `sk_buff`-style load reached `bpf_convert_filter`, it would emit loads of `skb->len`
(filter.c:879-884) or `skb->data` (:630-637, :495-563) against a 40- or 64-byte stack
object. The codes legal for `bpf_check_classic` but not handled by the consumer allowlist
are exactly `ALU|MOD|K`, `ALU|MOD|X`, `LD|B|ABS`, `LD|B|IND`, `LD|H|ABS`, `LD|H|IND`,
`LD|W|IND`, `LDX|B|MSH` (all rejected by `default`) plus the three rewritten LEN/ABS forms
[VERIFIED: computed]. Ancillary `k` values are rejected by the u32 bound. Test: all 65536
codes x representative `k` through both consumers in the VM; only the 43 codes are accepted.
Lean: post-rewrite programs contain only context-safe codes.

## 7. H7 — width and alignment  (L: none)

Only `BPF_W` loads exist after the rewrite; `LD|H|ABS` (0x28) and `LD|B|ABS` (0x30) are
rejected; `k & 3` forces 4-byte alignment. Covered by the H6 sweep.

## 8. H8 — jumps past the end, programs without RET  (L: none)

`bpf_check_classic` :1114-1133 bounds every target below `flen` and :1148-1154 requires the
last insn to be `RET`; `BPF_EMIT_JMP` re-checks `target < len` (:718). Since every non-jump
falls through to `pc + 1` and the last insn is a `RET`, every path ends in a `RET`.
Boundary tests: `JA k = flen-pc-2` (lands on the final RET) accepted; `k = flen-pc-1` rejected;
conditional with `pc+jt+1 == flen` rejected; a program whose last insn is a jump rejected.
Lean: termination-in-RET theorem.

## 9. H9 — program length, converted length and allocations  (L: none, I: medium)

Lengths 0 and 4097 are rejected at three layers. Worst-case expansion in the admitted subset:
`ALU|DIV|X` -> 5 insns (filter.c:693-704), conditional jump with negative `k` and both targets
non-zero -> 3 (:743-798), so `new_len <= 3 + 5*4096 = 20483 < S16_MAX`, meaning `BPF_EMIT_JMP`
cannot fail for an admitted program and `tmp_insns[32]` (:644) is never overrun. A failure
would surface as `-EINVAL` or the `BUG_ON` at :921, i.e. denial of service at worst.
[NEEDS EMPIRICAL CHECK for the constants]. Test: run the extracted converter on worst-case
4096-insn programs; in the VM, install them and confirm acceptance.

## 10. H10 — io_uring runtime context vs validator assumption  (L: none)

Same type in the same translation unit (bpf_filter.c:61 vs :188); bytes 0..9 written
explicitly, 10..39 by `memset` (offsets `opcode` 8, `sqe_flags` 9, `pdu_size` 10
[VERIFIED: probe]). Note this is the static layout match; the dynamic mismatch between the
populate thresholds and the network stack is H1, not this item. Test: a filter that returns
each of the ten words for an opcode without a pdu; expect zeros beyond byte 10.

## 11. H11 — no chain limit in io_uring  (L: certain, I: low)

seccomp caps the per-task chain at 32768 insns (seccomp.c:929-934); io_uring prepends
without bound (bpf_filter.c:429-432) and runs every filter per submission (:85-92).
Self-inflicted latency only; allocations are `GFP_KERNEL_ACCOUNT`. Test: install many
filters on one opcode, measure submission latency. Reported as DIFF.md D8.

## 12. H12 — io_uring restriction scope (design, not validator)  (L: certain, I: high for the threat model)

Ring-level registration needs no privilege (register.c:962-971); the task-level set is cloned
only into rings created afterwards (io_uring.c:3031-3032) and into forked children
(tctx.c:410-424); existing threads are not synchronised (no TSYNC analogue); rings that
already exist or arrive over `SCM_RIGHTS` are unfiltered; persistence across exec is by
absence of any exec hook. For an agent sandbox this must become an explicit SPEC.md
assumption: "every ring reachable by the sandboxed task was created by it after the
task-level filter was installed, and no ring fd is received from outside". Test: VM,
confirm each clause.

## 13. H13 — DENY_REST then a later filter on the same opcode  (L: certain, I: low)

The new node's `next` is the dummy (bpf_filter.c:430-431) and the loop denies on the dummy
(:86-87): the opcode stays denied. Fail-closed; may be unintended UX. Reported as DIFF.md D14.
Test: VM.

## 14. H14 — arithmetic corner cases are fail-closed  (spec notes)

Division or modulo by `X = 0` returns 0 (filter.c:693-702) -> `SECCOMP_RET_KILL_THREAD`
(0x0, include/uapi/linux/seccomp.h:39) or io_uring deny. Shifts by `X >= 32`: the
interpreter computes `(u32) DST << (u32) SRC` (the `ALU(` macro, kernel/bpf/core.c:1925-1940),
which is undefined in C for shift counts >= 32 and so must be specified as "unspecified value"
in SPEC.md, not as a safety property. `K` shifts are bounded by `bpf_check_classic` :1101-1104.

## 15. H15 — 32-bit callers  (L: none)

seccomp converts `compat_sock_fprog` (seccomp.c:727-735); io_uring has one 64-bit layout.
`struct sock_filter` is 8 bytes in both ABIs [VERIFIED: probe]. Test: the H5/H8 boundary
programs from an `-m32` binary (`CONFIG_IA32_EMULATION=y`).

## 16. H16 — the emulator cannot run off the end  (L: none)

`seccomp_is_const_allow` advances `pc += k` / `pc += jt|jf` then `pc++` (seccomp.c:807,
:831), matching the validator's target bounds, so `WARN_ON(1)` at :843 is unreachable for an
admitted program. Small Lean lemma.

## 17. H17 — no double fetch of user memory  (L: none)

Filter bytes are copied once (filter.c:1445) and all checks run on the kernel copy;
io_uring copies its registration struct once (bpf_filter.c:320). Nothing to test.

## 18. H18 — io_uring filter-set COW and refcount races  (out of scope)

Recent fix 50b617ba788e ("mark source as COW when cloning filters", 2026-09-19) shows the
area is still moving. Concurrency is first on the exclusion list; noted only.

## Phase 2 order

H1 first (confirm F-1 against the built kernel), then H2, H3, H4, H12 (document), H5-H9 as
boundary suites and proof targets, then H10, H11, H13, H15. H14/H16/H17 become SPEC.md notes.
