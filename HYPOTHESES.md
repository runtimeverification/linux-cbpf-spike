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
[NEEDS EMPIRICAL CHECK: spans io_uring/net.c and net/ipv6/*]. Recorded as FINDINGS.md F-1
[UNCONFIRMED]; see that file for the test procedure.

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
