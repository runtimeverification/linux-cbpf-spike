# INVENTORY.md — Phase 0 inventory of the cBPF admission paths

Tree: `~/linux-cbpf`, branch `cbpf-spike`, `v7.3-rc6-63-g0c2669a9f4a1` [VERIFIED: git describe].
Build: `~/build-cbpf`, x86_64; `CONFIG_SECCOMP_FILTER=y`, `CONFIG_IO_URING_BPF=y`,
`CONFIG_BPF_JIT` unset, `CONFIG_COMPAT=y`, `CONFIG_IA32_EMULATION=y`,
`CONFIG_CHECKPOINT_RESTORE` unset, `CONFIG_DEBUG_INFO_NONE=y` [VERIFIED: grep ~/build-cbpf/.config].
The host kernel (6.8.0-138-generic) is not the target and has no io_uring BPF
filter support; nothing below was measured on the host kernel.

Tag legend
- `[VERIFIED: read f:l]` — directly visible in the cited lines of one file.
- `[VERIFIED: objdump]` — checked in `~/build-cbpf/*.o` compiled from this tree.
- `[VERIFIED: probe]` — the tree's UAPI headers compiled in userspace with host gcc
  (same x86_64 ABI; the sizes agree with the objdump constants).
- `[VERIFIED: computed]` — derived mechanically by script (text diff, set difference).
- `[NEEDS EMPIRICAL CHECK]` — conclusion follows from reading more than one file;
  not yet executed against the built kernel.
- `[UNVERIFIED]` — reading only.

Unless tagged otherwise, every row below is `[VERIFIED: read]` of the cited lines.
Rows whose "what it does" column chains more than one file carry
`[NEEDS EMPIRICAL CHECK]` explicitly.

## Shared core — net/core/filter.c and kernel/bpf/core.c (both consumers)

| Function | file:line | What it checks / does | Property it is responsible for |
|---|---|---|---|
| `bpf_prog_create_from_user` | net/core/filter.c:1430 | `bpf_check_basics_ok` :1438; `bpf_prog_alloc(bpf_prog_size(len))` :1441; one `copy_from_user` of `len*8` bytes :1445 (user memory is never re-read afterwards); optional `bpf_prog_store_orig_filter` :1453; `bpf_prepare_filter(fp, trans)` :1464 | program length (gate), allocation |
| `bpf_check_basics_ok` | :1054 | `filter != NULL`; `1 <= flen <= BPF_MAXINSNS` (4096, include/uapi/linux/bpf_common.h:54) | program length |
| `bpf_prog_store_orig_filter` | :1157 | `kmemdup` of the pre-transformation cBPF into `fp->orig_prog` | none (bookkeeping; feeds the seccomp allow-cache emulator) |
| `bpf_prepare_filter` | :1336 | `bpf_check_classic` :1344 -> consumer `trans()` :1353 -> `bpf_jit_compile` :1364 (weak no-op kernel/bpf/core.c:3240; only sparc32 defines a cBPF JIT, arch/sparc/net/bpf_jit_comp_32.c:326) -> `bpf_migrate_filter` :1370 | fixes the order: generic check, then consumer rewrite, then conversion |
| `bpf_check_classic` | :1079 | per insn: `chk_code_allowed` :1090; DIV/MOD `k != 0` :1095-1099; LSH/RSH `k < 32` :1101-1104; ST/STX/LD\|MEM/LDX\|MEM `k < BPF_MEMWORDS` (16) :1106-1112; JA `k < flen-pc-1` :1114-1120; conditional `pc+jt+1 < flen`, `pc+jf+1 < flen` :1122-1133; LD\|ABS with `k >= SKF_AD_OFF` (u32 0xFFFFF000) only if a known ancillary :1135-1143; last insn must be RET\|K or RET\|A :1148-1152; then `check_load_and_stores` :1151 | allowed opcodes (generic set), forward jumps in range, terminating RET, scratch index range, shift/div operands |
| `chk_code_allowed` | :988 | 48-entry table of legal cBPF codes :990-1046; code beyond the table -> false :1048 | allowed opcodes |
| `check_load_and_stores` | :935 | forward dataflow over 16 scratch cells: ST/STX set a bit :952-955; LD\|MEM/LDX\|MEM need the bit :956-962; jumps AND the current set into the targets' masks :963-980. Relies on `k < 16` and targets `< flen` already enforced | scratch memory: no read before write on any path |
| `bpf_migrate_filter` | :1266 | `kmemdup` of the cBPF :1284; pass 1 computes length :1292; `bpf_prog_realloc` :1299; pass 2 remaps :1312; `bpf_prog_select_runtime` :1322 | allocation; converter driver |
| `bpf_convert_filter` | :584 | `1 <= len <= 4096` :597; prologue `A=0, X=0, CTX=ARG1` :616-623 (skb prologue only if `seen_ld_abs` :624-638); ALU and skb loads :652-705; jumps :729-798 with `BPF_EMIT_JMP` re-checking `target < len` and `off` fits s16 :713-727; LDX\|B\|MSH :801-825; RET :829-835; ST/STX -> stack slot `FP-(4k+4)` and `stack_depth` :838-850; LD/LDX\|MEM :853-859; LD/LDX\|IMM -> `MOV32_IMM` :862-866; TAX/TXA :869-876; LD/LDX\|W\|LEN -> load of `skb->len` from CTX :879-884 (never reached after the consumer rewrite); **LDX\|W\|ABS -> `BPF_LDX_MEM(BPF_W, A, CTX, k)`** :887-890; unknown -> `-EINVAL` :893-894 | forward jumps (second check); converter semantics for rewritten insns |
| `bpf_prog_select_runtime` | kernel/bpf/core.c:2741 -> `__bpf_prog_select_runtime` :2671 | called with `env = NULL`: the converted eBPF is **not** run through the eBPF verifier; interpreter chosen :2684 (`bpf_prog_select_interpreter` :2614); JIT only under `CONFIG_BPF_JIT` (unset here); `bpf_prog_lock_ro` :2716 | none — the cBPF checks above are the whole trust boundary |
| `___bpf_prog_run` | kernel/bpf/core.c:1869 | interpreter; `LDX_MEM_W` is `DST = *(u32 *)(SRC + off)` with no bounds check :2266-2267; 32-bit ALU ops :1925-1940 | none (executes what was admitted) |
| `bpf_prog_run_pin_on_cpu` | include/linux/filter.h:797 -> `bpf_prog_run` :784 -> `__bpf_prog_run` :756 | runs `prog->bpf_func(ctx, insnsi)` with migration disabled | none |

What the converter emits for the three instructions the consumer validators rewrite
(filter.c lines cited above, single file): `LDX|W|ABS k` -> `BPF_LDX_MEM(BPF_W, R0, R6(ctx), k)`
(32-bit load, zero-extended; `off` is s16 and `k <= 60`); `LD|IMM k` -> `MOV32_IMM(R0, k)`;
`LDX|IMM k` -> `MOV32_IMM(R7(X), k)`, where `k` is the context size written by the validator.

## Consumer 1 — seccomp (kernel/seccomp.c)

### Install path (syscall entry -> installed filter)

| Function | file:line | What it checks / does | Property |
|---|---|---|---|
| `SYSCALL_DEFINE3(seccomp)` | kernel/seccomp.c:2124 | -> `do_seccomp` :2099 | entry |
| `prctl_set_seccomp` | :2137 | `PR_SET_SECCOMP` -> `do_seccomp(op, 0, filter)` :2161 | entry (prctl) |
| `do_seccomp` | :2099 | `SECCOMP_SET_MODE_FILTER` -> `seccomp_set_mode_filter` :2108 | entry |
| `seccomp_set_mode_filter` | :1954 | flag validation :1964-1985; `seccomp_prepare_user_filter` :1988; listener fd :1992-2005; `siglock` :2015; `seccomp_may_assign_mode` :2017; `seccomp_attach_filter` :2025; `seccomp_assign_mode` :2031 | entry, mode |
| `seccomp_prepare_user_filter` | :722 | copies `struct sock_fprog` (native :736; `compat_sock_fprog` :727-733 for 32-bit callers) | ABI |
| `seccomp_prepare_filter` | :669 | `1 <= len <= BPF_MAXINSNS` :680; `no_new_privs` or `CAP_SYS_ADMIN` :691-693; `save_orig = true` on x86_64 because `SECCOMP_ARCH_NATIVE` is defined (arch/x86/include/asm/seccomp.h:20) :673-678 [NEEDS EMPIRICAL CHECK: two files]; `bpf_prog_create_from_user(&prog, fprog, seccomp_check_filter, save_orig)` :701-702 | program length (redundant gate), privilege |
| `seccomp_check_filter` | :278 | `LD\|W\|ABS` -> code := `LDX\|W\|ABS`, require `k < sizeof(struct seccomp_data) && (k & 3) == 0` :287-292; `LD\|W\|LEN` -> `LD\|IMM`, `k := sizeof` :293-296; `LDX\|W\|LEN` -> `LDX\|IMM`, `k := sizeof` :297-300; allowlist of 40 codes :302-340; anything else `-EINVAL` :341-342 | bounds of loads, alignment, width (only `BPF_W` survives), allowed opcodes (consumer set), packet-only opcodes rejected |
| `seccomp_attach_filter` | :921 | chain total `prog->len` + 4 per existing filter `<= MAX_INSNS_PER_PATH` = (1<<18)/8 = 32768 :929-934 (:238); TSYNC :937-947; flags :950-955; prepend :961; `seccomp_cache_prepare` :962; publish :963-964 | program length (per-task chain) |
| `seccomp_cache_prepare` -> `seccomp_cache_prepare_bitmap` -> `seccomp_is_const_allow` | :889 -> :847 -> :770 | emulates the **original** cBPF (`prog->orig_prog`, saved at filter.c:1453 before the rewrite at :1464 [NEEDS EMPIRICAL CHECK: two files]) for every `(arch, nr)` over the subset {`LD\|W\|ABS` at `k` = offsetof(nr), offsetof(arch); `RET\|K`; `JA`; `J{EQ,GE,GT,SET}\|K`; `ALU\|AND\|K`}; any other insn or non-constant load -> not cacheable :798-800, :836-838 | policy: allow cache must agree with real execution |

Where the context size enters: `struct seccomp_data` = include/uapi/linux/seccomp.h:62-67
(`int nr; __u32 arch; __u64 instruction_pointer; __u64 args[6]`) = 64 bytes, offsets
nr 0, arch 4, ip 8, args 16 [VERIFIED: probe]. The compiled validator compares `k` against
`0x3f` and writes `0x40` for the LEN rewrites [VERIFIED: objdump kernel/seccomp.o].
`sizeof(struct seccomp_data)` is used at kernel/seccomp.c:290, :295, :299 and nowhere else
on the admission path.

### Runtime path

| Function | file:line | What it does | Property |
|---|---|---|---|
| syscall entry hook | include/linux/entry-common.h:98 | `__seccomp_permit_syscall()` when `SYSCALL_WORK_SECCOMP` is set (include/linux/seccomp.h:28-33) | entry |
| `__seccomp_permit_syscall` | kernel/seccomp.c:1386 | mode dispatch :1397; `SECCOMP_MODE_FILTER` -> `__seccomp_filter` :1402 | entry |
| `__seccomp_filter` | :1260 | `struct seccomp_data sd` on the kernel stack :1263; `populate_seccomp_data` :1273 writes every field :254-263; `seccomp_run_filters` :1275; action dispatch :1279-1375 (unknown action -> kill :1353-1366) | runtime context = 64-byte fully initialised stack object |
| `seccomp_run_filters` | :404 | allow-cache lookup :416 (`seccomp_cache_check_allow` :367); per filter `bpf_prog_run_pin_on_cpu(f->prog, sd)` :424; lowest action wins :426-429 | policy |

## Consumer 2 — io_uring (io_uring/bpf_filter.c, register.c, io_uring.c)

### Install path

| Function | file:line | What it checks / does | Property |
|---|---|---|---|
| `SYSCALL_DEFINE4(io_uring_register)` | io_uring/register.c:1017 | `opcode < IORING_REGISTER_LAST` :1028; `fd == -1` -> `io_uring_register_blind` :1032; otherwise ring fd -> `__io_uring_register` under `uring_lock` :1039-1040 | entry |
| `io_uring_register_blind` | :1001 | `IORING_REGISTER_BPF_FILTER` (= 37, include/uapi/linux/io_uring.h:724) -> `io_register_bpf_filter_task` :1011-1012 | entry (task-level) |
| `io_register_bpf_filter_task` | :242 | `no_new_privs` or `CAP_SYS_ADMIN` :251-253 (comment: "Similar to seccomp"); `nr_args == 1` :255; `res = current->io_uring_restrict` or a fresh set :259-264; `io_register_bpf_filter(res, arg)` :266; publish :272-273 | privilege, scope |
| `__io_uring_register` | :750 | `submitter_task` check :764; register-restriction bitmap :767-771; `case IORING_REGISTER_BPF_FILTER` :962-971: `nr_args == 1`, `io_register_bpf_filter(&ctx->restrictions, arg)`, then caches the table in `ctx->bpf_filters` :969-970. **No privilege check on this path** | entry (ring-level) |
| `io_register_bpf_filter` | io_uring/bpf_filter.c:360 | `io_bpf_filter_import` :370; `sock_fprog{len = filter_len, filter = filter_ptr}` :374-375; `bpf_prog_create_from_user(&prog, &fprog, io_uring_check_cbpf_filter, false)` :377-378; filter-set alloc or COW :385-403; node :405-411; prepend under spinlock :427-432; `DENY_REST` fills empty slots with the dummy :438-447 | entry, stacking |
| `io_bpf_filter_import` | :314 | `copy_from_user` of `struct io_uring_bpf` :320; `cmd_type == IO_URING_BPF_CMD_FILTER` :322; `cmd_flags == 0 && resv == 0` :324; `opcode < IORING_OP_LAST` :327; `flags` subset of `{DENY_REST, SZ_STRICT}` :329; `resv`, `resv2` zero :331-334; `1 <= filter_len <= BPF_MAXINSNS` :335-336 (u32; narrowed to the u16 `sock_fprog.len` only after this check, at :374); `pdu_size` policy against `def->filter_pdu_size` :339-350; size copied back :353-355 | program length (redundant gate), ABI |
| `io_uring_check_cbpf_filter` | :174 | identical to `seccomp_check_filter` in source (after name normalisation: whitespace only) and in machine code (102 instructions each, differing only in the immediates `0x27/0x28` vs `0x3f/0x40`) [VERIFIED: computed; objdump]. `sizeof(struct io_uring_bpf_ctx)` at :188, :193, :197 | bounds of loads, alignment, width, allowed opcodes, packet-only opcodes rejected |
| `io_bpf_filter_clone` / `io_bpf_filter_cow` | :246 / :267 | share (refcount, COW flag) or copy a filter set between restriction holders | none (lifetime; concurrency is outside every proof) |
| `io_uring_create` | io_uring/io_uring.c:2966 | :3031-3032 clones `current->io_uring_restrict` into the new ring: `io_ctx_restriction_clone` :2952 -> `io_restriction_clone` :2940 -> `io_bpf_filter_clone` | scope: task-level filters reach only rings created afterwards |
| fork / exit / exec | kernel/fork.c:2221 `io_uring_fork` -> include/linux/io_uring.h:32 -> io_uring/tctx.c:410 `__io_uring_fork` (child gets a clone); kernel/fork.c:789, :2636 `io_uring_free` -> tctx.c:75 (dropped at task free). No exec hook: `io_uring_restrict` is referenced only under io_uring/ and include/linux/sched.h:1211 [VERIFIED: computed, grep] | scope [NEEDS EMPIRICAL CHECK: persistence across exec is inferred from the absence of code] |

Where the context size enters: `struct io_uring_bpf_ctx` = include/uapi/linux/io_uring/bpf_filter.h:13-47:
`user_data` @0 (u64), `opcode` @8 (u8), `sqe_flags` @9 (u8), `pdu_size` @10 (u8), `pad[5]` @11,
union @16 { `socket` 12 B, `open` 24 B, `connect` 24 B (family @16, port @20, pad @22, v4_addr/v6_addr @24) }
= 40 bytes [VERIFIED: probe]. The compiled validator compares `k` against `0x27` and writes
`0x28` [VERIFIED: objdump io_uring/bpf_filter.o]. `sizeof(struct io_uring_bpf_ctx)` is used at
io_uring/bpf_filter.c:188, :193, :197 and nowhere else on the admission path. No `static_assert`
or `BUILD_BUG_ON` constrains this struct's size or alignment [VERIFIED: computed, grep].
Per-opcode pdu sizes: io_uring/opdef.c:206 (CONNECT), :222 (OPENAT), :310 (OPENAT2), :409 (SOCKET);
every entry with `filter_pdu_size` also sets `filter_populate` [VERIFIED: computed, grep].

### Runtime path

| Function | file:line | What it does | Property |
|---|---|---|---|
| `io_submit_sqe` | io_uring/io_uring.c:1875 | `io_init_req` :1882 (opcode `< IORING_OP_LAST` + `array_index_nospec` :1742-1746; `def->prep` runs inside it); if `ctx->bpf_filters` -> `io_uring_run_bpf_filters` :1886-1890; denial -> `io_submit_fail_init` | entry; opcode bound precedes the table index |
| `io_uring_run_bpf_filters` | io_uring/bpf_filter.h:18 | NULL table -> allow | — |
| `__io_uring_run_bpf_filters` | io_uring/bpf_filter.c:57 | `struct io_uring_bpf_ctx bpf_ctx` on the kernel stack :61; `filters[req->opcode]` :65, :73; dummy -> `-EACCES` :76-77, :86-87; `io_uring_populate_bpf_ctx` :79; per filter `bpf_prog_run_pin_on_cpu(prog, &bpf_ctx)` :88, return 0 -> `-EACCES` :89-90 | runtime context = 40-byte stack object of the same type the validator sized |
| `io_uring_populate_bpf_ctx` | :26 | `opcode` :31; `sqe_flags = req->flags & SQE_VALID_FLAGS` :32 (7 bits, io_uring/io_uring.h:87, include/uapi/linux/io_uring.h:143-151); `user_data` :33; `memset` of bytes [10, 40) :35-36; `pdu_size` and `def->filter_populate` :42-45 | all 40 bytes initialised: 0..9 explicitly, 10..39 by memset [VERIFIED: probe offsets] |
| `filter_populate` hooks | io_uring/net.c:1708 (SOCKET: domain, type, protocol), :1717 (CONNECT: family if `addr_len >= 2`; v4 port/addr if `>= 16`; v6 port/addr if `>= 28`), io_uring/openclose.c:85 (OPENAT/OPENAT2: `how.flags`, `how.mode`, `how.resolve`) | fills the union from prepped request state | context semantics (see HYPOTHESES.md H1, H2) |

## Property -> responsible function

| Property | Generic (net/core/filter.c) | seccomp (kernel/seccomp.c) | io_uring |
|---|---|---|---|
| program length 1..4096 | `bpf_check_basics_ok` :1059; `bpf_convert_filter` :597 | `seccomp_prepare_filter` :680; chain `<= 32768` insns `seccomp_attach_filter` :933 | `io_bpf_filter_import` bpf_filter.c:335; no chain limit |
| allowed opcodes | `chk_code_allowed` :988 (48 codes) | `seccomp_check_filter` :302-340 (40 codes + 3 rewritten) | `io_uring_check_cbpf_filter` :200-238 (same 40 + 3) |
| bounds of context loads | none (skb semantics only) | `k < 64` :290 | `k < 40` :188 |
| alignment and width | none | `k & 3 == 0` :290; only `BPF_W` reaches the converter | same, :188 |
| forward jumps in range | `bpf_check_classic` :1114-1133; `bpf_convert_filter` `BPF_EMIT_JMP` :718 | — | — |
| terminating RET | `bpf_check_classic` :1148-1154 | — | — |
| scratch memory indexing | `bpf_check_classic` :1106-1112 (`k < 16`); `check_load_and_stores` :935 (written before read) | — | — |
| packet-only opcodes (`LD\|H/B\|ABS`, `LD\|*\|IND`, `LDX\|B\|MSH`, `LD/LDX\|W\|LEN`, ancillary `k`) | allowed by `chk_code_allowed` | rejected (`default`) or rewritten :287-300 | same :185-198 |
| context the runtime provides | — | `__seccomp_filter` :1263; `populate_seccomp_data` :244 | `__io_uring_run_bpf_filters` :61; `io_uring_populate_bpf_ctx` :26 |

Opcode sets, computed mechanically from the source [VERIFIED: computed]:
- legal for `bpf_check_classic` but rejected by both consumer validators (8 codes):
  `ALU|MOD|K`, `ALU|MOD|X`, `LD|B|ABS`, `LD|B|IND`, `LD|H|ABS`, `LD|H|IND`, `LD|W|IND`, `LDX|B|MSH`;
- rewritten by both: `LD|W|ABS` (-> `LDX|W|ABS`), `LD|W|LEN`, `LDX|W|LEN`;
- the consumer case lists contain no code outside `chk_code_allowed`;
- the seccomp and io_uring case lists are identical.
Ancillary loads (`LD|W|ABS` with `k >= 0xFFFFF000`) pass `bpf_check_classic` for the 16 known
`SKF_AD_*` values (include/linux/filter.h:1599-1631) and are then rejected by the consumer
bound `k < sizeof` [VERIFIED: read; the u32 comparison at seccomp.c:290 / bpf_filter.c:188].
