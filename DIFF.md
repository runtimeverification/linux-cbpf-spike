# DIFF.md — seccomp_check_filter vs io_uring_check_cbpf_filter, and how each consumer calls bpf_prepare_filter

Tree `~/linux-cbpf` at `v7.3-rc6-63-g0c2669a9f4a1`; objects from `~/build-cbpf` (x86_64,
`CONFIG_BPF_JIT` unset). Tags as in INVENTORY.md.

## 1. Verdict on the previous spike's claim

Claim: "the io_uring validator is a structural clone of seccomp's, differing in one
context-size constant". **Confirmed, and stronger than stated**:

- Source: after replacing the struct and function names, `diff` of kernel/seccomp.c:278-346
  against io_uring/bpf_filter.c:174-244 reports only the wrapped parameter list (one line
  split in two) and one extra blank line. Every `case` label, rewrite, check and return is
  the same text in the same order [VERIFIED: computed].
- Machine code: `objdump -d` of `seccomp_check_filter` (kernel/seccomp.o) and
  `io_uring_check_cbpf_filter` (io_uring/bpf_filter.o) gives 102 instructions each; the
  instruction streams differ only in three immediates: `cmp $0x3f` -> `cmp $0x27` (the
  `k >= sizeof` bound) and two `movl $0x40` -> `movl $0x28` (the LEN rewrites)
  [VERIFIED: objdump].
- The constants are `sizeof(struct seccomp_data)` = 64 and
  `sizeof(struct io_uring_bpf_ctx)` = 40 [VERIFIED: probe; consistent with objdump].

So at the validator level the two functions compute the same predicate with one parameter.
The differences that matter are around the call site and the runtime, listed in section 4.

## 2. Line-by-line listing

Left: kernel/seccomp.c (line numbers prefixed). Right: io_uring/bpf_filter.c.
`|` marks lines that differ textually; everything else is identical.

```
278: static int seccomp_check_filter(struct sock_filter *filter, unsigned int flen  |	174: static int io_uring_check_cbpf_filter(struct sock_filter *filter,
279: {										    |	175:                      unsigned int flen)
280:    int pc;									    |	176: {
281:    for (pc = 0; pc < flen; pc++) {						    |	177:    int pc;
282:        struct sock_filter *ftest = &filter[pc];				    |	178: 
283:        u16 code = ftest->code;						    |	179:    for (pc = 0; pc < flen; pc++) {
284:        u32 k = ftest->k;							    |	180:        struct sock_filter *ftest = &filter[pc];
285: 										    |	181:        u16 code = ftest->code;
286:        switch (code) {							    |	182:        u32 k = ftest->k;
287:        case BPF_LD | BPF_W | BPF_ABS:					    |	183: 
288:            ftest->code = BPF_LDX | BPF_W | BPF_ABS;			    |	184:        switch (code) {
289:            /* 32-bit aligned and not out of bounds. */			    |	185:        case BPF_LD | BPF_W | BPF_ABS:
290:            if (k >= sizeof(struct seccomp_data) || k & 3)			    |	186:            ftest->code = BPF_LDX | BPF_W | BPF_ABS;
291:                return -EINVAL;						    |	187:            /* 32-bit aligned and not out of bounds. */
292:            continue;							    |	188:            if (k >= sizeof(struct io_uring_bpf_ctx) || k & 3)
293:        case BPF_LD | BPF_W | BPF_LEN:					    |	189:                return -EINVAL;
294:            ftest->code = BPF_LD | BPF_IMM;					    |	190:            continue;
295:            ftest->k = sizeof(struct seccomp_data);				    |	191:        case BPF_LD | BPF_W | BPF_LEN:
296:            continue;							    |	192:            ftest->code = BPF_LD | BPF_IMM;
297:        case BPF_LDX | BPF_W | BPF_LEN:					    |	193:            ftest->k = sizeof(struct io_uring_bpf_ctx);
298:            ftest->code = BPF_LDX | BPF_IMM;				    |	194:            continue;
299:            ftest->k = sizeof(struct seccomp_data);				    |	195:        case BPF_LDX | BPF_W | BPF_LEN:
300:            continue;							    |	196:            ftest->code = BPF_LDX | BPF_IMM;
301:        /* Explicitly include allowed calls. */				    |	197:            ftest->k = sizeof(struct io_uring_bpf_ctx);
302:        case BPF_RET | BPF_K:						    |	198:            continue;
303:        case BPF_RET | BPF_A:						    |	199:        /* Explicitly include allowed calls. */
304:        case BPF_ALU | BPF_ADD | BPF_K:					    |	200:        case BPF_RET | BPF_K:
305:        case BPF_ALU | BPF_ADD | BPF_X:					    |	201:        case BPF_RET | BPF_A:
306:        case BPF_ALU | BPF_SUB | BPF_K:					    |	202:        case BPF_ALU | BPF_ADD | BPF_K:
307:        case BPF_ALU | BPF_SUB | BPF_X:					    |	203:        case BPF_ALU | BPF_ADD | BPF_X:
308:        case BPF_ALU | BPF_MUL | BPF_K:					    |	204:        case BPF_ALU | BPF_SUB | BPF_K:
309:        case BPF_ALU | BPF_MUL | BPF_X:					    |	205:        case BPF_ALU | BPF_SUB | BPF_X:
310:        case BPF_ALU | BPF_DIV | BPF_K:					    |	206:        case BPF_ALU | BPF_MUL | BPF_K:
311:        case BPF_ALU | BPF_DIV | BPF_X:					    |	207:        case BPF_ALU | BPF_MUL | BPF_X:
312:        case BPF_ALU | BPF_AND | BPF_K:					    |	208:        case BPF_ALU | BPF_DIV | BPF_K:
313:        case BPF_ALU | BPF_AND | BPF_X:					    |	209:        case BPF_ALU | BPF_DIV | BPF_X:
314:        case BPF_ALU | BPF_OR | BPF_K:					    |	210:        case BPF_ALU | BPF_AND | BPF_K:
315:        case BPF_ALU | BPF_OR | BPF_X:					    |	211:        case BPF_ALU | BPF_AND | BPF_X:
316:        case BPF_ALU | BPF_XOR | BPF_K:					    |	212:        case BPF_ALU | BPF_OR | BPF_K:
317:        case BPF_ALU | BPF_XOR | BPF_X:					    |	213:        case BPF_ALU | BPF_OR | BPF_X:
318:        case BPF_ALU | BPF_LSH | BPF_K:					    |	214:        case BPF_ALU | BPF_XOR | BPF_K:
319:        case BPF_ALU | BPF_LSH | BPF_X:					    |	215:        case BPF_ALU | BPF_XOR | BPF_X:
320:        case BPF_ALU | BPF_RSH | BPF_K:					    |	216:        case BPF_ALU | BPF_LSH | BPF_K:
321:        case BPF_ALU | BPF_RSH | BPF_X:					    |	217:        case BPF_ALU | BPF_LSH | BPF_X:
322:        case BPF_ALU | BPF_NEG:						    |	218:        case BPF_ALU | BPF_RSH | BPF_K:
323:        case BPF_LD | BPF_IMM:						    |	219:        case BPF_ALU | BPF_RSH | BPF_X:
324:        case BPF_LDX | BPF_IMM:						    |	220:        case BPF_ALU | BPF_NEG:
325:        case BPF_MISC | BPF_TAX:						    |	221:        case BPF_LD | BPF_IMM:
326:        case BPF_MISC | BPF_TXA:						    |	222:        case BPF_LDX | BPF_IMM:
327:        case BPF_LD | BPF_MEM:						    |	223:        case BPF_MISC | BPF_TAX:
328:        case BPF_LDX | BPF_MEM:						    |	224:        case BPF_MISC | BPF_TXA:
329:        case BPF_ST:							    |	225:        case BPF_LD | BPF_MEM:
330:        case BPF_STX:							    |	226:        case BPF_LDX | BPF_MEM:
331:        case BPF_JMP | BPF_JA:						    |	227:        case BPF_ST:
332:        case BPF_JMP | BPF_JEQ | BPF_K:					    |	228:        case BPF_STX:
333:        case BPF_JMP | BPF_JEQ | BPF_X:					    |	229:        case BPF_JMP | BPF_JA:
334:        case BPF_JMP | BPF_JGE | BPF_K:					    |	230:        case BPF_JMP | BPF_JEQ | BPF_K:
335:        case BPF_JMP | BPF_JGE | BPF_X:					    |	231:        case BPF_JMP | BPF_JEQ | BPF_X:
336:        case BPF_JMP | BPF_JGT | BPF_K:					    |	232:        case BPF_JMP | BPF_JGE | BPF_K:
337:        case BPF_JMP | BPF_JGT | BPF_X:					    |	233:        case BPF_JMP | BPF_JGE | BPF_X:
338:        case BPF_JMP | BPF_JSET | BPF_K:					    |	234:        case BPF_JMP | BPF_JGT | BPF_K:
339:        case BPF_JMP | BPF_JSET | BPF_X:					    |	235:        case BPF_JMP | BPF_JGT | BPF_X:
340:            continue;							    |	236:        case BPF_JMP | BPF_JSET | BPF_K:
341:        default:								    |	237:        case BPF_JMP | BPF_JSET | BPF_X:
342:            return -EINVAL;							    |	238:            continue;
343:        }									    |	239:        default:
344:    }									    |	240:            return -EINVAL;
345:    return 0;								    |	241:        }
346: }										    |	242:    }
										    >	243:    return 0;
										    >	244: }
```

Normalised diff (struct name -> `CTX_STRUCT`, function name -> `CHECK_FN`):

```
1c1,2
< static int CHECK_FN(struct sock_filter *filter, unsigned int flen)
---
> static int CHECK_FN(struct sock_filter *filter,
> 				      unsigned int flen)
3a5
> 
```

Instruction-level diff of the compiled functions (addresses and symbol names stripped):

```
61c61
< movl   $0x40,0x4(%rdx)
---
> movl   $0x28,0x4(%rdx)
68c68
< movl   $0x40,0x4(%rdx)
---
> movl   $0x28,0x4(%rdx)
75c75
< cmp    $0x3f,%ebp
---
> cmp    $0x27,%ebp
```

## 3. The call into bpf_prepare_filter, side by side

| Step | seccomp | io_uring |
|---|---|---|
| user struct | `struct sock_fprog` (or `compat_sock_fprog` for 32-bit callers), kernel/seccomp.c:722-741 | `struct io_uring_bpf` (fixed 64-bit layout, `filter_ptr` is `__u64`), io_uring/bpf_filter.c:314-358 |
| length pre-check | `fprog->len == 0 \|\| > BPF_MAXINSNS` -> `-EINVAL`, :680 | `!filter_len \|\| filter_len > BPF_MAXINSNS` -> `-EINVAL`, :335; then u32 -> u16 narrowing at :374 |
| privilege | always: `no_new_privs` or `CAP_SYS_ADMIN`, :691-693 | task-level path only (register.c:251-253); ring-level path has none (register.c:962-971) |
| call | `bpf_prog_create_from_user(&sfilter->prog, fprog, seccomp_check_filter, save_orig)`, :701 with `save_orig = true` on x86_64 (:673-678) | `bpf_prog_create_from_user(&prog, &fprog, io_uring_check_cbpf_filter, false)`, :377 |
| shared tail | `bpf_check_basics_ok` -> alloc -> one `copy_from_user` -> (`orig_prog` copy, seccomp only) -> `bpf_check_classic` -> `trans` -> `bpf_migrate_filter` -> `bpf_convert_filter` x2 -> `bpf_prog_select_runtime` (interpreter; no eBPF verifier), net/core/filter.c:1430-1470, :1336-1373, :1266-1334 | same |
| after admission | chain length `<= 32768` insns (:929-934), TSYNC, allow-cache emulation of `orig_prog` (:962, :770-845), publish under `siglock` | filter-set alloc/COW (:385-403), prepend to per-opcode list under spinlock (:427-432), optional `DENY_REST` fill (:438-447) |
| who can install | the task itself, for itself (and threads with TSYNC) | the ring owner for one ring; or the task for all rings it creates afterwards and for forked children (io_uring.c:3031; tctx.c:410) |
| runtime context | `struct seccomp_data` on the stack, every field written (kernel/seccomp.c:1263, :244-264) | `struct io_uring_bpf_ctx` on the stack, bytes 0..9 written, 10..39 memset, union filled by per-opcode hook (bpf_filter.c:61, :26-46) |
| return value | `u32` `SECCOMP_RET_*`; lowest action across the chain wins; unknown action kills (:404-432, :1353-1366) | `0` denies, non-zero allows; every filter in the opcode's list must allow (:85-92) |

## 4. Every difference, with intent and a witness program

Witness programs are `struct sock_filter` arrays; "accepted" means the validator chain
(`bpf_check_classic` + consumer check) returns 0. Witnesses are derived from the source
and are **not yet executed** against the built kernel: each is `[NEEDS EMPIRICAL CHECK]`
unless stated otherwise.

| # | Difference | Intentional? | Accepted by one, rejected by the other |
|---|---|---|---|
| D1 | Bound and LEN constant: 64 (`seccomp_data`) vs 40 (`io_uring_bpf_ctx`); seccomp.c:290,295,299 vs bpf_filter.c:188,193,197 | Yes: each validator sizes the context its runtime passes | `{LD\|W\|ABS k=40; RET\|K 0x7fff0000}`: seccomp accepts (args[3] low word), io_uring `-EINVAL`. Same for k in {44,48,52,56,60}. Reverse direction: none at the validator level, because every other check is identical and 40 < 64, so io_uring's accepted set is a strict subset of seccomp's [VERIFIED: computed from the identical predicate] |
| D2 | `LD\|W\|LEN` / `LDX\|W\|LEN` yield `A = 64` vs `A = 40` | Yes (follows from D1) | both accept `{LD\|W\|LEN; RET\|A}`; the returned value differs |
| D3 | Signature wrapped over two lines; one extra blank line; different doc comment (seccomp.c:266-277 vs bpf_filter.c:169-173) | Cosmetic | none |
| D4 | `save_orig`: `true` (x86_64) vs `false`; filter.c:1453 runs only for seccomp | Yes: seccomp needs `orig_prog` for the allow cache and `PTRACE_SECCOMP_GET_FILTER` | none (no effect on acceptance) |
| D5 | Length gate placement: both re-check 1..4096 before the shared `bpf_check_basics_ok`; io_uring stores the length in a u16 after the check | Yes | none (equivalent) |
| D6 | Privilege: seccomp always requires `no_new_privs` or `CAP_SYS_ADMIN`; io_uring only for the task-level (fd = -1) path | Yes: a ring-level filter restricts only the caller's own ring | a process without `no_new_privs` and without `CAP_SYS_ADMIN`: seccomp `-EACCES`, io_uring ring-level accepts any valid program |
| D7 | 32-bit callers: seccomp reads `compat_sock_fprog`; io_uring has one layout (`__u64 filter_ptr`) | Yes | none (`struct sock_filter` is 8 bytes in both ABIs [VERIFIED: probe]) |
| D8 | Chain limit: seccomp `MAX_INSNS_PER_PATH` = 32768 across the task's chain (+4 per filter); io_uring has no limit on the number or total size of filters per opcode | Omission in io_uring, probably not deliberate; impact is resource use only | with 7 filters of 4096 insns already installed, an 8th 4096-insn filter: seccomp `-ENOMEM` (7x4100 + 4096 = 32796 > 32768), io_uring accepts |
| D9 | Return semantics: `SECCOMP_RET_*` (action in the high 16 bits, data in the low 16) vs allow/deny bit | Yes | none at the validator; e.g. division by `X = 0` makes the converted program return 0 (filter.c:693-702), which is `SECCOMP_RET_KILL_THREAD` for seccomp and "deny" for io_uring — both fail closed |
| D10 | Runtime context population: all 64 bytes written by `populate_seccomp_data`; io_uring writes 10 bytes explicitly and memsets 30, then runs a per-opcode hook for 4 opcodes | Yes | none; both objects are fully initialised [VERIFIED: probe offsets for io_uring] |
| D11 | Post-admission emulation: seccomp re-interprets the original program in `seccomp_is_const_allow` to build the per-syscall allow cache; io_uring has no cache | Yes | none for acceptance; it adds a second interpreter whose agreement with the real one is a policy property (HYPOTHESES.md H3) |
| D12 | Scope and inheritance: seccomp is per task, synced with TSYNC, inherited on fork, kept across exec; io_uring filters are per ring, plus a per-task set cloned into rings created later and into forked children, kept across exec (no exec hook), never synced into existing threads, and never applied to rings that already exist or arrive over SCM_RIGHTS | Design choice of the io_uring API | not a validator difference; see HYPOTHESES.md H12 for the threat-model consequence |
| D13 | Install locking: seccomp under `siglock`; io_uring ring-level under `uring_lock` plus the filter-set spinlock; task-level without locks (`current` only) | Yes | none; concurrency is outside every proof here |
| D14 | `DENY_REST` and the dummy filter exist only in io_uring. A filter registered later for an opcode already holding the dummy gets `next = dummy` (bpf_filter.c:430-431), and the run loop denies on reaching the dummy (:86-87), so that opcode stays denied whatever the new filter returns | Fail-closed; possibly unintended UX | none for acceptance |
| D15 | Error codes: seccomp `-EINVAL/-EACCES/-ENOMEM/-EFAULT`; io_uring adds `-EMSGSIZE` (pdu size policy, :343-350) and `-EBUSY` (COW race, :308) | Yes | a registration whose `pdu_size` exceeds the opcode's kernel pdu: io_uring `-EMSGSIZE` before any program byte is read; seccomp has no such field |
| D16 | Order of checks is the same: generic `bpf_check_classic` on the user's codes, then the consumer rewrite, then conversion. Neither consumer can be reached with `LDX\|W\|ABS` (0x21) directly, because `chk_code_allowed` has no entry for it (filter.c:1014-1026) | Yes | `{LDX\|W\|ABS k=0; RET\|K 1}` is `-EINVAL` for both |

Summary: one semantic difference inside the validator (D1/D2); everything else is call-site,
scope, runtime-context and return-value policy. No program is accepted by io_uring and
rejected by seccomp at the validator level; the reverse set is exactly the loads with
`k in {40, 44, 48, 52, 56, 60}`. The sharper divergence is not in the validator at all but
between the io_uring validator's context assumption and the runtime population of that
context (HYPOTHESES.md H1, recorded as FINDINGS.md F-1).
