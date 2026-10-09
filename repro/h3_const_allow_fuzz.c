// SPDX-License-Identifier: GPL-2.0
/*
 * H3 differential harness: the kernel's seccomp_is_const_allow() (verbatim,
 * extracted from ~/linux-cbpf at build time by h3_build.sh) against a
 * reference cBPF interpreter that executes the ADMITTED, REWRITTEN program
 * the way the kernel runs it.
 *
 * Oracle: whenever the emulator says (arch, nr) is constant-allow, the real
 * filter must return action SECCOMP_RET_ALLOW for EVERY seccomp_data with that
 * (arch, nr), i.e. for any args/instruction_pointer. A counterexample is a
 * divergence: the cache would allow a syscall the filter would not.
 *
 * Programs are admitted exactly as the kernel admits them: verbatim
 * bpf_check_classic() then verbatim seccomp_check_filter() (which rewrites),
 * and the emulator runs on the ORIGINAL bytes (orig_prog) while the
 * interpreter runs the REWRITTEN bytes, mirroring bpf_prog_create_from_user().
 *
 * Pure userspace. No seccomp syscalls, no kernel interaction. Safe on the host.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <errno.h>
#include <time.h>

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>

/* ---- kernel-ism stubs required by the verbatim extract ---- */
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef int32_t s32;
#define BIT(n) (1UL << (n))
#define BPF_ANC BIT(15)
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define BUILD_BUG_ON(c) ((void)sizeof(char[1 - 2 * !!(c)]))
static unsigned long h3_warn_count;
#define WARN_ON(c) ({ int __w = !!(c); if (__w) h3_warn_count++; __w; })
#define WARN_ON_ONCE(c) WARN_ON(c)
#define BUG_ON(c) do { if (c) { fprintf(stderr, "BUG_ON hit\n"); abort(); } } while (0)
#define GFP_KERNEL 0
#define kmalloc_array(n, sz, gfp) calloc((n), (sz))
#define kfree(p) free(p)
#define fallthrough do { } while (0)
#define __NR_uretprobe 335
#define __NR_uprobe 336
#define SECCOMP_ARCH_NATIVE AUDIT_ARCH_X86_64
#define SECCOMP_ARCH_COMPAT AUDIT_ARCH_I386
struct sock_fprog_kern { u16 len; struct sock_filter *filter; };

#include "h3_kernel_extract.h"

/* ---- RNG ---- */
static uint64_t rng_s;
static inline uint64_t rnd64(void)
{
	rng_s ^= rng_s >> 12; rng_s ^= rng_s << 25; rng_s ^= rng_s >> 27;
	return rng_s * 2685821657736338717ULL;
}
static inline u32 rnd(void) { return (u32)(rnd64() >> 32); }
static inline u32 rndn(u32 n) { return n ? rnd() % n : 0; }

/* ---- reference interpreter: executes the REWRITTEN admitted program ---- */
enum { ANOM_NONE = 0, ANOM_BAD_OPCODE, ANOM_RAN_OFF_END, ANOM_UNREWRITTEN };
static int ref_anomaly;
static const char *anom_name[] = { "none", "bad-opcode", "ran-off-end", "unrewritten-insn" };

static u32 ref_run(const struct sock_filter *p, unsigned len,
		   const struct seccomp_data *sd)
{
	u32 A = 0, X = 0, M[BPF_MEMWORDS];
	unsigned pc = 0;

	memset(M, 0, sizeof(M));
	while (pc < len) {
		const struct sock_filter *i = &p[pc];
		u16 code = i->code;
		u32 k = i->k;

		switch (code) {
		case BPF_LDX | BPF_W | BPF_ABS:	/* seccomp rewrite: ctx load */
			memcpy(&A, (const char *)sd + k, 4);
			pc++;
			continue;
		case BPF_LD | BPF_W | BPF_ABS:
		case BPF_LD | BPF_W | BPF_LEN:
		case BPF_LDX | BPF_W | BPF_LEN:
			ref_anomaly = ANOM_UNREWRITTEN;
			return 0xdeadbeef;
		case BPF_LD | BPF_IMM:  A = k; pc++; continue;
		case BPF_LDX | BPF_IMM: X = k; pc++; continue;
		case BPF_LD | BPF_MEM:  A = M[k]; pc++; continue;
		case BPF_LDX | BPF_MEM: X = M[k]; pc++; continue;
		case BPF_ST:  M[k] = A; pc++; continue;
		case BPF_STX: M[k] = X; pc++; continue;
		case BPF_MISC | BPF_TAX: X = A; pc++; continue;
		case BPF_MISC | BPF_TXA: A = X; pc++; continue;
		case BPF_RET | BPF_K: return k;
		case BPF_RET | BPF_A: return A;
		case BPF_JMP | BPF_JA: pc += k + 1; continue;
		default:
			break;
		}
		if (BPF_CLASS(code) == BPF_ALU) {
			u32 src = (BPF_SRC(code) == BPF_X) ? X : k;

			switch (BPF_OP(code)) {
			case BPF_ADD: A += src; break;
			case BPF_SUB: A -= src; break;
			case BPF_MUL: A *= src; break;
			case BPF_DIV: if (src == 0) return 0; A /= src; break;
			case BPF_AND: A &= src; break;
			case BPF_OR:  A |= src; break;
			case BPF_XOR: A ^= src; break;
			case BPF_LSH: A <<= (src & 31); break;
			case BPF_RSH: A >>= (src & 31); break;
			case BPF_NEG: A = -A; break;
			default: ref_anomaly = ANOM_BAD_OPCODE; return 0xdeadbeef;
			}
			pc++;
			continue;
		}
		if (BPF_CLASS(code) == BPF_JMP) {
			u32 src = (BPF_SRC(code) == BPF_X) ? X : k;
			bool c;

			switch (BPF_OP(code)) {
			case BPF_JEQ:  c = A == src; break;
			case BPF_JGT:  c = A > src; break;
			case BPF_JGE:  c = A >= src; break;
			case BPF_JSET: c = (A & src) != 0; break;
			default: ref_anomaly = ANOM_BAD_OPCODE; return 0xdeadbeef;
			}
			pc += 1 + (c ? i->jt : i->jf);
			continue;
		}
		ref_anomaly = ANOM_BAD_OPCODE;
		return 0xdeadbeef;
	}
	ref_anomaly = ANOM_RAN_OFF_END;
	return 0xdeadbeef;
}

/* ---- admission exactly as the kernel does it ---- */
static bool admit(const struct sock_filter *orig, unsigned len, struct sock_filter *rw)
{
	if (len == 0 || len > BPF_MAXINSNS)
		return false;
	if (bpf_check_classic(orig, len) != 0)
		return false;
	memcpy(rw, orig, len * sizeof(*orig));
	if (seccomp_check_filter(rw, len) != 0)
		return false;
	return true;
}

/* ---- program generators ---- */
#define MAXP 128
enum { L_NEXT = 0, L_ALLOW = 0xFE, L_DENY = 0xFD };

static u32 pick_action(void)
{
	static const u32 acts[] = {
		SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_KILL_THREAD, SECCOMP_RET_TRAP,
		SECCOMP_RET_ERRNO | 1, SECCOMP_RET_TRACE, SECCOMP_RET_LOG,
		SECCOMP_RET_USER_NOTIF, SECCOMP_RET_ALLOW | 1 /* allow action, not exact */,
		SECCOMP_RET_KILL_THREAD | 7,
	};
	u32 r = rndn(10);
	if (r < 4) return SECCOMP_RET_ALLOW;
	return acts[rndn(ARRAY_SIZE(acts))];
}
static u32 pick_nrval(void)
{
	switch (rndn(8)) {
	case 0: return 335; case 1: return 336;
	case 2: return rnd();            /* huge */
	case 3: return AUDIT_ARCH_X86_64; case 4: return AUDIT_ARCH_I386;
	default: return rndn(600);
	}
}
static u32 pick_mask(void)
{
	switch (rndn(5)) {
	case 0: return 0xffff; case 1: return 0xff; case 2: return 0x7fffffff;
	case 3: return 1u << rndn(32); default: return rnd();
	}
}

/* filter-like programs: the realistic cacheable shapes */
static unsigned gen_structured(struct sock_filter *p)
{
	unsigned n = 0, i, ncmp = 1 + rndn(7);
	bool archchk = rndn(2), mask = rndn(4) == 0, argchk = rndn(3) == 0;
	u32 archval = rndn(3) == 0 ? rnd() : (rndn(2) ? AUDIT_ARCH_X86_64 : AUDIT_ARCH_I386);

	if (archchk) {
		p[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 4);
		p[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, archval, L_NEXT, L_DENY);
	}
	p[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0);
	if (mask)
		p[n++] = (struct sock_filter)BPF_STMT(BPF_ALU | BPF_AND | BPF_K, pick_mask());
	for (i = 0; i < ncmp && n < MAXP - 12; i++) {
		u16 op;
		switch (rndn(10)) {
		case 0: op = BPF_JGE; break; case 1: op = BPF_JGT; break;
		case 2: op = BPF_JSET; break; default: op = BPF_JEQ; break;
		}
		u8 jt = rndn(3) ? L_ALLOW : L_DENY, jf = rndn(5) ? L_NEXT : (rndn(2) ? L_ALLOW : L_DENY);
		p[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | op | BPF_K, pick_nrval(), jt, jf);
		if (rndn(6) == 0)	/* reload nr or arch mid-way */
			p[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, rndn(2) ? 0 : 4);
		if (rndn(8) == 0)
			p[n++] = (struct sock_filter)BPF_STMT(BPF_ALU | BPF_AND | BPF_K, pick_mask());
		if (rndn(10) == 0)
			p[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JA, rndn(2) ? L_ALLOW : L_DENY, 0, 0);
	}
	if (argchk) {	/* input-dependent decision: must never be cached */
		u32 off = 8 + 4 * rndn(14);	/* ip or args words, 8..60 */
		p[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, off);
		p[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, rndn(4), L_ALLOW, L_DENY);
	}
	/* end blocks */
	unsigned deny_pc, allow_pc;
	u32 deny = pick_action();
	if (deny == SECCOMP_RET_ALLOW) deny = SECCOMP_RET_KILL_THREAD;
	if (rndn(2)) {
		deny_pc = n;  p[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, deny);
		allow_pc = n; p[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
	} else {
		allow_pc = n; p[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
		deny_pc = n;  p[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, deny);
	}
	/* resolve symbolic targets */
	for (i = 0; i < n; i++) {
		if (BPF_CLASS(p[i].code) != BPF_JMP) continue;
		if (BPF_OP(p[i].code) == BPF_JA) {
			unsigned t = p[i].k == L_ALLOW ? allow_pc : deny_pc;
			p[i].k = t - (i + 1);
			continue;
		}
		if (p[i].jt == L_ALLOW) p[i].jt = allow_pc - (i + 1);
		else if (p[i].jt == L_DENY) p[i].jt = deny_pc - (i + 1);
		if (p[i].jf == L_ALLOW) p[i].jf = allow_pc - (i + 1);
		else if (p[i].jf == L_DENY) p[i].jf = deny_pc - (i + 1);
	}
	return n;
}

/* random instruction soup over the admitted opcode set */
static unsigned gen_soup(struct sock_filter *p)
{
	unsigned len = 1 + rndn(40), pc;
	bool written[BPF_MEMWORDS] = { false };

	for (pc = 0; pc + 1 < len; pc++) {
		unsigned maxoff = len - pc - 2;	/* target <= len-1 */
		u32 r = rndn(100);
		if (r < 28) {
			p[pc] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, rndn(3) ? (rndn(2) ? 0 : 4) : 4 * rndn(16));
		} else if (r < 36) {
			p[pc] = (struct sock_filter)BPF_STMT((rndn(2) ? BPF_LD : BPF_LDX) | BPF_IMM, rndn(2) ? rnd() : pick_nrval());
		} else if (r < 52) {
			static const u16 ops[] = { BPF_ADD, BPF_SUB, BPF_MUL, BPF_DIV, BPF_AND, BPF_OR, BPF_XOR, BPF_LSH, BPF_RSH };
			u16 op = ops[rndn(ARRAY_SIZE(ops))];
			if (rndn(6) == 0) { p[pc] = (struct sock_filter)BPF_STMT(BPF_ALU | BPF_NEG, 0); continue; }
			if (rndn(2)) {
				u32 k = (op == BPF_LSH || op == BPF_RSH) ? rndn(32) : (op == BPF_DIV ? 1 + rndn(1000) : (op == BPF_AND ? pick_mask() : rnd()));
				p[pc] = (struct sock_filter)BPF_STMT(BPF_ALU | op | BPF_K, k);
			} else {
				p[pc] = (struct sock_filter)BPF_STMT(BPF_ALU | op | BPF_X, 0);
			}
		} else if (r < 66) {
			static const u16 jops[] = { BPF_JEQ, BPF_JGE, BPF_JGT, BPF_JSET };
			u16 op = jops[rndn(4)];
			u8 jt = maxoff ? rndn(maxoff + 1) : 0, jf = maxoff ? rndn(maxoff + 1) : 0;
			if (jt > 255) jt = 255; if (jf > 255) jf = 255;
			if (rndn(4))
				p[pc] = (struct sock_filter)BPF_JUMP(BPF_JMP | op | BPF_K, pick_nrval(), jt, jf);
			else
				p[pc] = (struct sock_filter)BPF_JUMP(BPF_JMP | op | BPF_X, 0, jt, jf);
		} else if (r < 71) {
			p[pc] = (struct sock_filter)BPF_STMT(BPF_JMP | BPF_JA, maxoff ? rndn(maxoff + 1) : 0);
		} else if (r < 80) {
			u32 k = rndn(BPF_MEMWORDS);
			p[pc] = (struct sock_filter)BPF_STMT(rndn(2) ? BPF_ST : BPF_STX, k);
			written[k] = true;
		} else if (r < 86) {
			u32 k = rndn(BPF_MEMWORDS);
			if (!written[k]) { p[pc] = (struct sock_filter)BPF_STMT(BPF_ST, k); written[k] = true; }
			else p[pc] = (struct sock_filter)BPF_STMT((rndn(2) ? BPF_LD : BPF_LDX) | BPF_MEM, k);
		} else if (r < 90) {
			p[pc] = (struct sock_filter)BPF_STMT(BPF_MISC | (rndn(2) ? BPF_TAX : BPF_TXA), 0);
		} else if (r < 96) {
			if (rndn(3)) p[pc] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, pick_action());
			else p[pc] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_A, 0);
		} else {
			p[pc] = (struct sock_filter)BPF_STMT((rndn(2) ? BPF_LD : BPF_LDX) | BPF_W | BPF_LEN, 0);
		}
	}
	if (rndn(4)) p[len - 1] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, pick_action());
	else p[len - 1] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_A, 0);
	return len;
}

/* ---- driver ---- */
static inline u32 action_of(u32 r) { return r & SECCOMP_RET_ACTION_FULL; }

static void dump_prog(const struct sock_filter *p, unsigned len)
{
	for (unsigned i = 0; i < len; i++)
		printf("    { 0x%02x, %u, %u, 0x%08x },\n", p[i].code, p[i].jt, p[i].jf, p[i].k);
}

struct stats {
	unsigned long gen, rejected, admitted, emul, etrue, refruns, div_real, div_uprobe,
		      incomplete_checked, incomplete, anomalies;
};

static void check_program(const struct sock_filter *orig, const struct sock_filter *rw,
			  unsigned len, unsigned nrmax, unsigned T, struct stats *st,
			  unsigned *printed_real, unsigned *printed_uprobe)
{
	struct sock_fprog_kern fp = { .len = len, .filter = (struct sock_filter *)orig };
	static const u32 archs[2] = { SECCOMP_ARCH_NATIVE, SECCOMP_ARCH_COMPAT };

	for (int a = 0; a < 2; a++) {
		for (unsigned nr = 0; nr < nrmax; nr++) {
			struct seccomp_data sd0;
			memset(&sd0, 0, sizeof(sd0));
			sd0.nr = (int)nr; sd0.arch = archs[a];
			bool E = seccomp_is_const_allow(&fp, &sd0);
			st->emul++;
			if (!E) {
				if ((rnd() & 15) == 0) {	/* sampled incompleteness stat */
					bool all_allow = true;
					st->incomplete_checked++;
					for (unsigned t = 0; t < T && all_allow; t++) {
						struct seccomp_data sd = { .nr = (int)nr, .arch = archs[a], .instruction_pointer = rnd64() };
						for (int j = 0; j < 6; j++) sd.args[j] = (rndn(3) == 0) ? rndn(8) : rnd64();
						ref_anomaly = 0;
						u32 r = ref_run(rw, len, &sd);
						st->refruns++;
						if (ref_anomaly) { st->anomalies++; all_allow = false; break; }
						if (action_of(r) != SECCOMP_RET_ALLOW) all_allow = false;
					}
					if (all_allow) st->incomplete++;
				}
				continue;
			}
			st->etrue++;
			for (unsigned t = 0; t < T; t++) {
				struct seccomp_data sd = { .nr = (int)nr, .arch = archs[a], .instruction_pointer = rnd64() };
				for (int j = 0; j < 6; j++) sd.args[j] = (rndn(3) == 0) ? rndn(8) : rnd64();
				ref_anomaly = 0;
				u32 r = ref_run(rw, len, &sd);
				st->refruns++;
				if (ref_anomaly) {
					st->anomalies++;
					printf("ANOMALY %s: arch=%#x nr=%u\n", anom_name[ref_anomaly], archs[a], nr);
					dump_prog(orig, len);
					break;
				}
				if (action_of(r) == SECCOMP_RET_ALLOW)
					continue;
				bool uprobe = (archs[a] == SECCOMP_ARCH_NATIVE && (nr == __NR_uretprobe || nr == __NR_uprobe));
				if (uprobe) {
					st->div_uprobe++;
					if ((*printed_uprobe)++ < 2) {
						printf("DIVERGENCE (intentional uprobe passthrough): arch=%#x nr=%u emulator=ALLOW ref=0x%08x (action 0x%08x)\n",
						       archs[a], nr, r, action_of(r));
						dump_prog(orig, len);
					}
				} else {
					st->div_real++;
					if ((*printed_real)++ < 10) {
						printf("*** REAL DIVERGENCE *** arch=%#x nr=%u emulator=ALLOW ref=0x%08x (action 0x%08x)\n",
						       archs[a], nr, r, action_of(r));
						printf("    sd: ip=%#llx args=%#llx %#llx %#llx %#llx %#llx %#llx\n",
						       (unsigned long long)sd.instruction_pointer,
						       (unsigned long long)sd.args[0], (unsigned long long)sd.args[1], (unsigned long long)sd.args[2],
						       (unsigned long long)sd.args[3], (unsigned long long)sd.args[4], (unsigned long long)sd.args[5]);
						printf("    program (len %u):\n", len);
						dump_prog(orig, len);
					}
				}
				break;	/* one counterexample per (prog, arch, nr) is enough */
			}
		}
	}
}

/* ---- self-tests: known programs, known expectations ---- */
static int selftest(void)
{
	int fails = 0;
	struct sock_filter rw[MAXP];
	struct stats st;
	unsigned pr = 0, pu = 0;

	/* 1. classic allowlist: arch==x86_64 && nr==39 -> ALLOW else KILL */
	struct sock_filter t1[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 4),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 3),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 39, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
	};
	if (!admit(t1, 6, rw)) { printf("selftest1: not admitted\n"); fails++; }
	struct sock_fprog_kern fp1 = { 6, t1 };
	struct seccomp_data s = { .nr = 39, .arch = AUDIT_ARCH_X86_64 };
	if (!seccomp_is_const_allow(&fp1, &s)) { printf("selftest1: expected E=true for (x86_64,39)\n"); fails++; }
	s.nr = 40; if (seccomp_is_const_allow(&fp1, &s)) { printf("selftest1: expected E=false for nr 40\n"); fails++; }
	s.nr = 39; s.arch = AUDIT_ARCH_I386; if (seccomp_is_const_allow(&fp1, &s)) { printf("selftest1: expected E=false for i386\n"); fails++; }
	s.arch = AUDIT_ARCH_X86_64; s.args[0] = 123;
	if (action_of(ref_run(rw, 6, &s)) != SECCOMP_RET_ALLOW) { printf("selftest1: ref should ALLOW\n"); fails++; }
	s.nr = 40; if (action_of(ref_run(rw, 6, &s)) != SECCOMP_RET_KILL_PROCESS) { printf("selftest1: ref should KILL nr40\n"); fails++; }

	/* 2. args-dependent: nr==39 && args[0]==0 -> ALLOW else ERRNO: must never cache */
	struct sock_filter t2[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 39, 0, 3),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 16),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 1),
	};
	if (!admit(t2, 6, rw)) { printf("selftest2: not admitted\n"); fails++; }
	struct sock_fprog_kern fp2 = { 6, t2 };
	memset(&s, 0, sizeof(s)); s.nr = 39; s.arch = AUDIT_ARCH_X86_64;
	if (seccomp_is_const_allow(&fp2, &s)) { printf("selftest2: args-dependent program must not be const-allow\n"); fails++; }

	/* 3. positive control: deny-everything filter; the emulator still says ALLOW for uretprobe/uprobe */
	struct sock_filter t3[] = { BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS) };
	if (!admit(t3, 1, rw)) { printf("selftest3: not admitted\n"); fails++; }
	memset(&st, 0, sizeof(st));
	check_program(t3, rw, 1, 512, 4, &st, &pr, &pu);
	if (st.div_uprobe != 2 || st.div_real != 0) {
		printf("selftest3: expected exactly 2 intentional uprobe divergences, 0 real; got %lu/%lu\n", st.div_uprobe, st.div_real);
		fails++;
	}
	printf("selftests: %s (%d failures)\n", fails ? "FAIL" : "PASS", fails);
	return fails;
}

int main(int argc, char **argv)
{
	unsigned long N = argc > 1 ? strtoul(argv[1], 0, 0) : 200000;
	unsigned nrmax = argc > 2 ? (unsigned)strtoul(argv[2], 0, 0) : 512;
	unsigned T = argc > 3 ? (unsigned)strtoul(argv[3], 0, 0) : 32;
	rng_s = argc > 4 ? strtoull(argv[4], 0, 0) : (uint64_t)time(NULL) * 2654435761ULL;
	if (!rng_s) rng_s = 0x9E3779B97F4A7C15ULL;
	uint64_t seed = rng_s;
	struct sock_filter orig[MAXP], rw[MAXP];
	struct stats st; memset(&st, 0, sizeof(st));
	unsigned printed_real = 0, printed_uprobe = 0;

	printf("H3 differential: kernel seccomp_is_const_allow (verbatim) vs reference cBPF interpreter\n");
	printf("params: programs=%lu nrmax=%u samples/T=%u seed=%#llx\n", N, nrmax, T, (unsigned long long)seed);
	if (selftest())
		return 2;
	printed_real = printed_uprobe = 0;

	for (unsigned long i = 0; i < N; i++) {
		unsigned len = (rnd() & 1) ? gen_structured(orig) : gen_soup(orig);
		st.gen++;
		if (!admit(orig, len, rw)) { st.rejected++; continue; }
		st.admitted++;
		check_program(orig, rw, len, nrmax, T, &st, &printed_real, &printed_uprobe);
	}
	printf("\nRESULTS\n");
	printf("  programs generated       %lu\n  rejected by validators   %lu\n  admitted                 %lu\n", st.gen, st.rejected, st.admitted);
	printf("  (prog,arch,nr) emulated  %lu\n  emulator said ALLOW      %lu\n  reference runs           %lu\n", st.emul, st.etrue, st.refruns);
	printf("  divergences REAL         %lu\n  divergences uprobe (intentional passthrough) %lu\n", st.div_real, st.div_uprobe);
	printf("  interpreter anomalies    %lu\n  kernel WARN_ON hits      %lu\n", st.anomalies, h3_warn_count);
	printf("  incompleteness sample: %lu of %lu non-cached (arch,nr) were in fact always-allow (safe direction)\n", st.incomplete, st.incomplete_checked);
	printf("VERDICT: %s\n", (st.div_real == 0 && st.anomalies == 0 && h3_warn_count == 0) ?
	       "NO REAL DIVERGENCE (emulator never over-allows beyond the intentional uprobe passthrough)" :
	       "DIVERGENCE OR ANOMALY FOUND - see above");
	return (st.div_real || st.anomalies || h3_warn_count) ? 1 : 0;
}
