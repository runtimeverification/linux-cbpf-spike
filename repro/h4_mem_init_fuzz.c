// SPDX-License-Identifier: GPL-2.0
/*
 * H4 differential harness: can a cBPF program accepted by the kernel's
 * check_load_and_stores() (verbatim, via bpf_check_classic()) read a scratch
 * cell M[k] that was never written on the path actually taken?
 *
 * Three oracles per generated program:
 *  (A) exact must-write dataflow with reachability (independent reference):
 *      a program is SAFE iff every reachable LD|MEM/LDX|MEM reads a cell written
 *      on every path from entry.  kernel-accepts && ref-UNSAFE  => syntactic
 *      divergence candidate.
 *  (B) execution oracle: run the admitted (rewritten) program on random
 *      seccomp_data with per-cell "initialised" tracking; any read of an
 *      uninitialised cell on an executed path  => REAL divergence (leak).
 *  (C) incompleteness (safe direction): kernel-rejects && ref-SAFE.
 * Pure userspace, no kernel interaction.
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

typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef int32_t s32;
#define BIT(n) (1UL << (n))
#define BPF_ANC BIT(15)
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define BUILD_BUG_ON(c) ((void)sizeof(char[1 - 2 * !!(c)]))
static unsigned long h_warn_count;
#define WARN_ON(c) ({ int __w = !!(c); if (__w) h_warn_count++; __w; })
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

static uint64_t rng_s;
static inline uint64_t rnd64(void) { rng_s ^= rng_s >> 12; rng_s ^= rng_s << 25; rng_s ^= rng_s >> 27; return rng_s * 2685821657736338717ULL; }
static inline u32 rnd(void) { return (u32)(rnd64() >> 32); }
static inline u32 rndn(u32 n) { return n ? rnd() % n : 0; }

#define MAXP 64
#define ALL16 0xffffu

/* ---- (A) exact must-write analysis with reachability (DAG, forward jumps) ---- */
static bool ref_safe(const struct sock_filter *p, unsigned len, int *bad_pc)
{
	u16 in[MAXP]; bool reach[MAXP];
	for (unsigned i = 0; i < len; i++) { in[i] = ALL16; reach[i] = false; }
	in[0] = 0; reach[0] = true;
#define SUCC(t, o) do { unsigned _t = (t); if (_t >= len) { fprintf(stderr, "bad succ\n"); abort(); } in[_t] &= (o); reach[_t] = true; } while (0)
	for (unsigned pc = 0; pc < len; pc++) {
		if (!reach[pc]) continue;
		u16 code = p[pc].code, out = in[pc];
		u32 k = p[pc].k;
		if (code == BPF_ST || code == BPF_STX) out |= (u16)(1u << k);
		else if (code == (BPF_LD | BPF_MEM) || code == (BPF_LDX | BPF_MEM)) {
			if (!(in[pc] & (1u << k))) { *bad_pc = (int)pc; return false; }
		}
		if (BPF_CLASS(code) == BPF_RET) continue;
		if (BPF_CLASS(code) == BPF_JMP) {
			if (BPF_OP(code) == BPF_JA) SUCC(pc + 1 + k, out);
			else { SUCC(pc + 1 + p[pc].jt, out); SUCC(pc + 1 + p[pc].jf, out); }
		} else SUCC(pc + 1, out);
	}
#undef SUCC
	*bad_pc = -1;
	return true;
}

/* ---- (B) execution with uninitialised-cell tracking (runs the REWRITTEN program) ---- */
struct exec_res { u32 ret; int uninit_pc; u32 uninit_cell; bool poison_in_ret; int anomaly; };
static struct exec_res exec_track(const struct sock_filter *p, unsigned len, const struct seccomp_data *sd)
{
	struct exec_res r = { 0, -1, 0, false, 0 };
	u32 A = 0, X = 0, M[BPF_MEMWORDS]; bool init[BPF_MEMWORDS] = { false };
	bool A_tainted = false, X_tainted = false, Mt[BPF_MEMWORDS] = { false };
	unsigned pc = 0;
	for (unsigned i = 0; i < BPF_MEMWORDS; i++) M[i] = 0xDEAD0000u | i;	/* poison */
	while (pc < len) {
		const struct sock_filter *i = &p[pc]; u16 code = i->code; u32 k = i->k;
		switch (code) {
		case BPF_LDX | BPF_W | BPF_ABS: memcpy(&A, (const char *)sd + k, 4); A_tainted = false; pc++; continue;
		case BPF_LD | BPF_IMM:  A = k; A_tainted = false; pc++; continue;
		case BPF_LDX | BPF_IMM: X = k; X_tainted = false; pc++; continue;
		case BPF_LD | BPF_MEM:
			if (!init[k] && r.uninit_pc < 0) { r.uninit_pc = (int)pc; r.uninit_cell = k; }
			A = M[k]; A_tainted = !init[k] || Mt[k]; pc++; continue;
		case BPF_LDX | BPF_MEM:
			if (!init[k] && r.uninit_pc < 0) { r.uninit_pc = (int)pc; r.uninit_cell = k; }
			X = M[k]; X_tainted = !init[k] || Mt[k]; pc++; continue;
		case BPF_ST:  M[k] = A; init[k] = true; Mt[k] = A_tainted; pc++; continue;
		case BPF_STX: M[k] = X; init[k] = true; Mt[k] = X_tainted; pc++; continue;
		case BPF_MISC | BPF_TAX: X = A; X_tainted = A_tainted; pc++; continue;
		case BPF_MISC | BPF_TXA: A = X; A_tainted = X_tainted; pc++; continue;
		case BPF_RET | BPF_K: r.ret = k; return r;
		case BPF_RET | BPF_A: r.ret = A; r.poison_in_ret = A_tainted; return r;
		case BPF_JMP | BPF_JA: pc += k + 1; continue;
		case BPF_LD | BPF_W | BPF_ABS: case BPF_LD | BPF_W | BPF_LEN: case BPF_LDX | BPF_W | BPF_LEN:
			r.anomaly = 3; return r;
		default: break;
		}
		if (BPF_CLASS(code) == BPF_ALU) {
			u32 src = (BPF_SRC(code) == BPF_X) ? X : k; bool st = (BPF_SRC(code) == BPF_X) ? X_tainted : false;
			switch (BPF_OP(code)) {
			case BPF_ADD: A += src; break; case BPF_SUB: A -= src; break; case BPF_MUL: A *= src; break;
			case BPF_DIV: if (src == 0) { r.ret = 0; return r; } A /= src; break;
			case BPF_AND: A &= src; break; case BPF_OR: A |= src; break; case BPF_XOR: A ^= src; break;
			case BPF_LSH: A <<= (src & 31); break; case BPF_RSH: A >>= (src & 31); break;
			case BPF_NEG: A = -A; break;
			default: r.anomaly = 1; return r;
			}
			if (BPF_OP(code) != BPF_NEG) A_tainted = A_tainted || st;
			pc++; continue;
		}
		if (BPF_CLASS(code) == BPF_JMP) {
			u32 src = (BPF_SRC(code) == BPF_X) ? X : k; bool c;
			switch (BPF_OP(code)) {
			case BPF_JEQ: c = A == src; break; case BPF_JGT: c = A > src; break;
			case BPF_JGE: c = A >= src; break; case BPF_JSET: c = (A & src) != 0; break;
			default: r.anomaly = 1; return r;
			}
			pc += 1 + (c ? i->jt : i->jf); continue;
		}
		r.anomaly = 1; return r;
	}
	r.anomaly = 2; return r;
}

/* ---- structural pre-check (so check_load_and_stores can be called directly and attributed) ---- */
static bool structurally_valid(const struct sock_filter *p, unsigned len)
{
	if (len == 0 || len > MAXP) return false;
	if (p[len - 1].code != (BPF_RET | BPF_K) && p[len - 1].code != (BPF_RET | BPF_A)) return false;
	for (unsigned pc = 0; pc < len; pc++) {
		u16 c = p[pc].code; u32 k = p[pc].k;
		if (!chk_code_allowed(c)) return false;
		if (c == BPF_ST || c == BPF_STX || c == (BPF_LD | BPF_MEM) || c == (BPF_LDX | BPF_MEM)) { if (k >= BPF_MEMWORDS) return false; }
		if (c == (BPF_JMP | BPF_JA)) { if (k >= (u32)(len - pc - 1)) return false; }
		else if (BPF_CLASS(c) == BPF_JMP) { if (pc + p[pc].jt + 1 >= len || pc + p[pc].jf + 1 >= len) return false; }
		if (c == (BPF_ALU | BPF_DIV | BPF_K) && k == 0) return false;
		if ((c == (BPF_ALU | BPF_LSH | BPF_K) || c == (BPF_ALU | BPF_RSH | BPF_K)) && k >= 32) return false;
		if (c == (BPF_LD | BPF_W | BPF_ABS) && (k >= 64 || (k & 3))) return false;
	}
	return true;
}

/* ---- generators (structurally valid by construction; MEM-dense; no write tracking) ---- */
static u32 cell(void) { return rndn(10) < 7 ? rndn(4) : rndn(BPF_MEMWORDS); }
static u32 act(void) { static const u32 a[] = { SECCOMP_RET_ALLOW, SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_ERRNO | 7, SECCOMP_RET_TRAP }; return a[rndn(4)]; }

static unsigned gen_soup(struct sock_filter *p)
{
	unsigned len = 2 + rndn(46), pc;
	for (pc = 0; pc + 1 < len; pc++) {
		unsigned maxoff = len - pc - 2; u32 r = rndn(100);
		if (r < 35) {
			static const u16 m[] = { BPF_ST, BPF_STX, BPF_LD | BPF_MEM, BPF_LDX | BPF_MEM };
			p[pc] = (struct sock_filter)BPF_STMT(m[rndn(4)], cell());
		} else if (r < 55) {
			static const u16 j[] = { BPF_JEQ, BPF_JGE, BPF_JGT, BPF_JSET };
			u8 jt = (rndn(3) == 0 || !maxoff) ? 0 : rndn(maxoff + 1), jf = (rndn(3) == 0 || !maxoff) ? 0 : rndn(maxoff + 1);
			if (jt > 255) jt = 255;
			if (jf > 255) jf = 255;
			p[pc] = rndn(3) ? (struct sock_filter)BPF_JUMP(BPF_JMP | j[rndn(4)] | BPF_K, rndn(2) ? rndn(600) : rnd(), jt, jf)
					: (struct sock_filter)BPF_JUMP(BPF_JMP | j[rndn(4)] | BPF_X, 0, jt, jf);
		} else if (r < 63) {
			p[pc] = (struct sock_filter)BPF_STMT(BPF_JMP | BPF_JA, maxoff ? rndn(maxoff + 1) : 0);
		} else if (r < 71) {
			p[pc] = rndn(2) ? (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, act()) : (struct sock_filter)BPF_STMT(BPF_RET | BPF_A, 0);
		} else if (r < 86) {
			p[pc] = rndn(2) ? (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 4 * rndn(16))
					: (struct sock_filter)BPF_STMT((rndn(2) ? BPF_LD : BPF_LDX) | BPF_IMM, rnd());
		} else if (r < 96) {
			static const u16 o[] = { BPF_ADD, BPF_SUB, BPF_MUL, BPF_AND, BPF_OR, BPF_XOR, BPF_LSH, BPF_RSH };
			u16 op = o[rndn(8)];
			if (rndn(2)) p[pc] = (struct sock_filter)BPF_STMT(BPF_ALU | op | BPF_K, (op == BPF_LSH || op == BPF_RSH) ? rndn(32) : rnd());
			else p[pc] = (struct sock_filter)BPF_STMT(BPF_ALU | op | BPF_X, 0);
		} else {
			p[pc] = (struct sock_filter)BPF_STMT(BPF_MISC | (rndn(2) ? BPF_TAX : BPF_TXA), 0);
		}
	}
	p[len - 1] = rndn(5) ? (struct sock_filter)BPF_STMT(BPF_RET | BPF_A, 0) : (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, act());
	return len;
}

/* diamonds: branch on ctx; store cell on left / right / both / neither / dead; load at join */
static unsigned gen_diamond(struct sock_filter *p)
{
	unsigned n = 0; u32 c = cell(), c2 = cell(); int shape = rndn(6);
	p[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 4 * rndn(16));
	unsigned jpc = n++;	/* placeholder cond jump */
	unsigned left = n;
	if (shape != 3 && shape != 5) { p[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_IMM, rnd()); p[n++] = (struct sock_filter)BPF_STMT(rndn(2) ? BPF_ST : BPF_STX, c); }
	if (rndn(3) == 0) p[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, act());	/* left may end early */
	unsigned ja = n++;	/* JA over right */
	unsigned right = n;
	if (shape == 2 || shape == 4) { p[n++] = (struct sock_filter)BPF_STMT(rndn(2) ? BPF_ST : BPF_STX, c); }
	if (shape == 5) { p[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, act()); p[n++] = (struct sock_filter)BPF_STMT(BPF_ST, c); } /* dead store */
	if (rndn(4) == 0) p[n++] = (struct sock_filter)BPF_STMT(BPF_ST, c2);
	unsigned join = n;
	p[n++] = (struct sock_filter)BPF_STMT((rndn(2) ? BPF_LD : BPF_LDX) | BPF_MEM, rndn(4) ? c : c2);
	if (rndn(2)) p[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_MEM, c2);
	p[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_A, 0);
	p[jpc] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, rndn(8), 0, (u8)(right - jpc - 1));
	(void)left;
	p[ja] = (struct sock_filter)BPF_STMT(BPF_JMP | BPF_JA, join - ja - 1);
	return n;
}

static void dump(const struct sock_filter *p, unsigned len) { for (unsigned i = 0; i < len; i++) printf("    { 0x%02x, %u, %u, 0x%08x },\n", p[i].code, p[i].jt, p[i].jf, p[i].k); }

static int selftest(void)
{
	int f = 0, bad;
	/* unsafe diamond: store on one branch only, load at join */
	struct sock_filter d1[] = { BPF_STMT(BPF_LD|BPF_W|BPF_ABS,0), BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,39,0,2), BPF_STMT(BPF_LD|BPF_IMM,0x50123), BPF_STMT(BPF_ST,0), BPF_STMT(BPF_LD|BPF_MEM,0), BPF_STMT(BPF_RET|BPF_A,0) };
	if (bpf_check_classic(d1, 6) == 0) { printf("selftest d1: kernel ACCEPTED unsafe diamond!\n"); f++; }
	if (ref_safe(d1, 6, &bad)) { printf("selftest d1: ref says safe\n"); f++; }
	/* safe: both branches store */
	struct sock_filter d2[] = { BPF_STMT(BPF_LD|BPF_W|BPF_ABS,0), BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,39,0,3), BPF_STMT(BPF_LD|BPF_IMM,0x50123), BPF_STMT(BPF_ST,0), BPF_STMT(BPF_JMP|BPF_JA,2), BPF_STMT(BPF_LD|BPF_IMM,0x50456), BPF_STMT(BPF_ST,0), BPF_STMT(BPF_LD|BPF_MEM,0), BPF_STMT(BPF_RET|BPF_A,0) };
	if (bpf_check_classic(d2, 9) != 0) { printf("selftest d2: kernel rejected safe both-store\n"); f++; }
	if (!ref_safe(d2, 9, &bad)) { printf("selftest d2: ref says unsafe\n"); f++; }
	/* safe but conservatively rejected: phantom fall-through after RET */
	struct sock_filter d3[] = { BPF_STMT(BPF_LD|BPF_W|BPF_ABS,0), BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,39,0,3), BPF_STMT(BPF_LD|BPF_IMM,0x50123), BPF_STMT(BPF_ST,1), BPF_STMT(BPF_JMP|BPF_JA,1), BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW), BPF_STMT(BPF_LD|BPF_MEM,1), BPF_STMT(BPF_RET|BPF_A,0) };
	int k3 = bpf_check_classic(d3, 8); bool r3 = ref_safe(d3, 8, &bad);
	printf("selftest d3 (phantom-after-RET): kernel=%s ref=%s  (expected kernel reject, ref safe)\n", k3 ? "REJECT" : "ACCEPT", r3 ? "SAFE" : "UNSAFE");
	if (k3 == 0 || !r3) f++;
	/* dead-code store */
	struct sock_filter d4[] = { BPF_STMT(BPF_JMP|BPF_JA,1), BPF_STMT(BPF_ST,0), BPF_STMT(BPF_LD|BPF_MEM,0), BPF_STMT(BPF_RET|BPF_A,0) };
	if (bpf_check_classic(d4, 4) == 0) { printf("selftest d4: kernel ACCEPTED dead-store read!\n"); f++; }
	if (ref_safe(d4, 4, &bad)) { printf("selftest d4: ref says safe\n"); f++; }
	printf("selftests: %s (%d failures)\n", f ? "FAIL" : "PASS", f);
	return f;
}

int main(int argc, char **argv)
{
	unsigned long N = argc > 1 ? strtoul(argv[1], 0, 0) : 500000;
	unsigned T = argc > 2 ? (unsigned)strtoul(argv[2], 0, 0) : 64;
	rng_s = argc > 3 ? strtoull(argv[3], 0, 0) : (uint64_t)time(NULL) * 2654435761ULL;
	if (!rng_s) rng_s = 0x9E3779B97F4A7C15ULL;
	uint64_t seed = rng_s;
	struct sock_filter orig[MAXP], rw[MAXP];
	unsigned long gen = 0, structural = 0, k_acc = 0, k_rej = 0, ref_unsafe_n = 0, ref_safe_n = 0,
		      div_syn = 0, div_exec = 0, incomplete = 0, agree_rej = 0, execs = 0, anomalies = 0,
		      kernel_mismatch = 0, printed_syn = 0, printed_exec = 0, printed_inc = 0;

	printf("H4 differential: kernel check_load_and_stores (verbatim) vs exact must-write analysis + execution oracle\n");
	printf("params: programs=%lu exec-samples/T=%u seed=%#llx\n", N, T, (unsigned long long)seed);
	if (selftest()) return 2;

	for (unsigned long it = 0; it < N; it++) {
		unsigned len = (rndn(4) == 0) ? gen_diamond(orig) : gen_soup(orig);
		gen++;
		if (!structurally_valid(orig, len)) { structural++; continue; }
		int bad; bool rs = ref_safe(orig, len, &bad);
		int kc = bpf_check_classic(orig, len);		/* verbatim, includes check_load_and_stores */
		int km = check_load_and_stores(orig, len);	/* verbatim, direct */
		if ((kc == 0) != (km == 0)) { kernel_mismatch++; }
		if (rs) ref_safe_n++; else ref_unsafe_n++;
		if (kc == 0) {
			k_acc++;
			if (!rs) {
				div_syn++;
				if (printed_syn++ < 5) { printf("SYNTACTIC DIVERGENCE: kernel accepts, ref unsafe at pc %d\n", bad); dump(orig, len); }
			}
			/* execution oracle on the admitted, rewritten program */
			memcpy(rw, orig, len * sizeof(*orig));
			if (seccomp_check_filter(rw, len) != 0) continue;	/* not seccomp-admissible: skip exec */
			for (unsigned t = 0; t < T; t++) {
				struct seccomp_data sd = { .nr = (int)rndn(512), .arch = rndn(2) ? AUDIT_ARCH_X86_64 : AUDIT_ARCH_I386, .instruction_pointer = rnd64() };
				for (int j = 0; j < 6; j++) sd.args[j] = rndn(3) == 0 ? rndn(8) : rnd64();
				struct exec_res er = exec_track(rw, len, &sd);
				execs++;
				if (er.anomaly) { anomalies++; printf("ANOMALY %d\n", er.anomaly); dump(orig, len); break; }
				if (er.uninit_pc >= 0) {
					div_exec++;
					if (printed_exec++ < 5) {
						printf("*** REAL DIVERGENCE *** kernel-accepted program read uninitialised M[%u] at pc %d (poison in RET value: %s, ret=0x%08x)\n",
						       er.uninit_cell, er.uninit_pc, er.poison_in_ret ? "YES" : "no", er.ret);
						printf("    sd: arch=%#x nr=%d args=%#llx %#llx %#llx %#llx %#llx %#llx\n", sd.arch, sd.nr,
						       (unsigned long long)sd.args[0], (unsigned long long)sd.args[1], (unsigned long long)sd.args[2],
						       (unsigned long long)sd.args[3], (unsigned long long)sd.args[4], (unsigned long long)sd.args[5]);
						dump(orig, len);
					}
					break;
				}
			}
		} else {
			k_rej++;
			if (rs) { incomplete++; if (printed_inc++ < 2) { printf("incompleteness (safe direction): kernel rejects, ref safe\n"); dump(orig, len); } }
			else agree_rej++;
		}
	}
	printf("\nRESULTS\n");
	printf("  generated %lu, structurally invalid (skipped) %lu\n", gen, structural);
	printf("  kernel accepted %lu, kernel rejected %lu   (bpf_check_classic vs direct check_load_and_stores mismatches: %lu)\n", k_acc, k_rej, kernel_mismatch);
	printf("  reference: safe %lu, unsafe %lu\n", ref_safe_n, ref_unsafe_n);
	printf("  (A) syntactic divergences (kernel accepts, ref unsafe)   %lu\n", div_syn);
	printf("  (B) execution divergences (accepted program read uninit) %lu   over %lu executions\n", div_exec, execs);
	printf("  (C) incompleteness (kernel rejects, ref safe)            %lu   agree-reject %lu\n", incomplete, agree_rej);
	printf("  anomalies %lu, kernel WARN_ON hits %lu\n", anomalies, h_warn_count);
	printf("VERDICT: %s\n", (div_syn == 0 && div_exec == 0 && anomalies == 0 && kernel_mismatch == 0) ?
	       "NO DIVERGENCE: every kernel-accepted program is safe by the exact analysis and never read an uninitialised cell in execution" :
	       "DIVERGENCE OR ANOMALY FOUND - see above");
	return (div_syn || div_exec || anomalies || kernel_mismatch) ? 1 : 0;
}
