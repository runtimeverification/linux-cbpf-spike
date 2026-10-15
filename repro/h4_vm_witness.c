// SPDX-License-Identifier: GPL-2.0
/*
 * H4 VM witness: do the real kernel's admission decisions for scratch-memory
 * programs match the verbatim userspace extract, and does the RET A channel
 * really carry scratch contents to userspace (the leak channel H4 is about)?
 *
 *  W1 unsafe diamond (store on one branch only, load at join)   -> expect EINVAL
 *  W2 safe: both branches store distinct values, RET A           -> expect accepted;
 *      getpid -> errno 0x123 (291), getppid -> errno 0x456 (1110): the channel works
 *  W3 safe but conservatively rejected (phantom fall-through after RET) -> expect EINVAL
 *  W4 store only in dead code, load after                         -> expect EINVAL
 * Each in its own forked child. Run ONLY inside the virtme-ng VM.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

static int install(const struct sock_filter *f, unsigned short len)
{
	struct sock_fprog prog = { .len = len, .filter = (struct sock_filter *)f };
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return -errno;
	if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog)) return -errno;
	return 0;
}

static const struct sock_filter W1[] = {	/* unsafe diamond */
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 39, 0, 2),
	BPF_STMT(BPF_LD | BPF_IMM, 0x00050123),
	BPF_STMT(BPF_ST, 0),
	BPF_STMT(BPF_LD | BPF_MEM, 0),
	BPF_STMT(BPF_RET | BPF_A, 0),
};
static const struct sock_filter W2[] = {	/* safe: both branches store; only getpid/getppid use RET A, rest ALLOW */
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),			/* 0: A = nr */
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 39, 0, 3),		/* 1: getpid? ->2 else ->5 */
	BPF_STMT(BPF_LD | BPF_IMM, 0x00050123),			/* 2 */
	BPF_STMT(BPF_ST, 0),					/* 3: M[0] = ERRNO|0x123 */
	BPF_STMT(BPF_JMP | BPF_JA, 3),				/* 4: -> 8 (join) */
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 110, 0, 4),		/* 5: getppid? ->6 else ->10 */
	BPF_STMT(BPF_LD | BPF_IMM, 0x00050456),			/* 6 */
	BPF_STMT(BPF_ST, 0),					/* 7: M[0] = ERRNO|0x456 */
	BPF_STMT(BPF_LD | BPF_MEM, 0),				/* 8: join: A = M[0] (written on both paths) */
	BPF_STMT(BPF_RET | BPF_A, 0),				/* 9 */
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),		/* 10: everything else */
};
static const struct sock_filter W3[] = {	/* safe, but phantom fall-through after RET => kernel rejects */
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 39, 0, 3),
	BPF_STMT(BPF_LD | BPF_IMM, 0x00050123),
	BPF_STMT(BPF_ST, 1),
	BPF_STMT(BPF_JMP | BPF_JA, 1),
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	BPF_STMT(BPF_LD | BPF_MEM, 1),
	BPF_STMT(BPF_RET | BPF_A, 0),
};
static const struct sock_filter W4[] = {	/* store only in dead code */
	BPF_STMT(BPF_JMP | BPF_JA, 1),
	BPF_STMT(BPF_ST, 0),
	BPF_STMT(BPF_LD | BPF_MEM, 0),
	BPF_STMT(BPF_RET | BPF_A, 0),
};

struct tc { const char *name; const struct sock_filter *f; unsigned short len; int expect_install; };

static int run_case(const struct tc *t, int *ok)
{
	pid_t p = fork();
	if (p == 0) {
		int rc = install(t->f, t->len);
		if (rc) { printf("[%s] install -> %s\n", t->name, strerror(-rc)); _exit(rc == -EINVAL ? 20 : 21); }
		printf("[%s] install -> accepted\n", t->name);
		if (t->f == W2) {
			errno = 0; long r1 = syscall(39);  int e1 = errno;	/* getpid: left branch stores 0x50123 */
			errno = 0; long r2 = syscall(110); int e2 = errno;	/* getppid: right branch stores 0x50456 */
			printf("[%s] getpid  -> %ld errno=%d (expect 291 = 0x123)\n", t->name, r1, e1);
			printf("[%s] getppid -> %ld errno=%d (expect 1110 = 0x456)\n", t->name, r2, e2);
			_exit((e1 == 0x123 && e2 == 0x456) ? 30 : 31);
		}
		_exit(22);
	}
	int st = 0; waitpid(p, &st, 0);
	int code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
	if (t->expect_install == -EINVAL) *ok = (code == 20);
	else *ok = (t->f == W2) ? (code == 30) : (code == 22);
	return code;
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	const struct tc cases[] = {
		{ "W1 unsafe-diamond",      W1, 6, -EINVAL },
		{ "W2 safe-both-store",     W2, 11, 0 },
		{ "W3 safe-phantom-reject", W3, 8, -EINVAL },
		{ "W4 dead-store",          W4, 4, -EINVAL },
	};
	int pass = 0, fail = 0;
	printf("H4 VM witness: scratch-memory admission + RET A channel\n");
	for (unsigned i = 0; i < 4; i++) {
		int ok; int code = run_case(&cases[i], &ok);
		printf("  %s: %s (child exit %d)\n", cases[i].name, ok ? "as expected" : "UNEXPECTED", code);
		if (ok) pass++; else fail++;
	}
	printf("SUMMARY: %d expected, %d unexpected\n", pass, fail);
	printf("VERDICT: %s\n", fail ? "UNEXPECTED behaviour" :
	       "kernel admission matches the extract (unsafe/dead-store rejected, both-store accepted, phantom case conservatively rejected); RET A carries scratch contents (channel real, values deterministic)");
	return fail ? 1 : 0;
}
