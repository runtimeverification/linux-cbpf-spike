// SPDX-License-Identifier: GPL-2.0
/*
 * H3 VM witness: does the seccomp allow-cache let a syscall through that the
 * installed filter would deny? The only divergence the H3 differential found
 * is the intentional uprobe/uretprobe passthrough in seccomp_is_const_allow()
 * (commit 89d1d8434d24). This confirms it on the real kernel, plus controls.
 *
 * Observable for __NR_uprobe (336): called outside a uprobe trampoline the
 * syscall returns -EPROTO (arch/x86/kernel/uprobes.c sys_uprobe). So:
 *   EPROTO  => the syscall EXECUTED => filter bypassed (cache passthrough)
 *   EPERM   => the filter's RET_ERRNO(EPERM) ran => filter enforced
 * __NR_uretprobe (335) outside a trampoline raises SIGILL; observed via a
 * forked child's termination signal.
 *
 * Each test runs in its own forked child (filters cannot be removed).
 * Run ONLY inside the virtme-ng VM on the target kernel.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>

#define NR_URETPROBE 335
#define NR_UPROBE    336
#define NR_GETPID     39
#define NR_GETPPID   110

static int install(const struct sock_filter *f, unsigned short len)
{
	struct sock_fprog prog = { .len = len, .filter = (struct sock_filter *)f };
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return -errno;
	if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog)) return -errno;
	return 0;
}

/* filter: x86_64 && nr == DENY_NR -> ERRNO(EPERM); everything else ALLOW */
#define DENY_ONE(nr) { \
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 4), \
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 3), \
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0), \
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), 0, 1), \
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM), \
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), \
}

static void child_syscall_errno(const struct sock_filter *f, long nr, const char *tag)
{
	int rc = install(f, 6);
	if (rc) { printf("[%s] filter install failed: %s\n", tag, strerror(-rc)); _exit(100); }
	errno = 0;
	long r = syscall(nr);
	int e = errno;
	printf("[%s] syscall(%ld) -> %ld errno=%d (%s)\n", tag, nr, r, e, e ? strerror(e) : "-");
	_exit(e == EPROTO ? 10 : e == EPERM ? 11 : e == 0 ? 12 : 13);
}

static int run_child(void (*fn)(const struct sock_filter *, long, const char *),
		     const struct sock_filter *f, long nr, const char *tag, int *sig)
{
	pid_t p = fork();
	if (p == 0) { fn(f, nr, tag); _exit(99); }
	int st = 0; waitpid(p, &st, 0);
	*sig = WIFSIGNALED(st) ? WTERMSIG(st) : 0;
	return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

int main(void)
{
	static const struct sock_filter deny_uprobe[]    = DENY_ONE(NR_UPROBE);
	static const struct sock_filter deny_uretprobe[] = DENY_ONE(NR_URETPROBE);
	static const struct sock_filter deny_getpid[]    = DENY_ONE(NR_GETPID);
	int sig, rc, pass = 0, fail = 0;

	setvbuf(stdout, NULL, _IONBF, 0);	/* children _exit(): no stdio flush */

	printf("H3 VM witness: seccomp allow-cache vs installed filter\n\n");

	/* T1: filter denies uprobe(336) with EPERM. Cache passthrough predicts EPROTO. */
	rc = run_child(child_syscall_errno, deny_uprobe, NR_UPROBE, "T1 deny-uprobe", &sig);
	printf("  T1: %s  (child exit %d sig %d)\n\n",
	       rc == 10 ? "BYPASSED: syscall executed despite filter (cache passthrough) -- as predicted, intentional" :
	       rc == 11 ? "ENFORCED: filter denied it (no passthrough)" : "UNEXPECTED", rc, sig);
	if (rc == 10) pass++; else fail++;

	/* T1b: same for uretprobe(335): executing it outside a trampoline -> SIGILL. */
	rc = run_child(child_syscall_errno, deny_uretprobe, NR_URETPROBE, "T1b deny-uretprobe", &sig);
	printf("  T1b: %s  (child exit %d sig %d)\n\n",
	       sig == SIGILL ? "BYPASSED: syscall executed (SIGILL from sys_uretprobe) despite filter -- intentional passthrough" :
	       rc == 11 ? "ENFORCED: filter denied it" : "UNEXPECTED", rc, sig);
	if (sig == SIGILL) pass++; else fail++;

	/* T2 (negative control): filter denies getpid(39). Cache must NOT allow it. */
	rc = run_child(child_syscall_errno, deny_getpid, NR_GETPID, "T2 deny-getpid", &sig);
	printf("  T2: %s  (child exit %d sig %d)\n\n",
	       rc == 11 ? "ENFORCED: getpid denied with EPERM -- cache did not over-allow" :
	       rc == 12 ? "BYPASSED: getpid succeeded despite deny filter -- REAL DIVERGENCE" : "UNEXPECTED", rc, sig);
	if (rc == 11) pass++; else fail++;

	/* T3 (positive control): same deny-getpid filter; getppid(110) is on the const-ALLOW path. */
	rc = run_child(child_syscall_errno, deny_getpid, NR_GETPPID, "T3 allow-getppid", &sig);
	printf("  T3: %s  (child exit %d sig %d)\n\n",
	       rc == 12 ? "ALLOWED: getppid succeeded (const-allow path works)" : "UNEXPECTED", rc, sig);
	if (rc == 12) pass++; else fail++;

	printf("SUMMARY: %d expected outcomes, %d unexpected\n", pass, fail);
	printf("VERDICT: %s\n", fail == 0 ?
	       "the only cache-vs-filter divergence is the intentional uprobe/uretprobe passthrough; ordinary syscalls are enforced" :
	       "UNEXPECTED behaviour -- see above");
	return fail ? 1 : 0;
}
