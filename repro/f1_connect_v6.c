// SPDX-License-Identifier: GPL-2.0
/*
 * F-1 Phase 2 test: is an io_uring CONNECT cBPF filter that denies an IPv6
 * destination by port bypassed when the connect is issued with addr_len = 24
 * (SIN6_LEN_RFC2133) instead of 28 (sizeof(struct sockaddr_in6))?
 *
 * Runs entirely on loopback [::1] and must be run ONLY inside the virtme-ng VM
 * booting ~/build-cbpf/arch/x86/boot/bzImage. The 6.8 host kernel has no
 * io_uring BPF filters and will fail registration with -EINVAL (reported, not
 * worked around).
 *
 * Raw io_uring syscalls against the tree UAPI (no liburing). Builds a cBPF
 * program as a struct sock_filter[] and registers it via the real
 * IORING_REGISTER_BPF_FILTER ABI from include/uapi/linux/io_uring/bpf_filter.h.
 *
 * 2x2 probe matrix (each on its own fresh ring):
 *   filter deny_on_P : deny iff family==AF_INET6 && port_word==htons(P)
 *   filter deny_on_0 : deny iff family==AF_INET6 && port_word==0
 *   x addr_len in {28, 24}
 * The matrix pins down the port the filter observed at each length.
 * VERDICT CONFIRMED iff (deny_on_P,28) denied AND (deny_on_P,24) connected.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/filter.h>
#include <linux/io_uring.h>
#include <linux/io_uring/bpf_filter.h>

static int io_uring_setup(unsigned e, struct io_uring_params *p)
{ return (int)syscall(__NR_io_uring_setup, e, p); }
static int io_uring_enter(int fd, unsigned to, unsigned mn, unsigned fl)
{ return (int)syscall(__NR_io_uring_enter, fd, to, mn, fl, NULL, 0); }
static int io_uring_register(int fd, unsigned op, void *arg, unsigned n)
{ return (int)syscall(__NR_io_uring_register, fd, op, arg, n); }

struct ring {
	int fd;
	void *sq;              /* single-mmap base */
	struct io_uring_sqe *sqes;
	unsigned *sq_tail, *sq_mask, *sq_array;
	unsigned *cq_head, *cq_tail, *cq_mask;
	struct io_uring_cqe *cqes;
	size_t sq_sz, sqes_sz;
};

static int ring_setup(struct ring *r)
{
	struct io_uring_params p;
	size_t sring, cring;

	memset(r, 0, sizeof(*r));
	memset(&p, 0, sizeof(p));
	r->fd = io_uring_setup(8, &p);
	if (r->fd < 0)
		return -errno;
	if (!(p.features & IORING_FEAT_SINGLE_MMAP)) {
		fprintf(stderr, "no SINGLE_MMAP feature\n");
		return -ENOTSUP;
	}
	sring = p.sq_off.array + p.sq_entries * sizeof(unsigned);
	cring = p.cq_off.cqes  + p.cq_entries * sizeof(struct io_uring_cqe);
	r->sq_sz = sring > cring ? sring : cring;
	r->sq = mmap(NULL, r->sq_sz, PROT_READ | PROT_WRITE,
		     MAP_SHARED | MAP_POPULATE, r->fd, IORING_OFF_SQ_RING);
	if (r->sq == MAP_FAILED)
		return -errno;
	r->sqes_sz = p.sq_entries * sizeof(struct io_uring_sqe);
	r->sqes = mmap(NULL, r->sqes_sz, PROT_READ | PROT_WRITE,
		       MAP_SHARED | MAP_POPULATE, r->fd, IORING_OFF_SQES);
	if (r->sqes == MAP_FAILED)
		return -errno;
	r->sq_tail  = (unsigned *)((char *)r->sq + p.sq_off.tail);
	r->sq_mask  = (unsigned *)((char *)r->sq + p.sq_off.ring_mask);
	r->sq_array = (unsigned *)((char *)r->sq + p.sq_off.array);
	r->cq_head  = (unsigned *)((char *)r->sq + p.cq_off.head);
	r->cq_tail  = (unsigned *)((char *)r->sq + p.cq_off.tail);
	r->cq_mask  = (unsigned *)((char *)r->sq + p.cq_off.ring_mask);
	r->cqes     = (struct io_uring_cqe *)((char *)r->sq + p.cq_off.cqes);
	return 0;
}

static void ring_teardown(struct ring *r)
{
	if (r->sqes && r->sqes != MAP_FAILED)
		munmap(r->sqes, r->sqes_sz);
	if (r->sq && r->sq != MAP_FAILED)
		munmap(r->sq, r->sq_sz);
	if (r->fd >= 0)
		close(r->fd);
}

/* Register one ring-level CONNECT filter. Returns 0 or -errno. */
static int register_connect_filter(int ring_fd, const struct sock_filter *prog,
				    unsigned short len)
{
	struct io_uring_bpf reg;

	memset(&reg, 0, sizeof(reg));
	reg.cmd_type = IO_URING_BPF_CMD_FILTER;
	reg.filter.opcode = IORING_OP_CONNECT;
	reg.filter.flags = 0;
	reg.filter.filter_len = len;
	reg.filter.pdu_size =
		(uint8_t)sizeof(((struct io_uring_bpf_ctx *)0)->connect);
	reg.filter.filter_ptr = (uint64_t)(uintptr_t)prog;
	if (io_uring_register(ring_fd, IORING_REGISTER_BPF_FILTER, &reg, 1) < 0)
		return -errno;
	return 0;
}

/* Submit one CONNECT(fd, sa, addr_len); return CQE res, or -errno on infra. */
static int submit_connect(struct ring *r, int cfd,
			  const struct sockaddr_in6 *sa, unsigned addr_len,
			  uint64_t ud)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	unsigned idx, tail, head;
	int ret;

	tail = *r->sq_tail;
	idx = tail & *r->sq_mask;
	sqe = &r->sqes[idx];
	memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = IORING_OP_CONNECT;
	sqe->fd = cfd;
	sqe->addr = (uint64_t)(uintptr_t)sa;
	sqe->addr2 = addr_len;         /* io_connect_prep reads addr_len here */
	sqe->len = 0;
	sqe->user_data = ud;
	r->sq_array[idx] = idx;
	atomic_store_explicit((_Atomic unsigned *)r->sq_tail, tail + 1,
			      memory_order_release);

	ret = io_uring_enter(r->fd, 1, 1, IORING_ENTER_GETEVENTS);
	if (ret < 0)
		return -errno;

	head = *r->cq_head;
	while (head == atomic_load_explicit((_Atomic unsigned *)r->cq_tail,
					    memory_order_acquire))
		;                      /* GETEVENTS guarantees >=1; alarm guards */
	cqe = &r->cqes[head & *r->cq_mask];
	ret = cqe->res;
	atomic_store_explicit((_Atomic unsigned *)r->cq_head, head + 1,
			      memory_order_release);
	return ret;
}

/* one attempt on a fresh ring; returns CQE res or -errno (<= -4096 infra) */
static int attempt(const struct sock_filter *prog, unsigned short plen,
		   int family_dummy, const struct sockaddr_in6 *target,
		   unsigned addr_len, const char *tag)
{
	struct ring r;
	int cfd, rc, res;

	(void)family_dummy;
	rc = ring_setup(&r);
	if (rc < 0) {
		fprintf(stderr, "[%s] ring_setup: %s\n", tag, strerror(-rc));
		return rc - 100000;
	}
	rc = register_connect_filter(r.fd, prog, plen);
	if (rc < 0) {
		fprintf(stderr, "[%s] filter registration REJECTED: %s (%d)\n",
			tag, strerror(-rc), -rc);
		ring_teardown(&r);
		return rc - 200000;
	}
	cfd = socket(AF_INET6, SOCK_STREAM, 0);
	if (cfd < 0) {
		fprintf(stderr, "[%s] socket: %s\n", tag, strerror(errno));
		ring_teardown(&r);
		return -300000;
	}
	res = submit_connect(&r, cfd, target, addr_len, 0x1234);
	close(cfd);
	ring_teardown(&r);
	return res;
}

static const char *verdict_cell(int res)
{
	/* rotating buffers: safe to call several times in one printf */
	enum { CELL = 64 };
	static char bufs[8][CELL];
	static unsigned turn;
	char *buf = bufs[turn++ % 8];
	if (res == -EACCES)
		snprintf(buf, CELL, "DENIED (res=-EACCES)");
	else if (res == 0)
		snprintf(buf, CELL, "CONNECTED (res=0)");
	else if (res < -4096)
		snprintf(buf, CELL, "INFRA-FAIL (%d)", res);
	else
		snprintf(buf, CELL, "ALLOWED-but-res=%d (%s)",
			 res, strerror(res < 0 ? -res : 0));
	return buf;
}

int main(void)
{
	struct sockaddr_in6 sa, bound;
	socklen_t blen = sizeof(bound);
	int lfd, P;
	uint32_t port_word;
	int res_P28, res_P24, res_0_28, res_0_24;

	alarm(30);  /* never hang the VM */

	/* Listener on [::1]:ephemeral */
	lfd = socket(AF_INET6, SOCK_STREAM, 0);
	if (lfd < 0) { perror("socket(listener)"); return 2; }
	int one = 1;
	setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&sa, 0, sizeof(sa));
	sa.sin6_family = AF_INET6;
	sa.sin6_addr = in6addr_loopback;
	sa.sin6_port = 0;
	if (bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("bind"); return 2;
	}
	if (getsockname(lfd, (struct sockaddr *)&bound, &blen) < 0) {
		perror("getsockname"); return 2;
	}
	if (listen(lfd, 64) < 0) { perror("listen"); return 2; }
	P = ntohs(bound.sin6_port);
	port_word = (uint32_t)(uint16_t)htons(P);  /* word the filter will see */

	/* Target = [::1]:P, full 28-byte sockaddr in memory */
	memset(&sa, 0, sizeof(sa));
	sa.sin6_family = AF_INET6;
	sa.sin6_addr = in6addr_loopback;
	sa.sin6_port = htons(P);

	/* Filter A: deny iff family==AF_INET6 && port_word == htons(P) */
	struct sock_filter deny_on_P[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 16),             /* A=family */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET6, 0, 3),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 20),             /* A=port   */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, port_word, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, 0),                       /* deny     */
		BPF_STMT(BPF_RET | BPF_K, 1),                       /* allow    */
	};
	/* Filter B: deny iff family==AF_INET6 && port_word == 0 */
	struct sock_filter deny_on_0[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 16),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET6, 0, 3),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 20),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, 0),
		BPF_STMT(BPF_RET | BPF_K, 1),
	};

	printf("F-1 io_uring CONNECT IPv6 addr_len test\n");
	printf("listener [::1]:%d  htons(P)=0x%04x  filter-observed-port-word @len28 should be 0x%04x\n",
	       P, (unsigned)htons(P), port_word);

	res_P28  = attempt(deny_on_P, 6, 0, &sa, 28, "deny_on_P,len=28");
	res_P24  = attempt(deny_on_P, 6, 0, &sa, 24, "deny_on_P,len=24");
	res_0_28 = attempt(deny_on_0, 6, 0, &sa, 28, "deny_on_0,len=28");
	res_0_24 = attempt(deny_on_0, 6, 0, &sa, 24, "deny_on_0,len=24");

	/* ground truth: four ints by value, immune to buffer aliasing */
	printf("BUILD=rev2\n");
	printf("RAW: res_P28=%d res_P24=%d res_0_28=%d res_0_24=%d  (-EACCES=%d)\n",
	       res_P28, res_P24, res_0_28, res_0_24, -EACCES);

	printf("\n  filter       addr_len=28                 addr_len=24\n");
	printf("  deny_on_P    %-26s  %s\n", verdict_cell(res_P28), verdict_cell(res_P24));
	printf("  deny_on_0    %-26s  %s\n", verdict_cell(res_0_28), verdict_cell(res_0_24));

	/* Observed port word, inferred behaviorally from the matrix */
	printf("\nObserved connect.port the filter saw:\n");
	if (res_P28 == -EACCES && res_0_28 == 0)
		printf("  at addr_len=28: 0x%04x (== htons(P)) -- port populated\n", port_word);
	else
		printf("  at addr_len=28: ambiguous (P-probe=%s, 0-probe=%s)\n",
		       verdict_cell(res_P28), verdict_cell(res_0_28));
	if (res_P24 == 0 && res_0_24 == -EACCES)
		printf("  at addr_len=24: 0x0000 -- port NOT populated (filter blind)\n");
	else
		printf("  at addr_len=24: ambiguous (P-probe=%s, 0-probe=%s)\n",
		       verdict_cell(res_P24), verdict_cell(res_0_24));

	printf("\nVERDICT: ");
	if (res_P28 == -EACCES && res_P24 == 0) {
		printf("CONFIRMED -- CONNECT filter denying by IPv6 port is bypassed at addr_len=24\n");
		printf("  (len=28 denied with -EACCES; len=24 connected with res=0)\n");
		close(lfd);
		return 0;
	}
	if (res_P28 == -EACCES && res_P24 == -EACCES) {
		printf("REFUTED -- filter denied at both lengths; port appears populated at addr_len=24\n");
	} else if (res_P28 != -EACCES) {
		printf("INCONCLUSIVE -- filter did not deny at addr_len=28 (res=%d); test setup problem\n", res_P28);
	} else {
		printf("INCONCLUSIVE -- unexpected results; see matrix above\n");
	}
	close(lfd);
	return 1;
}
