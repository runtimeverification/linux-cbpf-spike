# FINDINGS.md

Tree `~/linux-cbpf` at `v7.3-rc6-63-g0c2669a9f4a1`. Nothing here is to be posted,
mailed, or published; disclosure through security@kernel.org is the user's decision
(CLAUDE.md). Each finding stays `[UNCONFIRMED]` until it reproduces against the built
kernel in Phase 2.

---

## F-1 — io_uring CONNECT filter is blind to the IPv6 port and address when 24 <= addr_len < 28  [CONFIRMED]

Status: `[CONFIRMED against the compiled C of this tree]` — reproduced in a virtme-ng VM
on 2026-10-08; see "Confirmation (Phase 2)" below. Originally reached by reasoning across
io_uring/net.c and net/ipv6/*; now empirically verified against the built kernel.
Class: policy bypass (a CONNECT restriction filter is evaded), not memory unsafety.

### Mechanism

The runtime context the CONNECT filter reads is filled by `io_connect_bpf_populate`
(io_uring/net.c:1717). For an IPv6 address it populates the port and address only past a
28-byte threshold:

- net.c:1744 — `if (conn->addr_len < (int)sizeof(*sin6)) break;` where `sin6` is
  `struct sockaddr_in6 *`, so the threshold is `sizeof(struct sockaddr_in6)` = 28
  [VERIFIED: probe]. On the `break`, `connect.port` and `connect.v6_addr` keep the zero
  left by the `memset` of the context union in `io_uring_populate_bpf_ctx`
  (io_uring/bpf_filter.c:35-36). `connect.family` was already set before the switch
  (net.c:1730), so the filter still sees `AF_INET6`.

The kernel's IPv6 connect paths, however, accept a 24-byte address:

- `SIN6_LEN_RFC2133` = 24 (include/net/ipv6.h:26) [VERIFIED: read].
- The minimum enforced is 24, not 28: net/ipv6/tcp_ipv6.c:125 and :150, net/ipv6/datagram.c:162,
  net/ipv6/udp.c:1300, net/ipv6/raw.c:227, net/sctp/socket.c:347 all reject only
  `addr_len < SIN6_LEN_RFC2133` [VERIFIED: read].
- `struct sockaddr_in6` places `sin6_port` at bytes 2..4 and `sin6_addr` at bytes 8..24
  (include/uapi/linux/in6.h:50-56) [VERIFIED: read]; only `sin6_scope_id` (24..28) is absent
  from a 24-byte address. So a real, routable destination port and address fit in 24 bytes.
- io_uring forwards the user's `addr_len` unchanged: `io_connect_prep` stores
  `conn->addr_len = sqe->addr2` (net.c:1820) and copies the bytes with `move_addr_to_kernel`
  (net.c:1827), which accepts any `0 <= ulen <= sizeof(sockaddr_storage)` (net/socket.c:249-258);
  `io_connect` then passes that same `addr_len` to `__sys_connect_file` (net.c:1847)
  [VERIFIED: read].

Result: with `addr_len = 24`, a filter is handed `family = AF_INET6, port = 0, v6_addr = ::`,
while the request proceeds to connect to the real destination carried in the user's buffer.

### Why it is a bypass

A CONNECT filter whose purpose is to deny a specific IPv6 destination port or address does so
by loading `connect.port` (context offset 20) or `connect.v6_addr` (offset 24) and comparing.
At `addr_len = 24` both read as zero, the comparison does not match, and the filter returns
"allow", so the blocked connect succeeds. The filter author followed the documented contract
in the UAPI header (include/uapi/linux/io_uring/bpf_filter.h:30-45), which says unpopulated
fields are zero and tells filters to mask sub-word fields, but does not warn that a fully
specified, acceptable IPv6 address can arrive with the port and address fields zeroed.

IPv4 is not affected: the populate threshold is `sizeof(struct sockaddr_in)` = 16 (net.c:1735),
which equals the minimum the IPv4 connect paths enforce (net/ipv4/tcp_ipv4.c:212,
net/ipv4/datagram.c:30, net/ipv4/raw.c:719) [VERIFIED: read].

### Impact for the agent-sandbox threat model

If an io_uring CONNECT filter is a sandbox's egress control, a sandboxed task can reach an
otherwise-blocked IPv6 host or port by issuing the connect with `addr_len = 24` instead of 28.
No elevated privilege is needed, and the ring-level registration path itself requires none
(register.c:962-971). This is a filter-policy escape, not kernel memory corruption.

### Confirmation (Phase 2) — [CONFIRMED]

Reproduced against the compiled C of this tree, inside a virtme-ng VM (host was only the
hypervisor; the test ran on the target kernel, never the host).

- Kernel under test: `7.3.0-rc6-00063-g0c2669a9f4a1` (`uname -r` in the guest), booting
  `~/build-cbpf/arch/x86/boot/bzImage`. Host kernel 6.8.0-138-generic ran QEMU only.
- Reproducer: `repro/f1_connect_v6.c` (raw io_uring syscalls against the tree UAPI, no
  liburing); launcher `repro/run.sh`; guest runner `repro/vm_run.sh`. Loopback `[::1]` only.
- Commands:
  ```sh
  gcc -O1 -Wall -Wextra -Wno-cpp -D__user= -I repro/stub \
      -I ~/linux-cbpf/include/uapi -I ~/linux-cbpf/arch/x86/include/uapi \
      -o repro/f1_connect_v6 repro/f1_connect_v6.c
  vng --run ~/build-cbpf/arch/x86/boot/bzImage --exec ~/linux-cbpf-spike/repro/vm_run.sh
  ```
- Ring-level filter registration (`IORING_REGISTER_BPF_FILTER`, fd != -1) succeeded with no
  privilege, as predicted.

Result for listener `[::1]:37439`, `htons(P) = 0x3f92`; raw CQE results
`res_P28 = -EACCES, res_P24 = 0, res_0_28 = 0, res_0_24 = -EACCES`:

| filter (deny iff ...)          | addr_len = 28       | addr_len = 24       |
|--------------------------------|---------------------|---------------------|
| `family==AF_INET6 && port==P`  | DENIED (`-EACCES`)  | CONNECTED (`res=0`) |
| `family==AF_INET6 && port==0`  | CONNECTED (`res=0`) | DENIED (`-EACCES`)  |

Port the filter observed: `0x3f92` (== `htons(P)`) at `addr_len = 28`; `0x0000` at
`addr_len = 24`. VERDICT: **CONFIRMED** — the port-deny CONNECT filter is bypassed at
`addr_len = 24`: the connect to the blocked destination completes (`res=0`), while the
identical request at `addr_len = 28` is denied. The `deny_on_0` cross-probe independently
confirms the observed port was the real port at length 28 and zero at length 24, so the
bypass is specifically the un-populated port/address field, not some other effect.

Harness note: an early displayed matrix was wrong due to a cosmetic bug in the reporting path
(two `%s` sharing one `static` buffer, then a `sizeof(pointer)` truncation); the underlying
raw-integer verdict was stable across every run and is printed verbatim on the `RAW:` line.
Both display bugs are fixed in the committed reproducer; the `BUILD=rev2` tag marks the fixed
binary.

### Suggested fix direction (for Phase 2, not applied here)

Align the populate threshold with the network stack: populate IPv6 port and address once
`addr_len >= SIN6_LEN_RFC2133` (24) rather than `>= sizeof(struct sockaddr_in6)` (28), reading
`sin6_addr` (which ends at byte 24) but leaving `sin6_scope_id` zero when it is absent. This
keeps the populated fields in step with what the kernel will actually use to connect. The fix
goes on branch `cbpf-spike` only, and only if the user asks for a patch (CLAUDE.md).

### Test procedure (Phase 2, to flip [UNCONFIRMED] -> confirmed)

To be run in the virtme-ng VM booting `~/build-cbpf/arch/x86/boot/bzImage`, never on the host:

1. Bind a listener on `[::1]` at an ephemeral port P; note P.
2. On a fresh ring, register a ring-level CONNECT filter that denies (returns 0) exactly when
   `connect.family == AF_INET6` and `connect.port == P`, and allows otherwise.
3. Submit an `IORING_OP_CONNECT` to `[::1]:P` with `addr2 = addr_len = 28`. Expected: the
   submission is denied (`-EACCES`), confirming the filter and the port field work at the
   full length.
4. Submit the same connect to `[::1]:P` but with `addr2 = addr_len = 24`. Finding F-1 predicts
   this is allowed and the connection to `[::1]:P` establishes, because the filter saw
   `port == 0`.
5. Confirmed if step 3 denies and step 4 connects. As a cross-check, have the filter also
   return `connect.port` in the low 16 bits of its allow/deny decision path, or log it, to show
   it observed 0 at `addr_len = 24` and P at `addr_len = 28`.

Record the exact kernel (`uname -r` inside the VM) and `.config` hashes with the result, per
the calibration rule.

### Calibration note

This finding chains io_uring/net.c, net/ipv6/*.c, net/socket.c and the two UAPI headers. Every
individual line cited is `[VERIFIED: read]` or `[VERIFIED: probe]`, but the conclusion that the
two thresholds can be driven apart by a chosen `addr_len` is multi-file reasoning and is
therefore `[UNCONFIRMED]` until step 5 above runs green against the compiled C. The previous
spike's multi-file hit rate was poor; treat F-1 as a hypothesis with a strong paper trail, not
a settled bug.
