#!/bin/sh
echo "=== VM kernel (target) ==="; uname -r; uname -a
echo "bzImage: /home/natalie/build-cbpf/arch/x86/boot/bzImage"; echo
echo "=== H4 witness ==="
/home/natalie/linux-cbpf-spike/repro/h4_vm_witness
echo "program-exit=$?"
