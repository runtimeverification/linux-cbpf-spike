#!/bin/sh
# Runs INSIDE the virtme-ng guest ONLY (target build-cbpf kernel).
echo "=== VM kernel (target) ==="; uname -r; uname -a
echo "bzImage: /home/natalie/build-cbpf/arch/x86/boot/bzImage"; echo
echo "=== H3 witness ==="
/home/natalie/linux-cbpf-spike/repro/h3_uprobe_passthrough
echo "program-exit=$?"
