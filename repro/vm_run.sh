#!/bin/sh
# Runs INSIDE the virtme-ng guest ONLY (booting the target build-cbpf kernel).
# Labels the result with the kernel it came from, per the calibration rule.
echo "=== VM kernel (target) ==="
uname -r
uname -a
echo "bzImage: /home/natalie/build-cbpf/arch/x86/boot/bzImage"
echo
echo "=== F-1 test ==="
/home/natalie/linux-cbpf-spike/repro/f1_connect_v6
echo "program-exit=$?"
