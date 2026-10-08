#!/bin/sh
# Host-side launcher. Boots the TARGET kernel (~/build-cbpf bzImage) under
# virtme-ng, runs the F-1 test inside the guest, and brings its stdout back.
# Isolated VM, loopback only. Never runs the test on the host kernel.
set -u
BZIMAGE="$HOME/build-cbpf/arch/x86/boot/bzImage"
GUEST="$HOME/linux-cbpf-spike/repro/vm_run.sh"
echo "# exact command:"
echo "vng --run $BZIMAGE --exec $GUEST"
echo
exec vng --run "$BZIMAGE" --exec "$GUEST"
