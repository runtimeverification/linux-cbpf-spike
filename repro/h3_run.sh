#!/bin/sh
# Host-side launcher: boot the TARGET kernel under virtme-ng and run the H3 witness.
set -u
BZIMAGE="$HOME/build-cbpf/arch/x86/boot/bzImage"
GUEST="$HOME/linux-cbpf-spike/repro/h3_vm_run.sh"
echo "# exact command:"; echo "vng --run $BZIMAGE --exec $GUEST"; echo
exec vng --run "$BZIMAGE" --exec "$GUEST"
