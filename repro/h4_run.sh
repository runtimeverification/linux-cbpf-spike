#!/bin/sh
set -u
BZIMAGE="$HOME/build-cbpf/arch/x86/boot/bzImage"
GUEST="$HOME/linux-cbpf-spike/repro/h4_vm_run.sh"
echo "# exact command:"; echo "vng --run $BZIMAGE --exec $GUEST"; echo
exec vng --run "$BZIMAGE" --exec "$GUEST"
