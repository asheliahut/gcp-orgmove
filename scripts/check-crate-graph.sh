#!/usr/bin/env bash
# Enforce dependency direction: cli -> parity -> core <- gcp.
set -euo pipefail
deps() { cargo metadata --format-version 1 --no-deps | jq -r --arg n "$1" \
  '.packages[] | select(.name==$n) | .dependencies[].name' ; }
fail=0
forbid() { # crate forbidden
  if deps "$1" | grep -qx "$2"; then echo "FORBIDDEN: $1 depends on $2"; fail=1; fi
}
for f in gcp-orgmove-gcp gcp-orgmove-parity gcp-orgmove-cli; do forbid gcp-orgmove-core $f; done
forbid gcp-orgmove-parity gcp-orgmove-gcp
forbid gcp-orgmove-parity gcp-orgmove-cli
forbid gcp-orgmove-gcp gcp-orgmove-parity
forbid gcp-orgmove-gcp gcp-orgmove-cli
exit $fail
