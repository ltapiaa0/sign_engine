#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build
SRC="${1:-sign.bend}"
NAME="$(basename "$SRC" .bend)"
TPC_L2="${TPC_L2:-0}"
MEM_L2="${MEM_L2:-28}"
VARS_L2="${VARS_L2:-$(( MEM_L2 < 29 ? MEM_L2 + 1 : 29 ))}"
FLAGS=(-O2 -DTPC_L2="$TPC_L2" -DG_NODE_L2="$MEM_L2" -DG_VARS_L2="$VARS_L2")
if [ "$NAME" = server ]; then
  FLAGS+=(-DHTTP_SERVER)
fi
bend gen-c "$SRC" > "build/$NAME.c"
patch --batch --forward --fuzz=0 --silent --no-backup-if-mismatch "build/$NAME.c" scripts/hvm-runtime.patch
gcc "${FLAGS[@]}" "build/$NAME.c" -o "build/$NAME" -lm -lpthread -ldl
echo "build/$NAME ready (TPC_L2=$TPC_L2, MEM_L2=$MEM_L2, VARS_L2=$VARS_L2)"
