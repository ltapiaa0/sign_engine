#!/usr/bin/env bash
# Compila sign.bend a un binario nativo (Bend -> C -> gcc).
#
#   scripts/build.sh            -> build/sign
#   TPC_L2=0 scripts/build.sh   -> 1 hilo  (TPC_L2=n usa 2^n hilos; por defecto 2 = 4 hilos)
#
# El binario lee/escribe input.pdf, key.pem, cert.pem, params.txt y
# output.pdf en el directorio actual (ver sign.bend).
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build
TPC_L2="${TPC_L2:-2}"
bend gen-c sign.bend > build/sign.c
gcc -O2 -DTPC_L2="$TPC_L2" build/sign.c -o build/sign -lm -lpthread -ldl
echo "build/sign listo (TPC_L2=$TPC_L2)"
