#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build
SRC="${1:-sign.bend}"
NAME="$(basename "$SRC" .bend)"
TPC_L2="${TPC_L2:-0}"
MEM_L2="${MEM_L2:-28}"
VARS_L2="${VARS_L2:-$(( MEM_L2 < 29 ? MEM_L2 + 1 : 29 ))}"
bend gen-c "$SRC" > "build/$NAME.raw.c"
python3 - "build/$NAME.raw.c" "build/$NAME.c" "$MEM_L2" "$VARS_L2" <<'PY'
import sys
src, dst, mem, vars_l2 = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
code = open(src).read()
patches = [
    ("#define ROOT 0xFFFFFFF8", "#define ROOT ((u32)((G_VARS_LEN - 1) << 3))", 1),
    ("#define HLEN (1ul << 16)", "#define HLEN (1ul << 25)", 1),
    ("#define G_NODE_LEN (1ul << 29)", f"#define G_NODE_LEN (1ul << {mem})", 1),
    ("#define G_VARS_LEN (1ul << 29)", f"#define G_VARS_LEN (1ul << {vars_l2})", 1),
    ("    u32 lc = tm->tid*(G_NODE_LEN/TPC) + (tm->vput%(G_NODE_LEN/TPC));\n",
     "    u32 lc = tm->tid*(G_VARS_LEN/TPC) + (tm->vput%(G_VARS_LEN/TPC));\n", 2),
    ("    tm->vput += 1;\n    if (lc > 0 && elem == 0) {\n      return lc;\n    }\n    // FIXME: check this decently\n    if (++(*lps) >= G_NODE_LEN/TPC)",
     "    tm->vput += 1;\n    if (lc > 0 && elem == 0) {\n      return lc;\n    }\n    // FIXME: check this decently\n    if (++(*lps) >= G_VARS_LEN/TPC)", 1),
    ("    tm->vput += 1;\n    if (lc > 0 && elem == 0) {\n      tm->vloc[got++] = lc;\n    }\n    // FIXME: check this decently\n    if (++lps >= G_NODE_LEN/TPC)",
     "    tm->vput += 1;\n    if (lc > 0 && elem == 0) {\n      tm->vloc[got++] = lc;\n    }\n    // FIXME: check this decently\n    if (++lps >= G_VARS_LEN/TPC)", 1),
    ("// Allocator\n// ---------\n",
     "void hvm_oom() {\n"
     "  FILE* f = fopen(\"error.txt\", \"w\");\n"
     "  if (f != NULL) {\n"
     "    fputs(\"runtime: out of memory\", f);\n"
     "    fclose(f);\n"
     "  }\n"
     "  printf(\"error: runtime: out of memory\\n\");\n"
     "  exit(1);\n"
     "}\n\n"
     "// Allocator\n// ---------\n", 1),
    ('printf("OOM\\n");', "hvm_oom();", 4),
    ("  bytes.len = 0;\n\n  // Readback loop\n  while (true) {\n    // Normalizes the net\n    normalize(net, book);\n",
     "  bytes.len = 0;\n\n  normalize(net, book);\n  while (true) {\n", 1),
    ("        boot_redex(net, new_pair(ctr.args_buf[1], ROOT));\n        port = ROOT;\n",
     "        port = ctr.args_buf[1];\n", 1),
    ("  while (get_tag(got) == REF) {\n    boot_redex(net, new_pair(got, ROOT));\n",
     "  while (get_tag(got) == REF) {\n"
     "    Def* def = &book->defs_buf[get_val(got) & 0xFFFFFFF];\n"
     "    if (def->node_len == 0 && def->rbag_len == 0 && get_tag(def->root) == NUM) {\n"
     "      got = def->root;\n"
     "      break;\n"
     "    }\n"
     "    boot_redex(net, new_pair(got, ROOT));\n", 1),
]
for old, new, count in patches:
    if code.count(old) != count:
        sys.exit(f"unexpected HVM runtime source: {old!r} found {code.count(old)} times, expected {count}")
    code = code.replace(old, new)
open(dst, "w").write(code)
PY
rm "build/$NAME.raw.c"
gcc -O2 -DTPC_L2="$TPC_L2" "build/$NAME.c" -o "build/$NAME" -lm -lpthread -ldl
echo "build/$NAME ready (TPC_L2=$TPC_L2, MEM_L2=$MEM_L2, VARS_L2=$VARS_L2)"
