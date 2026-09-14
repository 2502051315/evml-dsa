#!/bin/bash
D4="/home/suzeyan/ALLclaude/TIFS TDSC/archive_paper1/figures_redesign/csv_bundle/fig4"

echo "=== distance data ==="
head -3 "$D4/rechain_distance_extended_raw.csv"
echo "..."
for d in 0 1 12 24 48 64 96 128; do
    grep "^rechain,$d," "$D4/rechain_distance_extended_raw.csv" | head -1
done
echo "--- ev ---"
grep "^evmldsa" "$D4/rechain_distance_extended_raw.csv" | head -2
wc -l "$D4/rechain_distance_extended_raw.csv"

echo "=== archive data ==="
wc -l "$D4/archive_scaling_extended_raw.csv"
cat "$D4/archive_scaling_extended_raw.csv"
if pgrep -f extended_bench > /dev/null; then
    echo "ARCHIVE_RUNNING"
else
    echo "ARCHIVE_DONE"
fi
