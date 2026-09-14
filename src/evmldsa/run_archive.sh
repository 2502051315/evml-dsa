#!/bin/bash
pkill -9 -f extended_bench 2>/dev/null
sleep 1
cd "/home/suzeyan/ALLclaude/TIFS TDSC/archive_paper1/experiments_redesign"
OUTPUT="/home/suzeyan/ALLclaude/TIFS TDSC/archive_paper1/figures_redesign/csv_bundle/fig4/archive_scaling_extended_raw.csv"

echo "Testing archive mode..."
timeout 10 taskset -c 2 ./extended_bench archive > "$OUTPUT" 2>&1
EXIT=$?
echo "Test exit: $EXIT"
head -5 "$OUTPUT"
echo "---"

if [ $EXIT -eq 0 ] || [ $EXIT -eq 124 ]; then
    echo "Archive works, launching full run..."
    > "$OUTPUT"  # truncate for clean run
    setsid nohup taskset -c 2 ./extended_bench archive >> "$OUTPUT" 2>&1 &
    echo "PID: $!"
    echo "LAUNCHED"
else
    echo "ARCHIVE FAILED with exit $EXIT"
fi
