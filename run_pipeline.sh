#!/usr/bin/env bash
# Build historical data -> normalize -> detect.
# Choose 1-5 years with: HISTORY_YEARS=1 ./run_pipeline.sh
set -e
cd "$(dirname "$0")"
YEARS="${HISTORY_YEARS:-5}"
echo "== Step 1/3: Generating ${YEARS} year(s) of synthetic historical logs =="
HISTORY_YEARS="$YEARS" python3 src/generate_dataset.py
echo "== Step 2/3: Parsing & normalizing logs into SQLite (soc.db) =="
HISTORY_YEARS="$YEARS" python3 src/parse_logs.py
echo "== Step 3/3: Running rule-based detection engine =="
python3 src/detection_rules.py
echo ""
echo "Historical pipeline complete."
echo "Dashboard: streamlit run dashboard/app.py"
echo "Live simulator (optional): python3 src/live_simulator.py"
