#!/usr/bin/env bash
# Runs the full SOC pipeline end-to-end: generate -> parse/normalize -> detect -> (optionally) launch dashboard
set -e

cd "$(dirname "$0")"

echo "== Step 1/3: Generating synthetic log dataset =="
python3 src/generate_dataset.py

echo "== Step 2/3: Parsing & normalizing logs into SQLite (soc.db) =="
python3 src/parse_logs.py

echo "== Step 3/3: Running rule-based detection engine =="
python3 src/detection_rules.py

echo ""
echo "Pipeline complete. Database: soc.db"
echo "Launch the dashboard with:  streamlit run dashboard/app.py"
