#!/usr/bin/env bash
set -euo pipefail

BACKEND="http://127.0.0.1:8000"
RAW="$(cat data/sample_logs/ssh_bruteforce.log)"

echo "1) parse"
E1=$(curl -s -X POST -H 'Content-Type: application/json' -d "{"logs":"$(printf "%s" "$RAW" | sed 's/"/\"/g')"}" $BACKEND/parse)

echo "2) enrich"
E2=$(curl -s -X POST -H 'Content-Type: application/json' -d "$E1" $BACKEND/enrich)

echo "3) mitre-map (IBM RAG)"
E3=$(curl -s -X POST -H 'Content-Type: application/json' -d "$E2" $BACKEND/mitre-map)

echo "4) timeline"
T=$(curl -s -X POST -H 'Content-Type: application/json' -d "$E3" $BACKEND/timeline)

echo "5) report (IBM Granite)"
R=$(curl -s -X POST -H 'Content-Type: application/json' -d "$T" $BACKEND/report)
echo "$R" | jq -r .html > forensicmind.html
echo "Report written to forensicmind.html"

echo "6) graph-write (Neptune)"
curl -s -X POST -H 'Content-Type: application/json' -d "$T" $BACKEND/graph-write >/dev/null
echo "Graph written"

echo "7) graph-read"
curl -s $BACKEND/graph | jq . > graph.json
echo "Graph saved to graph.json"
