#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
export NIDS_MODELS_DIR="$(pwd)/models/saved"
cd nids_dashboard
python manage.py migrate --run-syncdb 2>/dev/null
python manage.py seed_metrics --path ../results/metrics/comparison.csv 2>/dev/null || true
echo "Starting Zero Day Hunter at http://127.0.0.1:8000/"
python manage.py runserver
