#!/bin/bash
# Compatibility entry point. Python owns job budgets and exact process groups.
set -euo pipefail
exec python3 "$(cd "$(dirname "$0")" && pwd)/run_baseline.py" "$@"
