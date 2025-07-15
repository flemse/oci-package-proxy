#!/bin/bash

# Build the example package as a wheel using Docker
docker run --rm \
  -v $(pwd)/e2e/python/producer/example_package:/app \
  -w /app \
  python:3.9 \
  bash -c "$(cat <<EOF
set -euo pipefail
python -m venv venv
source venv/bin/activate
pip install build
python -m build
EOF
)"
