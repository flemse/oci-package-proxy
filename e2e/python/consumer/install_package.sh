#!/bin/bash

# Install the example package wheel from the producer folder and run the consumer script using Docker
docker run --rm \
  -v $(pwd)/e2e/python:/app \
  -w /app \
  python:3.9 bash -c "$(cat <<EOF
set -euo pipefail
python -m venv venv
source venv/bin/activate
pip install ./producer/example_package/dist/example_package-0.1.0-py3-none-any.whl
python consumer/consume_example.py
EOF
)"
