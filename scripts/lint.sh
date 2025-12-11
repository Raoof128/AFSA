#!/usr/bin/env bash
set -euo pipefail

ruff check .
isort --profile black --check-only .
black --check .
