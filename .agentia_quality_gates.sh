#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "## Building plugin"
npm run build

echo "## Running tests"
npm test

echo "## All quality gates passed"