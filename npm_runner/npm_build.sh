#!/usr/bin/env bash
set -e

REPO_PATH="$1"

if [ -z "$REPO_PATH" ]; then
  echo "Usage: npm_build.sh <repo_path>"
  exit 1
fi

cd "$REPO_PATH"
npm run build
