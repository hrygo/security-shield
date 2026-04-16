#!/usr/bin/env bash
set -euo pipefail

# Build the Security Shield plugin
# Produces dist/ directory with compiled JS + type declarations

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "🔨 Building Security Shield plugin..."

# Install dependencies if needed
if [ ! -d "node_modules" ]; then
  echo "📦 Installing dependencies..."
  npm install
fi

# Clean and build
rm -rf dist/
npx tsc

echo "✅ Build complete: dist/"
echo "   - $(find dist -name '*.js' | wc -l | tr -d ' ') JS files"
echo "   - $(find dist -name '*.d.ts' | wc -l | tr -d ' ') declaration files"
