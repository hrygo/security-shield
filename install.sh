#!/usr/bin/env bash
set -euo pipefail

# Install Security Shield plugin to OpenClaw
# Usage: ./install.sh [--local]
#   --local:  Install to current machine's OpenClaw
#   (default): Print instructions only

OPENCLAW_DIR="${OPENCLAW_DIR:-${HOME}/.openclaw}"
PLUGIN_DIR="${OPENCLAW_DIR}/plugins/security-shield"

echo "🛡️  Security Shield Plugin Installer"
echo ""

# Check if built
if [ ! -d "dist" ]; then
  echo "⚠️  Build artifacts not found. Building first..."
  bash "$(dirname "$0")/build.sh"
fi

if [ "${1:-}" = "--local" ]; then
  echo "📁 Installing to: ${PLUGIN_DIR}"

  # Create directories
  mkdir -p "${PLUGIN_DIR}/src/detectors"
  mkdir -p "${PLUGIN_DIR}/audit"
  mkdir -p "${PLUGIN_DIR}/state"

  # Copy files
  cp -r dist/* "${PLUGIN_DIR}/"
  cp package.json openclaw.plugin.json "${PLUGIN_DIR}/"

  echo "✅ Installed to ${PLUGIN_DIR}"
  echo ""
  echo "Next steps:"
  echo "  1. Add security-shield to openclaw.json:"
  echo "     - plugins.entries.security-shield"
  echo "     - plugins.allow (add 'security-shield')"
  echo "     - plugins.load.paths (add plugin path)"
  echo "  2. Run: openclaw gateway restart"
  echo "  3. Run: openclaw status  (verify plugin loaded)"
  exit 0
fi

# Without --local, print instructions
echo "Usage: ./install.sh --local"
echo ""
echo "This will:"
echo "  1. Build the plugin (if dist/ doesn't exist)"
echo "  2. Copy compiled files to ${PLUGIN_DIR}"
echo "  3. Create audit/ and state/ directories"
echo ""
echo "After installation, configure openclaw.json and restart the gateway."
