#!/usr/bin/env bash
# Starts a local n8n (no Docker, no account setup needed) with the Hadhar workflow imported and active.
#   scripts/run-n8n.sh            -> foreground, for demos
#   Env you can set: TELEGRAM_BOT_TOKEN, HADHAR_LLM_KEY, HADHAR_WEBHOOK_TOKEN (see README)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
N8N="$ROOT/.n8n-runtime/node_modules/.bin/n8n"
[ -x "$N8N" ] || { echo "n8n is not installed yet. Run: npm run setup"; exit 1; }

export N8N_USER_FOLDER="${N8N_USER_FOLDER:-$ROOT/.n8n-local}"
export N8N_BLOCK_ENV_ACCESS_IN_NODE=false     # the workflow reads its settings from environment variables
export N8N_DIAGNOSTICS_ENABLED=false N8N_PERSONALIZATION_ENABLED=false N8N_VERSION_NOTIFICATIONS_ENABLED=false
export N8N_SECURE_COOKIE=false N8N_HOST=127.0.0.1 N8N_PORT="${N8N_PORT:-5678}" GENERIC_TIMEZONE=UTC
export N8N_RUNNERS_ENABLED=true

# Import only the first time: re-importing resets the workflow's saved state (offset, blocklist cache, family links).
# After pulling a new version of the workflow, run once with HADHAR_REIMPORT=1.
if [ "${HADHAR_REIMPORT:-0}" = "1" ] || ! "$N8N" export:workflow --id=HadharScamCheck1 --output=/dev/null >/dev/null 2>&1; then
  "$N8N" import:workflow --input="$ROOT/workflow/hadhar.workflow.json" >/dev/null
fi
"$N8N" publish:workflow --id=HadharScamCheck1 >/dev/null
exec "$N8N" start
