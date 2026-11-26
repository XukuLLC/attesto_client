#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: $0 CONFORMANCE_CHECKOUT [2025-11-25|2026-07-28]" >&2
  exit 64
fi

conformance_dir=$1
revision=${2:-2026-07-28}
requirements="$conformance_dir/requirements/$revision.yaml"

if [ ! -f "$requirements" ]; then
  echo "missing conformance requirements: $requirements" >&2
  exit 66
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
client="$script_dir/run_mcp_auth_client.sh"
scenarios=$(
  awk '
    /^client:$/ { in_client = 1; next }
    in_client && /^[^ ]/ { exit }
    in_client && /^  - auth\// { sub(/^  - /, ""); print }
  ' "$requirements"
)

status=0
for scenario in $scenarios; do
  echo "==> $revision $scenario"
  if ! (
    cd "$conformance_dir"
    npm run start -- client \
      --command "sh $client" \
      --scenario "$scenario" \
      --spec-version "$revision" \
      --timeout 30000
  ); then
    status=1
    if [ "${MCP_AUTH_FAIL_FAST:-0}" = "1" ]; then
      exit "$status"
    fi
  fi
done

exit "$status"
