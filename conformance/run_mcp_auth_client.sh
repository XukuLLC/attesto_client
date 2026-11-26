#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(dirname -- "$script_dir")

cd "$project_dir"
export ATTESTO_PATH=1
exec mix run conformance/mcp_auth_client.exs -- "$@"
