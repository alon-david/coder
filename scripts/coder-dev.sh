#!/usr/bin/env bash

# This is a shim for developing and dogfooding Coder so that we don't
# overwrite an existing session in ~/.config/coderv2
set -euo pipefail

SCRIPT_DIR=$(dirname "${BASH_SOURCE[0]}")
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib.sh"
PROJECT_ROOT=$(cd "$SCRIPT_DIR" && git rev-parse --show-toplevel)

CODER_DEV_DIR="$PROJECT_ROOT/.coderv2/"
CODER_DEV_BIN="${CODER_DEV_DIR}/coder"
if [[ ! -d "${CODER_DEV_DIR}" ]]; then
	mkdir -p "${CODER_DEV_DIR}"
fi

if [[ ! -x "${CODER_DEV_BIN}" ]]; then
	echo "Run this command first:"
	echo "go build -o ${CODER_DEV_BIN} ${PROJECT_ROOT}/cmd/coder"
	exit 1
fi

exec "${CODER_DEV_BIN}" --global-config "${CODER_DEV_DIR}" "$@"
