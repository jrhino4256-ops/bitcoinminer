#!/bin/bash
set -euo pipefail

# Only run in Claude Code cloud sessions
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

# Build dependencies for network_miner.cpp
packages=(libcurl4-openssl-dev libjsoncpp-dev)

missing=()
for pkg in "${packages[@]}"; do
  if ! dpkg -s "$pkg" >/dev/null 2>&1; then
    missing+=("$pkg")
  fi
done

if [ ${#missing[@]} -gt 0 ]; then
  export DEBIAN_FRONTEND=noninteractive
  sudo apt-get update -qq
  sudo apt-get install -y -qq "${missing[@]}"
fi

# Ubuntu installs jsoncpp headers under /usr/include/jsoncpp, so expose them
# to make `#include <json/json.h>` resolve without an extra -I flag
if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
  echo 'export CPLUS_INCLUDE_PATH="/usr/include/jsoncpp${CPLUS_INCLUDE_PATH:+:$CPLUS_INCLUDE_PATH}"' >> "$CLAUDE_ENV_FILE"
fi
