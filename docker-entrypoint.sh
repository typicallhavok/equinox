#!/bin/sh
# ====================================================================
# equinox entrypoint — make config "just work".
#
# The image ships a default config at /app/config.yaml, so a bare
#   docker run ... ghcr.io/<owner>/<repo>
# starts with no -v flag at all.
#
# If you mount your own directory over /app (e.g. -v "$(pwd):/app") and it
# has no config yet, we seed the bundled default into it so you get an
# editable, hot-reloadable template on first run — nginx-style.
# ====================================================================
set -e

CONFIG="${CONFIG:-/app/config.yaml}"
DEFAULT="/usr/share/equinox/config.default.yaml"

if [ ! -f "$CONFIG" ]; then
    echo "[entrypoint] no config at $CONFIG — seeding default template"
    mkdir -p "$(dirname "$CONFIG")"
    cp "$DEFAULT" "$CONFIG" || echo "[entrypoint] WARN: could not write $CONFIG (read-only mount?)"
fi

echo "[entrypoint] using config: $CONFIG"
exec l4 "$@"
