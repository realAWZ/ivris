#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

# Ensure local server is running on port 3000
if ! lsof -i :3000 >/dev/null 2>&1; then
  echo "Starting Ivris Server on port 3000..."
  python3 server.py &
  sleep 2
fi

echo "Starting Cloudflare Tunnel on http://127.0.0.1:3000..."
if [ -f "$DIR/../cloudflared" ]; then
  "$DIR/../cloudflared" tunnel --url http://127.0.0.1:3000
elif [ -f "$HOME/.local/bin/cloudflared" ]; then
  "$HOME/.local/bin/cloudflared" tunnel --url http://127.0.0.1:3000
else
  cloudflared tunnel --url http://127.0.0.1:3000
fi
