#!/bin/zsh
cd /Users/aydenzosche/.gemini/antigravity/scratch/kith-social
echo "==================================================="
echo "  IVRIS - RESUMING APPLE ID / TESTFLIGHT BUILD"
echo "==================================================="
echo ""
npx --yes eas-cli build --platform ios --profile production --auto-submit
echo ""
read "?Press Enter to close this window..."
