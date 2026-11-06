#!/bin/zsh
cd /Users/aydenzosche/.gemini/antigravity/scratch/kith-social
echo "==================================================="
echo "  IVRIS - APPLE TESTFLIGHT AUTOMATED LAUNCHER"
echo "==================================================="
echo ""
echo "Step 1: Logging into Expo (create a free account at expo.dev if needed)..."
npx --yes eas-cli login

echo ""
echo "Step 2: Linking EAS Project & Building for Apple TestFlight..."
npx --yes eas-cli build:configure -p ios
npx --yes eas-cli build --platform ios --profile production --auto-submit
