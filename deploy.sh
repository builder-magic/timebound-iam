#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  echo "Usage: ./deploy.sh <version>"
  echo "Example: ./deploy.sh 0.8.0"
  exit 1
fi

# Strip leading 'v' if provided
VERSION="${VERSION#v}"
TAG="v${VERSION}"

# Ensure we're on mainline and up to date
git checkout mainline
git pull origin mainline

# Update version in main.go
sed -i '' "s/serverVersion = \".*\"/serverVersion = \"${VERSION}\"/" main.go

# Verify the change
if ! grep -q "serverVersion = \"${VERSION}\"" main.go; then
  echo "ERROR: Failed to update version in main.go"
  exit 1
fi

# Build and test
just build
just test

# Commit and push directly to mainline
git add main.go
git commit -m "chore: bump version to ${VERSION}"
git push origin mainline

# Create release (this pushes the tag, triggering goreleaser + homebrew)
gh release create "$TAG" --title "$TAG" --generate-notes
echo ""
echo "Release ${TAG} created. GoReleaser will build binaries and update the Homebrew tap."
echo "Monitor: gh run list --limit 1"
