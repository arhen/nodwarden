#!/usr/bin/env bash
# Renders the animated overview (assets/overview-{dark,light}.webp).
# Needs: swift, imagemagick, img2webp (brew install webp). Run from anywhere.
set -euo pipefail
cd "$(dirname "$0")/.."
swiftc -O -parse-as-library -o /tmp/nw-diagrams docs/diagrams.swift 2>/dev/null \
  || swiftc -O -o /tmp/nw-diagrams docs/diagrams.swift
for theme in dark light; do
  dir="$(mktemp -d)"
  /tmp/nw-diagrams --frames "$theme" "$dir"
  magick mogrify -resize 1460x "$dir"/f*.png
  # 24 fps = 42 ms per frame; hold the last frame so the loop has a pause.
  frames=("$dir"/f*.png)
  last="${frames[${#frames[@]}-1]}"
  img2webp -loop 0 -lossy -q 80 -m 6 -mixed -d 42 "${frames[@]:0:${#frames[@]}-1}" -d 1400 "$last" \
    -o "assets/overview-$theme.webp" >/dev/null
  rm -rf "$dir"
  echo "assets/overview-$theme.webp $(du -h "assets/overview-$theme.webp" | cut -f1)"
done
