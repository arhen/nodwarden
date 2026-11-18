#!/usr/bin/env bash
# Builds NodWarden.app into ~/Applications. Run from anywhere.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
app="$HOME/Applications/NodWarden.app"

cargo build --release --manifest-path "$here/core/Cargo.toml"
mkdir -p "$here/build"
swiftc -O -swift-version 5 -parse-as-library -o "$here/build/nodwarden" "$here/NodWarden.swift" 2>&1 | grep -v "^$" || true
test -x "$here/build/nodwarden"

rm -rf "$app"
mkdir -p "$app/Contents/MacOS"
cp "$here/build/nodwarden" "$app/Contents/MacOS/nodwarden"
cp "$here/core/target/release/aac-core" "$app/Contents/MacOS/aac-core"
mkdir -p "$app/Contents/Resources"
cp "$here/assets/mark-512.png" "$app/Contents/Resources/mark.png"
cp "$here/assets/NodWarden.icns" "$app/Contents/Resources/NodWarden.icns"
cat > "$app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key><string>io.github.nodwarden</string>
    <key>CFBundleName</key><string>NodWarden</string>
    <key>CFBundleExecutable</key><string>nodwarden</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>2.0</string>
    <key>LSUIElement</key><true/>
    <key>CFBundleIconFile</key><string>NodWarden</string>
    <key>LSMinimumSystemVersion</key><string>14.0</string>
</dict>
</plist>
PLIST
codesign --force --deep --sign - "$app"
echo "built: $app"
