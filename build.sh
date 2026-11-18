#!/usr/bin/env bash
# Builds NodWarden.app into ~/Applications. Run from anywhere.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
app="$HOME/Applications/NodWarden.app"
version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$here/core/Cargo.toml" | head -1)"

cargo build --release --locked --manifest-path "$here/core/Cargo.toml"
mkdir -p "$here/build"
# Remove the old binary first so a failed compile can't install a stale one (#12).
rm -f "$here/build/nodwarden"
swiftc -O -swift-version 5 -parse-as-library -target arm64-apple-macos14.0 \
  -o "$here/build/nodwarden" "$here/NodWarden.swift"

rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$here/build/nodwarden" "$app/Contents/MacOS/nodwarden"
cp "$here/core/target/release/aac-core" "$app/Contents/MacOS/aac-core"
cp "$here/assets/mark-512.png" "$app/Contents/Resources/mark.png"
cp "$here/assets/NodWarden.icns" "$app/Contents/Resources/NodWarden.icns"
cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key><string>io.github.nodwarden</string>
    <key>CFBundleName</key><string>NodWarden</string>
    <key>CFBundleExecutable</key><string>nodwarden</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>${version}</string>
    <key>LSUIElement</key><true/>
    <key>CFBundleIconFile</key><string>NodWarden</string>
    <key>LSMinimumSystemVersion</key><string>14.0</string>
</dict>
</plist>
PLIST
# Hardened runtime: no DYLD_INSERT_LIBRARIES, no unsigned code loaded into either binary (#4).
codesign --force --options runtime --sign - "$app/Contents/MacOS/aac-core"
codesign --force --options runtime --sign - "$app"
codesign --verify --strict "$app"
echo "built: $app ($version)"
