#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2025 The Namecoin Project <www.namecoin.org>
#
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

# Name of the profile to create
PROFILE_NAME="proxy-profile"
PROFILE_DIR="$HOME/.mozilla/firefox/${PROFILE_NAME}.profile"
# Firefox's profiles.ini file where we need to register our new profile
PROFILES_INI="$HOME/.mozilla/firefox/profiles.ini"

mkdir -p "$PROFILE_DIR"

# Write the SOCKS5 proxy settings to user.js
# This is what actually tells Firefox to use our proxy.
cat > "$PROFILE_DIR/user.js" <<EOF
// Set up Firefox to use a SOCKS5 proxy
user_pref("network.proxy.type", 1);
user_pref("network.proxy.socks", "127.0.0.1");
user_pref("network.proxy.socks_port", 9050);
user_pref("network.proxy.socks_version", 5);
user_pref("network.proxy.socks_remote_dns", true);
user_pref("network.proxy.no_proxies_on", "");
EOF

# Make sure profiles.ini exists and register our profile there
mkdir -p "$(dirname "$PROFILES_INI")"
cat > "$PROFILES_INI" <<EOF
[General]
StartWithLastProfile=0

[Profile0]
Name=$PROFILE_NAME
IsRelative=0
Path=$PROFILE_DIR
Default=1
EOF

echo "Profile '$PROFILE_NAME' created and ready to use."
echo "Directory: $PROFILE_DIR"
echo "SOCKS5 proxy is set to 127.0.0.1:9050"

