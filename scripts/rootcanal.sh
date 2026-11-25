#!/bin/sh
# Runs rootcanal, Android's virtual Bluetooth controller, with its HCI server
# on TCP port 6402. Each TCP connection gets its own virtual controller, all
# on one virtual radio, so two hosts can discover and connect to each other.
#
# rootcanal ships for linux-x86_64 and macos-arm64 only. On Windows, run it
# in WSL by piping this script in (WSL forwards the port to localhost):
#
#   wsl -- sh -s < scripts/rootcanal.sh
#
# Extra arguments go to rootcanal; `-h` lists them.

set -e

version=1.13.0
venv="${ROOTCANAL_VENV:-$HOME/.venvs/rootcanal}"

if ! "$venv/bin/python" -c 'import rootcanal' 2>/dev/null; then
  echo "Installing rootcanal $version into $venv" >&2
  python3 -m venv "$venv"
  "$venv/bin/pip" install --quiet "rootcanal==$version"
fi

exec "$venv/bin/python" -m rootcanal "$@"
