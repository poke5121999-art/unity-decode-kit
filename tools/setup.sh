#!/bin/sh
# Download the third-party tools into third_party/ and build the Python venv. Safe to rerun.
set -eu
KIT=$(cd "$(dirname "$0")/.." && pwd)
TP="$KIT/third_party"
mkdir -p "$TP"
cd "$TP"

get() { [ -s "$2" ] || timeout 900 curl -fsSL -o "$2" "$1"; }

get https://github.com/LukeFZ/Il2CppInspectorRedux/releases/download/2026.2/Il2CppInspectorRedux.Legacy.CLI-linux-x64.zip inspector-legacy.zip
[ -d inspector-legacy ] || { mkdir inspector-legacy && python3 -c "import zipfile,sys;zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" inspector-legacy.zip inspector-legacy; }
chmod +x inspector-legacy/*/Il2CppInspector

get https://github.com/AssetRipper/AssetRipper/releases/download/2.0.0/AssetRipper_linux_x64.tar.xz AssetRipper_linux_x64.tar.xz
[ -d assetripper ] || { mkdir assetripper && tar -xJf AssetRipper_linux_x64.tar.xz -C assetripper; }

get https://github.com/SamboyCoding/Cpp2IL/releases/download/2022.1.0-pre-release.21/Cpp2IL-2022.1.0-pre-release.21-Linux Cpp2IL-Linux
chmod +x Cpp2IL-Linux

get https://dot.net/v1/dotnet-install.sh dotnet-install.sh
[ -x dotnet/dotnet ] || timeout 900 bash dotnet-install.sh --channel 10.0 --runtime dotnet --install-dir "$TP/dotnet"

get https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.5%2B8/OpenJDK25U-jdk_x64_linux_hotspot_25.0.5_8.tar.gz jdk25.tar.gz
[ -d jdk-25.0.5+8 ] || tar xzf jdk25.tar.gz

get https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.2_build/ghidra_12.2_PUBLIC_20261016.zip ghidra.zip
if [ ! -d ghidra_12.2_PUBLIC ]; then
  python3 -c "import zipfile,sys;zipfile.ZipFile(sys.argv[1]).extractall('.')" ghidra.zip
  chmod +x ghidra_12.2_PUBLIC/support/* ghidra_12.2_PUBLIC/ghidraRun
  find ghidra_12.2_PUBLIC -path '*os/linux_x86_64/*' -type f -exec chmod +x {} +
fi

get https://github.com/BurntSushi/ripgrep/releases/download/15.2.0/ripgrep-15.2.0-x86_64-unknown-linux-musl.tar.gz rg.tar.gz
[ -x rg ] || { tar xzf rg.tar.gz && mv ripgrep-15.2.0-x86_64-unknown-linux-musl/rg . && rm -rf ripgrep-15.2.0-x86_64-unknown-linux-musl; }

cd "$KIT"
[ -x .venv/bin/python ] || timeout 600 uv venv -q -p 3.13 .venv
WHEELS="$TP/ghidra_12.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/dist"
timeout 600 uv pip install -q -p .venv/bin/python --no-index --find-links "$WHEELS" pyghidra jpype1
timeout 600 uv pip install -q -p .venv/bin/python UnityPy capstone pefile lz4 pycryptodome
echo "setup ok"
