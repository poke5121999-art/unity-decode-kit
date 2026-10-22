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
[ -d dotnet/sdk ] || timeout 900 bash dotnet-install.sh --channel 10.0 --install-dir "$TP/dotnet"

# Il2CppInspectorRedux from source with udk's tolerant patch (damaged/protected builds no longer abort)
if [ ! -f inspector-tolerant/Il2CppInspector.dll ]; then
  [ -d inspector-src ] || timeout 600 git clone -q --depth 1 --branch 2026.2 --recurse-submodules https://github.com/LukeFZ/Il2CppInspectorRedux.git inspector-src
  (cd inspector-src && { git apply --check "$KIT/tools/inspector/tolerant.patch" 2>/dev/null && git apply "$KIT/tools/inspector/tolerant.patch" || true; })
  # MSBuild node reuse would keep a child alive holding the heavy-job lock fd: disable it
  MSBUILDDISABLENODEREUSE=1 DOTNET_ROOT="$TP/dotnet" DOTNET_CLI_TELEMETRY_OPTOUT=1 timeout 1500 "$TP/dotnet/dotnet" build --disable-build-servers -c Release -o "$TP/inspector-tolerant" inspector-src/Il2CppInspector.CLI/Il2CppInspector.CLI.csproj >/dev/null
fi

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

mkdir -p wwiser vgmstream
get https://github.com/bnnm/wwiser/releases/download/v20260808/wwiser.pyz wwiser/wwiser.pyz
get https://github.com/vgmstream/vgmstream/releases/download/r2117/vgmstream-linux.zip vgmstream.zip
[ -x vgmstream/vgmstream-cli ] || { python3 -c "import zipfile,sys;zipfile.ZipFile(sys.argv[1]).extractall('vgmstream')" vgmstream.zip && chmod +x vgmstream/*; }
get "https://sourceforge.net/projects/unluac/files/Unstable/unluac_2025_12_23.jar/download" unluac.jar
get https://github.com/frida/frida/releases/download/17.24.3/frida-gadget-17.24.3-linux-x86_64.so.xz frida-gadget.so.xz
[ -s frida-gadget.so ] || xz -dkf frida-gadget.so.xz

cd "$KIT"
[ -x .venv/bin/python ] || timeout 600 uv venv -q -p 3.13 .venv
WHEELS="$TP/ghidra_12.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/dist"
timeout 600 uv pip install -q -p .venv/bin/python --no-index --find-links "$WHEELS" pyghidra jpype1
timeout 600 uv pip install -q -p .venv/bin/python UnityPy capstone pefile lz4 pycryptodome frida frida-tools
(cd tools/spine && [ -d node_modules ] || timeout 600 npm install --silent --no-audit --no-fund)
echo "setup ok"
