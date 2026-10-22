# Source this: paths to the third-party tools the kit drives.
UDK=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)
export UDK
export DOTNET_ROOT="$UDK/third_party/dotnet"
export DOTNET_ROLL_FORWARD=Major
export JAVA_HOME="$UDK/third_party/jdk-25.0.5+8"
export GHIDRA_INSTALL_DIR="$UDK/third_party/ghidra_12.2_PUBLIC"
export PATH="$JAVA_HOME/bin:$UDK/.venv/bin:$PATH"
export INSPECTOR="$UDK/third_party/inspector-legacy/Il2CppInspectorRedux.Legacy.CLI-linux-x64/Il2CppInspector"
export CPP2IL="$UDK/third_party/Cpp2IL-Linux"
export ASSETRIPPER="$UDK/third_party/assetripper/AssetRipper.GUI.Free"
