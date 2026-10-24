#!/bin/sh
# Builds every third-party DLL into D:\walking-trade-ref\recompile\thirdparty-dlls and runs the API compat gate against the stubs.
# Prereq: sources in D:\walking-trade-ref\thirdparty-src (see README.md); apicompat built:  dotnet build apicompat -c Release -o /d/walking-trade-ref/recompile/apicompat-bin
cd "$(dirname "$0")"
for p in UniTask/UniTask DentedPixel/DentedPixel Steamworks.NET/com.rlabrecque.steamworks.net PriorityQueue/PriorityQueue KinoBloom/KinoBloom.Runtime SoftMaskForUGUI/Coffee.SoftMaskForUGUI Cinemachine/Cinemachine AnimationRigging/Unity.Animation.Rigging; do
  timeout 400 dotnet build $p.csproj -c Release 2>&1 | grep -E " error |Error\(s\)" | sort -u
  echo "--- compat $(basename $p)"; timeout 300 ./compat.sh $(basename $p) | head -5
done
# Newtonsoft.Json: Unity's prebuilt AOT dll, no compile
cp /d/walking-trade-ref/thirdparty-src/nj/up/package/Runtime/AOT/Newtonsoft.Json.dll /d/walking-trade-ref/recompile/thirdparty-dlls/
echo "--- compat Newtonsoft.Json"; timeout 300 ./compat.sh Newtonsoft.Json | head -5
# Coffee.SoftMaskForUGUI.R: upstream ships an empty marker dll
cp /d/walking-trade-ref/thirdparty-src/SoftMaskForUGUI/Packages/src/Runtime/Coffee.SoftMaskForUGUI.R.dll /d/walking-trade-ref/recompile/thirdparty-dlls/
