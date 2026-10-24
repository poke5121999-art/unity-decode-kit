#!/bin/sh
# usage: compat.sh <AssemblyName> [real.dll]   -> compares stub vs rebuilt DLL, prints missing public API
R=/d/walking-trade-ref
P=$R/unity-dll/ExportedProject/Assets/Plugins
U="/c/Program Files/Unity/Hub/Editor/6000.0.77f1/Editor/Data/Managed/UnityEngine"
dotnet $R/recompile/apicompat-bin/apicompat.dll "$P/$1.dll" "${2:-$R/recompile/thirdparty-dlls/$1.dll}" "$U" "$P" "/c/Program Files/Unity/Hub/Editor/6000.0.77f1/Editor/Data/NetStandard/ref/2.1.0"
