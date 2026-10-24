# Third-party DLL rebuilds (replace body-less AssetRipper stubs)

Each DLL keeps the stub's assembly name, so the stub's .meta GUID and scene MonoBehaviour refs still bind.
Sources: D:\walking-trade-ref\thirdparty-src (outside repo). Outputs: D:\walking-trade-ref\recompile\thirdparty-dlls.
Build everything + gate: `sh build.sh`. One lib: `dotnet build <Lib>/<Assembly>.csproj -c Release`.
Gate: `sh compat.sh <AssemblyName> [real.dll]` (apicompat/ = System.Reflection.MetadataLoadContext tool; build with
`dotnet build apicompat -c Release -o /d/walking-trade-ref/recompile/apicompat-bin`). It lists stub public/protected types and members
(name + parameter types) absent from the rebuilt DLL. Shared settings (netstandard2.1, unsafe, Unity defines): common.props.

| Assembly | Upstream / version | Why this version | Gate vs stub |
|---|---|---|---|
| UniTask | Cysharp/UniTask master a77a1b4 (package.json 2.5.11), src/UniTask/.../Runtime minus External/ (stub has no Addressables/DOTween/TMP part) | Only one built; needs UNITY_2022_3 + ENABLE_MANAGED_JOBS + ENABLE_UNITYWEBREQUEST + UNITASK_*_SUPPORT defines to expose JobHandle/UnityWebRequest/AsyncInstantiate APIs the stub has | 0 missing (real has 2 extra types) |
| Newtonsoft.Json | com.unity.nuget.newtonsoft-json 3.2.1 (= 13.0.2) Runtime/AOT/Newtonsoft.Json.dll, prebuilt | AOT build matches 144/144 types, 0 members missing. NuGet 13.0.3 lacks AotHelper (5 members); 13.0.1 lacks 15 | 0 missing |
| DentedPixel | dentedpixel/LeanTween f387a18, Assets/LeanTween/Framework | Single upstream version (2.50) | 0 missing |
| com.rlabrecque.steamworks.net | Steamworks.NET tag 2025.162.0 (stub Version.cs says 2025.162.0) | master 2025.165.0 misses 26 types; 162.1 has 1 extra. Defines UNITY_64;STEAMWORKS_WIN;STEAMWORKS_X64 | 0 missing |
| PriorityQueue | BlueRaja/High-Speed-Priority-Queue-for-C-Sharp master, `Priority Queue/*.cs` | Single version | 0 missing |
| KinoBloom.Runtime | keijiro/KinoBloom master, Assets/Kino/Bloom/Bloom.cs | Single type | 0 missing |
| Coffee.SoftMaskForUGUI | mob-sakai/SoftMaskForUGUI master 3.6.5, Packages/src/Runtime | Stub has v3 types (MaskingShape, TmpProxy); defines TMP_ENABLE, URP_ENABLE, SHADERGRAPH_CANVAS_ENABLE, UNITY_MODULE_VR | 3 missing, all explicit interface impls (`ISoftMasking.enabled/showMaskGraphic`), not callable by name |
| Coffee.SoftMaskForUGUI.R | upstream prebuilt marker dll (empty, only <Module>) copied | Same as stub | identical |
| Cinemachine | com.unity.cinemachine 2.10.5 (tgz from packages.unity.com) | 179/179 types, 0 members missing. 2.8.9 misses 2 types / 50 members; 2.9.7 does not compile with URP17 defines. Defines: CINEMACHINE_TIMELINE/PHYSICS/PHYSICS_2D/UGUI/URP/URP_14/UNITY_ANIMATION/UNITY_IMGUI, no PostProcessing v2/HDRP/InputSystem (stub has dummy types for them) | 0 missing |
| Unity.Animation.Rigging | com.unity.animation.rigging 1.3.1 | 1.3.1 0 missing; 1.2.1 misses 2 ReadOnlyTransformHandle methods | 0 missing |

Traps: env var `Src` collides with MSBuild property names (use unique names such as LeanSrc). Stub assemblies reference mscorlib, so the gate
resolver falls back to netstandard.dll. Not done: Cinemachine/Rigging against real Unity.Timeline / Burst bodies (still stub references at compile time; runtime binds by name).
