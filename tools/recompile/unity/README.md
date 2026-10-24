# Unity rebuild probe kit

Generic helpers to measure how far a Unity project (e.g. AssetRipper export) boots with recovered script DLLs.

- `Editor/UdkBuild.cs` - `UdkBuild.BuildWindows()`: Windows64 (or Linux64 with env `UDK_BUILD_TARGET=Linux64`) Mono development build of all enabled scenes
  (falls back to every scene in Assets/Scenes, Startup/Splash first). Output path from env `UDK_BUILD_OUT`.
  Logs `[UdkBuild] result=...` and build errors. Exit code 0 on success.
- `UdkProbe/` - runtime (not Editor), its own assembly. Auto-starts; logs scene loads, counts log messages per type, top
  exceptions, screenshots and a scene tree (including DontDestroyOnLoad) at 5/15/30/60/90 s, and writes
  `probe-summary.json` every 10 s into env `UDK_PROBE_DIR` (fallback persistentDataPath). `UDK_PROBE_CALLS` invokes
  methods on a schedule.
- `run-player.sh` - runs a build for a fixed time (renamed and given the original's Steam files) and prints the probe
  summary, the `[udk-stub]` methods reached and the exceptions.

Never leave a loose script under Assets: it compiles into Unity's own Assembly-CSharp.dll, which replaces the recovered
Assembly-CSharp.dll in the player, so every scene reference into it is a missing script. UdkBuild refuses to build then.
`python -m udk.scriptid` names the class behind each `m_Script` fileID of a DLL.

Run:
1. Copy `Editor/UdkBuild.cs` to `<project>/Assets/Editor/`, the `UdkProbe/` folder to `<project>/Assets/`.
2. `UDK_BUILD_OUT=<dir>/Game.exe Unity.exe -batchmode -quit -nographics -projectPath <project> -executeMethod UdkBuild.BuildWindows -logFile build.log`
3. `UDK_PROBE_DIR=<dir> Game.exe -screen-fullscreen 0 -screen-width 1280 -screen-height 720` for 120 s, then kill; read Player.log and probe-summary.json.
