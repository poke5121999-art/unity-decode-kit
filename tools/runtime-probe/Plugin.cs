using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using BepInEx;
using BepInEx.Unity.IL2CPP;
using HarmonyLib;

namespace MethodProbe
{
    // BepInEx 6 IL2CPP entry: call counting (Probe), invoke mode (Invoker) and the scenario driver (Scenario).
    [BepInPlugin("local.methodprobe", "MethodProbe", "1.0.0")]
    public class Plugin : BasePlugin
    {
        internal static Plugin Self;

        public override void Load()
        {
            Self = this;
            var list = Config.Bind("Probe", "MethodList", Path.Combine(Paths.ConfigPath, "methodprobe.txt"),
                "File with one Namespace.Type::Method per line (# comments allowed). Every overload is patched.").Value;
            var output = Config.Bind("Probe", "OutputFile", Path.Combine(Paths.BepInExRootPath, "methodprobe.jsonl"),
                "JSONL output, appended. The last line per method is its cumulative state.").Value;
            var flush = Config.Bind("Probe", "FlushSeconds", 5, "Flush period in seconds.").Value;
            var samples = Config.Bind("Probe", "MaxSamples", 5, "Samples kept per method.").Value;
            SetupInvoke();
            Probe.Hook(list, output, flush, samples, IsStruct, Log.LogInfo, Log.LogWarning, Log.LogError);
        }

        static bool IsStruct(Type t) => t != typeof(void) && !t.IsPrimitive && !t.IsEnum
            && (t.IsValueType || typeof(Il2CppSystem.ValueType).IsAssignableFrom(t));

        static string invIn, invOut; static double invDelay; static DateTime invStart; static int invDone;

        void SetupInvoke()
        {
            invIn = Config.Bind("Invoke", "InputFile", Path.Combine(Paths.ConfigPath, "methodprobe-invoke.jsonl"), "JSONL of static methods to call; absent = invoke mode off.").Value;
            invOut = Config.Bind("Invoke", "OutputFile", Path.Combine(Paths.BepInExRootPath, "methodprobe-invoke-out.jsonl"), "Invoke results JSONL.").Value;
            invDelay = Config.Bind("Invoke", "DelaySeconds", 10, "Seconds after plugin load before invoking.").Value;
            var trig = Config.Bind("Invoke", "TriggerMethod", "", "Optional Type::Method (instance or static, called every frame/regularly on the main thread); the first call after the delay runs the invocations there. Empty = run on a background thread after the delay.").Value;
            var scen = Config.Bind("Scenario", "Mode", "", "Empty = off; newgame = start a new game from the main menu, then idle; autoplay = newgame plus the UdkAutoPlay day loop (needs Invoke.TriggerMethod).").Value;
            Scenario.Setup(scen,
                Config.Bind("Scenario", "MenuType", "Runtime.Menu.MenuController", "Menu MonoBehaviour whose OnSaveSelected(int) / OnSaveCreated() start a new game.").Value,
                Config.Bind("Scenario", "Slot", 2, "Save slot the scenario creates.").Value,
                Config.Bind("Scenario", "DelaySeconds", 20, "Seconds after plugin load before pressing New Game.").Value,
                Config.Bind("Scenario", "Days", 3, "autoplay: in-game days to play.").Value,
                Config.Bind("Scenario", "LogFile", Path.Combine(Paths.BepInExRootPath, "scenario.log"), "Scenario progress, one line per step.").Value, Log);
            if (!File.Exists(invIn) && scen.Length == 0) return;
            invStart = DateTime.UtcNow;
            if (string.IsNullOrWhiteSpace(trig))
            {
                new Thread(() => { Thread.Sleep((int)(invDelay * 1000)); RunInvoke(); }) { IsBackground = true }.Start();
                return;
            }
            var parts = trig.Split(new[] { "::" }, StringSplitOptions.None);
            Type t = null;
            foreach (var a in AppDomain.CurrentDomain.GetAssemblies()) { try { t = a.GetType(parts[0], false); } catch { } if (t != null) break; }
            var m = t?.GetMethods(BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly).FirstOrDefault(x => x.Name == parts[1] && x.GetParameters().Length == 0);
            if (m == null) { Log.LogError("invoke trigger not found: " + trig + "; falling back to background thread"); new Thread(() => { Thread.Sleep((int)(invDelay * 1000)); RunInvoke(); }) { IsBackground = true }.Start(); return; }
            new Harmony("local.methodprobe.invoke").Patch(m, postfix: new HarmonyMethod(typeof(Plugin).GetMethod(nameof(Tick), BindingFlags.Static | BindingFlags.NonPublic)));
            Log.LogInfo("invoke mode armed on " + trig + " after " + invDelay + " s");
        }

        static void Tick()
        {
            Scenario.Tick();
            if (!File.Exists(invIn) || (DateTime.UtcNow - invStart).TotalSeconds < invDelay) return;
            if (invDone == 0) Self.Log.LogInfo("tick fired");
            RunInvoke();
        }

        static void RunInvoke()
        {
            if (Interlocked.Exchange(ref invDone, 1) != 0) return;
            try { Invoker.Run(invIn, invOut, Self.Log); }
            catch (Exception e) { Self.Log.LogError("invoke failed: " + e); }
        }
    }
}
