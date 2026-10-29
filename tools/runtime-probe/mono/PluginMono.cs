using System;
using System.IO;
using System.Reflection;
using System.Text;
using BepInEx;
using UnityEngine;

namespace MethodProbe
{
    // BepInEx 5 entry for our Mono build. Only counts calls: the run itself is driven by UdkProbe's UdkNewGame and
    // UdkAutoPlay (UDK_NEWGAME, UDK_AUTOPLAY), the same day loop Scenario.cs replays on the original game.
    [BepInPlugin("local.methodprobe", "MethodProbe", "1.0.0")]
    public class PluginMono : BaseUnityPlugin
    {
        void Awake()
        {
            var list = Config.Bind("Probe", "MethodList", Path.Combine(Paths.ConfigPath, "methodprobe.txt"),
                "File with one Namespace.Type::Method per line (# comments allowed). Every overload is patched.").Value;
            var output = Config.Bind("Probe", "OutputFile", Path.Combine(Paths.BepInExRootPath, "methodprobe.jsonl"),
                "JSONL output, appended. The last line per method is its cumulative state.").Value;
            var flush = Config.Bind("Probe", "FlushSeconds", 5, "Flush period in seconds.").Value;
            var samples = Config.Bind("Probe", "MaxSamples", 5, "Samples kept per method.").Value;
            Probe.Hook(list, output, flush, samples, IsStruct, Logger.LogInfo, Logger.LogWarning, Logger.LogError);
            navLog = Path.Combine(Path.GetDirectoryName(output), "navlog.txt");
        }

        // Every 5 s, the state of each mob navigator: the same line Scenario.NavLog writes on the original side, so a
        // customer that reaches its shelf here and not there can be compared field by field.
        string navLog;
        float nextNav;
        static readonly BindingFlags All = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;

        void Update()
        {
            if (Time.realtimeSinceStartup < nextNav) return;
            nextNav = Time.realtimeSinceStartup + 5f;
            var t = Type.GetType("Runtime.Mob.Navigation.RigidbodyNavigator, Runtime");
            if (t == null) return;
            var sb = new StringBuilder();
            foreach (var o in UnityEngine.Object.FindObjectsByType(t, FindObjectsSortMode.None))
            {
                var c = (Component)o;
                var rb = c.GetComponent<Rigidbody>();
                var path = Get(o, "_currentPath") as System.Collections.ICollection;
                sb.Append($"{Time.realtimeSinceStartup:F0}\t  nav {c.gameObject.name} pos={c.transform.position:F1} dest={Get(o, "DestinationPosition"):F1} " +
                          $"hasDest={Get(o, "_hasDestination")} calc={Get(o, "IsCalculatingPath")} unreach={Get(o, "IsDestinationUnreachable")} " +
                          $"path={Get(o, "_currentPathIndex")}/{(path == null ? -1 : path.Count)} v={Get(o, "_currentVelocity"):F2} stuck={Get(o, "StuckTime"):F1} " +
                          $"kin={rb?.isKinematic} rbv={rb?.linearVelocity.magnitude:F2}\n");
            }
            if (sb.Length > 0) try { File.AppendAllText(navLog, sb.ToString()); } catch { }
        }

        static object Get(object o, string name)
        {
            for (var t = o.GetType(); t != null; t = t.BaseType)
            {
                var p = t.GetProperty(name, All | BindingFlags.DeclaredOnly); if (p != null) return p.GetValue(o, null);
                var f = t.GetField(name, All | BindingFlags.DeclaredOnly); if (f != null) return f.GetValue(o);
            }
            return null;
        }

        static bool IsStruct(Type t) => t != typeof(void) && !t.IsPrimitive && !t.IsEnum && t.IsValueType;
    }
}
