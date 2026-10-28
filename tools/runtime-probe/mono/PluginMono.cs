using System;
using System.IO;
using BepInEx;

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
        }

        static bool IsStruct(Type t) => t != typeof(void) && !t.IsPrimitive && !t.IsEnum && t.IsValueType;
    }
}
