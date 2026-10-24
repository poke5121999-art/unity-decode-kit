using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using BepInEx;
using BepInEx.Unity.IL2CPP;
using HarmonyLib;

namespace MethodProbe
{
    [BepInPlugin("local.methodprobe", "MethodProbe", "1.0.0")]
    public class Plugin : BasePlugin
    {
        internal static Plugin Self;
        static readonly ConcurrentDictionary<MethodBase, Stat> Stats = new();
        static readonly List<Stat> All = new();
        static string OutPath;
        static int MaxSamples = 5;
        static readonly object FileLock = new();

        class Stat
        {
            public string Name;
            public long Calls;
            public long LastFlushed = -1;
            public List<string> Samples = new();
        }

        public override void Load()
        {
            Self = this;
            var listCfg = Config.Bind("Probe", "MethodList", Path.Combine(Paths.ConfigPath, "methodprobe.txt"),
                "File with one Namespace.Type::Method per line (# comments allowed). Every overload is patched.");
            var outCfg = Config.Bind("Probe", "OutputFile", Path.Combine(Paths.BepInExRootPath, "methodprobe.jsonl"),
                "JSONL output, appended. The last line per method is its cumulative state.");
            var flushCfg = Config.Bind("Probe", "FlushSeconds", 5, "Flush period in seconds.");
            MaxSamples = Config.Bind("Probe", "MaxSamples", 5, "Samples kept per method.").Value;
            OutPath = outCfg.Value;

            if (!File.Exists(listCfg.Value)) { Log.LogWarning("method list not found: " + listCfg.Value); return; }
            var asms = AppDomain.CurrentDomain.GetAssemblies();
            var harmony = new Harmony("local.methodprobe");
            var post = typeof(Plugin).GetMethod(nameof(Post), BindingFlags.Static | BindingFlags.NonPublic);
            var postVoid = typeof(Plugin).GetMethod(nameof(PostVoid), BindingFlags.Static | BindingFlags.NonPublic);

            foreach (var raw in File.ReadAllLines(listCfg.Value))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("#")) continue;
                var parts = line.Split(new[] { "::" }, StringSplitOptions.None);
                if (parts.Length != 2) { Log.LogWarning("bad line (need Type::Method): " + line); continue; }
                Type t = null;
                foreach (var a in asms)
                {
                    try { t = a.GetType(parts[0], false); } catch { }
                    if (t != null) break;
                }
                if (t == null) { Log.LogWarning("type not found: " + parts[0]); WriteMissing(line, "type not found"); continue; }
                var ms = t.GetMethods(BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly)
                          .Where(m => m.Name == parts[1] && !m.IsAbstract && !m.ContainsGenericParameters).ToList();
                if (ms.Count == 0) { Log.LogWarning("method not found: " + line); WriteMissing(line, "method not found"); continue; }
                foreach (var m in ms)
                {
                    try
                    {
                        var isVoid = m.ReturnType == typeof(void);
                        var st = new Stat { Name = line + (ms.Count > 1 ? "(" + string.Join(",", m.GetParameters().Select(p => p.ParameterType.Name)) + ")" : "") };
                        Stats[m] = st; lock (All) All.Add(st);
                        harmony.Patch(m, postfix: new HarmonyMethod(isVoid ? postVoid : post));
                        Log.LogInfo("hooked " + st.Name);
                    }
                    catch (Exception e) { Log.LogError("patch failed " + line + ": " + e.GetType().Name + ": " + e.Message); WriteMissing(line, "patch failed: " + e.Message); }
                }
            }
            var th = new Thread(() => { while (true) { Thread.Sleep(Math.Max(1, flushCfg.Value) * 1000); Flush(); } }) { IsBackground = true };
            th.Start();
            AppDomain.CurrentDomain.ProcessExit += (s, e) => Flush();
        }

        static void Post(MethodBase __originalMethod, object[] __args, object __result) => Record(__originalMethod, __args, __result, true);
        static void PostVoid(MethodBase __originalMethod, object[] __args) => Record(__originalMethod, __args, null, false);

        static void Record(MethodBase m, object[] args, object result, bool hasResult)
        {
            if (!Stats.TryGetValue(m, out var st)) return;
            var n = Interlocked.Increment(ref st.Calls);
            if (n > MaxSamples) return;
            string s;
            try
            {
                var sb = new StringBuilder("{\"args\":[");
                if (args != null) sb.Append(string.Join(",", args.Select(Render)));
                sb.Append("]");
                if (hasResult) sb.Append(",\"ret\":").Append(Render(result));
                sb.Append("}");
                s = sb.ToString();
            }
            catch (Exception e) { s = "{\"error\":" + Q(e.Message) + "}"; }
            lock (st) st.Samples.Add(s);
        }

        static string Render(object o)
        {
            if (o == null) return "null";
            var t = o.GetType();
            if (o is string str) return Q(str);
            if (o is bool b) return b ? "true" : "false";
            if (t.IsEnum) return Q(o.ToString());
            if (t.IsPrimitive) return Q(Convert.ToString(o, System.Globalization.CultureInfo.InvariantCulture));
            return Q("<" + t.FullName + ">");
        }

        static string Q(string s)
        {
            var sb = new StringBuilder("\"");
            foreach (var c in s ?? "")
            {
                if (c == '"' || c == '\\') sb.Append('\\').Append(c);
                else if (c < 32) sb.AppendFormat("\\u{0:x4}", (int)c);
                else sb.Append(c);
            }
            return sb.Append('"').ToString();
        }

        static void WriteMissing(string m, string why)
        {
            lock (FileLock) File.AppendAllText(OutPath, "{\"method\":" + Q(m) + ",\"error\":" + Q(why) + "}\n");
        }

        static void Flush()
        {
            try
            {
                Stat[] snap; lock (All) snap = All.ToArray();
                var sb = new StringBuilder();
                foreach (var st in snap)
                {
                    var c = Interlocked.Read(ref st.Calls);
                    if (c == st.LastFlushed) continue;
                    st.LastFlushed = c;
                    string[] samples; lock (st) samples = st.Samples.ToArray();
                    sb.Append("{\"method\":").Append(Q(st.Name)).Append(",\"calls\":").Append(c)
                      .Append(",\"samples\":[").Append(string.Join(",", samples)).Append("]}\n");
                }
                if (sb.Length > 0) lock (FileLock) File.AppendAllText(OutPath, sb.ToString());
            }
            catch (Exception e) { Self?.Log.LogError("flush failed: " + e.Message); }
        }
    }
}
