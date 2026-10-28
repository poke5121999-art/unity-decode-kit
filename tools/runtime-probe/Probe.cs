using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using HarmonyLib;

namespace MethodProbe
{
    // Call counting shared by the IL2CPP plugin (BepInEx 6, original game) and the Mono plugin (BepInEx 5, our build),
    // so a difference between the two profiles cannot come from the instrument.
    static class Probe
    {
        static readonly ConcurrentDictionary<MethodBase, Stat> Stats = new ConcurrentDictionary<MethodBase, Stat>();
        static readonly List<Stat> All = new List<Stat>();
        static readonly object FileLock = new object();
        static readonly DateTime Loaded = DateTime.UtcNow;
        static string OutPath;
        static int MaxSamples = 5;
        static Action<string> Warn, Error;

        class Stat
        {
            public string Name;
            public long Calls;
            // A postfix does not run when the method throws, so entered - calls = calls that ended in an exception
            // (TimeManager.Sleep counted 0 while every night it threw from a DayPassed handler).
            public long Entered;
            public long LastFlushed = -1;
            public List<string> Samples = new List<string>();
        }

        // isStruct: a struct return is hooked without __result (boxing an IL2CPP UniTask through interop is untested).
        public static void Hook(string listFile, string outPath, int flushSeconds, int maxSamples, Func<Type, bool> isStruct,
                                Action<string> info, Action<string> warn, Action<string> error)
        {
            OutPath = outPath; MaxSamples = maxSamples; Warn = warn; Error = error;
            if (!File.Exists(listFile)) { warn("method list not found: " + listFile); return; }
            var asms = AppDomain.CurrentDomain.GetAssemblies();
            var harmony = new Harmony("local.methodprobe");
            var post = typeof(Probe).GetMethod(nameof(Post), BindingFlags.Static | BindingFlags.NonPublic);
            var pre = new HarmonyMethod(typeof(Probe).GetMethod(nameof(Pre), BindingFlags.Static | BindingFlags.NonPublic));
            var postVoid = typeof(Probe).GetMethod(nameof(PostVoid), BindingFlags.Static | BindingFlags.NonPublic);
            var postBare = typeof(Probe).GetMethod(nameof(PostBare), BindingFlags.Static | BindingFlags.NonPublic);
            var postVoidBare = typeof(Probe).GetMethod(nameof(PostVoidBare), BindingFlags.Static | BindingFlags.NonPublic);
            foreach (var raw in File.ReadAllLines(listFile))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("#")) continue;
                var parts = line.Split(new[] { "::" }, StringSplitOptions.None);
                if (parts.Length != 2) { warn("bad line (need Type::Method): " + line); continue; }
                Type t = null;
                foreach (var a in asms)
                {
                    try { t = a.GetType(parts[0], false); } catch { }
                    if (t != null) break;
                }
                if (t == null) { warn("type not found: " + parts[0]); WriteMissing(line, "type not found"); continue; }
                var ms = t.GetMethods(BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly)
                          .Where(m => m.Name == parts[1] && !m.IsAbstract && !m.ContainsGenericParameters).ToList();
                if (ms.Count == 0) { warn("method not found: " + line); WriteMissing(line, "method not found"); continue; }
                foreach (var m in ms)
                {
                    try
                    {
                        var isVoid = m.ReturnType == typeof(void) || isStruct(m.ReturnType);
                        var st = new Stat { Name = line + (ms.Count > 1 ? "(" + string.Join(",", m.GetParameters().Select(p => p.ParameterType.Name)) + ")" : "") };
                        Stats[m] = st; lock (All) All.Add(st);
                        // Harmony writes __args back into ref/out parameters, so asking for __args on such a method
                        // overwrote `out landmark` with null in LandmarkRepository.TryGetLandmark (true + null ->
                        // IsMet NRE -> Sleep threw -> game time froze). Those methods are counted without arguments.
                        var byRef = m.GetParameters().Any(p => p.ParameterType.IsByRef);
                        var postfix = byRef ? (isVoid ? postVoidBare : postBare) : (isVoid ? postVoid : post);
                        harmony.Patch(m, prefix: pre, postfix: new HarmonyMethod(postfix));
                        info("hooked " + st.Name);
                    }
                    catch (Exception e) { error("patch failed " + line + ": " + e.GetType().Name + ": " + e.Message); WriteMissing(line, "patch failed: " + e.Message); }
                }
            }
            new Thread(() => { while (true) { Thread.Sleep(Math.Max(1, flushSeconds) * 1000); Flush(); } }) { IsBackground = true }.Start();
            AppDomain.CurrentDomain.ProcessExit += OnExit;
        }

        static void Pre(MethodBase __originalMethod)
        {
            if (Stats.TryGetValue(__originalMethod, out var st)) Interlocked.Increment(ref st.Entered);
        }

        static void Post(MethodBase __originalMethod, object[] __args, object __result) => Record(__originalMethod, __args, __result, true);
        static void PostVoid(MethodBase __originalMethod, object[] __args) => Record(__originalMethod, __args, null, false);
        static void PostBare(MethodBase __originalMethod, object __result) => Record(__originalMethod, null, __result, true);
        static void PostVoidBare(MethodBase __originalMethod) => Record(__originalMethod, null, null, false);

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

        internal static string Q(string s)
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

        static void OnExit(object s, EventArgs e) => Flush();

        static void Flush()
        {
            try
            {
                Stat[] snap; lock (All) snap = All.ToArray();
                var sb = new StringBuilder();
                foreach (var st in snap)
                {
                    var c = Interlocked.Read(ref st.Calls);
                    var e = Interlocked.Read(ref st.Entered);
                    if (c + e == st.LastFlushed) continue;
                    st.LastFlushed = c + e;
                    string[] samples; lock (st) samples = st.Samples.ToArray();
                    sb.Append("{\"method\":").Append(Q(st.Name)).Append(",\"calls\":").Append(c).Append(",\"entered\":").Append(e).Append(",\"t\":").Append((long)(DateTime.UtcNow - Loaded).TotalSeconds)
                      .Append(",\"samples\":[").Append(string.Join(",", samples)).Append("]}\n");
                }
                if (sb.Length > 0) lock (FileLock) File.AppendAllText(OutPath, sb.ToString());
            }
            catch (Exception e) { Error?.Invoke("flush failed: " + e.Message); }
        }
    }
}
