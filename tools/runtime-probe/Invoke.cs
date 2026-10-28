using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.Json;
using BepInEx.Logging;

namespace MethodProbe
{
    // Invoke mode: calls STATIC methods with primitive params from a JSONL file and records the returns.
    internal class LineSink { readonly string p; public LineSink(string p) { this.p = p; } public void AppendLine(string s) { File.AppendAllText(p, s + (char)10); } }
    internal static class Invoker
    {
        static readonly Dictionary<string, string> Alias = new(StringComparer.OrdinalIgnoreCase)
        {
            ["int"] = "Int32", ["float"] = "Single", ["bool"] = "Boolean", ["long"] = "Int64", ["double"] = "Double",
            ["byte"] = "Byte", ["short"] = "Int16", ["uint"] = "UInt32", ["string"] = "String",
        };

        public static void Run(string inPath, string outPath, ManualLogSource log)
        {
            log.LogInfo("invoke start"); File.WriteAllText(outPath, ""); var sb = new LineSink(outPath);
            int keys = 0, resolved = 0, ok = 0, err = 0;
            foreach (var raw in File.ReadAllLines(inPath))
            {
                if (string.IsNullOrWhiteSpace(raw)) continue;
                keys++;
                string key = "?";
                try
                {
                    using var doc = JsonDocument.Parse(raw);
                    var root = doc.RootElement;
                    key = root.GetProperty("key").GetString();
                    var ps = root.GetProperty("params").EnumerateArray().Select(e => Canon(e.GetString())).ToArray();
                    var m = Resolve(key, ps); log.LogInfo("resolved " + key + " -> " + (m != null));
                    if (m == null) { sb.AppendLine("{\"key\":" + Probe.Q(key) + ",\"error\":\"resolve failed: no static method with these parameter types\"}"); err++; continue; }
                    resolved++;
                    var skip = new HashSet<string>();
                    if (root.TryGetProperty("skip", out var sk))
                        foreach (var x in sk.EnumerateArray()) skip.Add(Norm(x));
                    foreach (var argset in root.GetProperty("args").EnumerateArray())
                    {
                        if (skip.Contains(Norm(argset)))
                        {
                            sb.AppendLine("{\"key\":" + Probe.Q(key) + ",\"args\":" + argset.GetRawText() + ",\"ret\":\"timeout\"}");
                            continue;
                        }
                        var vals = argset.EnumerateArray().ToArray();
                        string argsJson = argset.GetRawText();
                        try
                        {
                            var objs = new object[ps.Length];
                            var pi = m.GetParameters();
                            for (int i = 0; i < ps.Length; i++) objs[i] = Conv(vals[i], pi[i].ParameterType);
                            var r = m.Invoke(null, objs);
                            sb.AppendLine("{\"key\":" + Probe.Q(key) + ",\"args\":" + argsJson + ",\"ret\":" + Fmt(r) + "}");
                            ok++;
                        }
                        catch (Exception e)
                        {
                            var ie = e is TargetInvocationException && e.InnerException != null ? e.InnerException : e;
                            sb.AppendLine("{\"key\":" + Probe.Q(key) + ",\"args\":" + argsJson + ",\"error\":" + Probe.Q(ie.GetType().Name + ": " + ie.Message) + "}");
                            err++;
                        }
                    }
                }
                catch (Exception e)
                {
                    sb.AppendLine("{\"key\":" + Probe.Q(key) + ",\"error\":" + Probe.Q(e.GetType().Name + ": " + e.Message) + "}");
                    err++;
                }
            }

            log.LogInfo($"invoke done: keys={keys} resolved={resolved} ok={ok} errors={err} -> {outPath}");
        }

        static string Norm(JsonElement e) => string.Join(",", e.EnumerateArray().Select(v => v.GetRawText()));

        static string Canon(string s) => Alias.TryGetValue(s, out var a) ? a : s;

        static MethodInfo Resolve(string key, string[] ps)
        {
            var k = key; int p = k.IndexOf('('); if (p >= 0) k = k.Substring(0, p);
            var parts = k.Split(new[] { "::" }, StringSplitOptions.None);
            foreach (var a in AppDomain.CurrentDomain.GetAssemblies())
            {
                Type t = null;
                try { t = a.GetType(parts[0], false); } catch { }
                if (t == null) continue;
                foreach (var m in t.GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly))
                {
                    if (m.Name != parts[1]) continue;
                    var pi = m.GetParameters();
                    if (pi.Length == ps.Length && pi.Select(x => x.ParameterType.Name).SequenceEqual(ps)) return m;
                }
            }
            return null;
        }

        static object Conv(JsonElement e, Type t)
        {
            if (t == typeof(int)) return e.GetInt32();
            if (t == typeof(float)) return (float)e.GetDouble();
            if (t == typeof(bool)) return e.GetBoolean();
            if (t == typeof(long)) return e.GetInt64();
            if (t == typeof(double)) return e.GetDouble();
            if (t == typeof(byte)) return (byte)e.GetInt32();
            if (t == typeof(short)) return (short)e.GetInt32();
            if (t == typeof(uint)) return e.GetUInt32();
            if (t == typeof(string)) return e.GetString();
            throw new NotSupportedException("param type " + t.Name);
        }

        static string Fmt(object r)
        {
            if (r == null) return "null";
            if (r is bool b) return b ? "true" : "false";
            if (r is float f) return float.IsFinite(f) ? f.ToString("R", CultureInfo.InvariantCulture) : Probe.Q(f.ToString(CultureInfo.InvariantCulture));
            if (r is double d) return double.IsFinite(d) ? d.ToString("R", CultureInfo.InvariantCulture) : Probe.Q(d.ToString(CultureInfo.InvariantCulture));
            if (r is string s) return Probe.Q(s);
            if (r.GetType().IsPrimitive) return Convert.ToString(r, CultureInfo.InvariantCulture);
            return Probe.Q("<" + r.GetType().FullName + ">");
        }
    }
}
