using System.Globalization;
using System.Reflection;
using System.Runtime.Loader;
using System.Text.Json;

// Run recovered static methods on the inputs the original game was probed with (methodprobe invoke mode),
// writing the same {key,args,ret} records so the two files diff line by line.
static class Invoke
{
    public static int Run(string dllPath, string inputs, string outPath, List<string> refDirs)
    {
        var ctx = new AssemblyLoadContext("recovered", isCollectible: false);
        ctx.Resolving += (c, name) =>
        {
            foreach (var d in refDirs)
            {
                var f = Path.Combine(d, name.Name + ".dll");
                if (File.Exists(f)) return c.LoadFromAssemblyPath(Path.GetFullPath(f));
            }
            return null;
        };
        var asm = ctx.LoadFromAssemblyPath(Path.GetFullPath(dllPath));
        using var w = new StreamWriter(outPath);
        int calls = 0, errors = 0, timeouts = 0;
        foreach (var line in File.ReadLines(inputs))
        {
            if (line.Trim().Length == 0) continue;
            var row = JsonDocument.Parse(line).RootElement;
            var key = row.GetProperty("key").GetString();
            var ps = row.GetProperty("params").EnumerateArray().Select(p => p.GetString()).ToArray();
            MethodInfo m = null;
            try { m = Resolve(asm, key, ps); }
            catch (Exception e) { w.WriteLine(JsonSerializer.Serialize(new { key, error = e.GetType().Name + ": " + e.Message })); errors++; continue; }
            foreach (var argSet in row.GetProperty("args").EnumerateArray())
            {
                var raw = argSet.EnumerateArray().ToArray();
                var args = raw.Select((a, i) => Convert(a, ps[i])).ToArray();
                string ret = "timeout";
                var th = new Thread(() =>
                {
                    try { ret = Format(m.Invoke(null, args)); }
                    catch (TargetInvocationException e) { ret = "throw " + e.InnerException?.GetType().Name; }
                }) { IsBackground = true };
                th.Start();
                if (!th.Join(2000)) timeouts++;
                w.WriteLine(JsonSerializer.Serialize(new { key, args = raw.Select(a => a.GetRawText()).ToArray(), ret }));
                w.Flush();
                calls++;
            }
        }
        Console.WriteLine($"invoke: {calls} calls, {errors} unresolved, {timeouts} timed out (2 s) -> {outPath}");
        w.Close();
        Environment.Exit(0);
        return 0;
    }

    static MethodInfo Resolve(Assembly asm, string key, string[] ps)
    {
        var i = key.IndexOf("::", StringComparison.Ordinal);
        var typeName = key[..i].Replace('/', '+');
        var name = key[(i + 2)..key.IndexOf('(')];
        var t = asm.GetType(typeName, throwOnError: true);
        var types = ps.Select(p => p switch { "int" => typeof(int), "float" => typeof(float), "bool" => typeof(bool), "double" => typeof(double), "long" => typeof(long), _ => throw new ArgumentException($"unsupported param type '{p}'") }).ToArray();
        return t.GetMethod(name, BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic, null, types, null)
               ?? throw new MissingMethodException($"{key} not found");
    }

    static object Convert(JsonElement a, string p) => p switch
    {
        "int" => a.GetInt32(), "float" => a.GetSingle(), "bool" => a.GetBoolean(), "double" => a.GetDouble(), "long" => a.GetInt64(),
        _ => throw new ArgumentException($"unsupported param type '{p}'"),
    };

    public static string Format(object v) => v switch
    {
        null => "null",
        float f => f.ToString("R", CultureInfo.InvariantCulture),
        double d => d.ToString("R", CultureInfo.InvariantCulture),
        bool b => b ? "True" : "False",
        IFormattable x => x.ToString(null, CultureInfo.InvariantCulture),
        _ => v.ToString(),
    };
}
