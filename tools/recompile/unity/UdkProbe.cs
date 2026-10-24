using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using UnityEngine;
using UnityEngine.SceneManagement;

public static class UdkProbe
{
    static string dir;
    static readonly Dictionary<LogType, int> counts = new Dictionary<LogType, int>();
    static readonly Dictionary<string, int> exc = new Dictionary<string, int>();
    static readonly List<string> scenes = new List<string>();
    static readonly int[] shotTimes = { 5, 15, 30, 60, 90 };
    static int nextShot;
    static float nextWrite = 10f;
    static bool lastSceneDirty;
    // UDK_PROBE_CALLS="20:Runtime.Splash.SplashScreenController.Skip;40:..." invokes a method on every live object of
    // the type at that time, to drive a game whose input layer cannot be simulated.
    static readonly List<(float t, string type, string method)> calls = new List<(float, string, string)>();

    [RuntimeInitializeOnLoadMethod(RuntimeInitializeLoadType.BeforeSceneLoad)]
    static void Init()
    {
        dir = Environment.GetEnvironmentVariable("UDK_PROBE_DIR");
        if (string.IsNullOrEmpty(dir)) dir = Application.persistentDataPath;
        try { Directory.CreateDirectory(dir); } catch { }
        Application.logMessageReceived += OnLog;
        SceneManager.sceneLoaded += (s, m) => Rec("loaded " + s.name + " mode=" + m);
        SceneManager.sceneUnloaded += s => Rec("unloaded " + s.name);
        SceneManager.activeSceneChanged += (a, b) => Rec("active " + a.name + " -> " + b.name);
        foreach (var c in (Environment.GetEnvironmentVariable("UDK_PROBE_CALLS") ?? "").Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = c.Split(new[] { ':' }, 2);
            int dot = parts[1].LastIndexOf('.');
            calls.Add((float.Parse(parts[0]), parts[1].Substring(0, dot), parts[1].Substring(dot + 1)));
        }
        var go = new GameObject("UdkProbe");
        UnityEngine.Object.DontDestroyOnLoad(go);
        go.hideFlags = HideFlags.HideAndDontSave;
        go.AddComponent<Ticker>();
        Rec("probe init");
    }

    static void Rec(string what)
    {
        scenes.Add("frame=" + Time.frameCount + " t=" + Time.realtimeSinceStartup.ToString("F2") + " " + what);
        Debug.Log("[UdkProbe] " + what + " frame=" + Time.frameCount + " t=" + Time.realtimeSinceStartup.ToString("F2"));
    }

    static void OnLog(string msg, string stack, LogType type)
    {
        counts.TryGetValue(type, out int c); counts[type] = c + 1;
        if (type == LogType.Exception || type == LogType.Error)
        {
            string k = (msg ?? "").Split('\n')[0];
            if (k.Length > 300) k = k.Substring(0, 300);
            k = type + ": " + k;
            exc.TryGetValue(k, out int e); exc[k] = e + 1;
        }
    }

    static string Esc(string s) => (s ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", " ").Replace("\r", "");

    static void Write()
    {
        var sb = new StringBuilder();
        sb.Append("{\"time\":").Append(Time.realtimeSinceStartup.ToString("F1")).Append(",\"frame\":").Append(Time.frameCount);
        sb.Append(",\"activeScene\":\"").Append(Esc(SceneManager.GetActiveScene().name)).Append("\"");
        sb.Append(",\"counts\":{");
        sb.Append(string.Join(",", counts.Select(kv => "\"" + kv.Key + "\":" + kv.Value)));
        sb.Append("},\"scenes\":[").Append(string.Join(",", scenes.Select(s => "\"" + Esc(s) + "\""))).Append("]");
        sb.Append(",\"topExceptions\":[");
        sb.Append(string.Join(",", exc.OrderByDescending(kv => kv.Value).Take(20).Select(kv => "{\"count\":" + kv.Value + ",\"msg\":\"" + Esc(kv.Key) + "\"}")));
        sb.Append("]}");
        try { File.WriteAllText(Path.Combine(dir, "probe-summary.json"), sb.ToString()); } catch { }
    }

    static void Call(string typeName, string method)
    {
        var type = AppDomain.CurrentDomain.GetAssemblies().Select(a => a.GetType(typeName)).FirstOrDefault(x => x != null);
        if (type == null) { Rec("call " + typeName + " type not found"); return; }
        var objs = UnityEngine.Object.FindObjectsByType(type, FindObjectsInactive.Include, FindObjectsSortMode.None);
        var mi = type.GetMethod(method, System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic);
        foreach (var o in objs)
            try { mi.Invoke(o, null); } catch (Exception e) { Rec("call " + method + " threw " + (e.InnerException ?? e).GetType().Name); }
        Rec("call " + typeName + "." + method + " on " + objs.Length + " objects");
    }

    // What is on screen and why: active objects with their components, animator progress, cameras and canvases.
    static void DumpScene(string path)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < SceneManager.sceneCount; i++)
        {
            var sc = SceneManager.GetSceneAt(i);
            sb.Append("scene ").Append(sc.name).Append('\n');
            foreach (var root in sc.GetRootGameObjects()) Dump(root.transform, 1, sb);
        }
        try { File.WriteAllText(path, sb.ToString()); } catch { }
    }

    static void Dump(Transform t, int depth, StringBuilder sb)
    {
        if (depth > 8) return;
        var go = t.gameObject;
        sb.Append(' ', depth * 2).Append(go.activeInHierarchy ? "" : "(off) ").Append(go.name).Append(" [");
        foreach (var c in go.GetComponents<Component>())
        {
            if (c == null) { sb.Append("MISSING-SCRIPT "); continue; }
            sb.Append(c.GetType().Name);
            if (c is Behaviour b && !b.enabled) sb.Append("(disabled)");
            if (c is Animator an && an.isActiveAndEnabled)
            {
                var st = an.GetCurrentAnimatorStateInfo(0);
                sb.Append("{ctrl=").Append(an.runtimeAnimatorController ? an.runtimeAnimatorController.name : "null")
                  .Append(" clips=").Append(an.runtimeAnimatorController ? an.runtimeAnimatorController.animationClips.Length : 0)
                  .Append(" t=").Append(st.normalizedTime.ToString("F2")).Append(" len=").Append(st.length.ToString("F2")).Append("}");
            }
            if (c is Camera cam) sb.Append("{depth=").Append(cam.depth).Append(" mask=").Append(cam.cullingMask).Append(" rt=").Append(cam.targetTexture ? cam.targetTexture.name : "-").Append("}");
            if (c is Canvas cv) sb.Append("{mode=").Append(cv.renderMode).Append(" order=").Append(cv.sortingOrder).Append("}");
            if (c is CanvasGroup cg) sb.Append("{alpha=").Append(cg.alpha.ToString("F2")).Append("}");
            if (c is Renderer r && r.sharedMaterial) sb.Append("{mat=").Append(r.sharedMaterial.name).Append(" shader=").Append(r.sharedMaterial.shader.name).Append("}");
            sb.Append(' ');
        }
        sb.Append("]\n");
        if (go.activeInHierarchy) foreach (Transform ch in t) Dump(ch, depth + 1, sb);
    }

    class Ticker : MonoBehaviour
    {
        void Update()
        {
            float t = Time.realtimeSinceStartup;
            if (nextShot < shotTimes.Length && t >= shotTimes[nextShot])
            {
                try { ScreenCapture.CaptureScreenshot(Path.Combine(dir, "shot-" + shotTimes[nextShot] + "s.png")); } catch { }
                DumpScene(Path.Combine(dir, "scene-" + shotTimes[nextShot] + "s.txt"));
                nextShot++;
            }
            for (int i = calls.Count - 1; i >= 0; i--)
                if (t >= calls[i].t) { Call(calls[i].type, calls[i].method); calls.RemoveAt(i); }
            if (t >= nextWrite) { nextWrite += 10f; Write(); }
        }
        void OnApplicationQuit() { Write(); }
    }
}
