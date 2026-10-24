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

    class Ticker : MonoBehaviour
    {
        void Update()
        {
            float t = Time.realtimeSinceStartup;
            if (nextShot < shotTimes.Length && t >= shotTimes[nextShot])
            {
                try { ScreenCapture.CaptureScreenshot(Path.Combine(dir, "shot-" + shotTimes[nextShot] + "s.png")); } catch { }
                nextShot++;
            }
            if (t >= nextWrite) { nextWrite += 10f; Write(); }
        }
        void OnApplicationQuit() { Write(); }
    }
}
