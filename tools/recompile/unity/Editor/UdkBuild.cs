using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using UnityEditor;
using UnityEditor.Build;
using UnityEditor.Build.Reporting;
using UnityEngine;

public static class UdkBuild
{
    public static void BuildWindows()
    {
        string outPath = Environment.GetEnvironmentVariable("UDK_BUILD_OUT");
        if (string.IsNullOrEmpty(outPath)) { Debug.LogError("[UdkBuild] UDK_BUILD_OUT is not set"); EditorApplication.Exit(2); return; }
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outPath)));

        var scenes = EditorBuildSettings.scenes.Where(s => s.enabled).Select(s => s.path).ToList();
        if (scenes.Count == 0)
        {
            var all = AssetDatabase.FindAssets("t:Scene", new[] { "Assets/Scenes" })
                .Select(AssetDatabase.GUIDToAssetPath).Distinct().ToList();
            all = all.OrderBy(p => { var n = Path.GetFileNameWithoutExtension(p).ToLowerInvariant();
                return n.Contains("startup") ? 0 : n.Contains("splash") ? 1 : 2; }).ThenBy(p => p).ToList();
            EditorBuildSettings.scenes = all.Select(p => new EditorBuildSettingsScene(p, true)).ToArray();
            scenes = all;
        }
        Debug.Log("[UdkBuild] scenes: " + string.Join(", ", scenes));

        PlayerSettings.SetScriptingBackend(NamedBuildTarget.Standalone, ScriptingImplementation.Mono2x);
        var opts = new BuildPlayerOptions
        {
            scenes = scenes.ToArray(),
            locationPathName = outPath,
            target = BuildTarget.StandaloneWindows64,
            targetGroup = BuildTargetGroup.Standalone,
            options = BuildOptions.Development
        };
        var report = BuildPipeline.BuildPlayer(opts);
        var sum = report.summary;
        Debug.Log("[UdkBuild] result=" + sum.result + " errors=" + sum.totalErrors + " warnings=" + sum.totalWarnings +
                  " time=" + sum.totalTime + " size=" + sum.totalSize);
        foreach (var step in report.steps)
            foreach (var m in step.messages)
                if (m.type == LogType.Error || m.type == LogType.Exception) Debug.Log("[UdkBuild] error: " + m.content);
        EditorApplication.Exit(sum.result == BuildResult.Succeeded ? 0 : 1);
    }
}
