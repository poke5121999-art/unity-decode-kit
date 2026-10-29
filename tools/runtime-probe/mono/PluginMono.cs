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
            scenarioLog = Path.Combine(Path.GetDirectoryName(output), "scenario.log");
            if (Environment.GetEnvironmentVariable("UDK_FEATURES") == "1") StartCoroutine(Features());
            var sl = Environment.GetEnvironmentVariable("UDK_SAVELOAD");
            if (sl == "a" || sl == "b") StartCoroutine(SaveLoad(sl == "a"));
        }

        // Scenario.SaveLoad on the original side. Phase a (with UDK_NEWGAME): new game, two skill level-ups, two staff,
        // then the game's own save (SaveGameCoroutine) into SaveLoadSlot. Phase b (without UDK_NEWGAME): the menu loads
        // that slot and the same save runs again, leaving before/after snapshots in the slot's ring. Quits when done.
        const int SaveLoadSlot = 3;

        System.Collections.IEnumerator SaveLoad(bool fresh)
        {
            t0 = Time.realtimeSinceStartup;
            if (!fresh)
            {
                UnityEngine.Object menu = null;
                for (int i = 0; i < 90 && menu == null; i++)
                {
                    menu = First("Runtime.Menu.MenuController");
                    if (menu == null) yield return new WaitForSecondsRealtime(1);
                }
                if (menu == null) { L("menu not found"); yield break; }
                yield return new WaitForSecondsRealtime(5);
                Safe(() => Call(menu, "OnExistingSaveSelected", SaveLoadSlot), "OnExistingSaveSelected");
                L("existing save requested, slot " + SaveLoadSlot);
            }
            Component player = null;
            for (int i = 0; i < 180 && player == null; i++)
            {
                player = First("Runtime.Player.Movement.DefaultPlayerMovementProvider", true) as Component;
                if (player == null) yield return new WaitForSecondsRealtime(1);
            }
            if (player == null) { L("gave up finding player"); yield break; }
            yield return new WaitForSecondsRealtime(10);
            var gc = First("Runtime.Game.GameController", true) as MonoBehaviour;
            if (gc == null) { L("GameController not found"); yield break; }
            if (fresh)
            {
                var psc0 = First("Runtime.Player.States.PlayerStateController", true) as Behaviour;
                if (psc0 != null && !psc0.enabled) { Safe(() => Call(gc, "OnCutscenesCompleted"), "OnCutscenesCompleted"); L("intro cutscene force-completed"); }
                yield return new WaitForSecondsRealtime(3);
                UnityEngine.Random.InitState(20261029);
                var skills = Resources.FindObjectsOfTypeAll(Ty("Runtime.Progression.Skills.Skill"));
                Array.Sort(skills, (x, y) => string.CompareOrdinal(x.name, y.name));
                for (int i = 0; i < Math.Min(2, skills.Length); i++)
                {
                    var s = skills[i];
                    int need = Convert.ToInt32(Safe(() => Call(s, "GetXpToNextLevel"), "GetXpToNextLevel"));
                    Safe(() => Call(s, "AddExperience", need + 1), "AddExperience");
                    L($"saveload: skill {s.name} +{need + 1} xp");
                    yield return new WaitForSecondsRealtime(8);
                }
                var staff = Singleton("Runtime.Staff.StaffManager");
                for (int i = 0; i < 2; i++) { Safe(() => Call(staff, "SpawnStaffMemberAtPlayer"), "SpawnStaffMemberAtPlayer"); yield return new WaitForSecondsRealtime(2); }
                L("saveload: staff " + ((Get(staff, "Staff") as System.Collections.ICollection)?.Count ?? -1));
                yield return new WaitForSecondsRealtime(15);
                // Scenario.SaveLoad's extra saved systems: item prices, two zombie corpses, the raid.
                var items = Resources.FindObjectsOfTypeAll(Ty("Runtime.Item.ItemData"));
                Array.Sort(items, (x, y) => string.CompareOrdinal(x.name, y.name));
                int done = 0;
                foreach (var it in items)
                {
                    if (done == 3) break;
                    if (!Convert.ToBoolean(Get(it, "CanBeSold") ?? false)) continue;
                    int price = Convert.ToInt32(Get(it, "MarkedPrice") ?? 0) + 7;
                    Safe(() => Call(it, "SetMarkedPrice", price), "SetMarkedPrice");
                    Safe(() => Call(it, "SetAvailableForPurchase", true), "SetAvailableForPurchase");
                    L($"saveload: item {it.name} price {price}");
                    done++;
                }
                var zs = Singleton("Runtime.Events.ZombieSpawner");
                for (int i = 0; i < 2; i++)
                {
                    var at = player.transform.position + Quaternion.Euler(0, 180 * i, 0) * Vector3.forward * 8f;
                    var z = Safe(() => Call(zs, "SpawnAtPoint", at, Quaternion.identity), "SpawnAtPoint");
                    yield return new WaitForSecondsRealtime(2);
                    var dmg = z == null ? null : Get(Get(z, "Combatant"), "Damageable");
                    if (dmg != null) { Safe(() => Call(dmg, "Kill"), "Kill"); L("saveload: zombie killed"); }
                }
                yield return new WaitForSecondsRealtime(5);
                Safe(() => Call(Singleton("Runtime.Raid.RaidManager"), "RevealCurrentRaid"), "RevealCurrentRaid");
                L("saveload: raid revealed");
                yield return new WaitForSecondsRealtime(5);
                // UdkNewGame starts in slot 0; the original side's scenario creates the game in its configured slot.
                var f = gc.GetType().GetField("_currentSaveSlot", All);
                if (f != null) f.SetValue(gc, SaveLoadSlot);
            }
            else yield return new WaitForSecondsRealtime(10);
            L("saveload: current slot " + Get(gc, "_currentSaveSlot"));
            var en = Safe(() => Call(gc, "SaveGameCoroutine") as System.Collections.IEnumerator, "SaveGameCoroutine");
            if (en == null) yield break;
            gc.StartCoroutine(en);
            L("saveload: save requested");
            yield return new WaitForSecondsRealtime(10);
            L("saveload done");
            yield return new WaitForSecondsRealtime(3);
            Application.Quit();
        }

        // Scenario.Features on the original side, call for call and wait for wait; UdkNewGame (UDK_NEWGAME) has
        // started the game, UdkAutoPlay must be off. Quits when done.
        string scenarioLog;
        float t0;

        void L(string s)
        {
            Logger.LogInfo("scenario: " + s);
            try { File.AppendAllText(scenarioLog, $"{Time.realtimeSinceStartup - t0:F0}\t{s}\n"); } catch { }
        }

        static Type Ty(string n) => Type.GetType(n + ", Runtime");

        static object Call(object o, string name, params object[] a)
        {
            for (var t = o.GetType(); t != null; t = t.BaseType)
            {
                var m = Array.Find(t.GetMethods(All | BindingFlags.DeclaredOnly), x => x.Name == name && x.GetParameters().Length == a.Length);
                if (m != null) return m.Invoke(o, a);
            }
            throw new MissingMethodException(o.GetType().Name + "." + name);
        }

        T Safe<T>(Func<T> f, string tag)
        {
            try { return f(); }
            catch (Exception e) { var x = e.InnerException ?? e; L(tag + " THREW " + x.GetType().Name + ": " + x.Message); return default(T); }
        }

        static object Singleton(string typeName)
        {
            for (var bt = Ty(typeName); bt != null; bt = bt.BaseType)
            {
                var p = bt.GetProperty("Instance", BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.FlattenHierarchy);
                if (p != null) return p.GetValue(null, null);
            }
            return null;
        }

        static UnityEngine.Object First(string typeName, bool inactive = false)
        {
            var arr = UnityEngine.Object.FindObjectsByType(Ty(typeName), inactive ? FindObjectsInactive.Include : FindObjectsInactive.Exclude, FindObjectsSortMode.None);
            return arr.Length > 0 ? arr[0] : null;
        }

        System.Collections.IEnumerator Features()
        {
            t0 = Time.realtimeSinceStartup;
            Component player = null;
            for (int i = 0; i < 180 && player == null; i++)
            {
                player = First("Runtime.Player.Movement.DefaultPlayerMovementProvider", true) as Component;
                if (player == null) yield return new WaitForSecondsRealtime(1);
            }
            if (player == null) { L("gave up finding player"); yield break; }
            yield return new WaitForSecondsRealtime(10);
            var psc0 = First("Runtime.Player.States.PlayerStateController", true) as Behaviour;
            if (psc0 != null && !psc0.enabled)
            {
                var gc0 = First("Runtime.Game.GameController", true);
                if (gc0 != null) { Safe(() => Call(gc0, "OnCutscenesCompleted"), "OnCutscenesCompleted"); L("intro cutscene force-completed"); }
            }
            yield return new WaitForSecondsRealtime(3);
            UnityEngine.Random.InitState(20261029);

            var skills = Resources.FindObjectsOfTypeAll(Ty("Runtime.Progression.Skills.Skill"));
            Array.Sort(skills, (x, y) => string.CompareOrdinal(x.name, y.name));
            for (int i = 0; i < Math.Min(2, skills.Length); i++)
            {
                var s = skills[i];
                int need = Convert.ToInt32(Safe(() => Call(s, "GetXpToNextLevel"), "GetXpToNextLevel"));
                Safe(() => Call(s, "AddExperience", need + 1), "AddExperience");
                L($"features: skill {s.name} +{need + 1} xp");
                yield return new WaitForSecondsRealtime(8);
            }

            var staff = Singleton("Runtime.Staff.StaffManager");
            for (int i = 0; i < 2; i++) { Safe(() => Call(staff, "SpawnStaffMemberAtPlayer"), "SpawnStaffMemberAtPlayer"); yield return new WaitForSecondsRealtime(2); }
            L("features: staff " + ((Get(staff, "Staff") as System.Collections.ICollection)?.Count ?? -1));
            yield return new WaitForSecondsRealtime(15);

            var zs = Singleton("Runtime.Events.ZombieSpawner");
            for (int i = 0; i < 3; i++)
            {
                var at = player.transform.position + Quaternion.Euler(0, 120 * i, 0) * Vector3.forward * 6f;
                Safe(() => Call(zs, "SpawnAtPoint", at, Quaternion.identity), "SpawnAtPoint");
                yield return new WaitForSecondsRealtime(1);
            }
            L("features: zombies spawned");
            if (Environment.GetEnvironmentVariable("UDK_THREATDEBUG") == "1")
            {
                // The detectors' own _debug logging says what each threat check saw (range, hits, allies, races).
                int n = 0;
                foreach (var d in UnityEngine.Object.FindObjectsByType(Ty("Runtime.Combat.ProximityThreatDetector"), FindObjectsSortMode.None))
                {
                    var f = d.GetType().GetField("_debug", All);
                    if (f != null) { f.SetValue(d, true); n++; }
                }
                L("features: threat debug on " + n + " detectors");
            }
            yield return new WaitForSecondsRealtime(40);
            L("features done");
            yield return new WaitForSecondsRealtime(3);
            Application.Quit();
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
                if (Get(o, "_hasDestination") is bool has && has && rb != null && rb.linearVelocity.magnitude < 1f)
                {
                    sb.Append($"{Time.realtimeSinceStartup:F0}\t    blockers {c.gameObject.name}: ");
                    int k = 0;
                    foreach (var h in Physics.OverlapSphere(c.transform.position + Vector3.up * 0.9f, 1.0f, -1, QueryTriggerInteraction.Ignore))
                        if (h.attachedRigidbody != rb && k++ < 8) sb.Append(h.gameObject.name + "@" + h.transform.position.ToString("F1") + ", ");
                    sb.Append("\n");
                }
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
