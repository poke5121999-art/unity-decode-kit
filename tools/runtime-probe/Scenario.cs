using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using BepInEx.Logging;
using Il2CppInterop.Runtime;
using Il2CppInterop.Runtime.InteropTypes;
using UnityEngine;

namespace MethodProbe
{
    // Plays a run without input so two builds can be profiled under the same script.
    //   newgame  = the menu's own New Game path (OnSaveSelected, then OnSaveCreated), then idle.
    //   autoplay = newgame, then the day loop of recompiled-project/Assets/UdkProbe/UdkAutoPlay.cs (stock, open,
    //              spawn customers, serve, close, sleep), listed in D:/walking-trade-ref/SCENARIO-driver.md. The
    //              calls it forces are the same on both builds, so a call-profile diff must drop them.
    // Runs as a hand-stepped coroutine on the main thread: each yield is the number of seconds to wait.
    static class Scenario
    {
        const BindingFlags ALL = BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic;
        static string mode, menuType, logPath;
        static int slot, days;
        static double delay;
        static DateTime start, next;
        static IEnumerator<double> run;
        static ManualLogSource log;

        public static void Setup(string m, string menu, int s, double d, int nDays, string outPath, ManualLogSource l)
        {
            mode = m; menuType = menu; slot = s; delay = d; days = nDays; log = l; logPath = outPath;
            start = next = DateTime.UtcNow;
            if (mode.Length > 0) { run = Run(); log.LogInfo($"scenario {mode} armed: slot {slot}, {days} days, after {delay} s"); }
        }

        public static void Tick()
        {
            if (run == null || DateTime.UtcNow < next) return;
            try
            {
                if (run.MoveNext()) next = DateTime.UtcNow.AddSeconds(run.Current);
                else { L("scenario finished"); run = null; }
            }
            catch (Exception e) { L("scenario failed: " + (e.InnerException ?? e)); run = null; }
        }

        static void L(string s)
        {
            log.LogInfo("scenario: " + s);
            try { File.AppendAllText(logPath, $"{(DateTime.UtcNow - start).TotalSeconds:F0}\t{s}\n"); } catch { }
        }

        // --- reflection over interop wrappers (the same helper surface as UdkAutoPlay) ---
        static Type Ty(string n)
        {
            foreach (var a in AppDomain.CurrentDomain.GetAssemblies()) { try { var t = a.GetType(n, false); if (t != null) return t; } catch { } }
            return null;
        }

        static object Wrap(Type t, Il2CppObjectBase o) => o == null ? null : Activator.CreateInstance(t, o.Pointer);

        static List<object> FindAll(string typeName, bool inactive = false)
        {
            var t = Ty(typeName);
            if (t == null) return new List<object>();
            var arr = UnityEngine.Object.FindObjectsByType(Il2CppType.From(t), inactive ? FindObjectsInactive.Include : FindObjectsInactive.Exclude, FindObjectsSortMode.None);
            return arr.Select(o => Wrap(t, o)).ToList();
        }

        static object Singleton(string typeName)
        {
            for (var bt = Ty(typeName); bt != null; bt = bt.BaseType)
            {
                var p = bt.GetProperty("Instance", ALL | BindingFlags.FlattenHierarchy);
                if (p != null) return p.GetValue(null);
            }
            return null;
        }

        static object Get(object o, string name)
        {
            for (var t = o?.GetType(); t != null; t = t.BaseType)
            {
                var p = t.GetProperty(name, ALL | BindingFlags.DeclaredOnly); if (p != null && p.GetIndexParameters().Length == 0) return p.GetValue(o);
                var f = t.GetField(name, ALL | BindingFlags.DeclaredOnly); if (f != null) return f.GetValue(o);
            }
            return null;
        }

        static void Set(object o, string name, object v)
        {
            for (var t = o.GetType(); t != null; t = t.BaseType)
            {
                var p = t.GetProperty(name, ALL | BindingFlags.DeclaredOnly); if (p != null && p.CanWrite) { p.SetValue(o, v); return; }
                var f = t.GetField(name, ALL | BindingFlags.DeclaredOnly); if (f != null) { f.SetValue(o, v); return; }
            }
        }

        static object Call(object o, string name, params object[] a)
        {
            for (var t = o.GetType(); t != null; t = t.BaseType)
            {
                var m = t.GetMethods(ALL | BindingFlags.DeclaredOnly).FirstOrDefault(x => x.Name == name && x.GetParameters().Length == a.Length);
                if (m == null) continue;
                // An interop parameter typed as an interface (IReadOnlyList<T>) does not accept the concrete wrapper;
                // rewrap the same IL2CPP object as the parameter type.
                // A null for a boxed value-type wrapper (Il2CppSystem.Nullable<Guid> in ItemObject.Initialize) is unboxed
                // by interop and throws NullReferenceException before the game runs; pass the default value instead.
                var ps = m.GetParameters();
                var args = a.Select((x, i) => x is Il2CppObjectBase w && !ps[i].ParameterType.IsInstanceOfType(x)
                    ? Activator.CreateInstance(ps[i].ParameterType, w.Pointer)
                    : x == null && typeof(Il2CppSystem.ValueType).IsAssignableFrom(ps[i].ParameterType)
                        ? Activator.CreateInstance(ps[i].ParameterType) : x).ToArray();
                return m.Invoke(o, args);
            }
            throw new MissingMethodException(o.GetType().Name + "." + name);
        }

        static T Safe<T>(Func<T> f, string tag)
        {
            try { return f(); }
            catch (Exception e) { var x = e.InnerException ?? e; L(tag + " THREW " + x.GetType().Name + ": " + x.Message); return default; }
        }

        static IEnumerable<object> Items(object list)
        {
            if (list == null) yield break;
            if (list.GetType().GetMethod("get_Item", ALL) != null)
            {
                var n = Convert.ToInt32(Get(list, "Count") ?? Get(list, "Length"));
                for (int i = 0; i < n; i++) yield return Call(list, "get_Item", i);
                yield break;
            }
            // An interop IEnumerable<T> wrapper exposes only GetEnumerator; MoveNext lives on the non-generic base.
            var en = Call(list, "GetEnumerator");
            var mv = ((Il2CppObjectBase)en).Cast<Il2CppSystem.Collections.IEnumerator>();
            while (mv.MoveNext()) yield return Call(en, "get_Current");
        }

        static Component Comp(object o) => o == null ? null : ((Il2CppObjectBase)o).Cast<Component>();

        static object Nearest(string typeName, Component from) =>
            FindAll(typeName).OrderBy(c => Vector3.Distance(Comp(c).transform.position, from.transform.position)).FirstOrDefault();

        static object GetComponent(GameObject go, string typeName)
        {
            var t = Ty(typeName);
            return t == null ? null : Wrap(t, go.GetComponent(Il2CppType.From(t)));
        }

        static object controller;

        static object Inputs(string name, int type)
        {
            var it = Ty("Runtime.Player.PlayerActionItemInputEntry");
            var et = Ty("Runtime.Player.PlayerActionItemInteractInputType");
            var e = Activator.CreateInstance(it);
            Set(e, "Name", name);
            Set(e, "InputType", Enum.ToObject(et, type));
            var list = Activator.CreateInstance(typeof(Il2CppSystem.Collections.Generic.List<>).MakeGenericType(it));
            Call(list, "Add", e);
            return list;
        }

        static void Interact(object target) =>
            Safe(() => Call(target, "Interact", controller, Inputs("Interact", 0)), "Interact " + target.GetType().Name);

        static int Day => Convert.ToInt32(Get(Singleton("Runtime.Day.TimeManager"), "CurrentDay"));

        static IEnumerator<double> Run()
        {
            yield return delay;
            // New Game the way the button does it, so the save is built by the game's own NewSaveView.
            object menu = null;
            for (int i = 0; i < 60 && menu == null; i++) { menu = FindAll(menuType).FirstOrDefault(); if (menu == null) yield return 1; }
            if (menu == null) { L("menu not found: " + menuType); yield break; }
            Call(menu, "OnSaveSelected", slot);
            yield return 3;
            Call(menu, "OnSaveCreated");
            L("new game requested, slot " + slot);
            if (mode == "features")
            {
                var f = Features();
                while (f.MoveNext()) yield return f.Current;
                yield break;
            }
            if (mode != "autoplay") yield break;

            object player = null;
            for (int i = 0; i < 120 && (player == null || controller == null); i++)
            {
                player = FindAll("Runtime.Player.Movement.DefaultPlayerMovementProvider", true).FirstOrDefault();
                controller = FindAll("Runtime.Player.PlayerActionItemController", true).FirstOrDefault();
                if (player == null || controller == null) yield return 1;
            }
            if (player == null || controller == null) { L("gave up finding player"); yield break; }
            L("player+controller found; days=" + days);
            yield return 10;

            var psc0 = FindAll("Runtime.Player.States.PlayerStateController", true).FirstOrDefault();
            if (psc0 != null && !((Il2CppObjectBase)psc0).Cast<Behaviour>().enabled)
            {
                var gc0 = FindAll("Runtime.Game.GameController", true).FirstOrDefault();
                if (gc0 != null) { Safe(() => Call(gc0, "OnCutscenesCompleted"), "OnCutscenesCompleted"); L("intro cutscene force-completed"); }
            }

            var pc = Comp(player);
            int startDay = Day, lastDay = startDay, served = 0;
            while (Day - startDay < days)
            {
                int day = Day;
                L("=== DAY " + day + " ===");
                Stock();
                yield return 1;

                var tm = Singleton("Runtime.Day.TimeManager");
                var sm = Singleton("Runtime.Game.StoreManager");
                Set(sm, "_bypassQuestRequirement", true);
                Set(tm, "DaySpeedMultiplier", 2f);
                Safe(() => Call(sm, "TryToggleStoreOpen"), "TryToggleStoreOpen");
                yield return 2;

                var cem = Singleton("Runtime.Events.CustomerEventsManager");
                for (int si = 0; si < 6; si++) Safe(() => Call(cem, "SpawnCustomerAtRandomPoint"), "SpawnCustomer");
                yield return 3;

                var serveT0 = DateTime.UtcNow;
                while ((DateTime.UtcNow - serveT0).TotalSeconds < 40)
                {
                    var acceptNow = Safe(() => ServeStep(pc), "ServeStep");
                    if (acceptNow != null)
                    {
                        Safe(() => Call(acceptNow, "OnViewAccepted"), "OnViewAccepted"); served++;
                        yield return 0.5;
                        Safe(() => Call(acceptNow, "StopServing"), "StopServing");
                    }
                    yield return 1;
                }

                Safe(() => Call(tm, "SetTime", 19, 5, true), "SetTime");
                Safe(() => Call(sm, "CloseStore"), "CloseStore");
                yield return 1;
                var bed = Nearest("Runtime.Item.BedObject", pc);
                if (bed != null) Interact(bed);
                yield return 8;
                var slp = FindAll("Runtime.Player.States.SleepingPlayerState", true).FirstOrDefault();
                if (slp != null) Safe(() => Call(slp, "SleepViewCompleted"), "SleepViewCompleted");
                yield return 2;
                if (Day == day) { Safe(() => Call(tm, "Sleep", 7, 0), "Sleep"); yield return 3; }
                L($"day {day} done: served {served}");
                if (Day == lastDay) { L("day did not advance (stuck at " + Day + "), stopping"); yield break; }
                lastDay = Day;
            }
        }

        // Drives the systems the day loop never reaches, with the same calls and waits as PluginMono's features mode on
        // our build: skill level-ups (XP bar, level-up popup), hired staff, and zombies next to the player (melee
        // hits, effect pools). Random is seeded so both builds pick the same staff templates.
        static IEnumerator<double> Features()
        {
            object player = null;
            for (int i = 0; i < 120 && player == null; i++)
            {
                player = FindAll("Runtime.Player.Movement.DefaultPlayerMovementProvider", true).FirstOrDefault();
                if (player == null) yield return 1;
            }
            if (player == null) { L("gave up finding player"); yield break; }
            yield return 10;
            var psc0 = FindAll("Runtime.Player.States.PlayerStateController", true).FirstOrDefault();
            if (psc0 != null && !((Il2CppObjectBase)psc0).Cast<Behaviour>().enabled)
            {
                var gc0 = FindAll("Runtime.Game.GameController", true).FirstOrDefault();
                if (gc0 != null) { Safe(() => Call(gc0, "OnCutscenesCompleted"), "OnCutscenesCompleted"); L("intro cutscene force-completed"); }
            }
            yield return 3;
            UnityEngine.Random.InitState(20261029);

            var skillT = Ty("Runtime.Progression.Skills.Skill");
            var skills = Resources.FindObjectsOfTypeAll(Il2CppType.From(skillT)).Select(o => Wrap(skillT, o))
                .OrderBy(s => Comp2(s).name, StringComparer.Ordinal).Take(2).ToList();
            foreach (var s in skills)
            {
                int need = Convert.ToInt32(Safe(() => Call(s, "GetXpToNextLevel"), "GetXpToNextLevel"));
                Safe(() => Call(s, "AddExperience", need + 1), "AddExperience");
                L($"features: skill {Comp2(s).name} +{need + 1} xp");
                yield return 8;
            }

            var staff = Singleton("Runtime.Staff.StaffManager");
            for (int i = 0; i < 2; i++) { Safe(() => Call(staff, "SpawnStaffMemberAtPlayer"), "SpawnStaffMemberAtPlayer"); yield return 2; }
            L("features: staff " + Convert.ToInt32(Get(Get(staff, "Staff"), "Count") ?? -1));
            yield return 15;

            var zs = Singleton("Runtime.Events.ZombieSpawner");
            var pt = Comp(player).transform;
            for (int i = 0; i < 3; i++)
            {
                var at = pt.position + Quaternion.Euler(0, 120 * i, 0) * Vector3.forward * 6f;
                Safe(() => Call(zs, "SpawnAtPoint", at, Quaternion.identity), "SpawnAtPoint");
                yield return 1;
            }
            L("features: zombies spawned");
            yield return 40;
            L("features done");
        }

        static UnityEngine.Object Comp2(object o) => ((Il2CppObjectBase)o).Cast<UnityEngine.Object>();

        // One pass of the serve loop: pay what lies on the counter, start serving a queued customer, and return the
        // ServingPlayerState whose offer is open (the caller accepts it, waits, then stops serving).
        static DateTime lastServeLog;

        static object ServeStep(Component pc)
        {
            Pay();
            var co = Nearest("Runtime.Item.CheckoutObject", pc);
            if (co == null) return null;
            // QueuedCustomers enumerates a LinkedList through a boxed struct enumerator, which throws "Collection was
            // modified" through interop; its backing _queue has the count.
            int q = Convert.ToInt32(Get(Get(co, "_queue"), "Count") ?? 0);
            var cur = Get(Get(controller, "StateController"), "CurrentState");
            // An interop wrapper's ToString may not name the IL2CPP class, so ask the runtime for it.
            var curName = cur is Il2CppObjectBase cw ? cw.Cast<Il2CppSystem.Object>().GetIl2CppType().FullName : "" + cur;
            bool serving = curName.Contains("ServingPlayerState");
            if (q > 0 && !serving) Interact(co);
            var sp = FindAll("Runtime.Player.States.ServingPlayerState", true).FirstOrDefault();
            var offer = sp == null ? null : Get(sp, "_currentOffer");
            if ((DateTime.UtcNow - lastServeLog).TotalSeconds >= 5)
            {
                lastServeLog = DateTime.UtcNow;
                L($"serve q={q} state={curName} sp={(sp != null)} offer={(offer != null)}");
                NavLog();
            }
            return serving && offer != null ? sp : null;
        }

        // Where every mob navigator is and what it is doing, so a customer that never reaches its shelf tile shows why
        // (no path, path stuck at a corner, unreachable, kinematic body, zero velocity).
        static void NavLog()
        {
            foreach (var n in FindAll("Runtime.Mob.Navigation.RigidbodyNavigator"))
                Safe(() =>
                {
                    var c = Comp(n);
                    var rb = c.GetComponent<Rigidbody>();
                    var path = Get(n, "_currentPath");
                    int corners = path == null ? -1 : Convert.ToInt32(Get(path, "Count"));
                    L($"  nav {c.gameObject.name} pos={c.transform.position:F1} dest={Get(n, "DestinationPosition"):F1} " +
                      $"hasDest={Get(n, "_hasDestination")} calc={Get(n, "IsCalculatingPath")} unreach={Get(n, "IsDestinationUnreachable")} " +
                      $"path={Get(n, "_currentPathIndex")}/{corners} v={Get(n, "_currentVelocity"):F2} stuck={Get(n, "StuckTime"):F1} " +
                      $"kin={rb?.isKinematic} rbv={rb?.linearVelocity.magnitude:F2}");
                    return true;
                }, "NavLog");
        }

        static void Stock()
        {
            var repo = Singleton("Runtime.Item.ItemRepository");
            var shelves = FindAll("Runtime.Item.Shelving.ShelfObject");
            var svT = Ty("Runtime.Item.Shelving.ShelvableObject");
            int placed = 0, tried = 0, items = 0, prefabs = 0, shelvable = 0;
            var seen = new HashSet<string>();
            foreach (var idata in Items(Get(repo, "_items")))
            {
                if (placed >= 12 || tried >= 120) break;
                items++;
                var prefab = Comp(Get(idata, "_prefab"));
                if (prefab == null) continue;
                prefabs++;
                if (prefab.GetComponent(Il2CppType.From(svT)) == null) continue;
                shelvable++;
                if (!seen.Add("" + Get(idata, "Type"))) continue;
                tried++;
                foreach (var sh in shelves)
                {
                    var go = UnityEngine.Object.Instantiate(prefab.gameObject, Comp(sh).transform.position + Vector3.up * 1.0f, Quaternion.identity);
                    var so = GetComponent(go, "Runtime.Item.Shelving.ShelvableObject");
                    var io = GetComponent(go, "Runtime.Item.ItemObject");
                    if (io != null) Safe(() => Call(io, "Initialize", idata, 1, null), "ItemObject.Initialize");
                    var ok = Safe(() => (bool)Call(sh, "TryPlaceShelvable", so, Comp(so).transform, true), "TryPlaceShelvable");
                    if (ok) { placed++; if (io != null) Safe(() => Call(io, "ApplyChangesToShopGrid"), "ApplyChangesToShopGrid"); break; }
                    UnityEngine.Object.Destroy(go);
                }
            }
            L($"stock placed={placed} (items {items}, with prefab {prefabs}, shelvable {shelvable}, shelves {shelves.Count})");
        }

        static void Pay()
        {
            try
            {
                var depots = FindAll("Runtime.Player.StashCheckoutCurrencyDepot");
                foreach (var c in FindAll("Runtime.Player.CheckoutCurrencyObject"))
                {
                    int value = Convert.ToInt32(Get(c, "Value"));
                    if (value <= 0) continue;
                    var st = "" + Get(c, "State");
                    if (st == "Unchecked") { Safe(() => Call(c, "SetValidity", value == Convert.ToInt32(Get(c, "TrueValue")), true), "SetValidity"); st = "" + Get(c, "State"); }
                    if (st == "Valid")
                        foreach (var d in depots)
                            if (Convert.ToInt32(Get(d, "AcceptedValue")) == value) { Safe(() => Call(d, "TryDeposit", c), "TryDeposit"); break; }
                }
            }
            catch { }
        }
    }
}
