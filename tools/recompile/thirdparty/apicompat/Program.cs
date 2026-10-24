// usage: apicompat <stub.dll> <real.dll> <refdir>... ; prints stub public API missing in real.
using System; using System.Collections.Generic; using System.IO; using System.Linq; using System.Reflection;
class P {
  static string T(Type t){ try { return t.FullName ?? t.Name; } catch { return "?"; } }
  static string Sig(MethodBase m){ string ps; try { ps = string.Join(",", m.GetParameters().Select(p=>T(p.ParameterType))); } catch { ps="?"; } return m.Name+"("+ps+")"; }
  static Dictionary<string,HashSet<string>> Api(Assembly a){
    var d=new Dictionary<string,HashSet<string>>();
    Type[] ts; try { ts=a.GetTypes(); } catch(ReflectionTypeLoadException e){ ts=e.Types.Where(x=>x!=null).ToArray(); }
    foreach(var t in ts){
      if(!(t.IsPublic||t.IsNestedPublic||t.IsNestedFamily||t.IsNestedFamORAssem)) continue;
      var s=new HashSet<string>(); var f=BindingFlags.Public|BindingFlags.NonPublic|BindingFlags.Instance|BindingFlags.Static|BindingFlags.DeclaredOnly;
      try{
      foreach(var m in t.GetMethods(f)) if(m.IsPublic||m.IsFamily||m.IsFamilyOrAssembly) s.Add("M "+Sig(m));
      foreach(var m in t.GetConstructors(f)) if(m.IsPublic||m.IsFamily||m.IsFamilyOrAssembly) s.Add("C "+Sig(m));
      foreach(var m in t.GetFields(f)) if(m.IsPublic||m.IsFamily||m.IsFamilyOrAssembly) s.Add("F "+m.Name);
      foreach(var m in t.GetProperties(f)) s.Add("P "+m.Name);
      foreach(var m in t.GetEvents(f)) s.Add("E "+m.Name);
      }catch(Exception e){ s.Add("!ERR "+e.GetType().Name); }
      d[T(t)]=s;
    }
    return d;
  }
  static void Main(string[] a){
    var paths=new List<string>(); foreach(var dir in a.Skip(2)) paths.AddRange(Directory.GetFiles(dir,"*.dll"));
    paths.Add(a[0]); paths.Add(a[1]);
    var seen=new HashSet<string>(); var uniq=paths.Where(p=>seen.Add(Path.GetFileName(p)+"|"+(p==a[0]||p==a[1]?p:""))).ToList();
    // real+stub share a name: load via separate contexts
    Assembly Load(string p){
      var others=paths.Where(x=>x!=a[0]&&x!=a[1]&&!string.Equals(Path.GetFileNameWithoutExtension(x),Path.GetFileNameWithoutExtension(p),StringComparison.OrdinalIgnoreCase)).GroupBy(Path.GetFileName).Select(g=>g.First());
      var r=new FallbackResolver(others.Append(p));
      var c=new MetadataLoadContext(r,"netstandard"); r.Ctx=c; return c.LoadFromAssemblyPath(p);
    }
    var sa=Api(Load(a[0])); var ra=Api(Load(a[1]));
    int mt=0,mm=0; var lines=new List<string>();
    foreach(var kv in sa.OrderBy(k=>k.Key)){
      if(!ra.TryGetValue(kv.Key,out var rs)){ mt++; mm+=kv.Value.Count; lines.Add("TYPE "+kv.Key+" ("+kv.Value.Count+" members)"); continue; }
      foreach(var m in kv.Value.Where(x=>!rs.Contains(x)).OrderBy(x=>x)){ mm++; lines.Add("MEMBER "+kv.Key+" :: "+m); }
    }
    int extra=ra.Keys.Count(k=>!sa.ContainsKey(k));
    Console.WriteLine($"stubTypes={sa.Count} realTypes={ra.Count} missingTypes={mt} missingMembers(total incl. in missing types)={mm} extraTypesInReal={extra}");
    foreach(var l in lines) Console.WriteLine(l);
  }
}

class FallbackResolver : MetadataAssemblyResolver {
  Dictionary<string,string> map=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase); public MetadataLoadContext Ctx; string ns;
  public FallbackResolver(IEnumerable<string> ps){ foreach(var p in ps){ var n=Path.GetFileNameWithoutExtension(p); map[n]=p; if(n=="netstandard") ns=p; } }
  public override Assembly Resolve(MetadataLoadContext c, AssemblyName n){
    if(map.TryGetValue(n.Name,out var p)&&n.Name!="mscorlib") return c.LoadFromAssemblyPath(p);
    if(ns!=null) return c.LoadFromAssemblyPath(ns);
    return null; }
}
