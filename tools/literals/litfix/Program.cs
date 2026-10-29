using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Mono.Cecil;
using Mono.Cecil.Cil;

// litfix <in.dll> <litimpact.tsv> <out.dll>: rewrites ldstr operands that the recompile took from the wrong string
// because Ghidra gave several literals one StringLiteral_ name. Only "unique" rows are applied: each wrong literal
// is absent from the native method and has exactly one native literal under the same Ghidra name.
class P
{
    static string Norm(string n) => n.Replace("_003C", "<").Replace("_003E", ">");

    // litcollapse.py rows fixed by hand: the recompile kept one of two colliding literals for both branches of a
    // condition, so the single ldstr becomes `cond ? litTrue : litFalse` again. Line format (tab separated):
    //   method  wrongLiteral(JSON)  arg>0:<argIndex> | local==<value>:<getterName>  litTrue(JSON)  litFalse(JSON)
    // local==V:G compares the local stored right after the first call to G (e.g. currentZone from get_CurrentZone).
    static int Cond(AssemblyDefinition asm, string path)
    {
        int n = 0;
        foreach (var line in File.ReadLines(path))
        {
            var f = line.Split('\t');
            if (f.Length < 5 || line.StartsWith("#")) continue;
            string wrong = JsonSerializer.Deserialize<string>(f[1]), yes = JsonSerializer.Deserialize<string>(f[3]), no = JsonSerializer.Deserialize<string>(f[4]);
            var m = asm.MainModule.GetTypes().SelectMany(t => t.Methods.Where(x => x.HasBody && Norm(t.FullName.Replace('/', '.') + "$$" + x.Name) == f[0])).Single();
            var il = m.Body.GetILProcessor();
            var target = m.Body.Instructions.Single(i => i.OpCode == OpCodes.Ldstr && (string)i.Operand == wrong);
            var test = new List<Instruction>();
            if (f[2].StartsWith("arg>0:"))
            {
                test.Add(il.Create(OpCodes.Ldarg, m.Parameters[int.Parse(f[2].Substring(6)) - (m.HasThis ? 1 : 0)]));
                test.Add(il.Create(OpCodes.Ldc_I4_0));
                test.Add(il.Create(OpCodes.Cgt));
            }
            else if (f[2].StartsWith("local=="))
            {
                var p = f[2].Substring(7).Split(':');
                var call = m.Body.Instructions.First(i => (i.OpCode == OpCodes.Call || i.OpCode == OpCodes.Callvirt) && ((MethodReference)i.Operand).Name == p[1]);
                var st = call.Next;
                var local = st.OpCode == OpCodes.Stloc_0 ? m.Body.Variables[0] : st.OpCode == OpCodes.Stloc_1 ? m.Body.Variables[1]
                    : st.OpCode == OpCodes.Stloc_2 ? m.Body.Variables[2] : st.OpCode == OpCodes.Stloc_3 ? m.Body.Variables[3] : (VariableDefinition)st.Operand;
                test.Add(il.Create(OpCodes.Ldloc, local));
                test.Add(il.Create(OpCodes.Ldc_I4, int.Parse(p[0])));
                test.Add(il.Create(OpCodes.Ceq));
            }
            else throw new InvalidDataException("unknown condition " + f[2]);
            // target keeps its identity (branches into it stay valid) and becomes the first test instruction.
            var ldYes = il.Create(OpCodes.Ldstr, yes);
            var end = il.Create(OpCodes.Nop);
            var first = test[0];
            target.OpCode = first.OpCode; target.Operand = first.Operand;
            var at = target;
            foreach (var i in test.Skip(1).Concat(new[] { il.Create(OpCodes.Brtrue, ldYes), il.Create(OpCodes.Ldstr, no), il.Create(OpCodes.Br, end), ldYes, end }))
            { il.InsertAfter(at, i); at = i; }
            Console.WriteLine($"cond {f[0]}: {f[1]} -> {f[2]} ? {f[3]} : {f[4]}");
            n++;
        }
        return n;
    }

    static void Main(string[] a)
    {
        var fixes = new Dictionary<string, Dictionary<string, string>>();
        foreach (var line in File.ReadLines(a[1]))
        {
            var f = line.Split('\t');
            if (f.Length < 3 || f[0] != "unique") continue;
            var map = new Dictionary<string, string>();
            foreach (var pair in JsonDocument.Parse(f[2]).RootElement.EnumerateArray())
                map[pair[0].GetString()] = pair[1][0].GetString();
            fixes[f[1]] = map;
        }
        var rp = new ReaderParameters { AssemblyResolver = new DefaultAssemblyResolver() };
        ((DefaultAssemblyResolver)rp.AssemblyResolver).AddSearchDirectory(Path.GetDirectoryName(Path.GetFullPath(a[0])));
        var asm = AssemblyDefinition.ReadAssembly(a[0], rp);
        int methods = 0, ops = 0;
        var hit = new HashSet<string>();
        foreach (var t in asm.MainModule.GetTypes())
            foreach (var m in t.Methods.Where(m => m.HasBody))
            {
                var key = Norm(t.FullName.Replace('/', '.') + "$$" + m.Name);
                if (!fixes.TryGetValue(key, out var map)) continue;
                int n = 0;
                foreach (var i in m.Body.Instructions)
                    if (i.OpCode == OpCodes.Ldstr && map.TryGetValue((string)i.Operand, out var to)) { i.Operand = to; n++; }
                if (n > 0) { methods++; ops += n; hit.Add(key); }
            }
        if (a.Length > 3) ops += Cond(asm, a[3]);
        asm.Write(a[2]);
        Console.WriteLine($"rows {fixes.Count}, methods patched {methods}, ldstr rewritten {ops}");
        foreach (var k in fixes.Keys.Where(k => !hit.Contains(k))) Console.WriteLine("not found: " + k);
    }
}
