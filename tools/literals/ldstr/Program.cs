using System;
using System.IO;
using System.Linq;
using System.Text;
using Mono.Cecil;
using Mono.Cecil.Cil;

// ldstr <assembly> <out.tsv>: one line per method with a body, "Namespace.Type.Nested$$Method\tparamCount\tliterals",
// literals JSON-escaped and joined by \u0001 in IL order, so litdiff.py can line them up with the native method.
class P
{
    static string Esc(string s)
    {
        var b = new StringBuilder("\"");
        foreach (var c in s)
        {
            if (c == '"' || c == '\\') b.Append('\\').Append(c);
            else if (c < 0x20 || c == 0x7f) b.Append("\\u").Append(((int)c).ToString("x4"));
            else b.Append(c);
        }
        return b.Append('"').ToString();
    }

    static void Main(string[] a)
    {
        var asm = AssemblyDefinition.ReadAssembly(a[0]);
        using var w = new StreamWriter(a[1], false, new UTF8Encoding(false));
        foreach (var t in asm.MainModule.GetTypes())
            foreach (var m in t.Methods.Where(m => m.HasBody))
            {
                var lits = m.Body.Instructions.Where(i => i.OpCode == OpCodes.Ldstr).Select(i => Esc((string)i.Operand));
                w.WriteLine(t.FullName.Replace('/', '.') + "$$" + m.Name + "\t" + m.Parameters.Count + "\t" + string.Join("\u0001", lits));
            }
    }
}
