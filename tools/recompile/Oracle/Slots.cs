using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Text.Json;

// IL2CPP calls an interface method as Invoker(slot, TypeInfo_IFace, obj), where slot is the method's index in the
// interface's definition order. Stub DLLs keep that order, so dump it per interface.
static class Slots
{
    public static int Run(List<string> dirs, string outPath)
    {
        var table = new SortedDictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var d in dirs)
            foreach (var f in Directory.EnumerateFiles(d, "*.dll"))
            {
                try
                {
                    using var pe = new PEReader(File.OpenRead(f));
                    if (!pe.HasMetadata) continue;
                    var md = pe.GetMetadataReader();
                    foreach (var h in md.TypeDefinitions)
                    {
                        var t = md.GetTypeDefinition(h);
                        if ((t.Attributes & System.Reflection.TypeAttributes.Interface) == 0) continue;
                        var name = FullName(md, t);
                        if (table.ContainsKey(name)) continue;
                        table[name] = t.GetMethods().Select(m => md.GetString(md.GetMethodDefinition(m).Name)).ToList();
                    }
                }
                catch (BadImageFormatException) { }
            }
        File.WriteAllText(outPath, JsonSerializer.Serialize(table));
        Console.WriteLine($"slots: {table.Count} interfaces -> {outPath}");
        return 0;
    }

    static string FullName(MetadataReader md, TypeDefinition t)
    {
        var name = md.GetString(t.Name);
        var dt = t.GetDeclaringType();
        if (!dt.IsNil) return FullName(md, md.GetTypeDefinition(dt)) + "+" + name;
        var ns = md.GetString(t.Namespace);
        return ns.Length > 0 ? ns + "." + name : name;
    }
}
