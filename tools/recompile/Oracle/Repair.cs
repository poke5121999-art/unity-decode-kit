using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

// ILSpy sometimes prints a type by a name that is ambiguous or unresolvable in the exported project (Random,
// Object, nested Awaiter/Particle). The stub DLL the skeleton was decompiled from still knows the exact type of
// every signature, so look the declaration up there and write the type fully qualified.
static class Repair
{
    public static int Run(string srcDir, string asm, List<string> refDirs, string origDll)
    {
        var refs = new List<MetadataReference>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { asm };
        foreach (var d in refDirs)
            foreach (var f in Directory.EnumerateFiles(d, "*.dll"))
                if (seen.Add(Path.GetFileNameWithoutExtension(f)))
                    try { refs.Add(MetadataReference.CreateFromFile(f)); } catch (BadImageFormatException) { }
        var orig = CSharpCompilation.Create("lookup", null, refs.Append(MetadataReference.CreateFromFile(origDll)),
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary).WithMetadataImportOptions(MetadataImportOptions.All));
        var opts = new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, allowUnsafe: true);
        FieldLikeEvents(srcDir);
        int lastCount = int.MaxValue;
        for (int pass = 1; pass <= 5; pass++)
        {
            var files = Directory.EnumerateFiles(srcDir, "*.cs", SearchOption.AllDirectories).Where(f => !f.Contains("\\obj\\") && !f.Contains("/obj/")).ToList();
            var trees = files.Select(f => CSharpSyntaxTree.ParseText(File.ReadAllText(f), new CSharpParseOptions(LanguageVersion.Latest), f)).ToList();
            var comp = CSharpCompilation.Create(asm, trees, refs, opts);
            var errs = comp.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error && d.Location.IsInSource
                && (d.Id == "CS0104" || d.Id == "CS0246" || d.Id == "CS0118" || d.Id == "CS7036" || d.Id == "CS1729")).ToList();
            Console.WriteLine($"repair pass {pass}: {errs.Count} ambiguous/unresolved type names");
            if (errs.Count == 0) return 0;
            if (errs.Count >= lastCount) { foreach (var d in errs.Take(10)) Console.WriteLine("  no progress: " + d); return 1; }
            lastCount = errs.Count;
            int fixedCount = 0;
            foreach (var group in errs.GroupBy(d => d.Location.SourceTree))
            {
                var tree = group.Key;
                var model = comp.GetSemanticModel(tree);
                var fixes = new Dictionary<SyntaxNode, SyntaxNode>();
                foreach (var d in group)
                {
                    var node = tree.GetRoot().FindNode(d.Location.SourceSpan, getInnermostNodeForTie: true);
                    if (d.Id is "CS7036" or "CS1729")
                    {
                        if (node.AncestorsAndSelf().Any(n => n is AttributeSyntax)) continue;
                        if (BaseCall(node, model) is var (target, repl) && target != null) fixes[target] = repl;
                        continue;
                    }
                    if (node is not SimpleNameSyntax name) continue;
                    var full = Resolve(name, model, orig) ?? ObjectFallback(d, name);
                    if (full != null) fixes[name] = SyntaxFactory.ParseTypeName(full).WithTriviaFrom(name);
                }
                if (fixes.Count == 0) continue;
                var root = tree.GetRoot().ReplaceNodes(fixes.Keys, (o, _) => fixes[o]);
                File.WriteAllText(tree.FilePath, root.ToFullString());
                fixedCount += fixes.Count;
            }
            Console.WriteLine($"  rewrote {fixedCount}");
            if (fixedCount == 0) { foreach (var d in errs.Take(10)) Console.WriteLine("  left: " + d); return 1; }
        }
        return 0;
    }

    // Stub DLLs drop the backing field of a field-like event but keep [CompilerGenerated] on its accessors.
    // Turning those back into field-like events restores the field and the add/remove bodies the compiler wrote.
    static void FieldLikeEvents(string srcDir)
    {
        int n = 0;
        foreach (var f in Directory.EnumerateFiles(srcDir, "*.cs", SearchOption.AllDirectories))
        {
            var root = CSharpSyntaxTree.ParseText(File.ReadAllText(f), new CSharpParseOptions(LanguageVersion.Latest), f).GetRoot();
            var evs = root.DescendantNodes().OfType<EventDeclarationSyntax>().Where(e => e.ExplicitInterfaceSpecifier == null
                && e.AccessorList != null && e.AccessorList.Accessors.Count == 2
                && e.AccessorList.Accessors.All(a => a.AttributeLists.SelectMany(l => l.Attributes).Any(x => x.Name.ToString().EndsWith("CompilerGenerated")))).ToList();
            if (evs.Count == 0) continue;
            var nr = root.ReplaceNodes(evs, (o, _) => SyntaxFactory.EventFieldDeclaration(o.AttributeLists, o.Modifiers,
                SyntaxFactory.VariableDeclaration(o.Type.WithoutTrailingTrivia(), SyntaxFactory.SingletonSeparatedList(SyntaxFactory.VariableDeclarator(o.Identifier))))
                .WithTriviaFrom(o).NormalizeWhitespace(elasticTrivia: true));
            File.WriteAllText(f, nr.ToFullString());
            n += evs.Count;
        }
        Console.WriteLine($"field-like events restored: {n}");
    }

    static string Resolve(SimpleNameSyntax name, SemanticModel model, CSharpCompilation orig)
    {
        var decl = name.Ancestors().FirstOrDefault(a => a is MemberDeclarationSyntax and not BaseTypeDeclarationSyntax) as MemberDeclarationSyntax;
        var typeDecl = name.Ancestors().OfType<BaseTypeDeclarationSyntax>().FirstOrDefault();
        if (typeDecl == null || model.GetDeclaredSymbol(typeDecl) is not INamedTypeSymbol owner) return null;
        var origOwner = orig.GetTypeByMetadataName(MetadataName(owner));
        if (origOwner == null) return null;
        var pool = new List<ITypeSymbol>();
        void Walk(ITypeSymbol t)
        {
            if (t == null || pool.Contains(t)) return;
            pool.Add(t);
            if (t is INamedTypeSymbol n) foreach (var a in n.TypeArguments) Walk(a);
            if (t is IArrayTypeSymbol arr) Walk(arr.ElementType);
            if (t is IPointerTypeSymbol p) Walk(p.PointedAtType);
        }
        var memberName = decl switch
        {
            MethodDeclarationSyntax m => Unmangle(m.Identifier.Text),
            PropertyDeclarationSyntax p => Unmangle(p.Identifier.Text),
            FieldDeclarationSyntax f => Unmangle(f.Declaration.Variables.First().Identifier.Text),
            EventFieldDeclarationSyntax e => Unmangle(e.Declaration.Variables.First().Identifier.Text),
            EventDeclarationSyntax e => Unmangle(e.Identifier.Text),
            ConstructorDeclarationSyntax => ".ctor",
            _ => null,
        };
        var members = memberName == null ? origOwner.GetMembers() : origOwner.GetMembers(memberName);
        foreach (var m in members)
            switch (m)
            {
                case IFieldSymbol f: Walk(f.Type); break;
                case IPropertySymbol p: Walk(p.Type); foreach (var x in p.Parameters) Walk(x.Type); break;
                case IEventSymbol e: Walk(e.Type); break;
                case IMethodSymbol mm: Walk(mm.ReturnType); foreach (var x in mm.Parameters) Walk(x.Type); break;
            }
        if (decl == null)
        {
            foreach (var t in origOwner.Interfaces.Append(origOwner.BaseType)) Walk(t);
            foreach (var arg in origOwner.GetAttributes().SelectMany(a => a.ConstructorArguments))
                foreach (var v in arg.Kind == TypedConstantKind.Array ? arg.Values : System.Collections.Immutable.ImmutableArray.Create(arg))
                    if (v.Value is ITypeSymbol ts) Walk(ts);
        }
        var hit = pool.OfType<INamedTypeSymbol>().FirstOrDefault(t => t.Name == name.Identifier.Text);
        return hit?.OriginalDefinition.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat
            .WithGenericsOptions(SymbolDisplayGenericsOptions.None)) is { } s && hit.IsGenericType && name is GenericNameSyntax g
            ? s + g.TypeArgumentList.ToString()
            : hit?.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);
    }

    // Stub DLLs keep constructors but not their base(...) calls; chain to the cheapest base constructor with defaults.
    static (SyntaxNode, SyntaxNode) BaseCall(SyntaxNode node, SemanticModel model)
    {
        var ctor = node.AncestorsAndSelf().OfType<ConstructorDeclarationSyntax>().FirstOrDefault();
        var cls = node.AncestorsAndSelf().OfType<ClassDeclarationSyntax>().FirstOrDefault();
        if (cls == null || model.GetDeclaredSymbol(cls) is not INamedTypeSymbol t || t.BaseType == null || t.IsStatic) return (null, null);
        if (ctor?.Initializer != null) return (null, null);
        if (ctor == null && t.InstanceConstructors.Any(c => !c.IsImplicitlyDeclared)) return (null, null);
        var best = t.BaseType.InstanceConstructors.Where(c => c.DeclaredAccessibility != Accessibility.Private)
            .OrderBy(c => c.Parameters.Length).FirstOrDefault();
        if (best == null) return (null, null);
        var args = string.Join(", ", best.Parameters.Select(p => $"default({p.Type.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat)})"));
        var init = SyntaxFactory.ConstructorInitializer(SyntaxKind.BaseConstructorInitializer,
            SyntaxFactory.ParseArgumentList("(" + args + ")"));
        if (ctor != null) return (ctor, ctor.WithInitializer(init));
        var mod = cls.Modifiers.Any(SyntaxKind.AbstractKeyword) ? "protected" : "public";
        var added = (ConstructorDeclarationSyntax)SyntaxFactory.ParseMemberDeclaration($"{mod} {cls.Identifier.Text}() {{ }}");
        return (cls, cls.AddMembers(added.WithInitializer(init)));
    }

    // ILSpy spells a bare `object` keyword for System.Object, so a bare `Object` it printed means UnityEngine.Object.
    static string ObjectFallback(Diagnostic d, SimpleNameSyntax name) =>
        d.Id == "CS0104" && name.Identifier.Text == "Object" && d.GetMessage().Contains("'UnityEngine.Object'")
            ? "global::UnityEngine.Object" : null;

    static string Unmangle(string id) => System.Text.RegularExpressions.Regex.Replace(id, "_([0-9A-F]{4})",
        m => ((char)Convert.ToInt32(m.Groups[1].Value, 16)) is var c && !char.IsLetterOrDigit(c) && c != '_' ? c.ToString() : m.Value);

    static string MetadataName(INamedTypeSymbol t) =>
        t.ContainingType != null ? MetadataName(t.ContainingType) + "+" + Unmangle(t.MetadataName)
        : (t.ContainingNamespace.IsGlobalNamespace ? "" : t.ContainingNamespace.ToDisplayString() + ".") + t.MetadataName;
}
