using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

// Obfuscated libraries (Rewired) are valid IL but not valid C# once decompiled: an explicit interface
// implementation keeps a readable name while the interface member was renamed (.override joins them in IL),
// overloads differ only by return type, and old Unity types are now obsolete-as-error. These passes make such a
// skeleton compile; every member they add or rename is a stub, so it changes no recovered behaviour.
static class Obfuscated
{
    public static void Run(string srcDir, string asm, List<MetadataReference> refs, CSharpCompilationOptions opts)
    {
        int last = int.MaxValue;
        for (int pass = 1; pass <= 8; pass++)
        {
            var files = Directory.EnumerateFiles(srcDir, "*.cs", SearchOption.AllDirectories)
                .Where(f => !f.Contains("\\obj\\") && !f.Contains("/obj/")).ToList();
            var trees = files.Select(f => CSharpSyntaxTree.ParseText(File.ReadAllText(f), new CSharpParseOptions(LanguageVersion.Latest), f)).ToList();
            var comp = CSharpCompilation.Create(asm, trees, refs, opts);
            var errs = comp.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error && d.Location.IsInSource).ToList();
            var fixable = errs.Where(d => d.Id is "CS0539" or "CS0470" or "CS0535" or "CS0111" or "CS0619" or "CS0738" or "CS0104" or "CS0305" or "CS0103").ToList();
            Console.WriteLine($"obfuscation pass {pass}: {errs.Count} errors, {fixable.Count} of the kinds this pass fixes");
            if (fixable.Count == 0 || errs.Count >= last) return;
            last = errs.Count;
            foreach (var group in fixable.GroupBy(d => d.Location.SourceTree))
            {
                var tree = group.Key;
                var model = comp.GetSemanticModel(tree);
                var root = tree.GetRoot();
                var remove = new HashSet<SyntaxNode>();
                var replace = new Dictionary<SyntaxNode, SyntaxNode>();
                var addTo = new Dictionary<TypeDeclarationSyntax, List<MemberDeclarationSyntax>>();
                int dup = 0;
                foreach (var d in group)
                {
                    var node = root.FindNode(d.Location.SourceSpan, getInnermostNodeForTie: true);
                    var member = node.AncestorsAndSelf().OfType<MemberDeclarationSyntax>()
                        .FirstOrDefault(m => m is not BaseTypeDeclarationSyntax);
                    switch (d.Id)
                    {
                        case "CS0539" or "CS0470" when member != null:
                            remove.Add(member);
                            break;
                        case "CS0535" or "CS0738":
                            var td = node.AncestorsAndSelf().OfType<TypeDeclarationSyntax>().FirstOrDefault();
                            if (td == null || model.GetDeclaredSymbol(td) is not INamedTypeSymbol ts) break;
                            if (!addTo.ContainsKey(td)) addTo[td] = Missing(ts).ToList();
                            break;
                        case "CS0111" when member != null && !replace.ContainsKey(member):
                            replace[member] = Rename(member, ++dup);
                            break;
                        case "CS0305" when node.FirstAncestorOrSelf<AttributeSyntax>() is { } attr:
                            // [IteratorStateMachine(typeof(Open<>))] of a generic method: the attribute only names
                            // the compiler-generated class, so drop it rather than guess the arity syntax.
                            if (attr.Parent is AttributeListSyntax al && al.Attributes.Count == 1) remove.Add(al); else remove.Add(attr);
                            break;
                        case "CS0104" when node is SimpleNameSyntax sn && !replace.ContainsKey(sn):
                            var live = model.GetSymbolInfo(sn).CandidateSymbols.OfType<INamedTypeSymbol>().Where(c => !ObsoleteError(c)).ToList();
                            if (live.Count == 1)
                                replace[sn] = SyntaxFactory.ParseTypeName(live[0].ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat)).WithTriviaFrom(sn);
                            break;
                        case "CS0103" when member is PropertyDeclarationSyntax pd && !replace.ContainsKey(pd):
                            // An indexer the obfuscator renamed decompiles as a property whose body still reads the
                            // index parameter; keep the property, stub its accessors.
                            replace[pd] = StubAccessors(pd);
                            break;
                        case "CS0619" when node.FirstAncestorOrSelf<ConstructorInitializerSyntax>() is { } ci && !replace.ContainsKey(ci):
                            var baseType = model.GetEnclosingSymbol(ci.SpanStart)?.ContainingType?.BaseType;
                            var ok = baseType?.InstanceConstructors.Where(c => !ObsoleteError(c) && c.DeclaredAccessibility != Accessibility.Private)
                                .OrderBy(c => c.Parameters.Length).FirstOrDefault();
                            if (ok != null)
                                replace[ci] = ci.WithArgumentList(SyntaxFactory.ParseArgumentList("(" + string.Join(", ",
                                    ok.Parameters.Select(q => $"default({q.Type.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat)})")) + ")"));
                            break;
                        case "CS0619":
                            var t = node.AncestorsAndSelf().OfType<TypeSyntax>().FirstOrDefault();
                            if (t != null && model.GetSymbolInfo(t).Symbol is INamedTypeSymbol obs && obs.BaseType != null && !replace.ContainsKey(t))
                                replace[t] = SyntaxFactory.ParseTypeName(obs.BaseType.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat)).WithTriviaFrom(t);
                            break;
                    }
                }
                var all = remove.Concat(replace.Keys).Concat(addTo.Keys).ToList();
                var newRoot = root.ReplaceNodes(all, (o, rewritten) =>
                {
                    if (remove.Contains(o)) return null;
                    if (replace.TryGetValue(o, out var r) && o is not TypeDeclarationSyntax) return r;
                    if (o is TypeDeclarationSyntax td && addTo.TryGetValue(td, out var adds) && rewritten is TypeDeclarationSyntax rt)
                        return rt.AddMembers(adds.ToArray());
                    return rewritten;
                });
                if (newRoot != null) File.WriteAllText(tree.FilePath, newRoot.ToFullString());
            }
        }
    }

    static IEnumerable<MemberDeclarationSyntax> Missing(INamedTypeSymbol t)
    {
        var fq = SymbolDisplayFormat.FullyQualifiedFormat;
        foreach (var iface in t.AllInterfaces)
            foreach (var m in iface.GetMembers())
            {
                if (m.IsStatic || t.FindImplementationForInterfaceMember(m) != null) continue;
                var owner = iface.ToDisplayString(fq);
                switch (m)
                {
                    case IMethodSymbol ms when ms.MethodKind == MethodKind.Ordinary:
                        var tps = ms.TypeParameters.Length > 0 ? "<" + string.Join(", ", ms.TypeParameters.Select(p => p.Name)) + ">" : "";
                        var ps = string.Join(", ", ms.Parameters.Select(p => (p.RefKind == RefKind.Out ? "out " : p.RefKind == RefKind.Ref ? "ref " : p.RefKind == RefKind.In ? "in " : "")
                            + p.Type.ToDisplayString(fq) + " " + Safe(p.Name)));
                        var outs = string.Concat(ms.Parameters.Where(p => p.RefKind == RefKind.Out).Select(p => Safe(p.Name) + " = default; "));
                        var body = ms.ReturnsVoid ? "{ " + outs + "}" : "{ " + outs + "return default; }";
                        yield return SyntaxFactory.ParseMemberDeclaration(
                            $"{(ms.ReturnsVoid ? "void" : ms.ReturnType.ToDisplayString(fq))} {owner}.{Safe(ms.Name)}{tps}({ps}) {body}");
                        break;
                    case IPropertySymbol p when !p.IsIndexer:
                        var acc = (p.GetMethod != null ? "get { return default; } " : "") + (p.SetMethod != null ? "set { } " : "");
                        yield return SyntaxFactory.ParseMemberDeclaration($"{p.Type.ToDisplayString(fq)} {owner}.{Safe(p.Name)} {{ {acc}}}");
                        break;
                    case IPropertySymbol ix:
                        var ips = string.Join(", ", ix.Parameters.Select(q => q.Type.ToDisplayString(fq) + " " + Safe(q.Name)));
                        var iacc = (ix.GetMethod != null ? "get { return default; } " : "") + (ix.SetMethod != null ? "set { } " : "");
                        yield return SyntaxFactory.ParseMemberDeclaration($"{ix.Type.ToDisplayString(fq)} {owner}.this[{ips}] {{ {iacc}}}");
                        break;
                    case IEventSymbol e:
                        yield return SyntaxFactory.ParseMemberDeclaration($"event {e.Type.ToDisplayString(fq)} {owner}.{Safe(e.Name)} {{ add {{ }} remove {{ }} }}");
                        break;
                }
            }
    }

    static PropertyDeclarationSyntax StubAccessors(PropertyDeclarationSyntax pd)
    {
        bool set = pd.AccessorList?.Accessors.Any(a => a.IsKind(SyntaxKind.SetAccessorDeclaration)) == true;
        var list = (AccessorListSyntax)((PropertyDeclarationSyntax)SyntaxFactory.ParseMemberDeclaration(
            "int X { get { return default; } " + (set ? "set { } " : "") + "}")).AccessorList;
        return pd.WithExpressionBody(null).WithSemicolonToken(default).WithAccessorList(list);
    }

    public static bool ObsoleteError(ISymbol s) => s.GetAttributes().Any(a => a.AttributeClass?.Name == "ObsoleteAttribute"
        && a.ConstructorArguments.Length == 2 && a.ConstructorArguments[1].Value is true);

    static string Safe(string id) => SyntaxFacts.GetKeywordKind(id) != SyntaxKind.None ? "@" + id : id;

    static MemberDeclarationSyntax Rename(MemberDeclarationSyntax m, int n) => m switch
    {
        MethodDeclarationSyntax md => md.WithIdentifier(SyntaxFactory.Identifier(md.Identifier.Text + "_dup" + n)),
        PropertyDeclarationSyntax pd => pd.WithIdentifier(SyntaxFactory.Identifier(pd.Identifier.Text + "_dup" + n)),
        _ => m,
    };
}
