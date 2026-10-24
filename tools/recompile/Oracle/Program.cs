using System.Text.Json;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Text;

static class Program
{
    static int Main(string[] argv)
    {
        var a = Args.Parse(argv);
        if (a.Command == "extract")
            return Extract.Run(a.Get("src"), a.Get("out"), a.Get("srcname", "extract"));
        if (a.Command == "slots")
            return Slots.Run(a.All("refs"), a.Get("out"));
        if (a.Command == "invoke")
            return Invoke.Run(a.Get("dll"), a.Get("inputs"), a.Get("out"), a.All("refs"));
        if (a.Command == "repair")
            return Repair.Run(a.Get("src"), a.Get("asm"), a.All("refs"), a.Get("orig"));
        if (a.Command == "decls")
            return Decls.Run(a.Get("src"), a.Get("out"));
        var skel =Skeleton.Load(a.Get("src"), a.Get("asm"), a.All("refs"), a.All("ref-exclude"));
        switch (a.Command)
        {
            case "index":
                skel.WriteIndex(a.Get("out"));
                return 0;
            case "compile":
                var cands = Candidate.ReadJsonl(a.Get("candidates"));
                var res = skel.CompileCandidates(cands, int.Parse(a.Get("max-rounds", "30")));
                Candidate.WriteResults(a.Get("out"), res);
                var emit = a.Get("emit", null);
                if (emit != null) return skel.Emit(cands.Where(c => res[c.Key].Status == "ok").ToList(), emit) ? 0 : 1;
                return 0;
            default:
                Console.Error.WriteLine($"unknown command '{a.Command}' (index|compile)");
                return 2;
        }
    }
}

sealed class Args
{
    public string Command;
    readonly Dictionary<string, List<string>> _kv = new();

    public static Args Parse(string[] argv)
    {
        var a = new Args { Command = argv.Length > 0 ? argv[0] : "" };
        for (int i = 1; i < argv.Length; i++)
        {
            if (!argv[i].StartsWith("--")) throw new ArgumentException($"stray argument '{argv[i]}'");
            var k = argv[i][2..];
            var v = i + 1 < argv.Length && !argv[i + 1].StartsWith("--") ? argv[++i] : "true";
            if (!a._kv.TryGetValue(k, out var l)) a._kv[k] = l = new List<string>();
            l.Add(v);
        }
        return a;
    }

    public string Get(string k, string dflt = "\0")
    {
        if (_kv.TryGetValue(k, out var l)) return l[^1];
        if (dflt == "\0") throw new ArgumentException($"missing --{k}");
        return dflt;
    }

    public List<string> All(string k) => _kv.TryGetValue(k, out var l) ? l : new List<string>();
}

sealed class Candidate
{
    public string Key { get; set; }
    public string Src { get; set; }
    public string Body { get; set; }

    public static List<Candidate> ReadJsonl(string path)
    {
        var opts = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
        var list = new List<Candidate>();
        foreach (var line in File.ReadLines(path))
            if (line.Length > 0) list.Add(JsonSerializer.Deserialize<Candidate>(line, opts));
        return list;
    }

    public static void WriteResults(string path, Dictionary<string, Result> res)
    {
        using var w = new StreamWriter(path);
        foreach (var r in res.Values) w.WriteLine(JsonSerializer.Serialize(r));
        var by = res.Values.GroupBy(r => r.Status).ToDictionary(g => g.Key, g => g.Count());
        Console.WriteLine("results " + string.Join(" ", by.OrderBy(k => k.Key).Select(k => $"{k.Key}={k.Value}")) +
                          $" ok_managed={res.Values.Count(r => r.Status == "ok" && !r.Unsafe)}");
    }
}

sealed class Result
{
    public string Key { get; set; }
    public string Src { get; set; }
    public string Status { get; set; }
    public bool Unsafe { get; set; }
    public int Round { get; set; }
    public List<string> Errors { get; set; } = new();
    public List<string> Calls { get; set; }
}

sealed class Skeleton
{
    const string CandAnnotation = "udk-cand";
    string _asm;
    List<SyntaxTree> _trees;
    List<MetadataReference> _refs;
    CSharpCompilationOptions _opts;
    readonly Dictionary<string, (int Tree, TextSpan Span, string Kind)> _members = new();
    readonly HashSet<string> _ambiguous = new();
    readonly Dictionary<string, string> _loose = new();
    public int BaseErrors;

    public static Skeleton Load(string srcDir, string asm, List<string> refDirs, List<string> exclude)
    {
        var s = new Skeleton { _asm = asm };
        var parse = new CSharpParseOptions(LanguageVersion.Latest);
        s._trees = Directory.EnumerateFiles(srcDir, "*.cs", SearchOption.AllDirectories)
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}"))
            .OrderBy(f => f, StringComparer.Ordinal)
            .Select(f => CSharpSyntaxTree.ParseText(File.ReadAllText(f), parse, f))
            .ToList();
        var skip = new HashSet<string>(exclude.Append(asm), StringComparer.OrdinalIgnoreCase);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        s._refs = new List<MetadataReference>();
        foreach (var d in refDirs)
            foreach (var f in Directory.EnumerateFiles(d, "*.dll"))
            {
                var n = Path.GetFileNameWithoutExtension(f);
                if (skip.Contains(n) || !seen.Add(n)) continue;
                try { s._refs.Add(MetadataReference.CreateFromFile(f)); } catch (BadImageFormatException) { }
            }
        s._opts = new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, allowUnsafe: true,
            nullableContextOptions: NullableContextOptions.Disable, warningLevel: 0,
            generalDiagnosticOption: ReportDiagnostic.Default);
        s.IndexMembers();
        return s;
    }

    CSharpCompilation Compilation(List<SyntaxTree> trees) => CSharpCompilation.Create(_asm, trees, _refs, _opts);

    void IndexMembers()
    {
        var comp = Compilation(_trees);
        for (int i = 0; i < _trees.Count; i++)
        {
            var model = comp.GetSemanticModel(_trees[i]);
            foreach (var node in _trees[i].GetRoot().DescendantNodes())
            {
                IMethodSymbol sym = null;
                string kind = null;
                switch (node)
                {
                    case BaseMethodDeclarationSyntax m when m.Body != null || m.ExpressionBody != null:
                        sym = model.GetDeclaredSymbol(m) as IMethodSymbol; kind = "method"; break;
                    case AccessorDeclarationSyntax acc when acc.Body != null || acc.ExpressionBody != null:
                        sym = model.GetDeclaredSymbol(acc) as IMethodSymbol; kind = "accessor"; break;
                    case PropertyDeclarationSyntax p when p.ExpressionBody != null:
                        sym = (model.GetDeclaredSymbol(p) as IPropertySymbol)?.GetMethod; kind = "exprprop"; break;
                    case IndexerDeclarationSyntax ix when ix.ExpressionBody != null:
                        sym = (model.GetDeclaredSymbol(ix) as IPropertySymbol)?.GetMethod; kind = "exprprop"; break;
                }
                if (sym == null) continue;
                var key = Keys.Method(sym);
                if (_members.ContainsKey(key)) _ambiguous.Add(key);
                else _members[key] = (i, node.Span, kind);
            }
        }
        foreach (var tree in _trees.Select((t, i) => (t, i)))
        {
            var model = comp.GetSemanticModel(tree.t);
            foreach (var cls in tree.t.GetRoot().DescendantNodes().OfType<ClassDeclarationSyntax>())
            {
                if (model.GetDeclaredSymbol(cls) is not INamedTypeSymbol ts || ts.DeclaringSyntaxReferences.Length != 1) continue;
                var tk = Keys.Type(ts);
                if (!ts.IsStatic && !ts.InstanceConstructors.Any(c => !c.IsImplicitlyDeclared))
                    _members.TryAdd(tk + "::.ctor()", (tree.i, cls.Span, "newctor"));
                if (!ts.StaticConstructors.Any())
                    _members.TryAdd(tk + "::.cctor()", (tree.i, cls.Span, "newcctor"));
            }
        }
        foreach (var g in _members.Keys.GroupBy(Keys.Loose))
            _loose[g.Key] = g.Count() == 1 ? g.First() : null;
        BaseErrors = comp.GetDiagnostics().Count(d => d.Severity == DiagnosticSeverity.Error);
        Console.WriteLine($"skeleton {_asm}: {_trees.Count} files, {_members.Count} bodies, {_ambiguous.Count} ambiguous keys, {BaseErrors} base errors");
        foreach (var d in comp.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error).Take(int.Parse(Environment.GetEnvironmentVariable("ORACLE_SHOW_ERRORS") ?? "10")))
            Console.WriteLine("  base: " + d);
    }

    public void WriteIndex(string path)
    {
        using var w = new StreamWriter(path);
        w.WriteLine("key\tkind\tfile\tambiguous");
        foreach (var (k, v) in _members.OrderBy(k => k.Key, StringComparer.Ordinal))
            w.WriteLine($"{k}\t{v.Kind}\t{_trees[v.Tree].FilePath}\t{(_ambiguous.Contains(k) ? 1 : 0)}");
    }

    public Dictionary<string, Result> CompileCandidates(List<Candidate> cands, int maxRounds)
    {
        var res = new Dictionary<string, Result>();
        var live = new Dictionary<string, (Candidate C, BlockSyntax Block)>();
        foreach (var c in cands)
        {
            if (!_members.ContainsKey(c.Key) && _loose.TryGetValue(Keys.Loose(c.Key), out var exact) && exact != null)
                c.Key = exact;
            if (res.ContainsKey(c.Key)) continue;
            var r = res[c.Key] = new Result { Key = c.Key, Src = c.Src, Unsafe = Keys.LooksUnsafe(c.Body) };
            if (_ambiguous.Contains(c.Key)) { r.Status = "ambiguous"; continue; }
            if (!_members.ContainsKey(c.Key)) { r.Status = "no_target"; continue; }
            var block = SyntaxFactory.ParseStatement("{\n" + c.Body + "\n}", options: new CSharpParseOptions(LanguageVersion.Latest)) as BlockSyntax;
            var synErr = block == null ? new[] { "not a block" } :
                block.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error).Select(d => d.ToString()).Take(3).ToArray();
            if (synErr.Length > 0) { r.Status = "syntax_error"; r.Errors.AddRange(synErr); continue; }
            live[c.Key] = (c, block.WithAdditionalAnnotations(new SyntaxAnnotation(CandAnnotation, c.Key)));
        }
        for (int round = 1; round <= maxRounds && live.Count > 0; round++)
        {
            var trees = Rewrite(live.ToDictionary(k => k.Key, v => v.Value.Block));
            var comp = Compilation(trees);
            var failed = new Dictionary<string, List<string>>();
            int stray = 0;
            foreach (var d in comp.GetDiagnostics())
            {
                if (d.Severity != DiagnosticSeverity.Error) continue;
                var node = d.Location.IsInSource ? d.Location.SourceTree.GetRoot().FindNode(d.Location.SourceSpan, getInnermostNodeForTie: true) : null;
                var owner = node?.AncestorsAndSelf().FirstOrDefault(n => n.HasAnnotations(CandAnnotation));
                if (owner == null) { stray++; continue; }
                var key = owner.GetAnnotations(CandAnnotation).First().Data;
                if (!failed.TryGetValue(key, out var l)) failed[key] = l = new List<string>();
                if (l.Count < 4) l.Add($"{d.Id}: {d.GetMessage()}");
            }
            Console.WriteLine($"round {round}: live={live.Count} failed={failed.Count}");
            if (failed.Count == 0)
            {
                if (stray > BaseErrors)
                    Console.WriteLine($"WARNING: {stray - BaseErrors} errors outside any candidate and the skeleton; 'ok' is not emit-clean");
                foreach (var (k, calls) in CallSets(comp)) res[k].Calls = calls;
                foreach (var k in live.Keys) { res[k].Status = "ok"; res[k].Round = round; }
                live.Clear();
                break;
            }
            foreach (var (k, errs) in failed)
            {
                res[k].Status = "compile_error"; res[k].Round = round; res[k].Errors = errs;
                live.Remove(k);
            }
        }
        foreach (var k in live.Keys) res[k].Status = "undecided";
        return res;
    }

    // Every method a recovered body reaches, as "Type::MetadataName", for comparison with the native call list.
    static Dictionary<string, List<string>> CallSets(CSharpCompilation comp)
    {
        var outp = new Dictionary<string, List<string>>();
        foreach (var tree in comp.SyntaxTrees)
        {
            var root = tree.GetRoot();
            if (!root.ContainsAnnotations) continue;
            var model = comp.GetSemanticModel(tree);
            foreach (var block in root.GetAnnotatedNodes(CandAnnotation))
            {
                var set = new SortedSet<string>(StringComparer.Ordinal);
                void Add(IMethodSymbol m)
                {
                    if (m == null) return;
                    m = m.ReducedFrom ?? m;
                    set.Add(m.ContainingType.OriginalDefinition.Name + "::" + m.OriginalDefinition.MetadataName);
                }
                var ctorDecl = block as ConstructorDeclarationSyntax ?? block.Parent as ConstructorDeclarationSyntax;
                if (ctorDecl != null && model.GetDeclaredSymbol(ctorDecl) is IMethodSymbol ctorSym && !ctorSym.IsStatic)
                {
                    if (ctorDecl.Initializer != null) Add(model.GetSymbolInfo(ctorDecl.Initializer).Symbol as IMethodSymbol);
                    else Add(ctorSym.ContainingType.BaseType?.InstanceConstructors.FirstOrDefault(c => c.Parameters.Length == 0));
                }
                foreach (var node in block.DescendantNodesAndSelf())
                {
                    var op = model.GetOperation(node);
                    switch (op)
                    {
                        case Microsoft.CodeAnalysis.Operations.IInvocationOperation inv: Add(inv.TargetMethod); break;
                        case Microsoft.CodeAnalysis.Operations.IObjectCreationOperation oc: Add(oc.Constructor); break;
                        case Microsoft.CodeAnalysis.Operations.IDelegateCreationOperation dc when dc.Type is INamedTypeSymbol dt:
                            Add(dt.InstanceConstructors.FirstOrDefault()); break;
                        case Microsoft.CodeAnalysis.Operations.IEventAssignmentOperation ea
                            when ea.EventReference is Microsoft.CodeAnalysis.Operations.IEventReferenceOperation er:
                            Add(ea.Adds ? er.Event.AddMethod : er.Event.RemoveMethod); break;
                        case Microsoft.CodeAnalysis.Operations.IPropertyReferenceOperation pr:
                            var isTarget = pr.Parent is Microsoft.CodeAnalysis.Operations.IAssignmentOperation asg && asg.Target == pr;
                            if (isTarget) Add(pr.Property.SetMethod);
                            if (!isTarget || pr.Parent is Microsoft.CodeAnalysis.Operations.ICompoundAssignmentOperation) Add(pr.Property.GetMethod);
                            break;
                        case Microsoft.CodeAnalysis.Operations.IBinaryOperation b: Add(b.OperatorMethod); break;
                        case Microsoft.CodeAnalysis.Operations.IUnaryOperation u: Add(u.OperatorMethod); break;
                        case Microsoft.CodeAnalysis.Operations.IConversionOperation cv: Add(cv.OperatorMethod); break;
                        case Microsoft.CodeAnalysis.Operations.IForEachLoopOperation fe:
                            var info = model.GetForEachStatementInfo((CommonForEachStatementSyntax)node);
                            Add(info.GetEnumeratorMethod); Add(info.MoveNextMethod); Add(info.CurrentProperty?.GetMethod); Add(info.DisposeMethod);
                            break;
                    }
                }
                outp[block.GetAnnotations(CandAnnotation).First().Data] = set.ToList();
            }
        }
        return outp;
    }

    List<SyntaxTree> Rewrite(Dictionary<string, BlockSyntax> bodies)
    {
        var byTree = new Dictionary<int, Dictionary<TextSpan, List<(string Kind, BlockSyntax Block)>>>();
        foreach (var (k, b) in bodies)
        {
            var m = _members[k];
            if (!byTree.TryGetValue(m.Tree, out var d)) byTree[m.Tree] = d = new();
            if (!d.TryGetValue(m.Span, out var l)) d[m.Span] = l = new();
            l.Add((m.Kind, b));
        }
        var outTrees = new List<SyntaxTree>(_trees);
        foreach (var (ti, spans) in byTree)
        {
            var root = _trees[ti].GetRoot();
            var targets = root.DescendantNodes().Where(n => spans.ContainsKey(n.Span) && (IsMember(n) || n is ClassDeclarationSyntax)).ToList();
            var newRoot = root.ReplaceNodes(targets, (orig, rewritten) =>
                spans[orig.Span].Aggregate(rewritten, (n, e) => Swap(n, e.Kind, e.Block)));
            outTrees[ti] = _trees[ti].WithRootAndOptions(newRoot, _trees[ti].Options);
        }
        return outTrees;
    }

    static bool IsMember(SyntaxNode n) => n is BaseMethodDeclarationSyntax or AccessorDeclarationSyntax
        or PropertyDeclarationSyntax or IndexerDeclarationSyntax;

    // The candidate annotation goes on the whole member, not just its block: some body errors (CS0161 "not all
    // code paths return a value") are reported at the member's name.
    static SyntaxNode Swap(SyntaxNode n, string kind, BlockSyntax b)
    {
        var swapped = SwapBody(n, kind, b);
        var ann = b.GetAnnotations(CandAnnotation).FirstOrDefault();
        return ann == null || n is ClassDeclarationSyntax ? swapped : swapped.WithAdditionalAnnotations(ann);
    }

    static SyntaxNode SwapBody(SyntaxNode n, string kind, BlockSyntax b) => n switch
    {
        ClassDeclarationSyntax cls => cls.AddMembers(NewCtor(cls, kind == "newcctor", b)),
        BaseMethodDeclarationSyntax m => m.WithExpressionBody(null).WithSemicolonToken(default).WithBody(b),
        AccessorDeclarationSyntax acc => acc.WithExpressionBody(null).WithSemicolonToken(default).WithBody(b),
        PropertyDeclarationSyntax p => p.WithExpressionBody(null).WithSemicolonToken(default)
            .WithAccessorList(SyntaxFactory.AccessorList(SyntaxFactory.SingletonList(
                SyntaxFactory.AccessorDeclaration(SyntaxKind.GetAccessorDeclaration, b)))),
        IndexerDeclarationSyntax ix => ix.WithExpressionBody(null).WithSemicolonToken(default)
            .WithAccessorList(SyntaxFactory.AccessorList(SyntaxFactory.SingletonList(
                SyntaxFactory.AccessorDeclaration(SyntaxKind.GetAccessorDeclaration, b)))),
        _ => n,
    };

    // ILSpy drops constructors that only run field initializers; recovering them means adding the member back.
    static ConstructorDeclarationSyntax NewCtor(ClassDeclarationSyntax cls, bool isStatic, BlockSyntax b)
    {
        var mods = isStatic ? SyntaxFactory.TokenList(SyntaxFactory.Token(SyntaxKind.StaticKeyword))
            : SyntaxFactory.TokenList(SyntaxFactory.Token(cls.Modifiers.Any(SyntaxKind.AbstractKeyword) ? SyntaxKind.ProtectedKeyword : SyntaxKind.PublicKeyword));
        var ctor = SyntaxFactory.ConstructorDeclaration(cls.Identifier.WithoutTrivia()).WithModifiers(mods).WithBody(b);
        var ann = b.GetAnnotations(CandAnnotation).FirstOrDefault();
        return ann == null ? ctor : ctor.WithAdditionalAnnotations(ann);
    }

    public bool Emit(List<Candidate> ok, string path)
    {
        var bodies = ok.ToDictionary(c => c.Key, c => (BlockSyntax)SyntaxFactory.ParseStatement("{\n" + c.Body + "\n}"));
        var comp = Compilation(Rewrite(bodies));
        using var fs = File.Create(path);
        var r = comp.Emit(fs);
        foreach (var d in r.Diagnostics.Where(d => d.Severity == DiagnosticSeverity.Error).Take(20)) Console.Error.WriteLine(d);
        Console.WriteLine($"emit {path}: {(r.Success ? "ok" : "FAILED")} with {ok.Count} recovered bodies");
        return r.Success;
    }
}

static class Keys
{
    public static string Type(INamedTypeSymbol t)
    {
        if (t.ContainingType != null) return Type(t.ContainingType) + "/" + t.MetadataName;
        var ns = t.ContainingNamespace?.IsGlobalNamespace != false ? "" : t.ContainingNamespace.ToDisplayString() + ".";
        return ns + t.MetadataName;
    }

    public static string Param(ITypeSymbol t) => t switch
    {
        IArrayTypeSymbol a => Param(a.ElementType) + "[]",
        IPointerTypeSymbol p => Param(p.PointedAtType) + "*",
        _ => t.Name,
    };

    public static string Method(IMethodSymbol m)
    {
        var ps = string.Join(",", m.Parameters.Select(p => Param(p.Type) + (p.RefKind != RefKind.None ? "&" : "")));
        var ret = m.MethodKind == MethodKind.Conversion ? ":" + Param(m.ReturnType) : "";
        return $"{Type(m.ContainingType)}::{m.MetadataName}({ps}){ret}";
    }

    // Tolerates naming drift between producers: <X>d__3 vs _X_d__3, Action_1 vs Action, short vs full interface names.
    public static string Loose(string key)
    {
        var k = key.Replace("_003C", "_").Replace("_003E", "_").Replace("<", "_").Replace(">", "_");
        var i = k.IndexOf("::", StringComparison.Ordinal);
        var p = k.IndexOf('(', i);
        var name = k[(i + 2)..p];
        var dots = name.Split('.');
        if (dots.Length > 2) name = dots[^2] + "." + dots[^1];
        var head = System.Text.RegularExpressions.Regex.Replace(k[..(i + 2)], @"_\d+(`\d+)", "$1");
        var ps = System.Text.RegularExpressions.Regex.Replace(k[p..], @"(_|`)\d+(?=[,)\[&*])", "");
        return head + name + ps;
    }

    public static bool LooksUnsafe(string body) =>
        body.Contains("unsafe") || body.Contains("(byte*)") || body.Contains("fixed (") || body.Contains("stackalloc");
}
