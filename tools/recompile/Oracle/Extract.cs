using System.Text;
using System.Text.Json;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

// Pulls method bodies out of C# that does not compile (il2csharp output, LLM drafts) and keys
// them the same way Keys.Method keys skeleton symbols, using syntax alone.
static class Extract
{
    static readonly Dictionary<string, string> Keyword = new()
    {
        ["int"] = "Int32", ["uint"] = "UInt32", ["long"] = "Int64", ["ulong"] = "UInt64",
        ["short"] = "Int16", ["ushort"] = "UInt16", ["byte"] = "Byte", ["sbyte"] = "SByte",
        ["bool"] = "Boolean", ["char"] = "Char", ["float"] = "Single", ["double"] = "Double",
        ["decimal"] = "Decimal", ["string"] = "String", ["object"] = "Object", ["void"] = "Void",
        ["nint"] = "IntPtr", ["nuint"] = "UIntPtr",
    };

    public static int Run(string srcDir, string outPath, string srcName)
    {
        int n = 0;
        using var w = new StreamWriter(outPath);
        var parse = new CSharpParseOptions(LanguageVersion.Latest);
        foreach (var f in Directory.EnumerateFiles(srcDir, "*.cs", SearchOption.AllDirectories).OrderBy(f => f, StringComparer.Ordinal))
        {
            var root = CSharpSyntaxTree.ParseText(File.ReadAllText(f), parse, f).GetRoot();
            foreach (var node in root.DescendantNodes())
            {
                var (key, body) = node switch
                {
                    BaseMethodDeclarationSyntax m => (MethodKey(m), Body(m.Body, m.ExpressionBody, IsVoid(m))),
                    AccessorDeclarationSyntax acc => (AccessorKey(acc), Body(acc.Body, acc.ExpressionBody,
                        !acc.IsKind(SyntaxKind.GetAccessorDeclaration))),
                    PropertyDeclarationSyntax p when p.ExpressionBody != null =>
                        (Owner(p) + "::get_" + p.Identifier.Text + "()", Body(null, p.ExpressionBody, false)),
                    _ => (null, null),
                };
                if (key == null || body == null) continue;
                w.WriteLine(JsonSerializer.Serialize(new { key, src = srcName, body }));
                n++;
            }
        }
        Console.WriteLine($"extract {srcName}: {n} bodies -> {outPath}");
        return 0;
    }

    static bool IsVoid(BaseMethodDeclarationSyntax m) =>
        m is not MethodDeclarationSyntax md || md.ReturnType is PredefinedTypeSyntax { Keyword.Text: "void" };

    static string Body(BlockSyntax block, ArrowExpressionClauseSyntax arrow, bool isVoid)
    {
        if (block != null)
        {
            var inner = block.Statements.ToFullString();
            return inner.Trim().Length == 0 && block.CloseBraceToken.IsMissing ? null : inner;
        }
        if (arrow != null) return (isVoid ? "" : "return ") + arrow.Expression.ToFullString() + ";";
        return null;
    }

    static string MethodKey(BaseMethodDeclarationSyntax m)
    {
        string name = m switch
        {
            MethodDeclarationSyntax md => (md.ExplicitInterfaceSpecifier != null
                ? md.ExplicitInterfaceSpecifier.Name.ToString() + "." : "") + md.Identifier.Text +
                (md.TypeParameterList != null ? "`" + md.TypeParameterList.Parameters.Count : ""),
            ConstructorDeclarationSyntax c => c.Modifiers.Any(SyntaxKind.StaticKeyword) ? ".cctor" : ".ctor",
            DestructorDeclarationSyntax => "Finalize",
            OperatorDeclarationSyntax o => OperatorName(o.OperatorToken.Text, o.ParameterList.Parameters.Count),
            ConversionOperatorDeclarationSyntax c => c.ImplicitOrExplicitKeyword.Text == "implicit" ? "op_Implicit" : "op_Explicit",
            _ => null,
        };
        if (name == null) return null;
        var ret = m is ConversionOperatorDeclarationSyntax cv ? ":" + Short(cv.Type) : "";
        return $"{Owner(m)}::{name}({Params(m.ParameterList.Parameters)}){ret}";
    }

    static string AccessorKey(AccessorDeclarationSyntax acc)
    {
        var holder = acc.Parent?.Parent;
        var prefix = acc.Keyword.Text switch { "get" => "get_", "set" => "set_", "init" => "set_", "add" => "add_", "remove" => "remove_", _ => null };
        if (prefix == null) return null;
        switch (holder)
        {
            case PropertyDeclarationSyntax p:
                var iface = p.ExplicitInterfaceSpecifier != null ? p.ExplicitInterfaceSpecifier.Name + "." : "";
                var ps = prefix == "set_" ? Short(p.Type) : "";
                return $"{Owner(p)}::{iface}{prefix}{p.Identifier.Text}({ps})";
            case IndexerDeclarationSyntax ix:
                var ips = Params(ix.ParameterList.Parameters);
                if (prefix == "set_") ips = (ips.Length > 0 ? ips + "," : "") + Short(ix.Type);
                return $"{Owner(ix)}::{prefix}Item({ips})";
            case EventDeclarationSyntax e:
                return $"{Owner(e)}::{prefix}{e.Identifier.Text}({Short(e.Type)})";
        }
        return null;
    }

    static string OperatorName(string tok, int arity) => (tok, arity) switch
    {
        ("+", 2) => "op_Addition", ("-", 2) => "op_Subtraction", ("*", _) => "op_Multiply", ("/", _) => "op_Division",
        ("%", _) => "op_Modulus", ("==", _) => "op_Equality", ("!=", _) => "op_Inequality", ("<", _) => "op_LessThan",
        (">", _) => "op_GreaterThan", ("<=", _) => "op_LessThanOrEqual", (">=", _) => "op_GreaterThanOrEqual",
        ("-", 1) => "op_UnaryNegation", ("+", 1) => "op_UnaryPlus", ("!", _) => "op_LogicalNot", ("++", _) => "op_Increment",
        ("--", _) => "op_Decrement", ("&", _) => "op_BitwiseAnd", ("|", _) => "op_BitwiseOr", ("^", _) => "op_ExclusiveOr",
        ("true", _) => "op_True", ("false", _) => "op_False", _ => "op_" + tok,
    };

    static string Params(SeparatedSyntaxList<ParameterSyntax> ps) => string.Join(",", ps.Select(p =>
        Short(p.Type) + (p.Modifiers.Any(m => m.IsKind(SyntaxKind.RefKeyword) || m.IsKind(SyntaxKind.OutKeyword) || m.IsKind(SyntaxKind.InKeyword)) ? "&" : "")));

    public static string Short(TypeSyntax t) => t switch
    {
        null => "",
        PredefinedTypeSyntax p => Keyword.TryGetValue(p.Keyword.Text, out var k) ? k : p.Keyword.Text,
        ArrayTypeSyntax a => Short(a.ElementType) + string.Concat(a.RankSpecifiers.Select(_ => "[]")),
        PointerTypeSyntax p => Short(p.ElementType) + "*",
        NullableTypeSyntax => "Nullable",
        TupleTypeSyntax => "ValueTuple",
        QualifiedNameSyntax q => Short(q.Right),
        AliasQualifiedNameSyntax a => Short(a.Name),
        GenericNameSyntax g => g.Identifier.Text,
        IdentifierNameSyntax i => i.Identifier.Text,
        RefTypeSyntax r => Short(r.Type),
        _ => t.ToString(),
    };

    public static string Owner(SyntaxNode n)
    {
        var parts = new List<string>();
        string ns = "";
        for (var p = n.Parent; p != null; p = p.Parent)
        {
            if (p is BaseTypeDeclarationSyntax td)
            {
                var arity = td is TypeDeclarationSyntax { TypeParameterList: { } tp } ? "`" + tp.Parameters.Count : "";
                parts.Insert(0, Mangle(td.Identifier.Text) + arity);
            }
            else if (p is BaseNamespaceDeclarationSyntax nd)
                ns = nd.Name + (ns.Length > 0 ? "." + ns : "");
        }
        var root = n.SyntaxTree.GetRoot();
        if (ns.Length == 0 && root is CompilationUnitSyntax cu)
            ns = cu.Members.OfType<FileScopedNamespaceDeclarationSyntax>().FirstOrDefault()?.Name.ToString() ?? "";
        return (ns.Length > 0 ? ns + "." : "") + string.Join("/", parts);
    }

    // ILSpy writes compiler-generated names like <Foo>d__3 as _003CFoo_003Ed__3; other sources use the raw name.
    public static string Mangle(string id)
    {
        var sb = new StringBuilder();
        foreach (var ch in id)
            if (char.IsLetterOrDigit(ch) || ch == '_' || ch == '`') sb.Append(ch);
            else sb.Append('_').Append(((int)ch).ToString("X4"));
        return sb.ToString();
    }
}
