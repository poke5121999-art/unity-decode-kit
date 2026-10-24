using System.Text.Json;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

// One record per type: its declaration with every body removed, the context a translator needs.
static class Decls
{
    public static int Run(string srcDir, string outPath)
    {
        int n = 0;
        using var w = new StreamWriter(outPath);
        foreach (var f in Directory.EnumerateFiles(srcDir, "*.cs", SearchOption.AllDirectories).OrderBy(f => f, StringComparer.Ordinal))
        {
            var root = CSharpSyntaxTree.ParseText(File.ReadAllText(f), new CSharpParseOptions(LanguageVersion.Latest), f).GetRoot();
            var stripped = new Stripper().Visit(root);
            foreach (var td in stripped.DescendantNodes().OfType<BaseTypeDeclarationSyntax>())
            {
                var shallow = td is TypeDeclarationSyntax t
                    ? t.WithMembers(SyntaxFactory.List(t.Members.Where(m => m is not BaseTypeDeclarationSyntax))) : td;
                var name = td.Identifier.Text;
                var key = OwnerOf(td);
                w.WriteLine(JsonSerializer.Serialize(new { type = key, name, text = shallow.NormalizeWhitespace().ToFullString() }));
                n++;
            }
        }
        Console.WriteLine($"decls: {n} types -> {outPath}");
        return 0;
    }

    static string OwnerOf(BaseTypeDeclarationSyntax td)
    {
        var arity = td is TypeDeclarationSyntax { TypeParameterList: { } tp } ? "`" + tp.Parameters.Count : "";
        var inner = Extract.Mangle(td.Identifier.Text) + arity;
        var outer = Extract.Owner(td).TrimEnd('.');
        return outer.Length == 0 ? inner : (td.Parent is BaseTypeDeclarationSyntax ? outer + "/" + inner : outer + "." + inner);
    }

    sealed class Stripper : CSharpSyntaxRewriter
    {
        public override SyntaxNode VisitMethodDeclaration(MethodDeclarationSyntax n) =>
            n.WithBody(null).WithExpressionBody(null).WithSemicolonToken(SyntaxFactory.Token(SyntaxKind.SemicolonToken)).WithAttributeLists(default);
        public override SyntaxNode VisitConstructorDeclaration(ConstructorDeclarationSyntax n) =>
            n.WithBody(null).WithExpressionBody(null).WithInitializer(null).WithSemicolonToken(SyntaxFactory.Token(SyntaxKind.SemicolonToken)).WithAttributeLists(default);
        public override SyntaxNode VisitOperatorDeclaration(OperatorDeclarationSyntax n) =>
            n.WithBody(null).WithExpressionBody(null).WithSemicolonToken(SyntaxFactory.Token(SyntaxKind.SemicolonToken));
        public override SyntaxNode VisitConversionOperatorDeclaration(ConversionOperatorDeclarationSyntax n) =>
            n.WithBody(null).WithExpressionBody(null).WithSemicolonToken(SyntaxFactory.Token(SyntaxKind.SemicolonToken));
        public override SyntaxNode VisitAccessorDeclaration(AccessorDeclarationSyntax n) =>
            n.WithBody(null).WithExpressionBody(null).WithSemicolonToken(SyntaxFactory.Token(SyntaxKind.SemicolonToken)).WithAttributeLists(default);
        public override SyntaxNode VisitPropertyDeclaration(PropertyDeclarationSyntax n) =>
            n.ExpressionBody == null ? ((PropertyDeclarationSyntax)base.VisitPropertyDeclaration(n)).WithAttributeLists(default) :
            n.WithExpressionBody(null).WithSemicolonToken(default).WithAttributeLists(default)
             .WithAccessorList(SyntaxFactory.AccessorList(SyntaxFactory.SingletonList(
                 SyntaxFactory.AccessorDeclaration(SyntaxKind.GetAccessorDeclaration).WithSemicolonToken(SyntaxFactory.Token(SyntaxKind.SemicolonToken)))));
        public override SyntaxNode VisitFieldDeclaration(FieldDeclarationSyntax n) =>
            n.WithAttributeLists(SyntaxFactory.List(n.AttributeLists.Where(a => a.ToString().Contains("SerializeField"))));
    }
}
