namespace Yura.Core.Games;

/// <summary>
/// One node of a Valve KeyValues document: a block with children, or a key with a value.
/// </summary>
/// <remarks>
/// Nesting is modelled rather than flattened. Flattening a KeyValues file into a dictionary
/// loses every repeated key, and the two files Yura reads both repeat keys that matter:
/// <c>libraryfolders.vdf</c> has one <c>path</c> per library, and an <c>appmanifest</c> has
/// keys inside <c>InstalledDepots</c> that would shadow the top-level ones.
/// </remarks>
public sealed class VdfNode
{
    private readonly List<VdfNode> _children = [];

    internal VdfNode(string key, string? value = null)
    {
        Key = key;
        Value = value;
    }

    public string Key { get; }

    /// <summary>The scalar value, or null when this node is a block.</summary>
    public string? Value { get; }

    public IReadOnlyList<VdfNode> Children => _children;

    public bool IsBlock => Value is null;

    internal void Add(VdfNode child) => _children.Add(child);

    /// <summary>The first scalar child with this key, or null. Case-insensitive, as Steam's own reader is.</summary>
    public string? this[string key] => _children
        .FirstOrDefault(c => !c.IsBlock && string.Equals(c.Key, key, StringComparison.OrdinalIgnoreCase))
        ?.Value;

    /// <summary>Child blocks, in file order.</summary>
    public IEnumerable<VdfNode> Blocks => _children.Where(c => c.IsBlock);

    public override string ToString() => IsBlock ? $"{Key} {{{_children.Count}}}" : $"{Key} = {Value}";
}

/// <summary>
/// Reads Valve's KeyValues text format, which Steam uses for both <c>.vdf</c> and <c>.acf</c>.
/// </summary>
/// <remarks>
/// The format is not documented by Valve, but it is small: quoted or bare tokens, blocks in
/// braces, <c>//</c> comments, backslash escapes inside quotes, and <c>[$CONDITION]</c>
/// suffixes that only game scripts use. Parsing is deliberately total — anything malformed
/// ends the document instead of throwing, because the caller's job is to list fewer games,
/// never to fail.
/// </remarks>
public static class ValveDataFormat
{
    /// <summary>Refuse absurd input rather than exhausting memory on a file that is not a manifest.</summary>
    private const long MaxFileBytes = 16 * 1024 * 1024;

    /// <summary>Hostile or corrupt nesting must not overflow the stack, so depth is bounded.</summary>
    private const int MaxDepth = 64;

    /// <summary>Reads and parses a file, returning null when it cannot be read or parsed.</summary>
    public static VdfNode? Read(string path)
    {
        try
        {
            if (new FileInfo(path).Length > MaxFileBytes)
            {
                return null;
            }

            return Parse(File.ReadAllText(path));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            return null;
        }
    }

    /// <summary>
    /// Parses a document into a synthetic root whose children are the top-level nodes.
    /// </summary>
    public static VdfNode Parse(string text)
    {
        var root = new VdfNode(string.Empty);
        var stack = new Stack<VdfNode>();
        stack.Push(root);

        var position = 0;
        string? pendingKey = null;

        while (true)
        {
            var token = NextToken(text, ref position);
            if (token is null)
            {
                break;
            }

            var (kind, value) = token.Value;
            switch (kind)
            {
                case TokenKind.OpenBrace:
                    if (pendingKey is null || stack.Count > MaxDepth)
                    {
                        return root; // A block with no key, or nesting past anything legitimate.
                    }

                    var block = new VdfNode(pendingKey);
                    stack.Peek().Add(block);
                    stack.Push(block);
                    pendingKey = null;
                    break;

                case TokenKind.CloseBrace:
                    pendingKey = null;
                    if (stack.Count == 1)
                    {
                        return root; // Unbalanced; keep what was read.
                    }

                    stack.Pop();
                    break;

                default:
                    if (pendingKey is null)
                    {
                        pendingKey = value;
                    }
                    else
                    {
                        stack.Peek().Add(new VdfNode(pendingKey, value));
                        pendingKey = null;
                    }

                    break;
            }
        }

        return root;
    }

    private enum TokenKind
    {
        String,
        OpenBrace,
        CloseBrace,
    }

    private static (TokenKind Kind, string Value)? NextToken(string text, ref int position)
    {
        while (position < text.Length)
        {
            var c = text[position];

            if (char.IsWhiteSpace(c))
            {
                position++;
                continue;
            }

            // Comments run to the end of the line. Steam writes these in config files it
            // rewrites by hand.
            if (c == '/' && position + 1 < text.Length && text[position + 1] == '/')
            {
                while (position < text.Length && text[position] != '\n')
                {
                    position++;
                }

                continue;
            }

            // Platform conditionals ("[$WIN32]") qualify the preceding pair. Yura reads files
            // that never use them, and skipping is closer to Valve's behaviour than treating
            // one as a key would be.
            if (c == '[')
            {
                while (position < text.Length && text[position] != ']')
                {
                    position++;
                }

                position++;
                continue;
            }

            switch (c)
            {
                case '{':
                    position++;
                    return (TokenKind.OpenBrace, "{");
                case '}':
                    position++;
                    return (TokenKind.CloseBrace, "}");
                case '"':
                    return (TokenKind.String, ReadQuoted(text, ref position));
                default:
                    return (TokenKind.String, ReadBare(text, ref position));
            }
        }

        return null;
    }

    private static string ReadQuoted(string text, ref int position)
    {
        position++; // Opening quote.
        var builder = new System.Text.StringBuilder();
        while (position < text.Length)
        {
            var c = text[position++];
            if (c == '"')
            {
                break;
            }

            if (c != '\\' || position >= text.Length)
            {
                builder.Append(c);
                continue;
            }

            // Windows paths arrive as "D:\\SteamLibrary", so unescaping is not optional.
            var escaped = text[position++];
            builder.Append(escaped switch
            {
                'n' => '\n',
                't' => '\t',
                'r' => '\r',
                _ => escaped,
            });
        }

        return builder.ToString();
    }

    private static string ReadBare(string text, ref int position)
    {
        var start = position;
        while (position < text.Length)
        {
            var c = text[position];
            if (char.IsWhiteSpace(c) || c is '{' or '}' or '"')
            {
                break;
            }

            position++;
        }

        return text[start..position];
    }
}
