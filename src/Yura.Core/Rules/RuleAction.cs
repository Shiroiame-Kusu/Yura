namespace Yura.Core.Rules;

/// <summary>What happens to traffic that a rule matched.</summary>
public abstract record RuleAction
{
    private RuleAction() { }

    /// <summary>Send the traffic out the normal route, untouched. The default for unmatched traffic.</summary>
    public sealed record Direct : RuleAction
    {
        public static readonly Direct Instance = new();
        public override string ToString() => "Direct";
    }

    /// <summary>Refuse the connection. TCP is reset, UDP is dropped with an ICMP error.</summary>
    public sealed record Block : RuleAction
    {
        public static readonly Block Instance = new();
        public override string ToString() => "Block";
    }

    /// <summary>Forward the traffic to one user-supplied proxy endpoint.</summary>
    public sealed record Proxy(Guid EndpointId) : RuleAction
    {
        public override string ToString() => $"Proxy {EndpointId:D}";
    }

    /// <summary>Forward the traffic through an ordered chain of proxy endpoints.</summary>
    public sealed record Chain(Guid ChainId) : RuleAction
    {
        public override string ToString() => $"Chain {ChainId:D}";
    }

    /// <summary>True when the action needs a working proxy endpoint to be satisfiable.</summary>
    public bool RequiresProxy => this is Proxy or Chain;
}
