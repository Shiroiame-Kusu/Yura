namespace Yura.Core.Rules;

/// <summary>
/// What happens to DNS traffic from a process whose rule sends it through a proxy.
/// </summary>
/// <remarks>
/// Shared by both workflows: a game profile and a manual process rule resolve names the
/// same way. The default keeps DNS inside the proxy so the proxy's view of the network is
/// the one the application sees, and so a name lookup cannot leak the destination to the
/// local resolver.
/// </remarks>
public enum DnsPolicy
{
    /// <summary>
    /// DNS from proxied processes is captured like any other traffic. UDP lookups are relayed
    /// through the proxy's UDP association, or over TCP when the proxy cannot carry UDP.
    /// </summary>
    ThroughProxy,

    /// <summary>DNS from proxied processes goes out directly, bypassing the proxy.</summary>
    Direct,
}
