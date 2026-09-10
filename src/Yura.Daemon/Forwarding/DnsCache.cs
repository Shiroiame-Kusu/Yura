using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Text;

namespace Yura.Daemon.Forwarding;

/// <summary>
/// Remembers which name an application resolved to reach an address, learned from the DNS
/// answers that pass through the relay.
/// </summary>
/// <remarks>
/// Host-name rules cannot be matched at the packet layer: the kernel sees addresses. When a
/// proxied process's DNS goes through the relay, its answers go past us, and mapping every
/// A/AAAA record in an answer to the name that was asked for gives later flows to those
/// addresses a name to match against. TLS SNI and HTTP Host headers are the other source;
/// this one is what makes plain TCP and UDP flows nameable at all.
///
/// Entries expire with the record TTL, clamped to a sane range, so a stale mapping cannot
/// route the wrong destination for long.
/// </remarks>
public sealed class DnsCache
{
    private const int MaxEntries = 8192;
    private static readonly TimeSpan MinTtl = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan MaxTtl = TimeSpan.FromHours(1);

    private readonly ConcurrentDictionary<IPAddress, (string Name, DateTimeOffset Expires)> _entries = new();

    public int Count => _entries.Count;

    public string? Lookup(IPAddress address)
    {
        if (!_entries.TryGetValue(address, out var entry))
        {
            return null;
        }

        if (entry.Expires < DateTimeOffset.UtcNow)
        {
            _entries.TryRemove(address, out _);
            return null;
        }

        return entry.Name;
    }

    /// <summary>Feeds one DNS response message. Malformed input is ignored, never thrown.</summary>
    /// <returns>The number of address records learned.</returns>
    public int Learn(ReadOnlySpan<byte> response)
    {
        var learned = 0;
        foreach (var (address, name, ttl) in DnsMessage.ReadAddressRecords(response))
        {
            var clamped = ttl < MinTtl ? MinTtl : ttl > MaxTtl ? MaxTtl : ttl;
            _entries[address] = (name, DateTimeOffset.UtcNow + clamped);
            learned++;
        }

        if (_entries.Count > MaxEntries)
        {
            Prune();
        }

        return learned;
    }

    private void Prune()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var (address, entry) in _entries)
        {
            if (entry.Expires < now)
            {
                _entries.TryRemove(address, out _);
            }
        }

        // Still over capacity: drop the soonest-to-expire until we are not.
        if (_entries.Count > MaxEntries)
        {
            foreach (var address in _entries.OrderBy(e => e.Value.Expires).Take(_entries.Count - MaxEntries).Select(e => e.Key).ToList())
            {
                _entries.TryRemove(address, out _);
            }
        }
    }
}

/// <summary>Just enough DNS wire-format parsing to pull addresses out of an answer.</summary>
public static class DnsMessage
{
    private const ushort TypeA = 1;
    private const ushort TypeAaaa = 28;

    /// <summary>
    /// Yields (address, queried name, ttl) for every A/AAAA record in the answer section.
    /// All addresses are attributed to the question name rather than to a CNAME target,
    /// because the question name is what the application asked for and what a rule names.
    /// </summary>
    public static IReadOnlyList<(IPAddress Address, string Name, TimeSpan Ttl)> ReadAddressRecords(ReadOnlySpan<byte> message)
    {
        var results = new List<(IPAddress, string, TimeSpan)>();
        if (message.Length < 12)
        {
            return results;
        }

        var flags = BinaryPrimitives.ReadUInt16BigEndian(message[2..]);
        if ((flags & 0x8000) == 0)
        {
            return results; // a query, not a response
        }

        var questions = BinaryPrimitives.ReadUInt16BigEndian(message[4..]);
        var answers = BinaryPrimitives.ReadUInt16BigEndian(message[6..]);
        var offset = 12;

        string? queried = null;
        for (var i = 0; i < questions; i++)
        {
            if (!TryReadName(message, ref offset, out var name) || offset + 4 > message.Length)
            {
                return results;
            }

            queried ??= name;
            offset += 4; // qtype + qclass
        }

        if (queried is null)
        {
            return results;
        }

        for (var i = 0; i < answers; i++)
        {
            if (!TryReadName(message, ref offset, out _) || offset + 10 > message.Length)
            {
                break;
            }

            var type = BinaryPrimitives.ReadUInt16BigEndian(message[offset..]);
            var ttl = BinaryPrimitives.ReadUInt32BigEndian(message[(offset + 4)..]);
            var length = BinaryPrimitives.ReadUInt16BigEndian(message[(offset + 8)..]);
            offset += 10;
            if (offset + length > message.Length)
            {
                break;
            }

            var rdata = message.Slice(offset, length);
            offset += length;

            if (type == TypeA && length == 4)
            {
                results.Add((new IPAddress(rdata), queried, TimeSpan.FromSeconds(ttl)));
            }
            else if (type == TypeAaaa && length == 16)
            {
                results.Add((new IPAddress(rdata), queried, TimeSpan.FromSeconds(ttl)));
            }
        }

        return results;
    }

    /// <summary>Reads a possibly compressed name. Bounded so a malicious pointer loop cannot spin.</summary>
    private static bool TryReadName(ReadOnlySpan<byte> message, ref int offset, out string name)
    {
        var sb = new StringBuilder(64);
        var position = offset;
        var jumped = false;
        var hops = 0;
        name = string.Empty;

        while (true)
        {
            if (position >= message.Length || ++hops > 128)
            {
                return false;
            }

            var length = message[position];
            if (length == 0)
            {
                position++;
                break;
            }

            if ((length & 0xC0) == 0xC0)
            {
                if (position + 1 >= message.Length)
                {
                    return false;
                }

                var pointer = ((length & 0x3F) << 8) | message[position + 1];
                if (!jumped)
                {
                    offset = position + 2;
                }

                jumped = true;
                position = pointer;
                continue;
            }

            position++;
            if (position + length > message.Length)
            {
                return false;
            }

            if (sb.Length > 0)
            {
                sb.Append('.');
            }

            sb.Append(Encoding.ASCII.GetString(message.Slice(position, length)));
            position += length;
        }

        if (!jumped)
        {
            offset = position;
        }

        name = sb.ToString();
        return true;
    }
}
