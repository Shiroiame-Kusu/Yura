using System.Buffers.Binary;
using System.Net.Sockets;
using System.Text;

namespace Yura.Daemon.Forwarding;

/// <summary>
/// Learns the destination host name of a captured TCP flow from its first bytes, without
/// consuming them: a TLS ClientHello's SNI, or an HTTP request's Host header.
/// </summary>
/// <remarks>
/// Only run when a host-name rule exists that could apply. It costs the first round trip a
/// short wait for protocols where the server speaks first (SSH, SMTP), which is why it is
/// off unless a rule needs it. Peeking (<see cref="SocketFlags.Peek"/>) leaves the bytes in
/// the receive buffer, so the relay forwards the stream intact afterwards.
/// </remarks>
public static class HostSniffer
{
    private const int PeekSize = 8192;

    public static async Task<string?> PeekHostAsync(Socket client, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var buffer = new byte[PeekSize];
        var deadline = DateTimeOffset.UtcNow + timeout;
        using var window = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        window.CancelAfter(timeout);

        try
        {
            while (true)
            {
                int peeked;
                try
                {
                    peeked = await client.ReceiveAsync(buffer, SocketFlags.Peek, window.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    return null; // the client sent nothing within the window; not an error
                }

                if (peeked == 0)
                {
                    return null;
                }

                var data = buffer.AsSpan(0, peeked);
                if (TryParseTlsServerName(data, out var sni, out var needMore))
                {
                    return sni;
                }

                if (!needMore)
                {
                    return TryParseHttpHost(data);
                }

                if (peeked >= PeekSize || DateTimeOffset.UtcNow >= deadline)
                {
                    return null;
                }

                // A ClientHello split across segments: give the rest a moment to arrive.
                await Task.Delay(15, window.Token).ConfigureAwait(false);
            }
        }
        catch (Exception e) when (e is SocketException or ObjectDisposedException or OperationCanceledException)
        {
            return null;
        }
    }

    /// <summary>
    /// Parses the server_name extension out of a TLS ClientHello.
    /// </summary>
    /// <param name="needMore">
    /// True when the bytes look like the start of a ClientHello but do not contain all of it
    /// yet; the caller should peek again.
    /// </param>
    public static bool TryParseTlsServerName(ReadOnlySpan<byte> data, out string? host, out bool needMore)
    {
        host = null;
        needMore = false;

        // TLS record: type(1)=0x16 handshake, version(2), length(2)
        if (data.Length < 5)
        {
            needMore = data.Length > 0 && data[0] == 0x16;
            return false;
        }

        if (data[0] != 0x16 || data[1] != 0x03)
        {
            return false;
        }

        var recordLength = BinaryPrimitives.ReadUInt16BigEndian(data[3..]);
        if (data.Length < 5 + recordLength)
        {
            needMore = true;
            return false;
        }

        var handshake = data.Slice(5, recordLength);
        // Handshake: type(1)=0x01 ClientHello, length(3)
        if (handshake.Length < 4 || handshake[0] != 0x01)
        {
            return false;
        }

        var bodyLength = (handshake[1] << 16) | (handshake[2] << 8) | handshake[3];
        if (handshake.Length < 4 + bodyLength)
        {
            // The ClientHello continues in a later record; treat as incomplete.
            needMore = true;
            return false;
        }

        var body = handshake.Slice(4, bodyLength);
        var offset = 2 + 32; // client_version + random
        if (body.Length < offset + 1)
        {
            return false;
        }

        var sessionIdLength = body[offset];
        offset += 1 + sessionIdLength;
        if (body.Length < offset + 2)
        {
            return false;
        }

        var cipherSuitesLength = BinaryPrimitives.ReadUInt16BigEndian(body[offset..]);
        offset += 2 + cipherSuitesLength;
        if (body.Length < offset + 1)
        {
            return false;
        }

        var compressionLength = body[offset];
        offset += 1 + compressionLength;
        if (body.Length < offset + 2)
        {
            return false; // no extensions
        }

        var extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(body[offset..]);
        offset += 2;
        var end = Math.Min(body.Length, offset + extensionsLength);

        while (offset + 4 <= end)
        {
            var type = BinaryPrimitives.ReadUInt16BigEndian(body[offset..]);
            var length = BinaryPrimitives.ReadUInt16BigEndian(body[(offset + 2)..]);
            offset += 4;
            if (offset + length > end)
            {
                break;
            }

            if (type == 0x0000) // server_name
            {
                var list = body.Slice(offset, length);
                if (list.Length < 2)
                {
                    return false;
                }

                var listLength = BinaryPrimitives.ReadUInt16BigEndian(list);
                var position = 2;
                while (position + 3 <= Math.Min(list.Length, 2 + listLength))
                {
                    var nameType = list[position];
                    var nameLength = BinaryPrimitives.ReadUInt16BigEndian(list[(position + 1)..]);
                    position += 3;
                    if (position + nameLength > list.Length)
                    {
                        return false;
                    }

                    if (nameType == 0)
                    {
                        var name = Encoding.ASCII.GetString(list.Slice(position, nameLength));
                        if (IsPlausibleHost(name))
                        {
                            host = name;
                            return true;
                        }

                        return false;
                    }

                    position += nameLength;
                }

                return false;
            }

            offset += length;
        }

        return false;
    }

    /// <summary>Extracts the Host header from the start of an HTTP/1.x request.</summary>
    public static string? TryParseHttpHost(ReadOnlySpan<byte> data)
    {
        // Cheap gate: a request line starts with a method token followed by a space.
        var space = data.IndexOf((byte)' ');
        if (space is < 3 or > 10)
        {
            return null;
        }

        for (var i = 0; i < space; i++)
        {
            if (data[i] is < (byte)'A' or > (byte)'Z')
            {
                return null;
            }
        }

        var text = Encoding.ASCII.GetString(data[..Math.Min(data.Length, 4096)]);
        foreach (var line in text.Split("\r\n"))
        {
            if (line.Length == 0)
            {
                break; // end of headers
            }

            if (line.StartsWith("Host:", StringComparison.OrdinalIgnoreCase))
            {
                var value = line[5..].Trim();
                // Strip a port suffix; keep an IPv6 literal intact.
                if (!value.StartsWith('[') && value.LastIndexOf(':') is var colon and > 0)
                {
                    value = value[..colon];
                }
                else if (value.StartsWith('[') && value.IndexOf(']') is var close and > 0)
                {
                    value = value[1..close];
                }

                return IsPlausibleHost(value) ? value : null;
            }
        }

        return null;
    }

    private static bool IsPlausibleHost(string name) =>
        name.Length is > 0 and <= 253 &&
        name.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or ':' or '_');
}
