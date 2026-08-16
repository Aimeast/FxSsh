using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;

namespace FxSsh.Tests.Transport;

/// <summary>
/// Parses the ten name-lists of an SSH_MSG_KEXINIT payload (RFC 4253
/// section 7.1): kex, host key, encryption c2s/s2c, MAC c2s/s2c,
/// compression c2s/s2c, and languages c2s/s2c.
/// </summary>
internal static class KexInitParser
{
    public const int NameListCount = 10;

    /// <summary>
    /// Extracts all ten name-lists from a KEXINIT payload (including the type
    /// byte), each split on commas, in wire order.
    /// </summary>
    public static string[][] ParseNameLists(byte[] payload)
    {
        var pos = 0;
        if (payload[pos++] != RawSshClient.SshMsgKexInit)
            throw new InvalidOperationException("First server packet was not SSH_MSG_KEXINIT.");
        pos += 16; // cookie

        var lists = new List<string[]>(NameListCount);
        for (var i = 0; i < NameListCount; i++)
        {
            var len = (int)BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(pos, 4));
            pos += 4;
            lists.Add(Encoding.ASCII.GetString(payload, pos, len).Split(',', StringSplitOptions.RemoveEmptyEntries));
            pos += len;
        }

        return [.. lists];
    }
}
