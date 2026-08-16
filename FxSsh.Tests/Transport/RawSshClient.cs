using System;
using System.Buffers.Binary;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FxSsh.Algorithms;

namespace FxSsh.Tests.Transport;

/// <summary>
/// Minimal raw SSH transport client for protocol-level tests. It completes the
/// version-string exchange (RFC 4253 section 4.2), reads the server's
/// SSH_MSG_KEXINIT, and can then send and read framed packets. It performs NO
/// key exchange and NO encryption itself; a caller that has completed a key
/// exchange can hand the negotiated decryptor and MAC to
/// <see cref="ReadEncryptedPacketAsync"/> to read the first packets under the
/// new keys (e.g. SSH_MSG_EXT_INFO). Only useful pre-auth, which is exactly the
/// surface the fork's packet-sizing and first-packet-guess logic lives on.
///
/// Frame format (RFC 4253 section 6, no cipher/MAC yet):
///   [packet_length:4][padding_length:1][payload][padding]
///   packet_length = padding_length + payload + padding, total multiple of block size (8).
/// </summary>
internal sealed class RawSshClient : IDisposable
{
    public const int PreAuthBlockSize = 8;
    public const byte SshMsgDisconnect = 1;
    public const byte SshMsgUnimplemented = 3;
    public const byte SshMsgKexInit = 20;

    private readonly TcpClient _tcp;
    private readonly NetworkStream _stream;

    private RawSshClient(TcpClient tcp, NetworkStream stream, string serverVersion, byte[] serverKexInit)
    {
        _tcp = tcp;
        _stream = stream;
        ServerVersion = serverVersion;
        ServerKexInitPayload = serverKexInit;
    }

    public string ServerVersion { get; }
    public byte[] ServerKexInitPayload { get; }

    public static async Task<RawSshClient> ConnectAsync(int port, CancellationToken ct = default)
    {
        var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, port, ct);
        var stream = tcp.GetStream();

        var serverVersion = await ReadLineAsync(stream, ct);
        await WriteAllAsync(stream, [.. "SSH-2.0-TestClient\r\n"u8], ct);
        var serverKexInit = await ReadPacketAsync(stream, ct);

        return new RawSshClient(tcp, stream, serverVersion, serverKexInit);
    }

    public Task SendPacketAsync(byte[] framedPacket, CancellationToken ct = default)
        => WriteAllAsync(_stream, framedPacket, ct);

    /// <summary>Reads one framed packet; returns the payload including the type byte (pre-auth, no MAC).</summary>
    public Task<byte[]> ReadPacketAsync(CancellationToken ct = default)
        => ReadPacketAsync(_stream, ct);

    /// <summary>
    /// Reads one packet encrypted under the negotiated session keys and
    /// verifies its MAC (RFC 4253 section 6, non-ETM layout):
    /// [encrypt(packet_length || padding_length || payload || padding)][MAC].
    /// The MAC covers <c>seq || plaintext frame</c>, where
    /// <paramref name="sequence"/> is the peer's outbound sequence number for
    /// this packet. <paramref name="createDecryptor"/> supplies a fresh
    /// CTR/CBC decryptor (same key/IV); the length probe runs on a scratch
    /// instance so the real stream stays aligned at keystream byte 0 for a
    /// single full-frame Transform. Returns the decrypted payload including
    /// the type byte.
    /// </summary>
    public async Task<byte[]> ReadEncryptedPacketAsync(Func<EncryptionAlgorithm> createDecryptor, HmacAlgorithm mac, uint sequence, CancellationToken ct = default)
    {
        var lenCipher = new byte[4];
        if (!await ReadExactlyAsync(_stream, lenCipher, 4, ct))
            return [];

        // packet_length sits in the first 4 bytes of the first CTR keystream
        // block. Decrypt a full block (4 real bytes + zero pad) on a SCRATCH
        // stream: the transform consumes keystream in whole blocks, so a
        // 4-byte Transform on the real stream would misalign the body by 12
        // bytes.
        var scratchIn = new byte[16];
        lenCipher.CopyTo(scratchIn, 0);
        var scratchOut = new byte[16];
        createDecryptor().Transform(scratchIn, 16, scratchOut);

        var packetLength = (int)BinaryPrimitives.ReadUInt32BigEndian(scratchOut);
        if (packetLength is < 4 or > 35000 + 64)
            throw new IOException($"Malformed frame length {packetLength}.");

        // Read the remaining ciphertext, then decrypt the WHOLE frame in one
        // Transform call - exactly how the peer encrypted it.
        var allCipher = new byte[4 + packetLength];
        lenCipher.CopyTo(allCipher, 0);
        var rest = new byte[packetLength];
        if (!await ReadExactlyAsync(_stream, rest, packetLength, ct))
            return [];
        rest.CopyTo(allCipher, 4);

        var allPlain = new byte[4 + packetLength];
        createDecryptor().Transform(allCipher, 4 + packetLength, allPlain);

        var wireMac = new byte[mac.DigestLength];
        if (!await ReadExactlyAsync(_stream, wireMac, mac.DigestLength, ct))
            return [];

        var expectedMac = new byte[mac.DigestLength];
        mac.ComputeHash(allPlain, [], sequence, expectedMac);
        if (!wireMac.AsSpan().SequenceEqual(expectedMac))
            throw new InvalidDataException("MAC mismatch on encrypted packet.");

        var paddingLength = allPlain[4];
        var payloadLength = packetLength - 1 - paddingLength;
        var payload = new byte[payloadLength];
        Array.Copy(allPlain, 5, payload, 0, payloadLength);
        return payload;
    }

    /// <summary>
    /// Waits until the peer closes the connection: EOF, IOException, or an
    /// SSH_MSG_DISCONNECT packet. Returns false if the timeout elapses first
    /// (i.e. the connection stayed open).
    /// </summary>
    public async Task<bool> WaitForCloseAsync(TimeSpan timeout)
    {
        using var cts = new CancellationTokenSource(timeout);
        try
        {
            var payload = await ReadPacketAsync(cts.Token);
            if (payload.Length == 0) return true; // EOF: peer closed the connection
            // A DISCONNECT packet also means the session is being torn down.
            return payload[0] == SshMsgDisconnect;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or SocketException)
        {
            return true;
        }
    }

    /// <summary>Frames a payload with automatic block-aligned padding (padding >= 4).</summary>
    public static byte[] Frame(byte[] payload, int blockSize = PreAuthBlockSize)
    {
        // packet_length = 1 (padding_length byte) + payload + padding;
        // total wire size (4 + packet_length) must be a multiple of blockSize.
        var padding = (blockSize - ((payload.Length + 5) % blockSize)) % blockSize;
        if (padding < 4) padding += blockSize;
        return BuildFrame(1 + payload.Length + padding, payload);
    }

    /// <summary>
    /// Frames with an exact packet_length (boundary tests). The payload is
    /// zero-padded to fill the packet; padding_length is derived from the
    /// payload length.
    /// </summary>
    public static byte[] FrameWithLength(int packetLength, byte[] payload)
    {
        var paddingLength = packetLength - 1 - payload.Length;
        return paddingLength < 0 ? throw new ArgumentException("Payload does not fit the requested packet_length.", nameof(payload)) : BuildFrame(packetLength, payload);
    }

    private static byte[] BuildFrame(int packetLength, byte[] payload)
    {
        var paddingLength = packetLength - 1 - payload.Length;
        var frame = new byte[4 + packetLength];
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(0, 4), (uint)packetLength);
        frame[4] = (byte)paddingLength;
        Buffer.BlockCopy(payload, 0, frame, 5, payload.Length);
        return frame; // padding bytes are zeros
    }

    private static async Task<string> ReadLineAsync(NetworkStream stream, CancellationToken ct)
    {
        var sb = new StringBuilder();
        var single = new byte[1];
        while (true)
        {
            var read = await stream.ReadAsync(single.AsMemory(0, 1), ct);
            if (read == 0) throw new IOException("EOF while reading version string.");
            if (single[0] == (byte)'\n') return sb.ToString().TrimEnd('\r');
            sb.Append((char)single[0]);
        }
    }

    private static async Task<byte[]> ReadPacketAsync(NetworkStream stream, CancellationToken ct)
    {
        var lenBuf = new byte[4];
        if (!await ReadExactlyAsync(stream, lenBuf, 4, ct))
            return [];

        var packetLength = (int)BinaryPrimitives.ReadUInt32BigEndian(lenBuf);
        if (packetLength is < 4 or > 35000 + 64)
            throw new IOException($"Malformed frame length {packetLength}.");

        var rest = new byte[packetLength];
        if (!await ReadExactlyAsync(stream, rest, packetLength, ct))
            return [];

        // rest = [padding_length(1)][payload][padding]
        var paddingLength = rest[0];
        var payloadLength = packetLength - 1 - paddingLength;
        if (payloadLength < 0) return [];

        var payload = new byte[payloadLength];
        Array.Copy(rest, 1, payload, 0, payloadLength);
        return payload;
    }

    private static async Task<bool> ReadExactlyAsync(NetworkStream stream, byte[] buffer, int count, CancellationToken ct)
    {
        var offset = 0;
        while (offset < count)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset, count - offset), ct);
            if (read == 0) return false;
            offset += read;
        }
        return true;
    }

    private static async Task WriteAllAsync(NetworkStream stream, byte[] bytes, CancellationToken ct)
    {
        await stream.WriteAsync(bytes.AsMemory(0, bytes.Length), ct);
        await stream.FlushAsync(ct);
    }

    public void Dispose()
    {
        _stream.Dispose();
        _tcp.Dispose();
    }
}
