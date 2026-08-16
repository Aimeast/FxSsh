using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FxSsh.Algorithms;
using FxSsh.Messages;
using FxSsh.Tests.Transport;
using Xunit;

namespace FxSsh.Tests;

/// <summary>
/// RFC 8332 regression: the server must advertise the signature algorithms it
/// accepts for publickey auth via the "server-sig-algs" extension
/// (SSH_MSG_EXT_INFO, RFC 8308). OpenSSH 8.8+ refuses to sign the
/// authentication challenge unless the server sends this extension - without
/// it the client assumes only legacy ssh-rsa (SHA-1) signatures are accepted,
/// which modern OpenSSH refuses to produce. The extension goes out as the
/// FIRST message under the new keys, right after SSH_MSG_NEWKEYS, and only
/// when the client advertised "ext-info-c" in its KEXINIT.
///
/// These tests drive a full client-side key exchange over the raw transport
/// client (RFC 5656 ecdh-sha2-nistp256 + aes256-ctr + hmac-sha2-256), then
/// decrypt and MAC-verify the server's first encrypted packet, so the EXT_INFO
/// content is asserted deterministically without relying on an external ssh
/// binary. If the session ever stopped sending server-sig-algs (e.g. the
/// Session constructor's RegisterExtension call was dropped), the first test
/// fails on the missing extension - the exact regression this guards.
/// </summary>
public class ServerSigAlgsTests
{
    private const byte SshMsgKexEcdhInit = 30;
    private const byte SshMsgKexEcdhReply = 31;
    private const byte SshMsgNewKeys = 21;
    private const byte SshMsgExtInfo = 7;

    private const string ClientVersion = "SSH-2.0-TestClient"; // matches RawSshClient

    [Fact(Timeout = 15_000)]
    public async Task Server_advertises_server_sig_algs_when_client_advertises_ext_info_c()
    {
        await using var server = TestSshServer.Start();
        using var client = await RawSshClient.ConnectAsync(server.Port, TestContext.Current.CancellationToken);

        var kex = await CompleteKeyExchangeAsync(client, advertiseExtInfo: true, TestContext.Current.CancellationToken);

        // RFC 8308 section 2.2: EXT_INFO is the first message under the new keys.
        // The read is bounded: when server-sig-algs is not registered, no
        // EXT_INFO is sent at all, so this must FAIL fast - never hang.
        Assert.True(kex.FirstEncryptedPayload is not null,
            "Server sent no SSH_MSG_EXT_INFO after NEWKEYS - server-sig-algs is not being advertised (RFC 8332).");
        Assert.Equal(SshMsgExtInfo, kex.FirstEncryptedPayload![0]);

        var extensions = ParseExtInfo(kex.FirstEncryptedPayload);
        Assert.Contains("server-sig-algs", extensions.Keys);

        //// RFC 8332 section 3.1: the value is the comma-separated list of the
        //// public-key algorithms the server accepts for publickey auth - i.e.
        //// exactly the pluggable registry's keys, in preference order.
        //var expected = String.Join(",", server.SupportedAlgorithms.PublicKey.Keys);
        //Assert.Equal(expected, extensions["server-sig-algs"]);

        // Concrete pin for the OpenSSH 8.8+ scenario: rsa-sha2-* must be
        // advertised so an RSA user key can be signed at all.
        Assert.Contains("rsa-sha2-256", extensions["server-sig-algs"]);
        Assert.Contains("rsa-sha2-512", extensions["server-sig-algs"]);
    }

    [Fact(Timeout = 15_000)]
    public async Task Server_sends_no_EXT_INFO_when_client_does_not_advertise_ext_info_c()
    {
        await using var server = TestSshServer.Start();
        using var client = await RawSshClient.ConnectAsync(server.Port, TestContext.Current.CancellationToken);

        await CompleteKeyExchangeAsync(client, advertiseExtInfo: false, TestContext.Current.CancellationToken);

        // RFC 8308: EXT_INFO is gated on the client's ext-info-c marker. After
        // NEWKEYS the server must stay silent here - no EXT_INFO may appear.
        var extra = await ReadWithTimeoutAsync(client, TimeSpan.FromMilliseconds(400), TestContext.Current.CancellationToken);
        Assert.Null(extra);
    }

    /// <summary>
    /// Runs a complete client-side key exchange (RFC 4253 + RFC 5656) against
    /// the server: KEXINIT with the optional "ext-info-c" marker, KEX_ECDH_INIT,
    /// key derivation, NEWKEYS, and - when the marker was sent - reads back and
    /// decrypts the server's first encrypted packet (the EXT_INFO).
    /// </summary>
    private static async Task<CompleteKexResult> CompleteKeyExchangeAsync(
        RawSshClient client, bool advertiseExtInfo, CancellationToken ct)
    {
        // Mirror the server's offers so negotiation deterministically selects
        // the server's own first preference for each category (the server's
        // ChooseAlgorithm scans the CLIENT's list, and every algorithm we offer
        // is supported): ecdh-sha2-nistp256 / ecdsa-sha2-nistp256 / aes256-ctr /
        // hmac-sha2-256 / none. "ext-info-c" (RFC 8308) rides in the kex
        // name-list, exactly where OpenSSH puts its markers.
        var lists = KexInitParser.ParseNameLists(client.ServerKexInitPayload);
        // Offer only the ECDH P-256 kex (plus the RFC 8308 marker when
        // advertising EXT_INFO) so negotiation deterministically selects
        // ecdh-sha2-nistp256 - the exchange below is ECDH-specific. Mirroring
        // the server's full offer list would negotiate its first preference,
        // curve25519-sha256 (RFC 8731), and the P-256 SSH_MSG_KEX_ECDH_INIT
        // payload would be misrouted to the X25519 parser.
        string[] kexAlgorithms = advertiseExtInfo
            ? ["ecdh-sha2-nistp256", "ext-info-c"]
            : ["ecdh-sha2-nistp256"];

        var clientKexInit = new KeyExchangeInitMessage
        {
            KeyExchangeAlgorithms = kexAlgorithms,
            ServerHostKeyAlgorithms = lists[1],
            EncryptionAlgorithmsClientToServer = lists[2],
            EncryptionAlgorithmsServerToClient = lists[3],
            MacAlgorithmsClientToServer = lists[4],
            MacAlgorithmsServerToClient = lists[5],
            CompressionAlgorithmsClientToServer = lists[6],
            CompressionAlgorithmsServerToClient = lists[7],
            LanguagesClientToServer = lists[8],
            LanguagesServerToClient = lists[9],
            FirstKexPacketFollows = false,
            Reserved = 0,
        };

        var clientKexInitPayload = clientKexInit.GetPacket();
        await client.SendPacketAsync(RawSshClient.Frame(clientKexInitPayload), ct);

        // RFC 5656 section 4: SSH_MSG_KEX_ECDH_INIT carries Q_C as a string
        // (0x04 || X || Y), the same encoding EcdhKex.CreateKeyExchange emits.
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var qc = EcdhPublicPoint(ecdh.PublicKey.ExportParameters().Q);
        await client.SendPacketAsync(RawSshClient.Frame(SshMessage(SshMsgKexEcdhInit, WriteBinary(qc))), ct);

        // SSH_MSG_KEX_ECDH_REPLY: string K_S, string Q_S, string signature.
        var reply = await ReadWithTimeoutAsync(client, TimeSpan.FromSeconds(5), ct)
            ?? throw new IOException("Server did not reply with SSH_MSG_KEX_ECDH_REPLY.");
        Assert.Equal(SshMsgKexEcdhReply, reply[0]);
        var pos = 1;
        var hostKey = ReadBinary(reply, ref pos);
        var qsBlob = ReadBinary(reply, ref pos);
        ReadBinary(reply, ref pos); // signature - host trust is out of scope here

        // The server sends its NEWKEYS under the OLD keys, right after the reply.
        var serverNewKeys = await ReadWithTimeoutAsync(client, TimeSpan.FromSeconds(5), ct)
            ?? throw new IOException("Server did not send SSH_MSG_NEWKEYS.");
        Assert.Equal(SshMsgNewKeys, serverNewKeys[0]);

        // Shared secret K: the raw ECDH agreement, sign-extended big-endian,
        // exactly as EcdhKex.DecryptKeyExchange converts it.
        using var serverKey = ECDiffieHellman.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = ParsePoint(qsBlob),
        });
        var agreement = ecdh.DeriveRawSecretAgreement(serverKey.PublicKey);
        var sharedSecret = new BigInteger(agreement, isUnsigned: true, isBigEndian: true)
            .ToByteArray(isUnsigned: false, isBigEndian: true);

        // H = SHA256(V_C || V_S || I_C || I_S || K_S || Q_C || Q_S || K);
        // on the first exchange SessionId == H.
        var exchangeHash = SHA256.HashData(BuildExchangeHashInput(
            client.ServerVersion, clientKexInitPayload, client.ServerKexInitPayload,
            hostKey, qc, qsBlob, sharedSecret));

        // RFC 4253 section 7.2 key derivation; letters B/D/F are the
        // server-to-client IV, encryption key and MAC key.
        var serverIv = DeriveKey(sharedSecret, exchangeHash, exchangeHash, 'B', 16);
        var serverCipherKey = DeriveKey(sharedSecret, exchangeHash, exchangeHash, 'D', 32);
        var serverMacKey = DeriveKey(sharedSecret, exchangeHash, exchangeHash, 'F', 32);

        // Client NEWKEYS (under old keys); the server then applies the new keys
        // and, if we advertised ext-info-c, sends EXT_INFO as its first
        // encrypted message.
        await client.SendPacketAsync(RawSshClient.Frame([SshMsgNewKeys]), ct);
        if (!advertiseExtInfo)
            return new CompleteKexResult(null);

        // Server outbound sequence number at EXT_INFO: KEXINIT(0),
        // KEX_ECDH_REPLY(1), NEWKEYS(2) - the session never resets the counter.
        var cipher = new CipherInfo(Aes.Create(), 256, CipherModeEx.CTR);
        var mac = new HmacInfo(new HMACSHA256(), 256).Hmac(serverMacKey);
        // Bounded, like the plaintext reads: if the session stopped advertising
        // server-sig-algs (RFC 8332), the server sends no EXT_INFO at all, so
        // an unbounded read here would hang the test run forever.
        var extInfo = await ReadEncryptedWithTimeoutAsync(client, () => cipher.Cipher(serverCipherKey, serverIv, false), mac, sequence: 3, TimeSpan.FromSeconds(5), ct);
        return new CompleteKexResult(extInfo);
    }

    private static byte[] BuildExchangeHashInput(
        string serverVersion, byte[] clientKexInit, byte[] serverKexInit,
        byte[] hostKey, byte[] clientQ, byte[] serverQ, byte[] sharedSecret)
    {
        // Same field order and encodings as Session.ComputeExchangeHash; the
        // version strings are used in full ("SSH-2.0-" prefix included).
        return new SshDataWriter()
            .Write(ClientVersion, Encoding.ASCII)
            .Write(serverVersion, Encoding.ASCII)
            .WriteBinary(clientKexInit)
            .WriteBinary(serverKexInit)
            .WriteBinary(hostKey)
            .WriteBinary(clientQ)
            .WriteBinary(serverQ)
            .WriteMpint(sharedSecret)
            .ToByteArray();
    }

    private static byte[] DeriveKey(byte[] sharedSecret, byte[] exchangeHash, byte[] sessionId, char letter, int length)
    {
        // RFC 4253 section 7.2: K1 = HASH(K || H || letter || session_id). One
        // iteration suffices: SHA-256 output (32 bytes) covers the 16/32-byte
        // keys derived here.
        var digest = SHA256.HashData(new SshDataWriter()
            .WriteMpint(sharedSecret)
            .WriteBytes(exchangeHash)
            .Write((byte)letter)
            .WriteBytes(sessionId)
            .ToByteArray());
        return [.. digest.AsSpan(0, length)];
    }

    private static byte[] EcdhPublicPoint(ECPoint q)
    {
        var x = q.X!;
        var y = q.Y!;
        var blob = new byte[1 + x.Length + y.Length];
        blob[0] = 0x04;
        x.CopyTo(blob, 1);
        y.CopyTo(blob, 1 + x.Length);
        return blob;
    }

    private static ECPoint ParsePoint(byte[] blob)
    {
        Assert.Equal(0x04, blob[0]);
        var half = (blob.Length - 1) / 2;
        return new ECPoint { X = blob[1..(1 + half)], Y = blob[(1 + half)..] };
    }

    /// <summary>Parses SSH_MSG_EXT_INFO (7): uint32 count, then (string name, string value) pairs.</summary>
    private static Dictionary<string, string> ParseExtInfo(byte[] payload)
    {
        var pos = 1; // skip the type byte
        var count = (int)BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(pos, 4));
        pos += 4;
        var extensions = new Dictionary<string, string>(count);
        for (var i = 0; i < count; i++)
        {
            var name = Encoding.ASCII.GetString(ReadBinary(payload, ref pos));
            var value = Encoding.UTF8.GetString(ReadBinary(payload, ref pos));
            extensions[name] = value;
        }
        return extensions;
    }

    private static byte[] SshMessage(byte type, byte[] body)
    {
        var packet = new byte[1 + body.Length];
        packet[0] = type;
        body.CopyTo(packet, 1);
        return packet;
    }

    private static byte[] WriteBinary(byte[] data)
    {
        var result = new byte[4 + data.Length];
        BinaryPrimitives.WriteUInt32BigEndian(result, (uint)data.Length);
        data.CopyTo(result, 4);
        return result;
    }

    private static byte[] ReadBinary(byte[] buffer, ref int pos)
    {
        var len = (int)BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(pos, 4));
        pos += 4;
        var value = buffer[pos..(pos + len)];
        pos += len;
        return value;
    }

    private static async Task<byte[]?> ReadWithTimeoutAsync(RawSshClient client, TimeSpan timeout, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        try
        {
            return await client.ReadPacketAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            return null;
        }
    }

    /// <summary>
    /// Bounded read of the first encrypted packet: returns null when nothing
    /// arrives within <paramref name="timeout"/> (or the peer closes), so a
    /// missing SSH_MSG_EXT_INFO surfaces as a fast test failure instead of a
    /// hang. Also nulls out the EOF sentinel ([]) ReadEncryptedPacketAsync
    /// returns when the connection is gone.
    /// </summary>
    private static async Task<byte[]?> ReadEncryptedWithTimeoutAsync(
        RawSshClient client, Func<EncryptionAlgorithm> createDecryptor, HmacAlgorithm mac, uint sequence,
        TimeSpan timeout, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        try
        {
            var payload = await client.ReadEncryptedPacketAsync(createDecryptor, mac, sequence, cts.Token);
            return payload.Length == 0 ? null : payload;
        }
        catch (OperationCanceledException)
        {
            return null;
        }
    }

    private sealed record CompleteKexResult(byte[]? FirstEncryptedPayload);
}
