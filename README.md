## FxSsh
FxSsh is a lightweight [SSH](https://en.wikipedia.org/wiki/Secure_Shell) server side library.

---
### Nuget
[![NuGet version](https://badge.fury.io/nu/FxSsh.svg)](https://www.nuget.org/packages/FxSsh/)

`PM> Install-Package FxSsh`

Target `net8.0`

### RFCs
FxSsh adheres to the following RFC documents
- [RFC4250](https://tools.ietf.org/html/rfc4250)  Protocol Assigned Numbers
- [RFC4251](https://tools.ietf.org/html/rfc4251)  Protocol Architecture
- [RFC4252](https://tools.ietf.org/html/rfc4252)  Authentication Protocol
- [RFC4253](https://tools.ietf.org/html/rfc4253)  Transport Layer Protocol
- [RFC4254](https://tools.ietf.org/html/rfc4254)  Connection Protocol
- [RFC4344](https://tools.ietf.org/html/rfc4344)  Transport Layer Encryption Modes
- [RFC5647](https://tools.ietf.org/html/rfc5647)  AES Galois Counter Mode for the Secure Shell Transport Layer Protocol
- [RFC5656](https://tools.ietf.org/html/rfc5656)  Elliptic Curve Algorithm Integration
- [RFC6668](https://tools.ietf.org/html/rfc6668)  SHA-2 Data Integrity Algorithms
- [RFC8308](https://tools.ietf.org/html/rfc8308)  Extension Negotiation in the Secure Shell (SSH) Protocol
- [RFC8332](https://tools.ietf.org/html/rfc8332)  Use of RSA Keys with SHA-2
- [RFC8731](https://tools.ietf.org/html/rfc8731)  Secure Shell (SSH) Key Exchange Method Using Curve25519 and Curve448
- [draft-ietf-secsh-filexfer-02](https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02)  SSH File Transfer Protocol (sftp version 3)

### Supported Algorithms

| **Category**          | **Algorithms**                                                                |
|-----------------------|-------------------------------------------------------------------------------|
| **Public Key**        | RSA family: `rsa-sha2-256`, `rsa-sha2-512`<br>ECDsa family: `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521` |
| **Key Exchange (KEX)**| DH family: `diffie-hellman-group14-sha256`, `diffie-hellman-group16-sha512`, `diffie-hellman-group18-sha512`<br>ECDH family: `ecdh-sha2-nistp256`, `ecdh-sha2-nistp384`, `ecdh-sha2-nistp521`<br>X25519: `curve25519-sha256` |
| **Encryption**        | `aes256-ctr`, `aes128-gcm@openssh.com`, `aes256-gcm@openssh.com` |
| **MAC**               | `hmac-sha2-256`, `hmac-sha2-512`, `hmac-sha2-256-etm@openssh.com`, `hmac-sha2-512-etm@openssh.com` |
| **Compression**       | `none`                                                                        |

### Supported Services

| **Service**        | **Details**                                                             |
|--------------------|-------------------------------------------------------------------------|
| **Authentication** | `publickey`, `password`<br>`none` (optional, opt-in via `EnableNoneAuth`)          |
| **Connection**     | `session` (e.g., exec, shell)<br>`direct-tcpip`, `forwarded-tcpip`<br>`tcpip-forward` / `cancel-tcpip-forward` (reverse port forwarding)<br>`keepalive@openssh.com` (global request)<br>`subsystem` (dispatch via `SubsystemRequested`) |
| **subsystem**      | `sftp (version 3)`, provided by the core library's `FxSsh.Services.Sftp` (attach via `SftpService.Attach`, read-only via `SftpService(readOnly: true)`) |

### Tested Clients

| **Client**      | **Version**                                     |
|-----------------|-------------------------------------------------|
| OpenSSH         | `OpenSSH_for_Windows_9.5p1, LibreSSL 3.8.2`     |
| PuTTY           | `Release 0.82`                                  |
| WinSCP          | `6.3.6` (sftp only)                             |

### Performance Benchmarks

A comprehensive automated test report is available that demonstrates the full capabilities of this project: [benchmark_report.md](https://github.com/Aimeast/FxSsh/blob/dev/benchmark_report.md)

### Sample code
```cs
static int windowWidth, windowHeight;

static void Main(string[] args)
{
    var rsa2048BitPem = @"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQClBPKsmiTxCoez
E4Wt4nvNDVjLtkGQPUS/SbhJCL8J7pKrvsKRyXKM9GjGdxA7GKZR7sjqCWCU12oD
+EJuf/mpcA0JsBY4gUU8bp95U5mEM+ZOr2aNXYXAXy/J6GQRyd1jgkD2pm1qsWZJ
ahvXNJGMgx1lqI9woKU+PRssMtv1YupAxsSlo+xcfvC57fkaKIwUeCr6CkUlpIJN
zP5lvatKcpmjiWLSRHUpypx2wgZPz4SnB2qE77UH/yu1DlcsQgbVa7nr+qMWfxP7
Cpa+eTJC19c1GP+XxFaeqXDtuGaRlfBX/iihEcBnQuvsZJLg5jN0WKqvnpDfHgh/
M4IopC2pAgMBAAECggEBAImt6ibV6NJvHa7sL9FXMEFxzE8SffsxEyWiBS5yLKnF
sfu3CbEG6RrvZGeJuTIFK+caGekh78HfRGWRgSOehJe4lDgsAS4dtL1p8oYQmPnz
L0khEKgLimdpQ37q9GrfCGZYq4jebFXjMts3u4i/JFyenC1QCHVIovWdmAk1Wc2N
5bY+qlQZ4dSBl15cqNg0w4bbEF+yT+fOMm/raZANTr/IDIt88LcKpyimvUSGlZEE
OWx4hXAPbF4h/tqeH4O+Xzmtq/1pWwdbwNqWwOXow320c97U4ofCuDXcy0TeOwiX
gcPnaG99jX4Cy+IwdcVnDsJpN4FC2/sm1kGeOTRpIl0CgYEAy8gPV5RESpOyQ00j
dr36JQoymLwXDS114tuMPF7dX5YX3S+yyhl0ADa11tVH15CzOaVSF1wfxDeb1TRs
XcJoZBsxlH24BMPETB1ADy43pslRrkex54hcM4jDe3OYBTsVmV5A2sdxFGEKAbPn
uWsk8jeZ9AsEV3M2vinzJmS5XVsCgYEAz04dSW0GXiTBESYmno9DJiyx3dT4T0eq
bwtpZPCShEjU4BChwFg9V5fAmzw1iCrdYD68mwcxQYurp3Vgqo6u1YogRpeNfljq
VpKnVDbd3a1CTYYyWw81f4HzflpmWLgq1BGKkdwD83xZaFh7Y46cm+xEtrJpiVFM
GTagAokFvEsCgYB1EouV4g1V1wJ73c45Aq26J+CnlK+dl3d5jG5FpK6DosQ1A5kw
uGzHTqcrND7g3jXJMWw3FWr+nH//fe2f8/drQ6A5UfytaBbXL5rE3eWFAXXWrUPM
468swC6mNuOoZahkAx05U4lojtNj5QqEoMSKD114MfgdkYhquckCTq2brwKBgQC5
s1zS0II6xSvZw9YmhWj+gl0WvVduFWGcNZnE3SgyrddbnCp5VdIlbAASTx4ZC2Th
eXGUYh4CfC5ZRPFB96ywBxqggdQzEU1iHd8ctkWK9VCGh6cGIRqoTO2lCy/RW7Cp
5ci+nls/uu2QZmqppS+vETgAfNPDOXs0vtUZUEs9/wKBgDNQonVvTTQIRbaRbxXu
eVqxAVYBb8PSPBjfigb4/sGzu4iYaxuCHOkA8AK9B9SmGjaQHJ4h9t+kJKe9xNie
v7sG5pguzUyd+AJIafbeh2Iryva/Nw3Shb7Jl6EX/lX3o/B9hRziWKV0IvwCUF/1
iyxhUEyZT7ugi8eNl5zVJgmN
-----END PRIVATE KEY-----";
    var ecdsap256Pem = @"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgPHkoVMg7fVw+20dJ
iZrIo86ikidAv9V/ImB7q8QJ3f6hRANCAAShaGB2y+jNBGKsI+r4l+Bq82q+UVUn
lPBvdBz9mGA32F9oosJ1s6mPmsasSI5FdG0B8sbQMLD7j5/8Lcjb1P4I
-----END PRIVATE KEY-----";
    var ecdsap384Pem = @"-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDBgquj404eo5PGToagO
tXFnhf8/kryAfQFlNEqrruGrGrAmQWuHjDeG2yxnMYpgYrShZANiAASvXyCM6j2f
n5ytuT/ekSiWcd1KoGexHWxXE7AVWfdXY0o2iJpZxRIZbqhiLfIruAxYFlvNnaGh
UNEj76uLE5jR1xdH471mzsEPWrxi/CeTm0OyQ6yQg3pQH5FFVyCR1so=
-----END PRIVATE KEY-----";
    var ecdsap521Pem = @"-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAGXO87cgkpAPLIWoc
kZirXguaO7WeAFtO+z5TtfHyTLEgSUWlGhP1PZ3ZbyLf0ht6t4X46TQQn7Eyqkuy
XgXZ0RihgYkDgYYABAAa9hQJavg/gAqUEIVoL1TucLMu1gCElMvX68BrJQoYdoNe
gbR4mS/oiOdvU5zm4H2ABo6gDYo2Pl4W80lqL3nGdgAwdNN7udRi/A5wc39KvZ5w
bbDmx/ly7kvagszIWafjG8Hzg5v5kKBbdYw9A+9pN2cbhWXug41xR1rLDOI6hFSn
TA==
-----END PRIVATE KEY-----";

    Log.Configure(new LogOptions
    {
        MinLevel = LogLevel.Trace,
        Sink = new ConsoleLogSink(),
    });

    var server = new SshServer();
    server.AddHostKey("rsa-sha2-256", rsa2048BitPem);
    server.AddHostKey("rsa-sha2-512", rsa2048BitPem);
    server.AddHostKey("ecdsa-sha2-nistp256", ecdsap256Pem);
    server.AddHostKey("ecdsa-sha2-nistp384", ecdsap384Pem);
    server.AddHostKey("ecdsa-sha2-nistp521", ecdsap521Pem);

    server.ConnectionAccepted += server_ConnectionAccepted;

    server.Start();

    Task.Delay(-1).Wait();
}

static void server_ConnectionAccepted(object sender, Session e)
{
    Log.Info("Connection accepted.");

    e.ServiceRegistered += e_ServiceRegistered;
    e.KeysExchanged += e_KeysExchanged;
}

private static void e_KeysExchanged(object sender, KeyExchangeArgs e)
{
    foreach (var keyExchangeAlg in e.KeyExchangeAlgorithms)
    {
        Log.Debug($"Key exchange algorithm: {keyExchangeAlg}.");
    }
}

static void e_ServiceRegistered(object sender, SshService e)
{
    var session = (Session)sender;
    Log.Info($"Session {BitConverter.ToString(session.SessionId).Replace("-", "")} requesting {e.GetType().Name}.");

    if (e is UserAuthService)
    {
        var service = (UserAuthService)e;
        // WARNING: Enabling "none" auth poses a high security risk. Please ensure you understand the risks before using it.
        service.EnableNoneAuth = true;
        service.UserAuth += service_UserAuth;
    }
    else if (e is ConnectionService)
    {
        var service = (ConnectionService)e;
        service.CommandOpened += service_CommandOpened;
        service.SubsystemRequested += service_SubsystemRequested;
        service.EnvReceived += service_EnvReceived;
        service.PtyReceived += service_PtyReceived;
        service.TcpForwardRequest += service_TcpForwardRequest;
        service.TcpForwardRequestReceived += service_TcpForwardRequestReceived;
    }
}

static void service_TcpForwardRequestReceived(object sender, TcpForwardRequestArgs e)
{
    Log.Info($"Peer requests reverse forward at {e.Address}:{e.Port}.");

    var allow = true;  // func(e.Address, e.Port, e.AttachedUserAuthArgs);
    e.Accepted = allow;
}

/// <summary>
/// Fire-and-forget channel data send that swallows teardown
/// exceptions. The event handlers below are async void
/// (EventHandler&lt;T&gt;), so any ObjectDisposedException escaping
/// from Channel.SendDataAsync after ForceClose would land on the
/// thread pool and FailFast the whole process. Teardown races are
/// expected once the peer disconnects or the session is closed.
/// </summary>
static async Task TrySendChannelDataAsync(Channel channel, byte[] data)
{
    try
    {
        await channel.SendDataAsync(data);
    }
    catch (ObjectDisposedException)
    {
    }
    catch (Exception)
    {
        // Channel/session torn down mid-send; nothing left to do.
    }
}

/// <summary>
/// Fire-and-forget PTY input write that swallows teardown exceptions
/// (same rationale as <see cref="TrySendChannelDataAsync"/>).
/// </summary>
static async Task TryTerminalInputAsync(ITerminal terminal, ReadOnlyMemory<byte> data)
{
    try
    {
        await terminal.OnInputAsync(data);
    }
    catch (ObjectDisposedException)
    {
    }
    catch (Exception)
    {
        // Terminal disposed during teardown; nothing left to do.
    }
}

static void service_TcpForwardRequest(object sender, TcpRequestArgs e)
{
    Log.Info($"Received a request to forward data to {e.Host}:{e.Port}.");

    var allow = true;  // func(e.Host, e.Port, e.AttachedUserAuthArgs);

    if (!allow)
        return;

    var tcp = new TcpForwardService(e.Host, e.Port, e.OriginatorIP, e.OriginatorPort);
    e.Channel.DataReceived += (ss, ee) => tcp.OnData(ee);
    e.Channel.CloseReceived += (ss, ee) => tcp.OnClose();
    tcp.DataReceived += async (ss, ee) => await TrySendChannelDataAsync(e.Channel, ee);
    tcp.CloseReceived += (ss, ee) => e.Channel.SendClose();
    tcp.Start();
}

static void service_PtyReceived(object sender, PtyArgs e)
{
    Log.Info($"Request to create a PTY received for terminal type {e.Terminal}.");
    windowWidth = (int)e.WidthChars;
    windowHeight = (int)e.HeightRows;
}

static void service_EnvReceived(object sender, EnvironmentArgs e)
{
    Log.Info($"Received environment variable {e.Name}:{e.Value}.");
}

static void service_UserAuth(object sender, UserAuthArgs e)
{
    Log.Info($"Client {e.KeyAlgorithm} fingerprint: {e.Fingerprint}.");

    e.Result = true;
}

static void service_SubsystemRequested(object sender, SubsystemRequestedArgs e)
{
    Log.Info($"Subsystem requested: {e.Name}.");

    if (e.Name != "sftp")
        return;

    e.Agreed = true;
    // Default SFTP root is the current user's home directory.
    // To serve read-only, use: new SftpService(readOnly: true);
    var sftp = new SftpService();
    sftp.Attach(e.Channel);
}

static void service_CommandOpened(object sender, CommandRequestedArgs e)
{
    Log.Info($"Channel {e.Channel.ServerChannelId} runs {e.ShellType}: \"{e.CommandText}\", client key SHA256:{e.AttachedUserAuthArgs.Fingerprint}.");

    e.Agreed = true;  // func(e.ShellType, e.CommandText, e.AttachedUserAuthArgs);

    if (!e.Agreed)
        return;

    if (e.ShellType == "shell")
    {
        // Windows: Win32 Pseudo Console (ConPTY, Windows 10 1809+).
        // Linux: devpts/ptmx (see FxSsh.Services.Pty).
        var shell = OperatingSystem.IsWindows() ? "cmd.exe" : "bash";
        var terminal = TerminalFactory.Create(shell, windowWidth, windowHeight);

        e.Channel.WindowChange += (ss, ee) => terminal.Resize((int)ee.WidthColumns, (int)ee.HeightRows);
        e.Channel.DataReceived += async (ss, ee) => await TryTerminalInputAsync(terminal, ee);
        e.Channel.CloseReceived += (ss, ee) => terminal.OnClose();
        terminal.DataReceived += async (ss, ee) => await TrySendChannelDataAsync(e.Channel, ee);
        terminal.CloseReceived += (ss, ee) => e.Channel.SendClose(ee);

        terminal.Run();
    }
    else if (e.ShellType == "exec")
    {
        var parser = new Regex(@"(?<cmd>git-receive-pack|git-upload-pack|git-upload-archive) \'/?(?<proj>.+)\.git\'");
        var match = parser.Match(e.CommandText);
        var command = match.Groups["cmd"].Value;
        var project = match.Groups["proj"].Value;

        var git = new GitService(command, project);

        e.Channel.DataReceived += (ss, ee) => git.OnData(ee);
        e.Channel.CloseReceived += (ss, ee) => git.OnClose();
        git.DataReceived += async (ss, ee) => await TrySendChannelDataAsync(e.Channel, ee);
        git.CloseReceived += (ss, ee) => e.Channel.SendClose(ee);

        git.Start();
    }
    else if (e.ShellType == "subsystem")
    {
        // SFTP is handled through the dedicated SubsystemRequested
        // event (see service_SubsystemRequested); other subsystems
        // are rejected by leaving Agreed unset.
    }
}
```

### Generate private key
```cs
KeyGenerator.GenerateRsaKeyPem(2048); \\ generate rsa key with 2048 bits
KeyGenerator.GenerateECDsaKeyPem("nistp256"); \\ generate ecdsa key with curve nistp256
KeyGenerator.ConvertRsaBase64KeyToPem("base64"); \\ convert old rsa base64 key to pem format
```

---
### Acknowledgements from others
As noted in their own documentation, significant portions of Microsoft's
[Dev Tunnels SSH](https://github.com/microsoft/dev-tunnels-ssh/tree/main/src/cs/Ssh#acknowledgements)
library were originally derived from FxSsh.

### License
The MIT license

