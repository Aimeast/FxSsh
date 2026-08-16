## FxSsh

FxSsh 是一个轻量级的 [SSH](https://en.wikipedia.org/wiki/Secure_Shell) 服务端库。

---

### Nuget

[![NuGet version](https://badge.fury.io/nu/FxSsh.svg)](https://www.nuget.org/packages/FxSsh/)

`PM> Install-Package FxSsh`

目标框架 `net8.0`

### RFC 文档

FxSsh 遵循以下 RFC 文档：

- [RFC4250](https://tools.ietf.org/html/rfc4250)  协议分配号
- [RFC4251](https://tools.ietf.org/html/rfc4251)  协议架构
- [RFC4252](https://tools.ietf.org/html/rfc4252)  认证协议
- [RFC4253](https://tools.ietf.org/html/rfc4253)  传输层协议
- [RFC4254](https://tools.ietf.org/html/rfc4254)  连接协议
- [RFC4344](https://tools.ietf.org/html/rfc4344)  传输层加密模式
- [RFC5647](https://tools.ietf.org/html/rfc5647)  SSH 传输层协议的 AES Galois 计数器模式
- [RFC5656](https://tools.ietf.org/html/rfc5656)  椭圆曲线算法集成
- [RFC6668](https://tools.ietf.org/html/rfc6668)  SHA-2 数据完整性算法
- [RFC8308](https://tools.ietf.org/html/rfc8308)  SSH 协议扩展协商
- [RFC8332](https://tools.ietf.org/html/rfc8332)  RSA 密钥与 SHA-2 的使用
- [RFC8731](https://tools.ietf.org/html/rfc8731)  使用 Curve25519 与 Curve448 的 SSH 密钥交换方法
- [draft-ietf-secsh-filexfer-02](https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02)  SSH 文件传输协议（sftp 版本 3）

### 支持的算法

| **类别**            | **算法**                                                                                  |
|---------------------|-------------------------------------------------------------------------------------------|
| **公钥**            | RSA 系列：`rsa-sha2-256`、`rsa-sha2-512`<br>ECDsa 系列：`ecdsa-sha2-nistp256`、`ecdsa-sha2-nistp384`、`ecdsa-sha2-nistp521` |
| **密钥交换（KEX）** | DH 系列：`diffie-hellman-group14-sha256`、`diffie-hellman-group16-sha512`、`diffie-hellman-group18-sha512`<br>ECDH 系列：`ecdh-sha2-nistp256`、`ecdh-sha2-nistp384`、`ecdh-sha2-nistp521`<br>X25519：`curve25519-sha256` |
| **加密**            | `aes256-ctr`、`aes128-gcm@openssh.com`、`aes256-gcm@openssh.com`                          |
| **MAC**             | `hmac-sha2-256`、`hmac-sha2-512`、`hmac-sha2-256-etm@openssh.com`、`hmac-sha2-512-etm@openssh.com` |
| **压缩**            | `none`                                                                                    |

### 支持的服务

| **服务**            | **详情**                                                                                   |
|---------------------|-------------------------------------------------------------------------------------------|
| **认证**            | `publickey`、`password`<br>`none`（可选，通过 `EnableNoneAuth` 启用）                      |
| **连接**            | `session`（如 exec、shell）<br>`direct-tcpip`、`forwarded-tcpip`<br>`tcpip-forward` / `cancel-tcpip-forward`（反向端口转发）<br>`keepalive@openssh.com`（全局请求）<br>`subsystem`（通过 `SubsystemRequested` 分发） |
| **子系统**          | `sftp（版本 3）`，由核心库 `FxSsh.Services.Sftp` 提供（通过 `SftpService.Attach` 接入，可通过 `SftpService(readOnly: true)` 设为只读） |

### 已测试的客户端

| **客户端**          | **版本**                                               |
|---------------------|--------------------------------------------------------|
| OpenSSH             | `OpenSSH_for_Windows_9.5p1, LibreSSL 3.8.2`           |
| PuTTY               | `Release 0.82`                                        |
| WinSCP              | `6.3.6`（仅 sftp）                                    |

### 性能测试

这里有一份完整的自动化测试报告，展示了本项目的全部能力。[benchmark_report_zh-cn.md](https://github.com/Aimeast/FxSsh/blob/dev/benchmark_report_zh-cn.md)

### 示例代码

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
        // 警告：启用 "none" 认证存在极高的安全风险。请确保在使用前充分了解风险。
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
/// 发起即忘记（fire-and-forget）的通道数据发送，吞掉通道销毁期间的异常。
/// 下方的事件处理器是 async void（EventHandler&lt;T&gt;），因此 ForceClose
/// 后任何从 Channel.SendDataAsync 逃逸的 ObjectDisposedException 都会落到
/// 线程池上并导致整个进程 FailFast。一旦对端断开或会话关闭，出现销毁竞态
/// 是预期行为。
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
        // 通道/会话在发送中途被销毁；无需再做处理。
    }
}

/// <summary>
/// 发起即忘记的 PTY 输入写入，吞掉销毁期间的异常
/// （与 <see cref="TrySendChannelDataAsync"/> 的理由相同）。
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
        // 终端在销毁期间被释放；无需再做处理。
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
    // 默认 SFTP 根目录为当前用户的主目录。
    // 如需只读服务，请使用：new SftpService(readOnly: true);
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
        // Windows：Win32 伪控制台（ConPTY，Windows 10 1809+）。
        // Linux：devpts/ptmx（见 FxSsh.Services.Pty）。
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
        // SFTP 通过专门的 SubsystemRequested 事件处理
        // （参见 service_SubsystemRequested）；其他子系统
        // 通过不设置 Agreed 来拒绝。
    }
}
```

### 生成私钥

```cs
KeyGenerator.GenerateRsaKeyPem(2048);   // 生成 2048 位的 RSA 密钥
KeyGenerator.GenerateECDsaKeyPem("nistp256");   // 生成曲线 nistp256 的 ECDSA 密钥
KeyGenerator.ConvertRsaBase64KeyToPem("base64");   // 将旧的 RSA Base64 密钥转换为 PEM 格式
```

---

### 来自其他项目的致谢

根据其自身文档所述，微软的 [Dev Tunnels SSH](https://github.com/microsoft/dev-tunnels-ssh/tree/main/src/cs/Ssh#acknowledgements) 库的很大一部分最初源自 FxSsh。

### 许可证

MIT 许可证

