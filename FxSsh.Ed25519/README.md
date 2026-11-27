
# README - Ed25519 Public Key Extension for FxSsh

This package implements an implementation of the Ed25519 Edwards curve for public key
authentication for FxSsh as defined in [RFC 8709](https://www.rfc-editor.org/info/rfc8709/).

Ed25519 does not support any parameters like other supported public key algorithms
([RSA](../FxSsh/Algorithms/RsaKey.cs) and [ECDSA](../FxSsh/Algorithms/EcdsaKey.cs))
and is always fixed to 32-byte public and private keys.

Ed25519 SSH keys provide strong cryptographic security, excellent
performance and compact size, making them the modern default for
secure SSH authentication.

Unfortunately, the .NET base class library does not yet provide
a built-in implementation of Ed25519, so this Public Key Algorithm
implementation relies on the Bouncy Castle Crypto library, and is
therefore implemented in a separate package that can be _plugged_
into a FxSsh Algorithm Catalog.

## Example Usage

Adding Ed25519 host key to an FxSsh server instance:

```csharp
static async Task Main(string[] args)
{
    var ed25519Pem = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
        c2gtZWQyNTUxOQAAACCqxGY1n3w7m3ICIzW/Tk4Vat4vZHXrEid3sBtGzpfEjQAA
        AKBz7YuRc+2LkQAAAAtzc2gtZWQyNTUxOQAAACCqxGY1n3w7m3ICIzW/Tk4Vat4v
        ZHXrEid3sBtGzpfEjQAAAEC53QPBxeO8wj/4OEWZLM3R0QrRz+9Uavyk4tFnS2q3
        P6rEZjWffDubcgIjNb9OThVq3i9kdesSJ3ewG0bOl8SNAAAAEmVkZHNhLWtleS0y
        MDI2MTExOQECAwQFBgcICQoL
        -----END OPENSSH PRIVATE KEY-----
        """;

    Log.Configure(new LogOptions
    {
        MinLevel = LogLevel.Info,
        Sink = new ConsoleLogSink(),
    });

    var server = new SshServer();
    // Add support for Ed25519 server key
    server.AddHostKey("ssh-ed25519", ed25519Pem);
    // Add other algorithm keys as needed

    server.Algorithms.ConfigureHazmat(catalog =>
    {
        // Add support for Ed25519 client keys
        catalog.HostKeyCollection.Add("ssh-ed25519", x => new Ed25519Key(x));
    });

    // Wire-up your server event handlers here...

    await server.StartAsync();
}
```

### Generate Private Key

```csharp
KeyGenerator.GenerateEd25529KeyPem(); // Generates Ed25519 key of 32 bytes (256-bits)
```

## License

The MIT license
