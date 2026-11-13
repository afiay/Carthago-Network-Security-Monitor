// SPDX-License-Identifier: MIT
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Carthago.Tests;

/// <summary>Test-only TLS server key material; never changes certificate trust.</summary>
internal static class LoopbackTlsCertificateFixture
{
    internal static X509Certificate2 ForServer(X509Certificate2 generated)
    {
        // Schannel cannot use an ephemeral private key for SslStream.
        // Reimport the generated certificate into the current user's key set
        // (without PersistKeySet): the imported certificate owns temporary key
        // material and disposal releases it. No trust-store installation.
        // https://learn.microsoft.com/dotnet/core/extensions/sslstream-troubleshooting
        byte[] pfx = generated.Export(X509ContentType.Pkcs12);
        try
        {
            return new X509Certificate2(pfx, (string?)null,
                OperatingSystem.IsWindows() ? X509KeyStorageFlags.UserKeySet : X509KeyStorageFlags.EphemeralKeySet);
        }
        finally { CryptographicOperations.ZeroMemory(pfx); }
    }
}
