// SPDX-License-Identifier: MIT
// File: Services/Fingerprints/X509Ja4X.cs
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Carthago.Services.Fingerprints
{
    /// <summary>
    /// Cert-centric JA4X-style fingerprint: encodes structural aspects of leaf cert:
    /// - SigAlg OID, PubKey OID, KeySize, #SAN entries, presence of common extensions.
    /// Produces "x:<core>|<sha8>".
    /// </summary>
    public static class X509Ja4X
    {
        public static string FromCertificateDer(ReadOnlySpan<byte> der)
        {
            try
            {
                var cert = new X509Certificate2(der.ToArray());
                string sigOid = cert.SignatureAlgorithm?.Value ?? "unknown";
                string pubOid = cert.PublicKey?.Oid?.Value ?? "unknown";
                using RSA? rsa = cert.GetRSAPublicKey();
                using ECDsa? ecdsa = cert.GetECDsaPublicKey();
                int keyBits = rsa?.KeySize
                          ?? ecdsa?.KeySize
                          ?? 0;

                // SAN count
                int sanCount = 0;
                bool hasSKI = false, hasAKI = false, hasKeyUsage = false, hasExtKeyUsage = false;
                foreach (var ext in cert.Extensions)
                {
                    if (ext.Oid?.Value == "2.5.29.17") // SAN
                    {
                        // parse roughly: count commas/entries
                        var s = ext.Format(false);
                        sanCount = s.Split(new[] { ", " }, StringSplitOptions.RemoveEmptyEntries).Length;
                    }
                    else if (ext.Oid?.Value == "2.5.29.14") hasSKI = true;
                    else if (ext.Oid?.Value == "2.5.29.35") hasAKI = true;
                    else if (ext.Oid?.Value == "2.5.29.15") hasKeyUsage = true;
                    else if (ext.Oid?.Value == "2.5.29.37") hasExtKeyUsage = true;
                }

                var core = $"sig:{sigOid};pk:{pubOid};bits:{keyBits};san:{sanCount};ski:{B(hasSKI)};aki:{B(hasAKI)};ku:{B(hasKeyUsage)};eku:{B(hasExtKeyUsage)}";
                return $"x:{core}|{Sha8(core)}";
            }
            catch
            {
                return string.Empty;
            }
        }

        private static string B(bool b) => b ? "1" : "0";
        private static string Sha8(string s)
        {
            using var sha = SHA256.Create();
            return Convert.ToHexString(sha.ComputeHash(Encoding.ASCII.GetBytes(s))).ToLowerInvariant()[..8];
        }
    }
}
