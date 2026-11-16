// SPDX-License-Identifier: MIT
using System;
using System.Net;
using System.Security.Cryptography;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Bounded RFC 2865 response-authenticator validation of a captured RADIUS
    /// Access-Request / Access-Reject pair using an operator-supplied shared secret.
    /// Not a user authentication result and not wired into the R289 detector.
    /// Neither raw attributes nor secret bytes are retained by this contract.
    /// </summary>
    public static class RadiusAccessRejectExchangeVerifier
    {
        public static bool TryVerify(
            ReadOnlySpan<byte> request, string? requestSource, ushort requestSourcePort,
            string? requestDestination, ushort requestDestinationPort,
            ReadOnlySpan<byte> response, string? responseSource, ushort responseSourcePort,
            string? responseDestination, ushort responseDestinationPort,
            ReadOnlySpan<byte> sharedSecret, bool completeUdpPayloads,
            out RadiusPacketObservation reject)
        {
            reject = default;
            if (!completeUdpPayloads || sharedSecret.Length is < 1 or > 128 ||
                requestDestinationPort != 1812 || responseSourcePort != 1812 ||
                requestSourcePort != responseDestinationPort ||
                !SameAddress(requestSource, responseDestination) ||
                !SameAddress(requestDestination, responseSource) ||
                !RadiusPacketInspector.TryInspect(request, requestSourcePort, requestDestinationPort,
                    true, out var requestEnvelope) ||
                !RadiusPacketInspector.TryInspect(response, responseSourcePort, responseDestinationPort,
                    true, out var responseEnvelope) ||
                requestEnvelope.Code != 1 || responseEnvelope.Code != 3 ||
                requestEnvelope.HasMessageAuthenticatorAttribute ||
                responseEnvelope.HasMessageAuthenticatorAttribute ||
                request[1] != response[1])
                return false;

            // RFC 2865: MD5(Code|Identifier|Length|RequestAuthenticator|Attributes|Secret).
            // A Message-Authenticator requires separate HMAC validation: reject above.
            byte[] material = new byte[response.Length + sharedSecret.Length];
            byte[]? digest = null;
            try
            {
                response.Slice(0, 4).CopyTo(material.AsSpan(0, 4));
                request.Slice(4, 16).CopyTo(material.AsSpan(4, 16));
                response.Slice(20).CopyTo(material.AsSpan(20));
                sharedSecret.CopyTo(material.AsSpan(response.Length));
                digest = MD5.HashData(material);
                if (!CryptographicOperations.FixedTimeEquals(digest, response.Slice(4, 16)))
                    return false;
                reject = responseEnvelope;
                return true;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(material);
                if (digest != null) CryptographicOperations.ZeroMemory(digest);
            }
        }

        private static bool SameAddress(string? first, string? second)
        {
            if (!IPAddress.TryParse(first, out var a) || !IPAddress.TryParse(second, out var b))
                return false;
            if (a.IsIPv4MappedToIPv6) a = a.MapToIPv4();
            if (b.IsIPv4MappedToIPv6) b = b.MapToIPv4();
            return a.Equals(b) && !IPAddress.IsLoopback(a) &&
                !a.Equals(IPAddress.Any) && !a.Equals(IPAddress.IPv6Any) &&
                !a.Equals(IPAddress.Broadcast) && !a.IsIPv6Multicast &&
                !(a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
                  (a.GetAddressBytes()[0] & 0xF0) == 0xE0);
        }
    }
}
