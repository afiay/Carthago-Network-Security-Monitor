// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Conservative legacy HMS HICP "Configure" request-shape inspector.
    /// Caller must attest one complete, unfragmented, plaintext UDP datagram,
    /// UDP/3250 endpoint, capture provenance, and client-to-device direction.
    /// The text fields are untrusted; no password, MAC, IP, hostname, value,
    /// device identity, or response/outcome is retained. Secure HICP (SHICP)
    /// and non-Configure messages are intentionally unsupported.
    /// ISOLATED — NOT LIVE-CAPTURE INTEGRATED.
    /// </summary>
    public static class HicpConfigurationAttemptInspector
    {
        private const int MaximumDatagramBytes = 1200;
        private const int MaximumFieldBytes = 128;
        private const int MaximumFields = 24;

        public static bool TryInspect(
            ReadOnlySpan<byte> udpPayload,
            bool verifiedCompleteUdpDatagram,
            bool verifiedUnfragmentedIpPacket,
            bool verifiedUdp3250Endpoint,
            bool verifiedPlaintext,
            bool verifiedCaptureProvenance,
            bool verifiedClientToDeviceDirection,
            out HicpConfigurationAttemptObservation observation)
        {
            observation = default;
            ReadOnlySpan<byte> prefix = "Configure: "u8;
            if (!verifiedCompleteUdpDatagram || !verifiedUnfragmentedIpPacket ||
                !verifiedUdp3250Endpoint || !verifiedPlaintext ||
                !verifiedCaptureProvenance || !verifiedClientToDeviceDirection ||
                udpPayload.Length < prefix.Length + 17 + 1 + 6 ||
                udpPayload.Length > MaximumDatagramBytes ||
                !udpPayload.StartsWith(prefix))
                return false;

            // Legacy HICP target is six hyphen-delimited hex octets.
            // This is a shape check only; it does not authenticate the target.
            int offset = prefix.Length;
            for (int i = 0; i < 17; i++)
            {
                byte current = udpPayload[offset + i];
                if (i % 3 == 2)
                {
                    if (current != (byte)'-') return false;
                }
                else if (!IsHex(current))
                {
                    return false;
                }
            }
            offset += 17;
            if (udpPayload[offset++] != (byte)';')
                return false;

            int fieldCount = 0;
            bool hasNetworkSettings = false;
            bool hasNewPassword = false;
            bool hasKnownField = false;
            while (offset < udpPayload.Length)
            {
                while (offset < udpPayload.Length && udpPayload[offset] == (byte)' ')
                    offset++;
                if (offset == udpPayload.Length)
                    break; // a trailing separator or spaces are permitted

                int separator = udpPayload.Slice(offset).IndexOf((byte)';');
                int end = separator < 0 ? udpPayload.Length : offset + separator;
                ReadOnlySpan<byte> field = udpPayload.Slice(offset, end - offset);
                if (field.IsEmpty || field.Length > MaximumFieldBytes ||
                    ++fieldCount > MaximumFields)
                    return false;

                foreach (byte value in field)
                    if (value < 0x20 || value > 0x7e)
                        return false; // no binary, NUL, CR/LF or control bytes

                // Reject concatenated/coalesced Configure requests rather than
                // silently treating the second request as a field value.
                if (field.IndexOf("Configure: "u8) >= 0)
                    return false;

                int equals = field.IndexOf((byte)'=');
                if (equals < 1 || equals > 32)
                    return false;

                ReadOnlySpan<byte> key = field.Slice(0, equals);
                while (!key.IsEmpty && key[^1] == (byte)' ')
                    key = key.Slice(0, key.Length - 1);
                ReadOnlySpan<byte> valueSpan = field.Slice(equals + 1);
                while (!valueSpan.IsEmpty && valueSpan[0] == (byte)' ')
                    valueSpan = valueSpan.Slice(1);
                if (key.IsEmpty || valueSpan.IsEmpty)
                    return false;

                bool networkField = key.SequenceEqual("IP"u8) ||
                    key.SequenceEqual("SN"u8) || key.SequenceEqual("GW"u8) ||
                    key.SequenceEqual("DHCP"u8) || key.SequenceEqual("HN"u8) ||
                    key.SequenceEqual("DNS1"u8) || key.SequenceEqual("DNS2"u8);
                bool passwordChange = key.SequenceEqual("New password"u8);
                bool otherKnown = key.SequenceEqual("PSWD"u8) ||
                    key.SequenceEqual("Protocol version"u8) ||
                    key.SequenceEqual("MAC"u8) ||
                    key.SequenceEqual("FB type"u8) ||
                    key.SequenceEqual("Module version"u8);
                hasNetworkSettings |= networkField;
                hasNewPassword |= passwordChange;
                hasKnownField |= networkField || passwordChange || otherKnown;

                offset = end == udpPayload.Length ? end : end + 1;
            }

            // Port-only traffic and unknown text keys are not HICP evidence.
            if (fieldCount == 0 || !hasKnownField)
                return false;

            observation = new HicpConfigurationAttemptObservation(
                fieldCount,
                hasNetworkSettings,
                hasNewPassword);
            return true;
        }

        private static bool IsHex(byte value) =>
            (value >= (byte)'0' && value <= (byte)'9') ||
            (value >= (byte)'a' && value <= (byte)'f') ||
            (value >= (byte)'A' && value <= (byte)'F');
    }

    /// <summary>
    /// Unverified request-shape metadata only, never an authenticated or
    /// successful device reconfiguration and never a CVE exploit assertion.
    /// </summary>
    public readonly record struct HicpConfigurationAttemptObservation(
        int ParsedFieldCount,
        bool HasNetworkSettingFieldUnverified,
        bool HasNewPasswordFieldUnverified);
}
