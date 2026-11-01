// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// GNU GDB Remote Serial Protocol client-command envelope only.
    /// The caller must attest exactly one complete, plaintext, client-to-stub
    /// packet and the capture source. This is NOT a TCP stream reassembler,
    /// gdbserver authenticator, command-parameter validator or detection rule.
    /// No command payload, addresses, register contents or arguments are retained.
    /// ISOLATED — NOT LIVE-CAPTURE INTEGRATED.
    /// </summary>
    public static class GdbRspCommandInspector
    {
        private const int MaximumEncodedPayloadLength = 4096;

        public static bool TryInspect(
            ReadOnlySpan<byte> packet,
            bool verifiedCompletePacketBoundary,
            bool verifiedPlaintext,
            bool verifiedCaptureProvenance,
            bool verifiedClientToStubDirection,
            out GdbRspCommandObservation observation)
        {
            observation = default;
            if (!verifiedCompletePacketBoundary || !verifiedPlaintext ||
                !verifiedCaptureProvenance || !verifiedClientToStubDirection ||
                packet.Length is < 5 or > MaximumEncodedPayloadLength + 4 ||
                packet[0] != (byte)'$' || packet[^3] != (byte)'#')
                return false;

            ReadOnlySpan<byte> encoded = packet.Slice(1, packet.Length - 4);
            int high = HexValue(packet[^2]);
            int low = HexValue(packet[^1]);
            if (high < 0 || low < 0 || encoded.IsEmpty)
                return false;

            int sum = 0;
            bool escaped = false;
            for (int i = 0; i < encoded.Length; i++)
            {
                byte value = encoded[i];
                sum = (sum + value) & 0xff; // checksum is over encoded bytes
                if (value == (byte)'
                    return false;

                if (value == (byte)'}')
                {
                    if (++i == encoded.Length)
                        return false;
                    byte next = encoded[i];
                    sum = (sum + next) & 0xff;
                    byte decoded = (byte)(next ^ 0x20);
                    if (decoded != (byte)'
                        return false;
                    escaped = true;
                }
            }

            if (sum != ((high << 4) | low))
                return false;

            GdbRspCommandKind kind = encoded[0] switch
            {
                (byte)'q' => encoded.StartsWith("qRcmd,"u8)
                    ? GdbRspCommandKind.RemoteMonitor : GdbRspCommandKind.Query,
                (byte)'Q' => GdbRspCommandKind.Configuration,
                (byte)'m' => encoded.IndexOf((byte)',') > 1
                    ? GdbRspCommandKind.MemoryRead : GdbRspCommandKind.Unknown,
                (byte)'M' or (byte)'X' => encoded.IndexOf((byte)',') > 1 &&
                    encoded.IndexOf((byte)':') > 2
                    ? GdbRspCommandKind.MemoryWrite : GdbRspCommandKind.Unknown,
                (byte)'g' => encoded.Length == 1
                    ? GdbRspCommandKind.RegisterRead : GdbRspCommandKind.Unknown,
                (byte)'p' => encoded.Length > 1 && HexValue(encoded[1]) >= 0
                    ? GdbRspCommandKind.RegisterRead : GdbRspCommandKind.Unknown,
                (byte)'G' => encoded.Length > 1 && IsHex(encoded.Slice(1))
                    ? GdbRspCommandKind.RegisterWrite : GdbRspCommandKind.Unknown,
                (byte)'P' => encoded.IndexOf((byte)'=') > 1
                    ? GdbRspCommandKind.RegisterWrite : GdbRspCommandKind.Unknown,
                (byte)'c' or (byte)'C' or (byte)'s' or (byte)'S' => GdbRspCommandKind.ExecutionControl,
                (byte)'v' => GdbRspCommandKind.ExtendedControl,
                (byte)'Z' or (byte)'z' => encoded.IndexOf((byte)',') > 1
                    ? GdbRspCommandKind.BreakpointChange : GdbRspCommandKind.Unknown,
                (byte)'D' => encoded.Length == 1 || encoded[1] == (byte)';'
                    ? GdbRspCommandKind.DetachOrKill : GdbRspCommandKind.Unknown,
                (byte)'k' => encoded.Length == 1
                    ? GdbRspCommandKind.DetachOrKill : GdbRspCommandKind.Unknown,
                (byte)'?' => encoded.Length == 1
                    ? GdbRspCommandKind.StopReasonQuery : GdbRspCommandKind.Unknown,
                (byte)'!' => encoded.Length == 1
                    ? GdbRspCommandKind.ExtendedMode : GdbRspCommandKind.Unknown,
                (byte)'H' => encoded.Length >= 3 &&
                    (encoded[1] == (byte)'c' || encoded[1] == (byte)'g')
                    ? GdbRspCommandKind.ThreadControl : GdbRspCommandKind.Unknown,
                (byte)'T' => encoded.Length > 1 && IsHex(encoded.Slice(1))
                    ? GdbRspCommandKind.ThreadControl : GdbRspCommandKind.Unknown,
                (byte)'R' => GdbRspCommandKind.Restart,
                _ => GdbRspCommandKind.Unknown
            };
            if (kind == GdbRspCommandKind.Unknown)
                return false;

            bool potentiallyStateChanging = kind is
                GdbRspCommandKind.RemoteMonitor or GdbRspCommandKind.Configuration or
                GdbRspCommandKind.MemoryWrite or GdbRspCommandKind.RegisterWrite or
                GdbRspCommandKind.ExecutionControl or GdbRspCommandKind.ExtendedControl or
                GdbRspCommandKind.BreakpointChange or GdbRspCommandKind.DetachOrKill or
                GdbRspCommandKind.ExtendedMode or GdbRspCommandKind.Restart;

            observation = new GdbRspCommandObservation(
                kind, encoded.Length, escaped, potentiallyStateChanging);
            return true;
        }

        private static bool IsHex(ReadOnlySpan<byte> value)
        {
            if (value.IsEmpty || (value.Length & 1) != 0)
                return false;
            foreach (byte digit in value)
                if (HexValue(digit) < 0)
                    return false;
            return true;
        }

        private static int HexValue(byte value)
        {
            if (value >= (byte)'0' && value <= (byte)'9')
                return value - (byte)'0';
            if (value >= (byte)'a' && value <= (byte)'f')
                return value - (byte)'a' + 10;
            if (value >= (byte)'A' && value <= (byte)'F')
                return value - (byte)'A' + 10;
            return -1;
        }
    }

    public enum GdbRspCommandKind
    {
        Unknown = 0,
        Query,
        RemoteMonitor,
        Configuration,
        MemoryRead,
        MemoryWrite,
        RegisterRead,
        RegisterWrite,
        ExecutionControl,
        ExtendedControl,
        BreakpointChange,
        DetachOrKill,
        StopReasonQuery,
        ExtendedMode,
        ThreadControl,
        Restart
    }

    /// <summary>
    /// Untrusted, privacy-safe command-family shape. No proof of authenticated
    /// debugging, target access, command acceptance, or malicious execution.
    /// </summary>
    public readonly record struct GdbRspCommandObservation(
        GdbRspCommandKind CommandKindUnverified,
        int EncodedPayloadLength,
        bool ContainsEscapedBytes,
        bool PotentiallyStateChangingUnverified);
}
 || value == (byte)'#')
                    return false;

                if (value == (byte)'}')
                {
                    if (++i == encoded.Length)
                        return false;
                    byte next = encoded[i];
                    sum = (sum + next) & 0xff;
                    byte decoded = (byte)(next ^ 0x20);
                    if (decoded is not ((byte)'$' or (byte)'#' or (byte)'}' or (byte)'*'))
                        return false;
                    escaped = true;
                }
            }

            if (sum != ((high << 4) | low))
                return false;

            GdbRspCommandKind kind = encoded[0] switch
            {
                (byte)'q' => encoded.StartsWith("qRcmd,"u8)
                    ? GdbRspCommandKind.RemoteMonitor : GdbRspCommandKind.Query,
                (byte)'Q' => GdbRspCommandKind.Configuration,
                (byte)'m' => encoded.IndexOf((byte)',') > 1
                    ? GdbRspCommandKind.MemoryRead : GdbRspCommandKind.Unknown,
                (byte)'M' or (byte)'X' => encoded.IndexOf((byte)',') > 1 &&
                    encoded.IndexOf((byte)':') > 2
                    ? GdbRspCommandKind.MemoryWrite : GdbRspCommandKind.Unknown,
                (byte)'g' => encoded.Length == 1
                    ? GdbRspCommandKind.RegisterRead : GdbRspCommandKind.Unknown,
                (byte)'p' => encoded.Length > 1 && HexValue(encoded[1]) >= 0
                    ? GdbRspCommandKind.RegisterRead : GdbRspCommandKind.Unknown,
                (byte)'G' => encoded.Length > 1 && IsHex(encoded.Slice(1))
                    ? GdbRspCommandKind.RegisterWrite : GdbRspCommandKind.Unknown,
                (byte)'P' => encoded.IndexOf((byte)'=') > 1
                    ? GdbRspCommandKind.RegisterWrite : GdbRspCommandKind.Unknown,
                (byte)'c' or (byte)'C' or (byte)'s' or (byte)'S' => GdbRspCommandKind.ExecutionControl,
                (byte)'v' => GdbRspCommandKind.ExtendedControl,
                (byte)'Z' or (byte)'z' => encoded.IndexOf((byte)',') > 1
                    ? GdbRspCommandKind.BreakpointChange : GdbRspCommandKind.Unknown,
                (byte)'D' => encoded.Length == 1 || encoded[1] == (byte)';'
                    ? GdbRspCommandKind.DetachOrKill : GdbRspCommandKind.Unknown,
                (byte)'k' => encoded.Length == 1
                    ? GdbRspCommandKind.DetachOrKill : GdbRspCommandKind.Unknown,
                (byte)'?' => encoded.Length == 1
                    ? GdbRspCommandKind.StopReasonQuery : GdbRspCommandKind.Unknown,
                (byte)'!' => encoded.Length == 1
                    ? GdbRspCommandKind.ExtendedMode : GdbRspCommandKind.Unknown,
                (byte)'H' => encoded.Length >= 3 &&
                    (encoded[1] == (byte)'c' || encoded[1] == (byte)'g')
                    ? GdbRspCommandKind.ThreadControl : GdbRspCommandKind.Unknown,
                (byte)'T' => encoded.Length > 1 && IsHex(encoded.Slice(1))
                    ? GdbRspCommandKind.ThreadControl : GdbRspCommandKind.Unknown,
                (byte)'R' => GdbRspCommandKind.Restart,
                _ => GdbRspCommandKind.Unknown
            };
            if (kind == GdbRspCommandKind.Unknown)
                return false;

            bool potentiallyStateChanging = kind is
                GdbRspCommandKind.RemoteMonitor or GdbRspCommandKind.Configuration or
                GdbRspCommandKind.MemoryWrite or GdbRspCommandKind.RegisterWrite or
                GdbRspCommandKind.ExecutionControl or GdbRspCommandKind.ExtendedControl or
                GdbRspCommandKind.BreakpointChange or GdbRspCommandKind.DetachOrKill or
                GdbRspCommandKind.ExtendedMode or GdbRspCommandKind.Restart;

            observation = new GdbRspCommandObservation(
                kind, encoded.Length, escaped, potentiallyStateChanging);
            return true;
        }

        private static bool IsHex(ReadOnlySpan<byte> value)
        {
            if (value.IsEmpty || (value.Length & 1) != 0)
                return false;
            foreach (byte digit in value)
                if (HexValue(digit) < 0)
                    return false;
            return true;
        }

        private static int HexValue(byte value)
        {
            if (value >= (byte)'0' && value <= (byte)'9')
                return value - (byte)'0';
            if (value >= (byte)'a' && value <= (byte)'f')
                return value - (byte)'a' + 10;
            if (value >= (byte)'A' && value <= (byte)'F')
                return value - (byte)'A' + 10;
            return -1;
        }
    }

    public enum GdbRspCommandKind
    {
        Unknown = 0,
        Query,
        RemoteMonitor,
        Configuration,
        MemoryRead,
        MemoryWrite,
        RegisterRead,
        RegisterWrite,
        ExecutionControl,
        ExtendedControl,
        BreakpointChange,
        DetachOrKill,
        StopReasonQuery,
        ExtendedMode,
        ThreadControl,
        Restart
    }

    /// <summary>
    /// Untrusted, privacy-safe command-family shape. No proof of authenticated
    /// debugging, target access, command acceptance, or malicious execution.
    /// </summary>
    public readonly record struct GdbRspCommandObservation(
        GdbRspCommandKind CommandKindUnverified,
        int EncodedPayloadLength,
        bool ContainsEscapedBytes,
        bool PotentiallyStateChangingUnverified);
}
 && decoded != (byte)'#' &&
                        decoded != (byte)'}' && decoded != (byte)'*')
                        return false;
                    escaped = true;
                }
            }

            if (sum != ((high << 4) | low))
                return false;

            GdbRspCommandKind kind = encoded[0] switch
            {
                (byte)'q' => encoded.StartsWith("qRcmd,"u8)
                    ? GdbRspCommandKind.RemoteMonitor : GdbRspCommandKind.Query,
                (byte)'Q' => GdbRspCommandKind.Configuration,
                (byte)'m' => encoded.IndexOf((byte)',') > 1
                    ? GdbRspCommandKind.MemoryRead : GdbRspCommandKind.Unknown,
                (byte)'M' or (byte)'X' => encoded.IndexOf((byte)',') > 1 &&
                    encoded.IndexOf((byte)':') > 2
                    ? GdbRspCommandKind.MemoryWrite : GdbRspCommandKind.Unknown,
                (byte)'g' => encoded.Length == 1
                    ? GdbRspCommandKind.RegisterRead : GdbRspCommandKind.Unknown,
                (byte)'p' => encoded.Length > 1 && HexValue(encoded[1]) >= 0
                    ? GdbRspCommandKind.RegisterRead : GdbRspCommandKind.Unknown,
                (byte)'G' => encoded.Length > 1 && IsHex(encoded.Slice(1))
                    ? GdbRspCommandKind.RegisterWrite : GdbRspCommandKind.Unknown,
                (byte)'P' => encoded.IndexOf((byte)'=') > 1
                    ? GdbRspCommandKind.RegisterWrite : GdbRspCommandKind.Unknown,
                (byte)'c' or (byte)'C' or (byte)'s' or (byte)'S' => GdbRspCommandKind.ExecutionControl,
                (byte)'v' => GdbRspCommandKind.ExtendedControl,
                (byte)'Z' or (byte)'z' => encoded.IndexOf((byte)',') > 1
                    ? GdbRspCommandKind.BreakpointChange : GdbRspCommandKind.Unknown,
                (byte)'D' => encoded.Length == 1 || encoded[1] == (byte)';'
                    ? GdbRspCommandKind.DetachOrKill : GdbRspCommandKind.Unknown,
                (byte)'k' => encoded.Length == 1
                    ? GdbRspCommandKind.DetachOrKill : GdbRspCommandKind.Unknown,
                (byte)'?' => encoded.Length == 1
                    ? GdbRspCommandKind.StopReasonQuery : GdbRspCommandKind.Unknown,
                (byte)'!' => encoded.Length == 1
                    ? GdbRspCommandKind.ExtendedMode : GdbRspCommandKind.Unknown,
                (byte)'H' => encoded.Length >= 3 &&
                    (encoded[1] == (byte)'c' || encoded[1] == (byte)'g')
                    ? GdbRspCommandKind.ThreadControl : GdbRspCommandKind.Unknown,
                (byte)'T' => encoded.Length > 1 && IsHex(encoded.Slice(1))
                    ? GdbRspCommandKind.ThreadControl : GdbRspCommandKind.Unknown,
                (byte)'R' => GdbRspCommandKind.Restart,
                _ => GdbRspCommandKind.Unknown
            };
            if (kind == GdbRspCommandKind.Unknown)
                return false;

            bool potentiallyStateChanging = kind is
                GdbRspCommandKind.RemoteMonitor or GdbRspCommandKind.Configuration or
                GdbRspCommandKind.MemoryWrite or GdbRspCommandKind.RegisterWrite or
                GdbRspCommandKind.ExecutionControl or GdbRspCommandKind.ExtendedControl or
                GdbRspCommandKind.BreakpointChange or GdbRspCommandKind.DetachOrKill or
                GdbRspCommandKind.ExtendedMode or GdbRspCommandKind.Restart;

            observation = new GdbRspCommandObservation(
                kind, encoded.Length, escaped, potentiallyStateChanging);
            return true;
        }

        private static bool IsHex(ReadOnlySpan<byte> value)
        {
            if (value.IsEmpty || (value.Length & 1) != 0)
                return false;
            foreach (byte digit in value)
                if (HexValue(digit) < 0)
                    return false;
            return true;
        }

        private static int HexValue(byte value)
        {
            if (value >= (byte)'0' && value <= (byte)'9')
                return value - (byte)'0';
            if (value >= (byte)'a' && value <= (byte)'f')
                return value - (byte)'a' + 10;
            if (value >= (byte)'A' && value <= (byte)'F')
                return value - (byte)'A' + 10;
            return -1;
        }
    }

    public enum GdbRspCommandKind
    {
        Unknown = 0,
        Query,
        RemoteMonitor,
        Configuration,
        MemoryRead,
        MemoryWrite,
        RegisterRead,
        RegisterWrite,
        ExecutionControl,
        ExtendedControl,
        BreakpointChange,
        DetachOrKill,
        StopReasonQuery,
        ExtendedMode,
        ThreadControl,
        Restart
    }

    /// <summary>
    /// Untrusted, privacy-safe command-family shape. No proof of authenticated
    /// debugging, target access, command acceptance, or malicious execution.
    /// </summary>
    public readonly record struct GdbRspCommandObservation(
        GdbRspCommandKind CommandKindUnverified,
        int EncodedPayloadLength,
        bool ContainsEscapedBytes,
        bool PotentiallyStateChangingUnverified);
}
 || value == (byte)'#')
                    return false;

                if (value == (byte)'}')
                {
                    if (++i == encoded.Length)
                        return false;
                    byte next = encoded[i];
                    sum = (sum + next) & 0xff;
                    byte decoded = (byte)(next ^ 0x20);
                    if (decoded is not ((byte)'$' or (byte)'#' or (byte)'}' or (byte)'*'))
                        return false;
                    escaped = true;
                }
            }

            if (sum != ((high << 4) | low))
                return false;

            GdbRspCommandKind kind = encoded[0] switch
            {
                (byte)'q' => encoded.StartsWith("qRcmd,"u8)
                    ? GdbRspCommandKind.RemoteMonitor : GdbRspCommandKind.Query,
                (byte)'Q' => GdbRspCommandKind.Configuration,
                (byte)'m' => encoded.IndexOf((byte)',') > 1
                    ? GdbRspCommandKind.MemoryRead : GdbRspCommandKind.Unknown,
                (byte)'M' or (byte)'X' => encoded.IndexOf((byte)',') > 1 &&
                    encoded.IndexOf((byte)':') > 2
                    ? GdbRspCommandKind.MemoryWrite : GdbRspCommandKind.Unknown,
                (byte)'g' => encoded.Length == 1
                    ? GdbRspCommandKind.RegisterRead : GdbRspCommandKind.Unknown,
                (byte)'p' => encoded.Length > 1 && HexValue(encoded[1]) >= 0
                    ? GdbRspCommandKind.RegisterRead : GdbRspCommandKind.Unknown,
                (byte)'G' => encoded.Length > 1 && IsHex(encoded.Slice(1))
                    ? GdbRspCommandKind.RegisterWrite : GdbRspCommandKind.Unknown,
                (byte)'P' => encoded.IndexOf((byte)'=') > 1
                    ? GdbRspCommandKind.RegisterWrite : GdbRspCommandKind.Unknown,
                (byte)'c' or (byte)'C' or (byte)'s' or (byte)'S' => GdbRspCommandKind.ExecutionControl,
                (byte)'v' => GdbRspCommandKind.ExtendedControl,
                (byte)'Z' or (byte)'z' => encoded.IndexOf((byte)',') > 1
                    ? GdbRspCommandKind.BreakpointChange : GdbRspCommandKind.Unknown,
                (byte)'D' => encoded.Length == 1 || encoded[1] == (byte)';'
                    ? GdbRspCommandKind.DetachOrKill : GdbRspCommandKind.Unknown,
                (byte)'k' => encoded.Length == 1
                    ? GdbRspCommandKind.DetachOrKill : GdbRspCommandKind.Unknown,
                (byte)'?' => encoded.Length == 1
                    ? GdbRspCommandKind.StopReasonQuery : GdbRspCommandKind.Unknown,
                (byte)'!' => encoded.Length == 1
                    ? GdbRspCommandKind.ExtendedMode : GdbRspCommandKind.Unknown,
                (byte)'H' => encoded.Length >= 3 &&
                    (encoded[1] == (byte)'c' || encoded[1] == (byte)'g')
                    ? GdbRspCommandKind.ThreadControl : GdbRspCommandKind.Unknown,
                (byte)'T' => encoded.Length > 1 && IsHex(encoded.Slice(1))
                    ? GdbRspCommandKind.ThreadControl : GdbRspCommandKind.Unknown,
                (byte)'R' => GdbRspCommandKind.Restart,
                _ => GdbRspCommandKind.Unknown
            };
            if (kind == GdbRspCommandKind.Unknown)
                return false;

            bool potentiallyStateChanging = kind is
                GdbRspCommandKind.RemoteMonitor or GdbRspCommandKind.Configuration or
                GdbRspCommandKind.MemoryWrite or GdbRspCommandKind.RegisterWrite or
                GdbRspCommandKind.ExecutionControl or GdbRspCommandKind.ExtendedControl or
                GdbRspCommandKind.BreakpointChange or GdbRspCommandKind.DetachOrKill or
                GdbRspCommandKind.ExtendedMode or GdbRspCommandKind.Restart;

            observation = new GdbRspCommandObservation(
                kind, encoded.Length, escaped, potentiallyStateChanging);
            return true;
        }

        private static bool IsHex(ReadOnlySpan<byte> value)
        {
            if (value.IsEmpty || (value.Length & 1) != 0)
                return false;
            foreach (byte digit in value)
                if (HexValue(digit) < 0)
                    return false;
            return true;
        }

        private static int HexValue(byte value)
        {
            if (value >= (byte)'0' && value <= (byte)'9')
                return value - (byte)'0';
            if (value >= (byte)'a' && value <= (byte)'f')
                return value - (byte)'a' + 10;
            if (value >= (byte)'A' && value <= (byte)'F')
                return value - (byte)'A' + 10;
            return -1;
        }
    }

    public enum GdbRspCommandKind
    {
        Unknown = 0,
        Query,
        RemoteMonitor,
        Configuration,
        MemoryRead,
        MemoryWrite,
        RegisterRead,
        RegisterWrite,
        ExecutionControl,
        ExtendedControl,
        BreakpointChange,
        DetachOrKill,
        StopReasonQuery,
        ExtendedMode,
        ThreadControl,
        Restart
    }

    /// <summary>
    /// Untrusted, privacy-safe command-family shape. No proof of authenticated
    /// debugging, target access, command acceptance, or malicious execution.
    /// </summary>
    public readonly record struct GdbRspCommandObservation(
        GdbRspCommandKind CommandKindUnverified,
        int EncodedPayloadLength,
        bool ContainsEscapedBytes,
        bool PotentiallyStateChangingUnverified);
}
