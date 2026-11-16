// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Globalization;
using Carthago.Models;

namespace Carthago.Views;

/// <summary>
/// Read-only presentation for nullable packet headers. Never overwrites the
/// recorded values or manufactures header evidence for detector rules.
/// </summary>
internal static class LiveTrafficHeaderFormatter
{
    internal const string IcmpType = "icmp-type";
    internal const string IcmpCode = "icmp-code";
    internal const string TcpText = "tcp-text";
    internal const string TcpRaw = "tcp-raw";
    internal const string NotApplicable = "N/A";
    internal const string Unavailable = "—";

    internal static string Format(TrafficRecord? record, string? column)
    {
        if (record is null) return Unavailable;

        var protocol = record.Protocol;
        var tcp = record.IsTcp || string.Equals(protocol, "TCP", StringComparison.OrdinalIgnoreCase);
        var icmp = string.Equals(protocol, "ICMP", StringComparison.OrdinalIgnoreCase)
            || string.Equals(protocol, "ICMPv4", StringComparison.OrdinalIgnoreCase)
            || string.Equals(protocol, "ICMPv6", StringComparison.OrdinalIgnoreCase)
            || string.Equals(protocol, "ICMP6", StringComparison.OrdinalIgnoreCase);
        var unknownProtocol = string.IsNullOrWhiteSpace(protocol) && !record.IsTcp && !record.IsUdp;

        switch (column)
        {
            case IcmpType:
                if (record.IcmpTypeCode.HasValue)
                    return (record.IcmpTypeCode.Value >> 8).ToString(CultureInfo.InvariantCulture);
                return icmp || unknownProtocol ? Unavailable : NotApplicable;

            case IcmpCode:
                if (record.IcmpTypeCode.HasValue)
                    return (record.IcmpTypeCode.Value & 0xFF).ToString(CultureInfo.InvariantCulture);
                return icmp || unknownProtocol ? Unavailable : NotApplicable;

            case TcpText:
                if (!tcp && !record.TcpFlags.HasValue && string.IsNullOrWhiteSpace(record.Flags))
                    return unknownProtocol ? Unavailable : NotApplicable;
                if (!string.IsNullOrWhiteSpace(record.Flags))
                    return record.Flags.Trim();
                return record.TcpFlags.HasValue ? FormatTcpNames(record.TcpFlags.Value) : Unavailable;

            case TcpRaw:
                if (record.TcpFlags.HasValue)
                {
                    var flags = record.TcpFlags.Value;
                    return "0x" + flags.ToString("X3", CultureInfo.InvariantCulture) +
                        " (" + flags.ToString(CultureInfo.InvariantCulture) + ")";
                }
                // A textual flag label is not evidence of a raw header bitmask.
                return tcp || unknownProtocol || !string.IsNullOrWhiteSpace(record.Flags)
                    ? Unavailable : NotApplicable;

            default:
                return Unavailable;
        }
    }

    private static string FormatTcpNames(ushort raw)
    {
        var labels = new List<string>(9);
        if ((raw & 0x100) != 0) labels.Add("NS");
        if ((raw & 0x002) != 0) labels.Add("SYN");
        if ((raw & 0x010) != 0) labels.Add("ACK");
        if ((raw & 0x001) != 0) labels.Add("FIN");
        if ((raw & 0x004) != 0) labels.Add("RST");
        if ((raw & 0x008) != 0) labels.Add("PSH");
        if ((raw & 0x020) != 0) labels.Add("URG");
        if ((raw & 0x040) != 0) labels.Add("ECE");
        if ((raw & 0x080) != 0) labels.Add("CWR");
        if ((raw & ~0x1FF) != 0) labels.Add("UNKNOWN");
        return labels.Count == 0 ? "NONE" : string.Join(", ", labels);
    }
}
