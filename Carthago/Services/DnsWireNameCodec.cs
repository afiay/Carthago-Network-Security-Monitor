// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Carthago.Services;

public enum DnsWireNameError
{
    None,
    InvalidBase64Label,
    InvalidLabelLength,
    NameTooLong,
    MalformedWireName,
    InvalidCompressionPointer
}

/// <summary>
/// Immutable representation of DNS labels as the exact bytes observed on the wire.
/// A presentation-format QName cannot represent arbitrary binary DNS labels losslessly.
/// </summary>
public sealed class DnsWireName
{
    private readonly byte[][] _labels;

    internal DnsWireName(IReadOnlyList<byte[]> labels, int decompressedLength)
    {
        _labels = labels.Select(label => (byte[])label.Clone()).ToArray();
        DecompressedLength = decompressedLength;
    }

    public int LabelCount => _labels.Length;
    public int DecompressedLength { get; }

    public byte[] GetLabelBytes(int index) => (byte[])_labels[index].Clone();
}

/// <summary>Strict, lossless DNS label conversion and bounded wire-name parsing.</summary>
public static class DnsWireNameCodec
{
    private const int MaximumLabelLength = 63;
    private const int MaximumNameLength = 255;

    public static bool TryFromBase64Labels(IEnumerable<string>? encodedLabels,
        out DnsWireName? name, out DnsWireNameError error)
    {
        name = null;
        error = DnsWireNameError.InvalidBase64Label;
        if (encodedLabels is null)
            return false;

        var labels = new List<byte[]>();
        var length = 1; // Root label terminator.
        foreach (var encoded in encodedLabels)
        {
            if (string.IsNullOrEmpty(encoded))
                return false;

            byte[] bytes;
            try
            {
                bytes = Convert.FromBase64String(encoded);
            }
            catch (FormatException)
            {
                return false;
            }

            // Convert.FromBase64String tolerates whitespace and noncanonical pad bits.
            if (bytes.Length == 0 || !string.Equals(Convert.ToBase64String(bytes), encoded,
                    StringComparison.Ordinal))
                return false;

            if (bytes.Length > MaximumLabelLength)
            {
                error = DnsWireNameError.InvalidLabelLength;
                return false;
            }

            length += 1 + bytes.Length;
            if (length > MaximumNameLength)
            {
                error = DnsWireNameError.NameTooLong;
                return false;
            }
            labels.Add(bytes);
        }

        name = new DnsWireName(labels, length);
        error = DnsWireNameError.None;
        return true;
    }

    public static string[] ToBase64Labels(DnsWireName name)
    {
        ArgumentNullException.ThrowIfNull(name);
        return Enumerable.Range(0, name.LabelCount)
            .Select(index => Convert.ToBase64String(name.GetLabelBytes(index))).ToArray();
    }

    public static string CanonicalIdentityKey(DnsWireName name)
    {
        ArgumentNullException.ThrowIfNull(name);
        var wire = new byte[name.DecompressedLength];
        var cursor = 0;
        for (var index = 0; index < name.LabelCount; index++)
        {
            var label = name.GetLabelBytes(index);
            wire[cursor++] = (byte)label.Length;
            foreach (var octet in label)
                wire[cursor++] = octet is >= (byte)'A' and <= (byte)'Z'
                    ? (byte)(octet + 32) : octet;
        }
        wire[cursor] = 0;
        return Convert.ToHexString(wire);
    }

    public static bool TryGetSafeAsciiQName(DnsWireName name, out string? display)
    {
        ArgumentNullException.ThrowIfNull(name);
        display = null;
        var labels = new string[name.LabelCount];
        for (var i = 0; i < labels.Length; i++)
        {
            var label = name.GetLabelBytes(i);
            // Never render punctuation that could be mistaken for DNS structure or escapes.
            if (label.Any(value => value < 0x21 || value > 0x7e ||
                    value is (byte)'.' or (byte)'\\'))
                return false;
            labels[i] = Encoding.ASCII.GetString(label);
        }
        display = string.Join('.', labels);
        return true;
    }

    public static bool TryReadQuestion(byte[]? message, int offset,
        out DnsWireName? name, out int nextOffset, out DnsWireNameError error)
    {
        name = null;
        nextOffset = offset;
        error = DnsWireNameError.MalformedWireName;
        if (message is null || offset < 0 || offset >= message.Length)
            return false;

        var labels = new List<byte[]>();
        var cursor = offset;
        var length = 1;
        var jumped = false;
        var steps = 0;
        while (true)
        {
            if (++steps > message.Length || cursor >= message.Length)
                return false;

            var header = message[cursor];
            if ((header & 0xc0) == 0xc0)
            {
                if (cursor + 1 >= message.Length)
                    return false;
                var pointer = ((header & 0x3f) << 8) | message[cursor + 1];
                // Strictly backward pointers prevent forward references and cycles.
                if (pointer >= cursor)
                {
                    error = DnsWireNameError.InvalidCompressionPointer;
                    return false;
                }
                if (!jumped)
                    nextOffset = cursor + 2;
                jumped = true;
                cursor = pointer;
                continue;
            }

            if ((header & 0xc0) != 0)
                return false; // Reserved/extended label types are unsupported.
            cursor++;
            if (header == 0)
            {
                if (!jumped)
                    nextOffset = cursor;
                name = new DnsWireName(labels, length);
                error = DnsWireNameError.None;
                return true;
            }

            if (header > MaximumLabelLength || header > message.Length - cursor)
                return false;
            length += 1 + header;
            if (length > MaximumNameLength)
            {
                error = DnsWireNameError.NameTooLong;
                return false;
            }
            var label = new byte[header];
            Array.Copy(message, cursor, label, 0, header);
            labels.Add(label);
            cursor += header;
        }
    }
}
