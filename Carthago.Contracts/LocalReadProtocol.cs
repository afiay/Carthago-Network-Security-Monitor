// SPDX-License-Identifier: MIT
using System.Buffers.Binary;

namespace Carthago.Contracts;

public enum ReadCommand : byte { HostStatus = 1, RulesSummary = 2 }
public enum ReadState : byte { Available = 1, Unavailable = 2 }
public sealed record ReadRequest(ReadCommand Command, Guid Correlation);
public sealed record ReadResponse(ReadCommand Command, Guid Correlation, ReadState State,
    int Registered, int EnabledByDefault, int Planned, DateTimeOffset ObservedUtc);

/// <summary>Fixed-size, versioned read-only protocol. No caller-supplied identity or payload.</summary>
public static class LocalReadProtocol
{
    public const byte Version = 1;
    public const int RequestBytes = 18;
    public const int ResponseBytes = 39;
    public const byte Acknowledgment = 0x06;

    public static byte[] EncodeRequest(ReadRequest request)
    {
        if (!ValidCommand(request.Command) || request.Correlation == Guid.Empty)
            throw new InvalidDataException("Invalid request.");
        var bytes = new byte[RequestBytes];
        bytes[0] = Version;
        bytes[1] = (byte)request.Command;
        request.Correlation.TryWriteBytes(bytes.AsSpan(2, 16));
        return bytes;
    }

    public static ReadRequest DecodeRequest(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != RequestBytes || bytes[0] != Version)
            throw new InvalidDataException("Invalid request frame.");
        var request = new ReadRequest((ReadCommand)bytes[1], new Guid(bytes.Slice(2, 16)));
        _ = EncodeRequest(request);
        return request;
    }

    public static byte[] EncodeResponse(ReadResponse response)
    {
        Validate(response);
        var bytes = new byte[ResponseBytes];
        bytes[0] = Version;
        bytes[1] = (byte)response.Command;
        response.Correlation.TryWriteBytes(bytes.AsSpan(2, 16));
        bytes[18] = (byte)response.State;
        BinaryPrimitives.WriteInt32BigEndian(bytes.AsSpan(19, 4), response.Registered);
        BinaryPrimitives.WriteInt32BigEndian(bytes.AsSpan(23, 4), response.EnabledByDefault);
        BinaryPrimitives.WriteInt32BigEndian(bytes.AsSpan(27, 4), response.Planned);
        BinaryPrimitives.WriteInt64BigEndian(bytes.AsSpan(31, 8), response.ObservedUtc.ToUnixTimeMilliseconds());
        return bytes;
    }

    public static ReadResponse DecodeResponse(ReadOnlySpan<byte> bytes, ReadRequest expected)
    {
        if (bytes.Length != ResponseBytes || bytes[0] != Version)
            throw new InvalidDataException("Invalid response frame.");
        var response = new ReadResponse((ReadCommand)bytes[1], new Guid(bytes.Slice(2, 16)),
            (ReadState)bytes[18], BinaryPrimitives.ReadInt32BigEndian(bytes.Slice(19, 4)),
            BinaryPrimitives.ReadInt32BigEndian(bytes.Slice(23, 4)),
            BinaryPrimitives.ReadInt32BigEndian(bytes.Slice(27, 4)),
            DateTimeOffset.FromUnixTimeMilliseconds(BinaryPrimitives.ReadInt64BigEndian(bytes.Slice(31, 8))));
        Validate(response);
        if (response.Command != expected.Command || response.Correlation != expected.Correlation)
            throw new InvalidDataException("Response correlation mismatch.");
        return response;
    }

    private static bool ValidCommand(ReadCommand command)
        => command is ReadCommand.HostStatus or ReadCommand.RulesSummary;

    private static void Validate(ReadResponse value)
    {
        if (!ValidCommand(value.Command) || value.Correlation == Guid.Empty ||
            value.State is not (ReadState.Available or ReadState.Unavailable) ||
            value.Registered < 0 || value.EnabledByDefault < 0 || value.Planned < 0 ||
            value.EnabledByDefault > value.Registered || value.Planned > value.Registered ||
            ((value.Command == ReadCommand.HostStatus || value.State == ReadState.Unavailable) &&
             (value.Registered != 0 || value.EnabledByDefault != 0 || value.Planned != 0)))
            throw new InvalidDataException("Invalid response fields.");
    }
}
