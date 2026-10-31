// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Classic ADB transport message shape (AOSP aprotocol), not the separate
    /// host smart-socket protocol on TCP/5037. Requires one complete reassembled
    /// plaintext transport message and trusted ADB transport endpoint.
    /// Does not verify checksum, authentication, stream state or execution.
    /// Payload, identities, stream IDs and auth material are never retained.
    /// </summary>
    public static class AdbTransportMessageInspector
    {
        private const int HeaderLength = 24;
        private const int MaximumPayloadLength = 4096; // conservative pre-negotiation cap
        private const uint Cnxn = 0x4e584e43;
        private const uint Auth = 0x48545541;
        private const uint Open = 0x4e45504f;
        private const uint Okay = 0x59414b4f;
        private const uint Clse = 0x45534c43;
        private const uint Wrte = 0x45545257;

        public static bool TryInspect(ReadOnlySpan<byte> message,
            bool verifiedCompletePlaintextMessage, bool verifiedAdbTransportEndpoint,
            out AdbTransportMessageObservation observation)
        {
            observation = default;
            if (!verifiedCompletePlaintextMessage || !verifiedAdbTransportEndpoint ||
                message.Length is < HeaderLength or > HeaderLength + MaximumPayloadLength)
                return false;

            uint command = BinaryPrimitives.ReadUInt32LittleEndian(message.Slice(0, 4));
            uint arg0 = BinaryPrimitives.ReadUInt32LittleEndian(message.Slice(4, 4));
            uint arg1 = BinaryPrimitives.ReadUInt32LittleEndian(message.Slice(8, 4));
            uint declaredLength = BinaryPrimitives.ReadUInt32LittleEndian(message.Slice(12, 4));
            uint magic = BinaryPrimitives.ReadUInt32LittleEndian(message.Slice(20, 4));
            if (magic != (command ^ 0xffffffffu) ||
                declaredLength != (uint)(message.Length - HeaderLength))
                return false;

            bool supported = command switch
            {
                Cnxn => arg0 != 0 && arg1 >= 4096 && declaredLength > 0,
                Auth => arg0 is 1 or 2 or 3 && arg1 == 0 && declaredLength > 0,
                Open => arg0 != 0 && arg1 == 0 && declaredLength > 0,
                Okay => arg0 != 0 && arg1 != 0 && declaredLength == 0,
                Clse => arg1 != 0 && declaredLength == 0,
                Wrte => arg0 != 0 && arg1 != 0 && declaredLength > 0,
                _ => false // modern extensions require separate documented support
            };
            if (!supported)
                return false;

            observation = new AdbTransportMessageObservation(
                command, (int)declaredLength, command == Auth);
            return true;
        }
    }

    public readonly record struct AdbTransportMessageObservation(
        uint Command, int PayloadLength, bool AuthenticationMessageUnverified);
}
