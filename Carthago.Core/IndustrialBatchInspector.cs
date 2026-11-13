// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using Carthago.Models;

namespace Carthago.Services.ProtocolIntelligence
{
    // Exact, bounded, capture-only native request projections.
    // No addresses inside protocol messages, values, credentials or raw
    // application bytes are returned. Wire validation is not authentication.
    internal static class IndustrialBatchInspector
    {
        internal static string? Label(IndustrialBatchOperation operation) => operation switch
        {
            IndustrialBatchOperation.BacnetDeviceSystemStatusRead => "industrial.bacnet_device_system_status_read.request",
            IndustrialBatchOperation.BacnetDeviceAllPropertiesRead => "industrial.bacnet_device_all_properties_read.request",
            IndustrialBatchOperation.BacnetInputOutOfService => "industrial.bacnet_input_out_of_service.request",
            IndustrialBatchOperation.BacnetAtomicFileRead => "industrial.bacnet_atomic_file_read.request",
            IndustrialBatchOperation.BacnetAtomicFileWrite => "industrial.bacnet_atomic_file_write.request",
            IndustrialBatchOperation.FinsCpuStatusRead => "industrial.fins_cpu_status_read.request",
            IndustrialBatchOperation.FinsBulkDataMemoryRead => "industrial.fins_bulk_data_memory_read.request",
            IndustrialBatchOperation.Dnp3IntegrityRead => "industrial.dnp3_integrity_read.request",
            IndustrialBatchOperation.Dnp3AbsoluteTimeWrite => "industrial.dnp3_absolute_time_write.request",
            IndustrialBatchOperation.ModbusReadWriteSamePairZero => "industrial.modbus_read_write_same_pair_zero.request",
            IndustrialBatchOperation.ModbusBulkFileWrite => "industrial.modbus_bulk_file_write.request",
            IndustrialBatchOperation.SnmpInterfaceAdminDown => "industrial.snmp_interface_admin_down.request",
            IndustrialBatchOperation.SnmpIpv4ForwardingDisable => "industrial.snmp_ipv4_forwarding_disable.request",
            _ => null
        };

        internal static IndustrialBatchOperation InspectUdp(int sourcePort, int destinationPort, ReadOnlySpan<byte> p)
        {
            if (sourcePort is < 1 or > 65535) return IndustrialBatchOperation.None;
            return destinationPort switch
            {
                47808 => InspectBacnet(p),
                9600 when sourcePort == 9600 => InspectFins(p),
                20000 when sourcePort == 20000 => InspectDnp3(p),
                161 when sourcePort != 161 => SnmpEnterpriseSetInspector.InspectNetworkControlSet(p),
                _ => IndustrialBatchOperation.None
            };
        }

        private static ushort Be16(ReadOnlySpan<byte> p, int i)
            => BinaryPrimitives.ReadUInt16BigEndian(p.Slice(i, 2));
        private static ushort Le16(ReadOnlySpan<byte> p, int i)
            => BinaryPrimitives.ReadUInt16LittleEndian(p.Slice(i, 2));

        private static bool BacnetHeader(ReadOnlySpan<byte> p)
            => p.Length is >= 10 and <= 1476 && p[0] == 0x81 && p[1] == 0x0A &&
                Be16(p, 2) == p.Length && p[4] == 1 && (p[5] & 0xFC) == 4 &&
                (p[6] & 0xFD) == 0 && (p[7] & 0x0F) <= 5 && (p[7] >> 4) <= 7;

        private static bool BacnetObject(ReadOnlySpan<byte> p, byte tag, uint firstType, uint secondType)
        {
            if (p.Length < 15 || p[10] != tag) return false;
            uint id = BinaryPrimitives.ReadUInt32BigEndian(p.Slice(11, 4));
            uint type = id >> 22;
            return (type == firstType || type == secondType) && (id & 0x3FFFFF) != 0x3FFFFF;
        }

        private static IndustrialBatchOperation InspectBacnet(ReadOnlySpan<byte> p)
        {
            if (!BacnetHeader(p)) return IndustrialBatchOperation.None;
            if (p.Length == 17 && p[9] == 12 && BacnetObject(p, 0x0C, 8, 8) &&
                p[15] == 0x19 && p[16] == 112)
                return IndustrialBatchOperation.BacnetDeviceSystemStatusRead;
            if (p.Length == 19 && p[9] == 14 && BacnetObject(p, 0x0C, 8, 8) &&
                p[15] == 0x1E && p[16] == 0x09 && p[17] == 8 && p[18] == 0x1F)
                return IndustrialBatchOperation.BacnetDeviceAllPropertiesRead;
            // BACnet application Boolean encodes true in the tag LVT,
            // not in a following data byte. No array index or priority.
            if (p.Length == 20 && p[9] == 15 && BacnetObject(p, 0x0C, 0, 3) &&
                p[15] == 0x19 && p[16] == 81 && p[17] == 0x3E &&
                p[18] == 0x11 && p[19] == 0x3F)
                return IndustrialBatchOperation.BacnetInputOutOfService;
            // AtomicReadFile/AtomicWriteFile use application ObjectIdentifier
            // followed by stream-access choice [0], signed position and data.
            if (p.Length == 22 && p[9] == 6 && BacnetObject(p, 0xC4, 10, 10) &&
                p[15] == 0x0E && p[16] == 0x31 && p[17] == 0 &&
                p[18] == 0x22 && Be16(p, 19) == 512 && p[21] == 0x0F)
                return IndustrialBatchOperation.BacnetAtomicFileRead;
            if (p.Length == 279 && p[9] == 7 && BacnetObject(p, 0xC4, 10, 10) &&
                p[15] == 0x0E && p[16] == 0x31 && p[17] == 0 &&
                p[18] == 0x65 && p[19] == 0xFE && Be16(p, 20) == 256 &&
                p[278] == 0x0F)
                return IndustrialBatchOperation.BacnetAtomicFileWrite;
            return IndustrialBatchOperation.None;
        }

        private static bool FinsHeader(ReadOnlySpan<byte> p)
            => p.Length >= 12 && p[0] == 0x80 && p[1] == 0 && p[2] == 2 &&
                p[3] == 0 && p[5] == 0 && p[6] == 0 && p[8] == 0 &&
                p[4] is >= 1 and <= 254 && p[7] is >= 1 and <= 254 && p[4] != p[7];

        private static IndustrialBatchOperation InspectFins(ReadOnlySpan<byte> p)
        {
            if (!FinsHeader(p)) return IndustrialBatchOperation.None;
            if (p.Length == 12 && p[10] == 6 && p[11] == 1)
                return IndustrialBatchOperation.FinsCpuStatusRead;
            if (p.Length == 18 && p[10] == 1 && p[11] == 1 && p[12] == 0x82 &&
                Be16(p, 13) <= 32512 && p[15] == 0 && Be16(p, 16) == 256)
                return IndustrialBatchOperation.FinsBulkDataMemoryRead;
            return IndustrialBatchOperation.None;
        }

        private static bool Dnp3Header(ReadOnlySpan<byte> p, int dataLength)
        {
            // Both supported messages have exactly one <=16-byte data block.
            if (p.Length != 12 + dataLength || dataLength is < 3 or > 16 ||
                p[0] != 5 || p[1] != 0x64 || p[2] != 5 + dataLength || p[3] != 0xC4 ||
                Dnp3UnsolicitedBinaryEventInspector.Crc(p[..8]) != Le16(p, 8) ||
                Dnp3UnsolicitedBinaryEventInspector.Crc(p.Slice(10, dataLength)) != Le16(p, 10 + dataLength))
                return false;
            ushort dst = Le16(p, 4), src = Le16(p, 6);
            return src != dst && src < 0xFFF0 && dst < 0xFFF0 &&
                (p[10] & 0xC0) == 0xC0 && (p[11] & 0xF0) == 0xC0;
        }

        private static IndustrialBatchOperation InspectDnp3(ReadOnlySpan<byte> p)
        {
            if (Dnp3Header(p, 15) && p[12] == 1)
            {
                int seen = 0;
                for (int i = 13; i < 25; i += 3)
                {
                    if (p[i] != 60 || p[i + 2] != 6 || p[i + 1] is < 1 or > 4)
                        return IndustrialBatchOperation.None;
                    int bit = 1 << (p[i + 1] - 1);
                    if ((seen & bit) != 0) return IndustrialBatchOperation.None;
                    seen |= bit;
                }
                if (seen == 15) return IndustrialBatchOperation.Dnp3IntegrityRead;
            }
            if (Dnp3Header(p, 13) && p[12] == 2 && p[13] == 50 &&
                p[14] == 1 && p[15] == 7 && p[16] == 1)
                return IndustrialBatchOperation.Dnp3AbsoluteTimeWrite;
            return IndustrialBatchOperation.None;
        }

        internal static IndustrialBatchOperation InspectModbus(ReadOnlySpan<byte> p)
        {
            if (p.Length is < 8 or > 260 || Be16(p, 2) != 0 ||
                Be16(p, 4) != p.Length - 6 || p[6] is < 1 or > 247)
                return IndustrialBatchOperation.None;
            if (p.Length == 21 && p[7] == 0x17 && Be16(p, 8) <= 65534 &&
                Be16(p, 8) == Be16(p, 12) && Be16(p, 10) == 2 &&
                Be16(p, 14) == 2 && p[16] == 4 &&
                Be16(p, 17) == 0 && Be16(p, 19) == 0)
                return IndustrialBatchOperation.ModbusReadWriteSamePairZero;
            if (p.Length is >= 216 and <= 256 && p[7] == 0x15 &&
                p[8] == p.Length - 9 && p[9] == 6 && Be16(p, 10) != 0)
            {
                int record = Be16(p, 12), words = Be16(p, 14);
                if (words is >= 100 and <= 120 && record <= 9999 &&
                    record + words <= 10000 && p.Length == 16 + words * 2)
                    return IndustrialBatchOperation.ModbusBulkFileWrite;
            }
            return IndustrialBatchOperation.None;
        }
    }
}
