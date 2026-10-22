// SPDX-License-Identifier: MIT
// File: Services/Cisco/CiscoDiscoveryService.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Carthago.Models;

namespace Carthago.Services.Cisco
{
    /// <summary>
    /// Tiny SNMP-based discovery service: walks the Cisco CDP MIB (cdpCacheEntry)
    /// through an adapter so SNMP package compatibility stays isolated.
    /// </summary>
    public sealed class CiscoDiscoveryService
    {
        private const string CdpCacheEntryRoot = "1.3.6.1.4.1.9.9.23.1.2.1.1";
        private static readonly int CdpCacheEntryRootSegmentCount = CdpCacheEntryRoot.Split('.').Length;

        private const int CdpCacheAddressTypeCol = 4;
        private const int CdpCacheAddressCol = 5;
        private const int CdpCacheDeviceIdCol = 6;
        private const int CdpCacheDevicePortCol = 7;
        private const int CdpCachePlatformCol = 8;
        private const int CdpCacheCapsCol = 9;

        private readonly ISnmpClientAdapter _snmpClient;

        public CiscoDiscoveryService(ISnmpClientAdapter? snmpClient = null)
            => _snmpClient = snmpClient ?? new SnmpSharpNetClientAdapter();

        public Task<IReadOnlyList<CiscoNeighbor>> DiscoverNeighborsAsync(
            CiscoDevice device,
            string community)
        {
            if (device == null)
                throw new ArgumentNullException(nameof(device));
            if (string.IsNullOrWhiteSpace(device.Host))
                throw new ArgumentException("Device.Host must be set for SNMP discovery", nameof(device));
            if (string.IsNullOrWhiteSpace(community))
                throw new ArgumentException("SNMP community is required", nameof(community));
            if (!IPAddress.TryParse(device.Host, out _))
                throw new ArgumentException("Device.Host must be an IP address for SNMP discovery in this build.", nameof(device));

            return Task.Run<IReadOnlyList<CiscoNeighbor>>(() =>
            {
                var neighbors = new Dictionary<(int ifIndex, int devIndex), CiscoNeighbor>();
                var variables = _snmpClient.Walk(device.Host, 161, community, CdpCacheEntryRoot);

                foreach (var variable in variables)
                    ParseCdpVariable(variable, neighbors);

                return (IReadOnlyList<CiscoNeighbor>)neighbors.Values
                    .Where(static neighbor => !string.IsNullOrWhiteSpace(neighbor.RemoteDeviceId))
                    .ToList();
            });
        }

        private static void ParseCdpVariable(
            SnmpWalkVariable variable,
            IDictionary<(int ifIndex, int devIndex), CiscoNeighbor> table)
        {
            if (variable == null || string.IsNullOrWhiteSpace(variable.Oid))
                return;

            var oidNumbers = variable.Oid.Split('.', StringSplitOptions.RemoveEmptyEntries)
                .Select(static part => int.TryParse(part, out var value) ? value : -1)
                .ToArray();
            if (oidNumbers.Length < CdpCacheEntryRootSegmentCount + 3 || oidNumbers.Any(static value => value < 0))
                return;

            var column = oidNumbers[CdpCacheEntryRootSegmentCount];
            var ifIndex = oidNumbers[CdpCacheEntryRootSegmentCount + 1];
            var devIndex = oidNumbers[CdpCacheEntryRootSegmentCount + 2];
            var key = (ifIndex, devIndex);

            if (!table.TryGetValue(key, out var neighbor))
            {
                neighbor = new CiscoNeighbor
                {
                    Protocol = "CDP",
                    LocalInterface = ifIndex.ToString()
                };
                table[key] = neighbor;
            }

            switch (column)
            {
                case CdpCacheDeviceIdCol:
                    neighbor.RemoteDeviceId = variable.ValueText ?? string.Empty;
                    break;
                case CdpCacheDevicePortCol:
                    neighbor.RemoteInterface = variable.ValueText ?? string.Empty;
                    break;
                case CdpCachePlatformCol:
                    neighbor.RemotePlatform = variable.ValueText ?? string.Empty;
                    break;
                case CdpCacheCapsCol:
                    neighbor.RemoteCapabilities = variable.ValueText ?? string.Empty;
                    break;
                case CdpCacheAddressCol when variable.OctetStringBytes is { Length: 4 } octets:
                    neighbor.RemoteMgmtAddress = string.Format(
                        System.Globalization.CultureInfo.InvariantCulture,
                        "{0}.{1}.{2}.{3}",
                        octets[0],
                        octets[1],
                        octets[2],
                        octets[3]);
                    break;
                case CdpCacheAddressTypeCol:
                default:
                    break;
            }
        }
    }
}
