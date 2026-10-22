// SPDX-License-Identifier: MIT
// File: Models/CiscoNeighbor.cs

using System;

namespace Carthago.Models
{
    /// <summary>
    /// One L2/L3 neighbor discovered via CDP/LLDP/SNMP.
    /// </summary>
    public sealed class CiscoNeighbor
    {
        /// <summary>Discovery protocol (CDP, LLDP, etc.).</summary>
        public string Protocol { get; set; } = "CDP";

        /// <summary>Local interface index / name (e.g. "Gi1/0").</summary>
        public string LocalInterface { get; set; } = string.Empty;

        /// <summary>Remote device ID from CDP/LLDP (e.g. "IOU1").</summary>
        public string RemoteDeviceId { get; set; } = string.Empty;

        /// <summary>Remote sysName (if available via SNMP MIB-II).</summary>
        public string RemoteSysName { get; set; } = string.Empty;

        /// <summary>Remote management address, if we can infer it.</summary>
        public string RemoteMgmtAddress { get; set; } = string.Empty;

        /// <summary>Remote platform string (e.g. "Linux Uni").</summary>
        public string RemotePlatform { get; set; } = string.Empty;

        /// <summary>Capabilities bitmask/decoded string.</summary>
        public string RemoteCapabilities { get; set; } = string.Empty;

        /// <summary>Remote port name (e.g. "Eth0/1").</summary>
        public string RemoteInterface { get; set; } = string.Empty;
    }
}
