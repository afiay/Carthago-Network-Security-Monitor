// SPDX-License-Identifier: MIT
// File: Models/CiscoLink.cs

using System;

namespace Carthago.Models
{
    /// <summary>
    /// Logical link between two CiscoDevice nodes in the topology.
    /// </summary>
    public sealed class CiscoLink
    {
        public CiscoDevice? Local { get; set; }
        public CiscoDevice? Remote { get; set; }

        public string Protocol { get; set; } = string.Empty;
        public string LocalInterface { get; set; } = string.Empty;
        public string RemoteInterface { get; set; } = string.Empty;

        public DateTime LastSeenUtc { get; set; }
    }
}
