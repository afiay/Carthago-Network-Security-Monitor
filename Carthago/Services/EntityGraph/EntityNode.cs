// SPDX-License-Identifier: MIT
// File: Services/EntityGraph/EntityNode.cs
using System;
using System.Collections.Generic;

namespace Carthago.Services.EntityGraph
{
    public enum EntityNodeKind
    {
        Host,
        IP,
        MAC,
        User,
        Process,
        DnsDomain,
        Sni,
        ASN,
        Country,
        Service,
        Port,
        Protocol,
        CloudSaasProvider,
        IoTDevice,
        OTDevice,
        Incident,
        DetectionEvent
    }

    public sealed class EntityNode
    {
        public string EntityId { get; set; } = string.Empty;
        public EntityNodeKind Kind { get; set; }
        public string DisplayName { get; set; } = string.Empty;
        public DateTime FirstSeenUtc { get; set; } = DateTime.UtcNow;
        public DateTime LastSeenUtc { get; set; } = DateTime.UtcNow;
        public int ObservationCount { get; set; }
        public Dictionary<string, string> Attributes { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }
}
