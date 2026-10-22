// SPDX-License-Identifier: MIT
// File: Services/EntityGraph/EntityEdge.cs
using System;
using System.Collections.Generic;

namespace Carthago.Services.EntityGraph
{
    public enum EntityEdgeKind
    {
        CommunicatedWith,
        QueriedDomain,
        UsedProtocol,
        ConnectedToService,
        BelongsToMac,
        ResolvedToIp,
        TriggeredRule,
        PartOfIncident,
        UploadedTo,
        AuthenticatedTo,
        DiscoveredService,
        SameHostAs,
        SuspiciousRelation
    }

    public sealed class EntityEdge
    {
        public string EdgeId { get; set; } = Guid.NewGuid().ToString("N");
        public string SourceEntityId { get; set; } = string.Empty;
        public string TargetEntityId { get; set; } = string.Empty;
        public EntityEdgeKind Kind { get; set; }
        public DateTime FirstSeenUtc { get; set; } = DateTime.UtcNow;
        public DateTime LastSeenUtc { get; set; } = DateTime.UtcNow;
        public int ObservationCount { get; set; }
        public List<string> EventIds { get; set; } = new();
    }
}
