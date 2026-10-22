// SPDX-License-Identifier: MIT
// File: Services/EntityGraph/EntityGraphStore.cs
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;

namespace Carthago.Services.EntityGraph
{
    public sealed class EntityGraphStore
    {
        private sealed class GraphState
        {
            public Dictionary<string, EntityNode> Nodes { get; set; } = new(StringComparer.OrdinalIgnoreCase);
            public Dictionary<string, EntityEdge> Edges { get; set; } = new(StringComparer.OrdinalIgnoreCase);
            public List<EntityObservation> Observations { get; set; } = new();
        }

        private readonly EntityGraphOptions _options;
        private readonly SemaphoreSlim _gate = new(1, 1);
        private readonly JsonSerializerOptions _json = new()
        {
            WriteIndented = true,
            PropertyNameCaseInsensitive = true,
            Converters = { new JsonStringEnumConverter() }
        };

        public EntityGraphStore(EntityGraphOptions? options = null)
            => _options = options ?? new EntityGraphOptions();

        private string PathName => Path.Combine(_options.DirectoryPath, _options.FileName);

        public async Task<IReadOnlyList<string>> ObserveDetectionAsync(DetectionEvent evt, CancellationToken cancellationToken = default)
        {
            if (evt == null) throw new ArgumentNullException(nameof(evt));
            await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var state = await LoadUnsafeAsync(cancellationToken).ConfigureAwait(false);
                var now = evt.TimestampUtc == default ? DateTime.UtcNow : evt.TimestampUtc;
                var ids = new List<string>();

                var eventId = EntityId(EntityNodeKind.DetectionEvent, evt.EventId);
                UpsertNode(state, eventId, EntityNodeKind.DetectionEvent, evt.EventId, now, new() { ["ruleId"] = evt.RuleId });
                ids.Add(eventId);

                string? src = First(evt.SourceIp);
                string? dst = First(evt.DestinationIp, evt.DestinationHost);
                if (!string.IsNullOrWhiteSpace(src))
                {
                    var srcId = EntityId(EntityNodeKind.Host, src!);
                    UpsertNode(state, srcId, EntityNodeKind.Host, src!, now);
                    AddEdge(state, srcId, eventId, EntityEdgeKind.TriggeredRule, evt.EventId, now);
                    ids.Add(srcId);

                    if (!string.IsNullOrWhiteSpace(dst))
                    {
                        var dstId = EntityId(EntityNodeKind.Host, dst!);
                        UpsertNode(state, dstId, EntityNodeKind.Host, dst!, now);
                        AddEdge(state, srcId, dstId, EntityEdgeKind.CommunicatedWith, evt.EventId, now);
                        ids.Add(dstId);
                    }
                }

                if (!string.IsNullOrWhiteSpace(evt.Protocol))
                {
                    var protoId = EntityId(EntityNodeKind.Protocol, evt.Protocol!);
                    UpsertNode(state, protoId, EntityNodeKind.Protocol, evt.Protocol!, now);
                    AddEdge(state, eventId, protoId, EntityEdgeKind.UsedProtocol, evt.EventId, now);
                    ids.Add(protoId);
                }

                if (evt.DestinationPort.HasValue)
                {
                    var portId = EntityId(EntityNodeKind.Port, evt.DestinationPort.Value.ToString());
                    UpsertNode(state, portId, EntityNodeKind.Port, evt.DestinationPort.Value.ToString(), now);
                    AddEdge(state, eventId, portId, EntityEdgeKind.ConnectedToService, evt.EventId, now);
                    ids.Add(portId);
                }

                if (!string.IsNullOrWhiteSpace(evt.Asn))
                {
                    var asnId = EntityId(EntityNodeKind.ASN, evt.Asn!);
                    UpsertNode(state, asnId, EntityNodeKind.ASN, evt.Asn!, now);
                    AddEdge(state, eventId, asnId, EntityEdgeKind.SuspiciousRelation, evt.EventId, now);
                    ids.Add(asnId);
                }

                if (!string.IsNullOrWhiteSpace(evt.Country))
                {
                    var countryId = EntityId(EntityNodeKind.Country, evt.Country!);
                    UpsertNode(state, countryId, EntityNodeKind.Country, evt.Country!, now);
                    AddEdge(state, eventId, countryId, EntityEdgeKind.SuspiciousRelation, evt.EventId, now);
                    ids.Add(countryId);
                }

                state.Observations.Add(new EntityObservation
                {
                    TimestampUtc = now,
                    Source = "detection-journal",
                    EventId = evt.EventId,
                    RuleId = evt.RuleId,
                    EntityIds = ids.Distinct(StringComparer.OrdinalIgnoreCase).ToList()
                });

                await SaveUnsafeAsync(state, cancellationToken).ConfigureAwait(false);
                return ids.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            }
            finally { _gate.Release(); }
        }

        public async Task<IReadOnlyList<EntityNode>> QueryNodesAsync(EntityGraphQuery? query = null, CancellationToken cancellationToken = default)
        {
            await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var state = await LoadUnsafeAsync(cancellationToken).ConfigureAwait(false);
                IEnumerable<EntityNode> nodes = state.Nodes.Values;
                if (query?.EntityId != null) nodes = nodes.Where(n => string.Equals(n.EntityId, query.EntityId, StringComparison.OrdinalIgnoreCase));
                if (query?.Kind != null) nodes = nodes.Where(n => n.Kind == query.Kind.Value);
                if (!string.IsNullOrWhiteSpace(query?.Contains)) nodes = nodes.Where(n => n.DisplayName.Contains(query.Contains!, StringComparison.OrdinalIgnoreCase));
                return nodes.OrderBy(n => n.Kind).ThenBy(n => n.DisplayName).ToList();
            }
            finally { _gate.Release(); }
        }

        public async Task<IReadOnlyList<EntityEdge>> ReadEdgesAsync(CancellationToken cancellationToken = default)
        {
            await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try { return (await LoadUnsafeAsync(cancellationToken).ConfigureAwait(false)).Edges.Values.ToList(); }
            finally { _gate.Release(); }
        }

        public async Task<IReadOnlyList<EntityObservation>> ReadObservationsAsync(CancellationToken cancellationToken = default)
        {
            await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try { return (await LoadUnsafeAsync(cancellationToken).ConfigureAwait(false)).Observations.ToList(); }
            finally { _gate.Release(); }
        }

        private async Task<GraphState> LoadUnsafeAsync(CancellationToken cancellationToken)
        {
            if (!File.Exists(PathName)) return new GraphState();
            try
            {
                await using var fs = File.OpenRead(PathName);
                return await JsonSerializer.DeserializeAsync<GraphState>(fs, _json, cancellationToken).ConfigureAwait(false) ?? new GraphState();
            }
            catch { return new GraphState(); }
        }

        private async Task SaveUnsafeAsync(GraphState state, CancellationToken cancellationToken)
        {
            Directory.CreateDirectory(_options.DirectoryPath);
            var temp = PathName + ".tmp";
            await using (var fs = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                await JsonSerializer.SerializeAsync(fs, state, _json, cancellationToken).ConfigureAwait(false);
                if (_options.FlushAfterEveryWrite) await fs.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            File.Move(temp, PathName, true);
        }

        private static string? First(params string?[] values) => values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v));
        public static string EntityId(EntityNodeKind kind, string value) => $"{kind.ToString().ToLowerInvariant()}:{Normalize(value)}";
        private static string Normalize(string value) => value.Trim().ToLowerInvariant();

        private static void UpsertNode(GraphState state, string id, EntityNodeKind kind, string display, DateTime now, Dictionary<string, string>? attrs = null)
        {
            if (!state.Nodes.TryGetValue(id, out var node))
            {
                node = new EntityNode { EntityId = id, Kind = kind, DisplayName = display, FirstSeenUtc = now };
                state.Nodes[id] = node;
            }
            node.LastSeenUtc = now;
            node.ObservationCount++;
            if (attrs != null)
                foreach (var kv in attrs) node.Attributes[kv.Key] = kv.Value;
        }

        private static void AddEdge(GraphState state, string source, string target, EntityEdgeKind kind, string eventId, DateTime now)
        {
            var id = $"{source}|{kind}|{target}";
            if (!state.Edges.TryGetValue(id, out var edge))
            {
                edge = new EntityEdge { EdgeId = id, SourceEntityId = source, TargetEntityId = target, Kind = kind, FirstSeenUtc = now };
                state.Edges[id] = edge;
            }
            edge.LastSeenUtc = now;
            edge.ObservationCount++;
            if (!string.IsNullOrWhiteSpace(eventId) && !edge.EventIds.Contains(eventId, StringComparer.OrdinalIgnoreCase))
                edge.EventIds.Add(eventId);
        }
    }
}
