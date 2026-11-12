// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Models;
using Carthago.Services.ProtocolIntelligence;

namespace Carthago.Services;

// Session-owned, bounded observed DNS evidence. This is not a resolver cache:
// a name/IP mapping is a candidate, not proof of the application hostname.
internal sealed class DnsConnectionEnrichment
{
    private const int MaxPending = 4096;
    private const int MaxAnswers = 8192;
    private const long QueryLifetimeMs = 30_000;
    private const long MaxTtlMs = 3_600_000;
    private readonly object _gate = new();
    private readonly Dictionary<QueryKey, long> _pending = new();
    private readonly Dictionary<AnswerKey, Dictionary<string, Answer>> _answers = new();
    private int _answerCount;
    private long _nextPrune;

    private readonly record struct QueryKey(string Client, string Resolver, int ClientPort, ushort Id, string Name, ushort Type);
    private readonly record struct AnswerKey(string Client, string Address);
    private readonly record struct Answer(long Observed, long Expires);

    internal void Observe(TrafficRecord record, long now)
    {
        lock (_gate)
        {
            if (now >= _nextPrune)
            {
                Prune(now);
                _nextPrune = now + 1000;
            }

            if (record.IsUdp && record.DnsAddressObservation is { } rich)
            {
                ObserveDns(record, rich.TransactionId, rich.Name, rich.QuestionType, rich.IsResponse, rich.Answers, now);
                return;
            }

            if (record.DnsValidatedAQuestion && record.DnsValidatedTransactionId is ushort id
                && record.IsUdp && record.ApplicationProtocol == "DNS"
                && NormalizeName(record.DnsValidatedQuestionName) is string name)
            {
                var answers = record.DnsValidatedSingleAAnswer && !record.DnsValidatedNxdomain
                    && record.DnsValidatedAnswerAddress is string addressAnswer
                    && record.DnsValidatedAnswerTtl is int ttl && ttl > 0
                    ? new[] { new DnsAddressObservationInspector.AddressAnswer(addressAnswer, (uint)ttl) }
                    : Array.Empty<DnsAddressObservationInspector.AddressAnswer>();
                ObserveDns(record, id, name, 1, record.DnsIsResponse, answers, now);
                return;
            }

            // Only local-client outbound transport observations. DNS/mDNS are
            // never themselves treated as subsequent application connections.
            if (record.SrcIsLocalHost != true || (!record.IsTcp && !record.IsUdp)
                || record.SourcePort is not > 0 || record.DestinationPort is not > 0
                || record.SourcePort == 53 || record.DestinationPort == 53
                || record.ApplicationProtocol is "DNS" or "mDNS"
                || NormalizeIp(record.Source) is not string client
                || NormalizeIp(record.Destination) is not string address)
                return;

            if (!_answers.TryGetValue(new AnswerKey(client, address), out var bucket)) return;
            var names = bucket.Where(pair => pair.Value.Observed <= now && now < pair.Value.Expires)
                .Select(pair => pair.Key).OrderBy(n => n, StringComparer.Ordinal).ToArray();
            if (names.Length == 0) return;

            record.DnsCorrelatedNames = string.Join("; ", names);
            record.DnsCorrelatedNameCount = names.Length;
            record.DnsCorrelationEvidence = "MatchedDnsQueryResponse";
            if (NormalizeName(record.Sni) is string sni)
                record.DnsSniAgreement = names.Contains(sni, StringComparer.Ordinal) ? "MatchesObservedCandidate" : "NotInObservedCandidates";
            else
                record.DnsSniAgreement = "NotObserved";
        }
    }

    private void ObserveDns(TrafficRecord r, ushort id, string name, ushort type, bool response,
        IReadOnlyList<DnsAddressObservationInspector.AddressAnswer> answers, long now)
    {
        if ((response ? r.DstIsLocalHost : r.SrcIsLocalHost) != true
            || (response ? r.SourcePort : r.DestinationPort) != 53
            || (response ? r.DestinationPort : r.SourcePort) is not (> 0 and <= 65535)
            || NormalizeIp(response ? r.Destination : r.Source) is not string client
            || NormalizeIp(response ? r.Source : r.Destination) is not string resolver)
            return;
        int port = (response ? r.DestinationPort : r.SourcePort)!.Value;
        var key = new QueryKey(client, resolver, port, id, name, type);
        if (!response)
        {
            if (_pending.TryGetValue(key, out var previous) && now >= previous && now - previous < QueryLifetimeMs)
                return; // retransmit does not extend lifetime
            if (_pending.Count >= MaxPending) return;
            _pending[key] = now;
            return;
        }
        if (!_pending.TryGetValue(key, out var sent) || now < sent) return;
        _pending.Remove(key);
        if (now - sent >= QueryLifetimeMs) return;

        foreach (var answer in answers)
        {
            if (answer.Ttl == 0 || !IPAddress.TryParse(answer.Address, out var ip)
                || (type == 1 && ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                || (type == 28 && ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6))
                continue;
            var address = EndpointIpEnrichment.Normalize(ip).ToString();
            var answerKey = new AnswerKey(client, address);
            if (!_answers.TryGetValue(answerKey, out var bucket))
            {
                if (_answerCount >= MaxAnswers) continue;
                _answers[answerKey] = bucket = new Dictionary<string, Answer>(StringComparer.Ordinal);
            }
            if (!bucket.ContainsKey(name))
            {
                if (_answerCount >= MaxAnswers) continue;
                _answerCount++;
            }
            bucket[name] = new Answer(now, now + Math.Min(MaxTtlMs, (long)answer.Ttl * 1000));
        }
    }

    private void Prune(long now)
    {
        foreach (var key in _pending.Where(p => now >= p.Value && now - p.Value >= QueryLifetimeMs).Select(p => p.Key).ToArray())
            _pending.Remove(key);
        foreach (var pair in _answers)
        {
            foreach (var name in pair.Value.Where(p => now >= p.Value.Expires).Select(p => p.Key).ToArray())
            {
                pair.Value.Remove(name);
                _answerCount--;
            }
        }
        foreach (var key in _answers.Where(p => p.Value.Count == 0).Select(p => p.Key).ToArray())
            _answers.Remove(key);
    }

    private static string? NormalizeIp(string? value)
        => IPAddress.TryParse(value, out var ip) ? EndpointIpEnrichment.Normalize(ip).ToString() : null;

    private static string? NormalizeName(string? value)
    {
        var name = value?.TrimEnd('.').ToLowerInvariant();
        return !string.IsNullOrWhiteSpace(name) && name.Length <= 253 ? name : null;
    }
}
