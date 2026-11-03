// SPDX-License-Identifier: MIT
// File: Services/Benchmarking/RuleReplaySample.cs
using System.Collections.Generic;
using Carthago.Models;
using Carthago.Services.EnvironmentTuning;

namespace Carthago.Services.Benchmarking
{
    public enum ReplaySampleClassification
    {
        Benign,
        Malicious,
        // Malicious behavior whose intended detector currently requires a
        // trusted producer that Carthago does not yet have. These fixtures
        // verify fail-closed reason codes and are excluded from supported
        // detector/alert recall denominators.
        UnsupportedMalicious
    }

    public sealed class RuleReplaySample
    {
        public string Name { get; set; } = string.Empty;
        public ReplaySampleClassification? Classification { get; set; }
        public Sensitivity? Sensitivity { get; set; }
        public List<TrafficRecord> Records { get; set; } = new();
        // Optional offline-only, synthetic HTTP request bytes by record index.
        // The benchmark parses them through the same HttpLight parser as live
        // capture, deriving trusted credential flags before header redaction.
        // Never deserialize an arbitrary trust flag directly from replay JSON.
        public Dictionary<int, string> RawHttpRequestsByRecordIndex { get; set; } = new();
        // Offline-only synthetic Modbus/OT TCP payloads, hex encoded and bounded.
        // The replay runner derives ApplicationProtocol with the SAME bounded OT
        // parser used by capture; fixture narrative or pre-set protocol labels
        // cannot stand in for an observed write function.
        public Dictionary<int, string> RawOtTcpPayloadsByRecordIndex { get; set; } = new();
        // Offline-only synthetic BACnet/IP UDP payloads. The benchmark derives
        // capture-only WriteProperty provenance with the same bounded inspector
        // used by PacketHandler; JSON cannot set the internal trust flag.
        public Dictionary<int, string> RawBacnetUdpPayloadsByRecordIndex { get; set; } = new();
        // Offline-only synthetic Redis RESP2 client requests. The benchmark
        // derives the capture-only request flag with the same bounded RESP2
        // inspector used by PacketHandler. This does not authenticate a server
        // reply, authorization, or command outcome.
        public Dictionary<int, string> RawRedisResp2RequestsByRecordIndex { get; set; } = new();
        public List<string> ExpectedMatches { get; set; } = new();
        public List<string> UnsupportedRuleIds { get; set; } = new();
        public Dictionary<string, string> UnsupportedReasonCodesByRuleId { get; set; } = new();
        public List<string> ExpectedEmittedMatches { get; set; } = new();
        public List<string> ExpectedSuppressedMatches { get; set; } = new();
        public List<string> ExpectedShadowedMatches { get; set; } = new();
        public List<string> ExpectedNonMatches { get; set; } = new();
        public List<RuleReplaySampleAssertion> Assertions { get; set; } = new();
        public double ExpectedMinimumConfidence { get; set; }
        public int? MaximumUnexpectedMatches { get; set; }
        public bool BaselineLearningMode { get; set; }
        public EnvironmentTuningOptions EnvironmentTuning { get; set; } = new();
    }
}
