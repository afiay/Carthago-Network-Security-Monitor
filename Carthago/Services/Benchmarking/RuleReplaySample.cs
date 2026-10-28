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
        Malicious
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
        public List<string> ExpectedMatches { get; set; } = new();
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
