// SPDX-License-Identifier: MIT
// File: Engine/Rules/Abstractions/RuleEvaluationContext.cs
using System;
using Carthago.Models;
using Carthago.Engine.Rules;
using Carthago.Services;
using Carthago.Services.TrustedAudit;

namespace Carthago.Engine.Rules
{
    public sealed class RuleEvaluationContext
    {
        public RuleEvaluationContext(
            TrafficRecord record,
            Sensitivity sensitivity,
            DateTime timestampUtc,
            RuleEngineHealthSnapshot? healthSnapshot = null)
            : this(record, sensitivity, timestampUtc, healthSnapshot, null, null, false)
        {
        }

        internal RuleEvaluationContext(
            TrafficRecord record,
            Sensitivity sensitivity,
            DateTime timestampUtc,
            RuleEngineHealthSnapshot? healthSnapshot,
            OAuthDeviceFlowRuleCapability trustedR275Capability)
            : this(record, sensitivity, timestampUtc, healthSnapshot,
                trustedR275Capability ?? throw new ArgumentNullException(
                    nameof(trustedR275Capability)), null, true)
        {
        }

        internal RuleEvaluationContext(
            TrafficRecord record,
            Sensitivity sensitivity,
            DateTime timestampUtc,
            RuleEngineHealthSnapshot? healthSnapshot,
            OAuthDeviceFlowRuleCapability trustedR275Capability,
            OAuthDeviceFlowPromotionAuthorization trustedR275PromotionAuthorization)
            : this(record, sensitivity, timestampUtc, healthSnapshot,
                trustedR275Capability ?? throw new ArgumentNullException(
                    nameof(trustedR275Capability)),
                trustedR275PromotionAuthorization ?? throw new ArgumentNullException(
                    nameof(trustedR275PromotionAuthorization)), true)
        {
        }

        private RuleEvaluationContext(
            TrafficRecord record,
            Sensitivity sensitivity,
            DateTime timestampUtc,
            RuleEngineHealthSnapshot? healthSnapshot,
            OAuthDeviceFlowRuleCapability? trustedR275Capability,
            OAuthDeviceFlowPromotionAuthorization? trustedR275PromotionAuthorization,
            bool requireCapabilityBinding)
        {
            // Preserve the host's historical local/unspecified timestamp normalization.
            // Portable callers must supply UTC explicitly; no host capability is transferred.
            Packet = new PacketEvaluationContext(record, sensitivity,
                timestampUtc.Kind == DateTimeKind.Utc ? timestampUtc : timestampUtc.ToUniversalTime());
            HealthSnapshot = healthSnapshot
                ?? RuleEngineHealthSnapshot.Empty(TimestampUtc);

            if (requireCapabilityBinding
                && (trustedR275Capability == null
                    || !trustedR275Capability.IsBoundTo(Record, TimestampUtc)))
                throw new ArgumentException(
                    "Trusted R275 capability is not bound to this exact record and timestamp.",
                    nameof(trustedR275Capability));

            if (trustedR275PromotionAuthorization != null
                && (trustedR275Capability == null
                    || !trustedR275PromotionAuthorization.IsBoundTo(
                        trustedR275Capability, Record, TimestampUtc)))
                throw new ArgumentException(
                    "Trusted R275 promotion authorization is not bound to this capability, record and timestamp.",
                    nameof(trustedR275PromotionAuthorization));

            TrustedR275Capability = trustedR275Capability;
            TrustedR275PromotionAuthorization = trustedR275PromotionAuthorization;
        }

        internal static RuleEvaluationContext CreateForEngine(
            TrafficRecord record, Sensitivity sensitivity, DateTime timestampUtc,
            RuleEngineHealthSnapshot healthSnapshot)
        {
            var context = new RuleEvaluationContext(record, sensitivity, timestampUtc, healthSnapshot);
            context.R272Source = record.Source;
            context.R272Signals = RuleEngine.SnapshotR272Signals(record.Source, context.TimestampUtc);
            return context;
        }

        private string? R272Source { get; set; }
        private System.Collections.Generic.IReadOnlyList<(string RuleId, string Family)> R272Signals { get; set; }
            = Array.Empty<(string, string)>();

        internal System.Collections.Generic.IReadOnlyList<(string RuleId, string Family)> GetR272Signals()
            => string.Equals(Record.Source, R272Source, StringComparison.Ordinal)
                ? R272Signals : Array.Empty<(string, string)>();

        public PacketEvaluationContext Packet { get; }
        public TrafficRecord Record => Packet.Record;
        public Sensitivity Sensitivity => Packet.Sensitivity;
        public DateTime TimestampUtc => Packet.TimestampUtc;
        public RuleEngineHealthSnapshot HealthSnapshot { get; }

        // Deliberately internal. Public RuleEvaluationContext construction stays
        // packet-only and cannot attach or fabricate trusted R275 evidence.
        internal OAuthDeviceFlowRuleCapability? TrustedR275Capability { get; }
        internal OAuthDeviceFlowPromotionAuthorization? TrustedR275PromotionAuthorization { get; }
    }
}
