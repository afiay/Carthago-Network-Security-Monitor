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
            : this(record, sensitivity, timestampUtc, healthSnapshot, null, false)
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
                    nameof(trustedR275Capability)), true)
        {
        }

        private RuleEvaluationContext(
            TrafficRecord record,
            Sensitivity sensitivity,
            DateTime timestampUtc,
            RuleEngineHealthSnapshot? healthSnapshot,
            OAuthDeviceFlowRuleCapability? trustedR275Capability,
            bool requireCapabilityBinding)
        {
            Record = record ?? throw new ArgumentNullException(nameof(record));
            Sensitivity = sensitivity;
            TimestampUtc = timestampUtc.Kind == DateTimeKind.Utc
                ? timestampUtc
                : timestampUtc.ToUniversalTime();
            HealthSnapshot = healthSnapshot
                ?? RuleEngineHealthSnapshot.Empty(TimestampUtc);

            if (requireCapabilityBinding
                && (trustedR275Capability == null
                    || !trustedR275Capability.IsBoundTo(Record, TimestampUtc)))
                throw new ArgumentException(
                    "Trusted R275 capability is not bound to this exact record and timestamp.",
                    nameof(trustedR275Capability));

            TrustedR275Capability = trustedR275Capability;
        }

        public TrafficRecord Record { get; }
        public Sensitivity Sensitivity { get; }
        public DateTime TimestampUtc { get; }
        public RuleEngineHealthSnapshot HealthSnapshot { get; }

        // Deliberately internal. Public RuleEvaluationContext construction stays
        // packet-only and cannot attach or fabricate trusted R275 evidence.
        internal OAuthDeviceFlowRuleCapability? TrustedR275Capability { get; }
    }
}
