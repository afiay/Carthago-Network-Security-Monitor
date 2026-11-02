// SPDX-License-Identifier: MIT
// GA R437 — SOURCE CANDIDATE — UNVERIFIED. Diagnostic correlation only.
using System;
using System.Net;
using Carthago.Models;
using Carthago.Services.EnvironmentTuning;

namespace Carthago.Services.TrustedAudit
{
    public enum RedisSoftwareWireCorrelationStatus
    {
        MalformedVendorNotification,
        NoAuditEvent,
        AuditNotCommand,
        GenericCommandNotConfig,
        AuditStreamNotContinuous,
        MissingCapturedReply,
        EndpointOrPortMismatch,
        TimestampMismatch,
        ReplyStatusMismatch,
        ServerInventoryMissing,
        ServerOutsideInventory,
        AdminPolicyMissing,
        ApprovedAdminClient,
        GenericConfigSubcommandUnproven
    }

    /// <summary>
    /// Vendor-event-to-packet diagnostic. No authenticity, transaction identity
    /// or CONFIG SET subcommand can be inferred from a generic CONFIG event.
    /// This result is never sufficient for a signed RedisConfigSetCommandSucceeded
    /// claim, an R437 positive, or an Alert-mode decision.
    /// </summary>
    public sealed record RedisSoftwareWireCorrelationAssessment(
        RedisSoftwareWireCorrelationStatus Status,
        string Diagnostic)
    {
        public bool AlertPermitted => false;
        public bool ConfigSetVerified => false;
        public bool AuthenticatedRedisServer => false;
    }

    public static class RedisSoftwareAuditWireCorrelation
    {
        private static readonly TimeSpan MaxSkew = TimeSpan.FromSeconds(30);

        public static RedisSoftwareWireCorrelationAssessment Assess(
            RedisSoftwareAuditObservation? audit,
            RedisAuditDeliveryAssessment? continuity,
            TrafficRecord? capturedServerReply,
            DateTimeOffset capturedReplyUtc,
            ApprovedAssetRegistry? approvals)
        {
            if (audit == null)
                return Fail(RedisSoftwareWireCorrelationStatus.NoAuditEvent,
                    "R437_VENDOR_AUDIT_MISSING");
            if (audit.Kind != RedisSoftwareAuditEventKind.Command)
                return Fail(RedisSoftwareWireCorrelationStatus.AuditNotCommand,
                    "R437_VENDOR_AUDIT_NOT_COMMAND");
            if (audit.CommandClass != RedisSoftwareCommandClass.GenericConfig)
                return Fail(RedisSoftwareWireCorrelationStatus.GenericCommandNotConfig,
                    "R437_VENDOR_AUDIT_NOT_CONFIG");
            if (continuity == null
                || continuity.Status != RedisAuditDeliveryStatus.Contiguous
                || continuity.CurrentSequence != audit.AuditSequence)
                return Fail(RedisSoftwareWireCorrelationStatus.AuditStreamNotContinuous,
                    "R437_VENDOR_AUDIT_DELIVERY_NOT_CONTIGUOUS");

            if (capturedServerReply == null || !capturedServerReply.IsTcp
                || capturedServerReply.IsUdp || capturedServerReply.IsQuic
                || !string.Equals(capturedServerReply.Protocol, "TCP",
                    StringComparison.OrdinalIgnoreCase)
                || !string.Equals(capturedServerReply.ApplicationProtocol,
                    "redis.resp2", StringComparison.Ordinal)
                || capturedServerReply.RedisRespConfigSetRequestObserved
                || capturedServerReply.RedisRespConfigSetReplyOkObserved
                    == capturedServerReply.RedisRespConfigSetReplyErrorObserved
                || capturedServerReply.SourcePort != 6379
                || capturedServerReply.DestinationPort is not (> 0 and <= 65535))
                return Fail(RedisSoftwareWireCorrelationStatus.MissingCapturedReply,
                    "R437_VENDOR_AUDIT_WIRE_REPLY_MISSING");

            if (!IPAddress.TryParse(capturedServerReply.Source, out var capturedServer)
                || !IPAddress.TryParse(capturedServerReply.Destination, out var capturedClient)
                || !IPAddress.TryParse(audit.ServerIp, out var auditedServer)
                || !IPAddress.TryParse(audit.ClientIp, out var auditedClient)
                || !capturedServer.Equals(auditedServer)
                || !capturedClient.Equals(auditedClient)
                || capturedServerReply.SourcePort != audit.ServerPort
                || capturedServerReply.DestinationPort != audit.ClientPort)
                return Fail(RedisSoftwareWireCorrelationStatus.EndpointOrPortMismatch,
                    "R437_VENDOR_AUDIT_TCP_FOUR_TUPLE_MISMATCH");

            if (capturedReplyUtc.Offset != TimeSpan.Zero
                || (audit.OccurredAtUtc - capturedReplyUtc).Duration() > MaxSkew)
                return Fail(RedisSoftwareWireCorrelationStatus.TimestampMismatch,
                    "R437_VENDOR_AUDIT_WIRE_TIME_MISMATCH");

            if ((audit.CommandOutcome == RedisSoftwareCommandOutcome.Succeeded)
                    != capturedServerReply.RedisRespConfigSetReplyOkObserved
                || (audit.CommandOutcome == RedisSoftwareCommandOutcome.Failed)
                    != capturedServerReply.RedisRespConfigSetReplyErrorObserved)
                return Fail(RedisSoftwareWireCorrelationStatus.ReplyStatusMismatch,
                    "R437_VENDOR_AUDIT_WIRE_OUTCOME_MISMATCH");

            if (approvals == null || !approvals.HasApprovedRedisServers)
                return Fail(RedisSoftwareWireCorrelationStatus.ServerInventoryMissing,
                    "R437_VENDOR_REDIS_INVENTORY_UNCONFIGURED");
            if (!approvals.IsApprovedRedisServer(audit.ServerIp))
                return Fail(RedisSoftwareWireCorrelationStatus.ServerOutsideInventory,
                    "R437_VENDOR_REDIS_SERVER_NOT_APPROVED");
            if (!approvals.HasApprovedAdminHosts)
                return Fail(RedisSoftwareWireCorrelationStatus.AdminPolicyMissing,
                    "R437_VENDOR_ADMIN_POLICY_UNCONFIGURED");
            if (approvals.IsAdminHost(audit.ClientIp))
                return Fail(RedisSoftwareWireCorrelationStatus.ApprovedAdminClient,
                    "R437_VENDOR_APPROVED_ADMIN_GENERIC_CONFIG");

            // Even the matching TCP 4-tuple, a 30s time window, an incrementing
            // audit sequence and a generic CONFIG outcome do NOT prove the exact
            // CONFIG SET subcommand, a unique command transaction or the source
            // of an unauthenticated Redis Software notification.
            return Fail(RedisSoftwareWireCorrelationStatus.GenericConfigSubcommandUnproven,
                "R437_VENDOR_CONFIG_SET_SUBCOMMAND_NOT_ATTESTED");
        }

        private static RedisSoftwareWireCorrelationAssessment Fail(
            RedisSoftwareWireCorrelationStatus status, string diagnostic)
            => new(status, diagnostic);
    }
}
