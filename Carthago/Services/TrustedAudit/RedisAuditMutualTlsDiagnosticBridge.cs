// SPDX-License-Identifier: MIT
// R437 authenticated relay → existing diagnostic intake. SOURCE CANDIDATE — UNVERIFIED.
using System;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;

namespace Carthago.Services.TrustedAudit
{
    public delegate ValueTask<(TrafficRecord? Reply, DateTimeOffset CapturedUtc)>
        RedisAuditCaptureReplyLookup(
            RedisSoftwareAuditObservation vendorObservation,
            CancellationToken cancellationToken);

    public delegate ValueTask RedisAuditDiagnosticSink(
        RedisSoftwareWireCorrelationAssessment assessment,
        CancellationToken cancellationToken);

    /// <summary>
    /// Authenticates the locally forwarding relay using an operator-pinned
    /// mTLS client certificate, decodes its bounded vendor notifications, and
    /// correlates them against a caller-supplied *capture-only* reply lookup.
    ///
    /// This bridge does not speak Redis Software's own raw TCP audit transport.
    /// The external operator-controlled relay is responsible for source
    /// authentication, reliable framing and monitoring audit_sink_* metrics.
    /// Pinning the relay is not equivalent to authenticating the Redis daemon.
    ///
    /// Evidence remains diagnostic only: generic CONFIG never becomes a
    /// RedisConfigSetCommandSucceeded signed receipt or a positive R437 alert.
    /// </summary>
    public sealed class RedisAuditMutualTlsDiagnosticBridge
    {
        private readonly RedisAuditMutualTlsRelayReceiver _receiver;
        private readonly RedisSoftwareAuditDiagnosticIntake _intake;

        public RedisAuditMutualTlsDiagnosticBridge(
            RedisAuditMutualTlsRelayReceiver receiver,
            RedisSoftwareAuditDiagnosticIntake intake)
        {
            _receiver = receiver ?? throw new ArgumentNullException(nameof(receiver));
            _intake = intake ?? throw new ArgumentNullException(nameof(intake));
        }

        /// <summary>
        /// One accepted mTLS relay session; no background service or automatic
        /// network start. No raw JSON is forwarded to the diagnostic sink.
        /// A malformed notification terminates the session instead of silently
        /// skipping an unknown audit_seq that could hide command events.
        /// </summary>
        public Task<RedisAuditRelaySessionResult> AcceptOneAsync(
            TcpListener loopbackListener,
            RedisAuditCaptureReplyLookup findCaptureReply,
            RedisAuditDiagnosticSink reportDiagnostic,
            CancellationToken cancellationToken = default)
        {
            if (findCaptureReply == null)
                throw new ArgumentNullException(nameof(findCaptureReply));
            if (reportDiagnostic == null)
                throw new ArgumentNullException(nameof(reportDiagnostic));

            return _receiver.AcceptOneAsync(loopbackListener,
                async (pinnedRelayId, rawJson, token) =>
                {
                    if (!RedisSoftwareAuditNotificationParser.TryParse(
                        rawJson, out var vendor) || vendor == null)
                    {
                        await reportDiagnostic(new(
                            RedisSoftwareWireCorrelationStatus.MalformedVendorNotification,
                            "R437_VENDOR_AUDIT_MALFORMED"), token)
                            .ConfigureAwait(false);
                        throw new InvalidDataException(
                            "Malformed authenticated-relay audit event; session closed.");
                    }

                    // This callback may provide a packet-handler observation or
                    // nothing. It must never manufacture capture-only Redis flags.
                    // IP/time/port coincidence still cannot prove causality.
                    var (reply, capturedAt) = await findCaptureReply(vendor, token)
                        .ConfigureAwait(false);

                    var diagnostic = _intake.Inspect(
                        pinnedRelayId, rawJson, reply, capturedAt);
                    await reportDiagnostic(diagnostic, token).ConfigureAwait(false);

                    // A duplicate or sequence gap poisons the worker. Closing
                    // the session avoids pretending later traffic is complete.
                    if (diagnostic.Status ==
                        RedisSoftwareWireCorrelationStatus.AuditStreamNotContinuous)
                        throw new InvalidDataException(
                            "Audit sequence gap, duplicate or missing initial continuity.");
                }, cancellationToken);
        }
    }
}
