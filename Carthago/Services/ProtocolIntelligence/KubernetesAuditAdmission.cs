// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Isolated, fail-closed admission contract for Kubernetes API-server audit
    /// events. A configured key does not itself prove API-server identity.
    /// No runtime ingestion or R294-R296 alert path is enabled here.
    /// </summary>
    public sealed class KubernetesAuditAdmission
    {
        private const int MaxEvents = 4096;
        private readonly object _gate = new();
        private readonly HashSet<string> _seen = new(StringComparer.Ordinal);
        private readonly Queue<string> _order = new();
        private DateTime _latest = DateTime.MinValue;

        public bool TryAdmit(KubernetesAuditCandidate candidate,
            ReadOnlySpan<byte> exporterKey, ReadOnlySpan<byte> signature,
            DateTime nowUtc, out KubernetesAuditObservation observation)
        {
            observation = default;
            if (candidate == null || nowUtc.Kind != DateTimeKind.Utc ||
                candidate.TimestampUtc.Kind != DateTimeKind.Utc ||
                candidate.TimestampUtc > nowUtc.AddMinutes(2) ||
                candidate.TimestampUtc < nowUtc.AddMinutes(-10) ||
                exporterKey.Length < 32 || signature.Length != 32 ||
                !Safe(candidate.AuditId, 128) || !Safe(candidate.Cluster, 128) ||
                !Safe(candidate.Principal, 256) || !Safe(candidate.Resource, 32) ||
                !Safe(candidate.Verb, 32) || !Safe(candidate.Stage, 32) ||
                !Safe(candidate.Namespace, 128, true) ||
                !Safe(candidate.Subresource, 32, true) ||
                !Safe(candidate.Decision, 32))
                return false;

            // Delimit every field to prevent concatenation collisions.
            string payload = string.Join("|", new[] {
                Field(candidate.AuditId), Field(candidate.Cluster),
                Field(candidate.Principal), Field(candidate.Resource),
                Field(candidate.Verb), Field(candidate.Stage),
                Field(candidate.Namespace), Field(candidate.Subresource),
                Field(candidate.Decision),
                candidate.TimestampUtc.Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture)
            });
            byte[] bytes = Encoding.UTF8.GetBytes("carthago-k8s-audit-v1|" + payload);
            byte[] digest = HMACSHA256.HashData(exporterKey, bytes);
            bool valid = CryptographicOperations.FixedTimeEquals(digest, signature);
            CryptographicOperations.ZeroMemory(digest);
            CryptographicOperations.ZeroMemory(bytes);
            if (!valid) return false;

            // Only terminal audit stages have a known decision. A requestReceived
            // or responseStarted record cannot establish a completed outcome.
            if (candidate.Stage != "ResponseComplete" ||
                (candidate.Decision != "allow" && candidate.Decision != "deny"))
                return false;

            KubernetesAuditOperation operation =
                candidate.Resource == "secrets" && candidate.Subresource == "" &&
                (candidate.Verb == "get" || candidate.Verb == "list")
                    ? KubernetesAuditOperation.SecretsRead :
                candidate.Resource == "pods" && candidate.Subresource == "exec" &&
                candidate.Verb == "create"
                    ? KubernetesAuditOperation.PodExecRequest :
                candidate.Resource == "pods" && candidate.Subresource == "portforward" &&
                candidate.Verb == "create"
                    ? KubernetesAuditOperation.PortForwardRequest :
                    KubernetesAuditOperation.Other;

            lock (_gate)
            {
                if (candidate.TimestampUtc < _latest.AddMinutes(-10) ||
                    _seen.Contains(candidate.Cluster + "|" + candidate.AuditId) ||
                    _seen.Count >= MaxEvents)
                    return false;
                if (candidate.TimestampUtc > _latest) _latest = candidate.TimestampUtc;
                string key = candidate.Cluster + "|" + candidate.AuditId;
                _seen.Add(key);
                _order.Enqueue(key);
            }

            // A completed audit response is not proof of a successful exec
            // session, secret exfiltration or unauthorized administrative action.
            observation = new KubernetesAuditObservation(operation,
                candidate.Decision == "allow", candidate.TimestampUtc);
            return true;
        }

        public void Reset()
        {
            lock (_gate) { _seen.Clear(); _order.Clear(); _latest = DateTime.MinValue; }
        }

        private static bool Safe(string? s, int max, bool allowEmpty = false)
        {
            if (s == null || s.Length > max || (!allowEmpty && s.Length == 0))
                return false;
            foreach (char c in s)
                if (char.IsControl(c) || c == '|') return false;
            return true;
        }
        private static string Field(string value) => value.Length.ToString(
            System.Globalization.CultureInfo.InvariantCulture) + ":" + value;
    }

    public enum KubernetesAuditOperation
    {
        Other, SecretsRead, PodExecRequest, PortForwardRequest
    }

    public sealed record KubernetesAuditCandidate(
        string AuditId, string Cluster, string Principal, string Resource,
        string Verb, string Stage, string Namespace, string Subresource,
        string Decision, DateTime TimestampUtc);

    public readonly record struct KubernetesAuditObservation(
        KubernetesAuditOperation Operation, bool AuditAllowed, DateTime TimestampUtc);
}
