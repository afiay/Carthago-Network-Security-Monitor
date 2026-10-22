// SPDX-License-Identifier: MIT
// File: Engine/Rules/Execution/RuleCandidateSelector.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Models;

namespace Carthago.Engine.Rules.Execution
{
    public sealed class RuleCandidateSelector
    {
        private readonly RuleExecutionIndex _index;

        public RuleCandidateSelector(RuleExecutionIndex? index = null)
            => _index = index ?? RuleExecutionIndex.CreateDefault();

        public RuleExecutionPlan CreatePlan(IReadOnlyList<IDetectionRule> rules, TrafficRecord record)
        {
            if (rules == null) throw new ArgumentNullException(nameof(rules));
            if (record == null) throw new ArgumentNullException(nameof(record));

            var looksDns = LooksDns(record);
            var looksHttp = LooksHttp(record);
            var looksTls = LooksTls(record);
            var looksIoTOrOt = LooksIoTOrOt(record);
            var looksIdentityOrAdmin = LooksIdentityOrAdmin(record);
            var looksContainerCloud = LooksContainerCloud(record);

            var entries = new List<RuleExecutionPlanEntry>(rules.Count);
            foreach (var rule in rules)
            {
                if (!_index.Entries.TryGetValue(rule.Descriptor.RuleId, out var entry))
                {
                    entries.Add(new RuleExecutionPlanEntry(rule, true, "No index metadata available; evaluated conservatively."));
                    continue;
                }

                if (entry.AlwaysRun)
                {
                    entries.Add(new RuleExecutionPlanEntry(rule, true, "Legacy or health rule always evaluates."));
                    continue;
                }

                if (entry.RequiresDns && !looksDns)
                {
                    entries.Add(new RuleExecutionPlanEntry(rule, false, "Skipped by selector: DNS telemetry not present for this record."));
                    continue;
                }

                if (entry.RequiresHttp && !looksHttp)
                {
                    entries.Add(new RuleExecutionPlanEntry(rule, false, "Skipped by selector: HTTP telemetry not present for this record."));
                    continue;
                }

                if (entry.RequiresTls && !looksTls)
                {
                    entries.Add(new RuleExecutionPlanEntry(rule, false, "Skipped by selector: TLS telemetry not present for this record."));
                    continue;
                }

                if (entry.RequiresIoTOrOt && !looksIoTOrOt)
                {
                    entries.Add(new RuleExecutionPlanEntry(rule, false, "Skipped by selector: IoT/OT protocol context not present for this record."));
                    continue;
                }

                if (entry.RequiresIdentityOrAdmin && !looksIdentityOrAdmin)
                {
                    entries.Add(new RuleExecutionPlanEntry(rule, false, "Skipped by selector: identity or admin-service context not present for this record."));
                    continue;
                }

                if (entry.RequiresContainerOrCloud && !looksContainerCloud)
                {
                    entries.Add(new RuleExecutionPlanEntry(rule, false, "Skipped by selector: container or cloud context not present for this record."));
                    continue;
                }

                entries.Add(new RuleExecutionPlanEntry(rule, true, "Relevant telemetry family present."));
            }

            return new RuleExecutionPlan(entries, entries.Count, entries.Count(static entry => entry.ShouldEvaluate));
        }

        private static bool LooksDns(TrafficRecord record)
            => !string.IsNullOrWhiteSpace(record.DnsQname)
               || !string.IsNullOrWhiteSpace(record.DnsQtype)
               || !string.IsNullOrWhiteSpace(record.DnsAnswers);

        private static bool LooksHttp(TrafficRecord record)
            => !string.IsNullOrWhiteSpace(record.HttpMethod)
               || !string.IsNullOrWhiteSpace(record.HttpHost)
               || !string.IsNullOrWhiteSpace(record.HttpUri)
               || !string.IsNullOrWhiteSpace(record.HttpRequestHeaders)
               || !string.IsNullOrWhiteSpace(record.HttpUserAgent);

        private static bool LooksTls(TrafficRecord record)
            => !string.IsNullOrWhiteSpace(record.Sni)
               || !string.IsNullOrWhiteSpace(record.TlsSni)
               || !string.IsNullOrWhiteSpace(record.TlsVersion)
               || !string.IsNullOrWhiteSpace(record.Ja3)
               || !string.IsNullOrWhiteSpace(record.Ja4)
               || !string.IsNullOrWhiteSpace(record.CertIssuer)
               || !string.IsNullOrWhiteSpace(record.CertSubject);

        private static bool LooksIoTOrOt(TrafficRecord record)
            => ContainsAny(record.Info, "mqtt", "bacnet", "modbus", "dnp3", "opc ua", "opcua", "profinet", "coap", "zigbee", "camera", "nvr", "telnet", "upnp")
               || ContainsAny(record.ApplicationProtocol, "mqtt", "bacnet", "modbus", "dnp3", "opc", "coap", "zigbee")
               || ContainsAny(record.ApplicationService, "mqtt", "bacnet", "modbus", "dnp3", "opc", "coap", "zigbee");

        private static bool LooksIdentityOrAdmin(TrafficRecord record)
            => ContainsAny(record.Info, "login", "auth", "kerberos", "ldap", "winrm", "rdp", "smb", "psexec", "wmi", "radius", "oauth", "saml", "mfa")
               || ContainsAny(record.HttpUri, "login", "signin", "oauth", "saml", "mfa", "auth")
               || ContainsAny(record.HttpRequestHeaders, "authorization", "oauth", "saml", "bearer", "basic")
               || ContainsAny(record.ProcessName, "ssh", "rdp", "mstsc", "powershell", "wmic", "psexec");

        private static bool LooksContainerCloud(TrafficRecord record)
            => ContainsAny(record.HttpHost, "amazonaws", "azure", "googleapis", "github", "gitlab", "docker", "kubernetes", "gcr.io", "acr", "artifact", "vault")
               || ContainsAny(record.HttpUri, "metadata", "serviceaccounts", "/api/v1", "/apis/", "/secrets", "/exec", "/portforward")
               || ContainsAny(record.Info, "kubernetes", "docker", "container", "cloud", "vault", "github", "gitlab", "terraform", "aws", "azure", "gcp");

        private static bool ContainsAny(string? value, params string[] needles)
        {
            if (string.IsNullOrWhiteSpace(value))
                return false;

            foreach (var needle in needles)
            {
                if (value.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }

            return false;
        }
    }
}
