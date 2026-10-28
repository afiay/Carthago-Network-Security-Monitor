// SPDX-License-Identifier: MIT
using System;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;
namespace Carthago.Tests;
internal static class NetworkBatch196200Context
{
    internal static readonly DateTime Origin = new(2026, 10, 28, 3, 0, 0, DateTimeKind.Utc);
    internal static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => new(r, Sensitivity.Balanced, Origin.AddSeconds(seconds));
    internal static TrafficRecord Nx(string name = "host.example1.com")
    {
        var r = NetworkBatch186195Context.Response(name, 300);
        r.DnsRcode = "NXDOMAIN"; r.DnsAnswers = null;
        return r;
    }
    internal static TrafficRecord Private(string answers = "10.10.0.9", int? ttl = 1)
    {
        var r = NetworkBatch186195Context.Response("secret197.example.net", 1);
        r.DnsAnswers = answers; r.DnsTtl = ttl;
        return r;
    }
    internal static TrafficRecord Imds(string provider)
    {
        var r = NetworkBatch166175Context.Http("/latest/meta-data/iam/security-credentials/role-a");
        r.Id = Guid.NewGuid(); r.Source = "10.196.0.10"; r.Destination = "169.254.169.254";
        r.DestinationPort = 80; r.Protocol = "HTTP";
        r.ApplicationProtocol = "HTTP"; r.ApplicationService = "HTTP";
        r.HttpHost = provider == "gcp" ? "metadata.google.internal" : "169.254.169.254";
        if (provider == "gcp") r.HttpUri = "/computeMetadata/v1/instance/service-accounts/default/token";
        if (provider == "azure") r.HttpUri = "/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F";
        r.HttpRequestHeaders = "Host: " + r.HttpHost
            + (provider == "gcp" ? "\r\nMetadata-Flavor: Google" : "")
            + (provider == "azure" ? "\r\nMetadata: true" : "");
        return r;
    }
}
