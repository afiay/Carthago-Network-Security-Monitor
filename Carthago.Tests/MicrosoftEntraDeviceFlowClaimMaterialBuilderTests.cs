// SPDX-License-Identifier: MIT
// R275 authenticated Entra-to-packet claim material tests.
// SOURCE CANDIDATE — UNVERIFIED.
using System;
using System.Collections.Generic;
using Carthago.Models;
using Carthago.Services.TrustedAudit;
using Xunit;

namespace Carthago.Tests;

public sealed class MicrosoftEntraDeviceFlowClaimMaterialBuilderTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 11, 3, 20, 0, 0, TimeSpan.Zero);

    private static MicrosoftEntraDeviceCodeAuditObservation Authenticated()
        => new(
            Now,
            "203.0.113.25",
            new string('a', 64),
            new string('b', 64),
            new string('c', 64),
            fromTrustedProviderTransport: true);

    private static MicrosoftEntraDeviceCodeAuditObservation Untrusted()
        => new(
            Now,
            "203.0.113.25",
            new string('a', 64),
            new string('b', 64),
            new string('c', 64),
            fromTrustedProviderTransport: false);

    private static TrafficRecord Flow(string host = "login.microsoftonline.com") => new()
    {
        Source = "203.0.113.25",
        Destination = "20.190.128.10",
        SourcePort = 53000,
        DestinationPort = 443,
        Protocol = "TCP",
        ApplicationProtocol = "TLS",
        IsTcp = true,
        Sni = host
    };

    private static MicrosoftEntraDeviceFlowClaimMaterialBuilder Builder()
        => new(new[]
        {
            "login.microsoftonline.com",
            "login.microsoft.com"
        });

    [Fact]
    public void Authenticated_Entra_And_Approved_Captured_Tls_Flow_Produce_Unsigned_Material()
    {
        Assert.True(Builder().TryBuild(
            Authenticated(), Flow(), Now,
            out var material, out var reason), reason);

        Assert.NotNull(material);
        Assert.Equal(
            "R275_UNSIGNED_CLAIM_MATERIAL_READY_FOR_EXTERNAL_SIGNER",
            reason);
        Assert.Equal("203.0.113.25", material.SourceIp);
        Assert.Equal("20.190.128.10", material.DestinationIp);
        Assert.Equal("login.microsoftonline.com", material.IdentityHost);
        Assert.Equal(64, material.ActorHash.Length);
        Assert.Equal(64, material.ResourceHash.Length);
        Assert.Equal(64, material.TraceHash.Length);
    }

    [Fact]
    public void Untrusted_Projected_Entra_Json_Cannot_Reach_Claim_Material()
    {
        Assert.False(Builder().TryBuild(
            Untrusted(), Flow(), Now,
            out var material, out var reason));
        Assert.Null(material);
        Assert.Equal("R275_ENTRA_TRANSPORT_NOT_AUTHENTICATED", reason);
    }

    [Fact]
    public void Provider_Source_Must_Match_Captured_Client_Address()
    {
        var flow = Flow();
        flow.Source = "203.0.113.26";

        Assert.False(Builder().TryBuild(
            Authenticated(), flow, Now,
            out _, out var reason));
        Assert.Equal("R275_ENTRA_CAPTURE_SOURCE_MISMATCH", reason);
    }

    [Fact]
    public void Destination_Ip_Is_Always_Derived_From_Capture()
    {
        var flow = Flow();
        flow.Destination = "20.190.128.11";

        Assert.True(Builder().TryBuild(
            Authenticated(), flow, Now,
            out var material, out var reason), reason);
        Assert.Equal("20.190.128.11", material!.DestinationIp);
    }

    [Theory]
    [InlineData("login.microsoftonline.com.attacker.test")]
    [InlineData("microsoftonline.com.attacker.test")]
    [InlineData("evil.example")]
    [InlineData("")]
    public void Lookalike_Or_Unapproved_Identity_Host_Is_Rejected(string host)
    {
        Assert.False(Builder().TryBuild(
            Authenticated(), Flow(host), Now,
            out _, out var reason));
        Assert.Equal("R275_IDENTITY_HOST_NOT_APPROVED", reason);
    }

    [Theory]
    [InlineData("LOGIN.MICROSOFTONLINE.COM")]
    [InlineData("login.microsoftonline.com.")]
    [InlineData("sub.login.microsoftonline.com")]
    public void Approved_Host_Normalization_And_Subdomains_Are_Supported(string host)
    {
        Assert.True(Builder().TryBuild(
            Authenticated(), Flow(host), Now,
            out var material, out var reason), reason);
        Assert.NotNull(material);
    }

    [Fact]
    public void Time_Binding_Has_Strict_Two_Minute_Utc_Boundary()
    {
        Assert.True(Builder().TryBuild(
            Authenticated(), Flow(), Now.AddMinutes(2),
            out _, out _));

        Assert.False(Builder().TryBuild(
            Authenticated(), Flow(), Now.AddMinutes(2).AddSeconds(1),
            out _, out var outsideReason));
        Assert.Equal("R275_ENTRA_CAPTURE_TIME_MISMATCH", outsideReason);

        Assert.False(Builder().TryBuild(
            Authenticated(), Flow(), Now.ToOffset(TimeSpan.FromHours(1)),
            out _, out var offsetReason));
        Assert.Equal("R275_ENTRA_CAPTURE_TIME_MISMATCH", offsetReason);
    }

    [Fact]
    public void Missing_Or_NonTls443_Capture_Cannot_Create_Material()
    {
        Assert.False(Builder().TryBuild(
            Authenticated(), null, Now,
            out _, out var missingReason));
        Assert.Equal("R275_CAPTURE_CORROBORATION_UNAVAILABLE", missingReason);

        var wrongPort = Flow();
        wrongPort.DestinationPort = 8443;
        Assert.False(Builder().TryBuild(
            Authenticated(), wrongPort, Now,
            out _, out var portReason));
        Assert.Equal("R275_CAPTURE_CORROBORATION_UNAVAILABLE", portReason);
    }

    [Fact]
    public void Builder_Requires_Explicit_Approved_Host_Policy()
    {
        Assert.Throws<ArgumentException>(() =>
            new MicrosoftEntraDeviceFlowClaimMaterialBuilder(Array.Empty<string>()));
        Assert.Throws<ArgumentNullException>(() =>
            new MicrosoftEntraDeviceFlowClaimMaterialBuilder(null!));
    }
}
