// SPDX-License-Identifier: MIT
// R275 Microsoft Entra projected SigninLogs parser tests. SOURCE CANDIDATE — UNVERIFIED.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Carthago.Services.TrustedAudit;
using Xunit;

namespace Carthago.Tests;

public sealed class MicrosoftEntraDeviceCodeAuditIntakeTests
{
    private static Dictionary<string, object> Valid() => new(StringComparer.Ordinal)
    {
        ["Type"] = "SigninLogs",
        ["Id"] = "11111111-1111-4111-8111-111111111111",
        ["CreatedDateTime"] = "2026-11-03T20:00:00.0000000+00:00",
        ["AuthenticationProtocol"] = "deviceCode",
        ["ResultType"] = "0",
        ["RiskState"] = "confirmedCompromised",
        ["RiskDetail"] = "adminConfirmedSigninCompromised",
        ["IPAddress"] = "203.0.113.25",
        ["UserId"] = "22222222-2222-4222-8222-222222222222",
        ["AppId"] = "33333333-3333-4333-8333-333333333333",
        ["ResourceId"] = "44444444-4444-4444-8444-444444444444",
        ["HomeTenantId"] = "55555555-5555-4555-8555-555555555555",
        ["ResourceTenantId"] = "66666666-6666-4666-8666-666666666666"
    };

    private static bool Try(
        Dictionary<string, object> fields,
        out MicrosoftEntraDeviceCodeAuditObservation? observation,
        out string reason)
        => MicrosoftEntraDeviceCodeAuditIntake.TryInspectUntrustedProjectedJson(
            JsonSerializer.Serialize(fields), out observation, out reason);

    [Fact]
    public void Admin_Confirmed_Successful_Device_Code_Signin_Produces_Unsigned_Minimized_Candidate()
    {
        Assert.True(Try(Valid(), out var observation, out var reason), reason);
        Assert.NotNull(observation);
        Assert.Equal("UNTRUSTED_ENTRA_SIGNIN_CANDIDATE_ONLY", reason);
        Assert.Equal("203.0.113.25", observation.SourceIp);
        Assert.Equal(64, observation.ActorHash.Length);
        Assert.Equal(64, observation.ResourceHash.Length);
        Assert.Equal(64, observation.TraceHash.Length);
        Assert.False(observation.FromTrustedProviderTransport);

        var names = typeof(MicrosoftEntraDeviceCodeAuditObservation)
            .GetProperties().Select(property => property.Name).ToArray();
        Assert.DoesNotContain("UserId", names);
        Assert.DoesNotContain("UserPrincipalName", names);
        Assert.DoesNotContain("AppId", names);
        Assert.DoesNotContain("ResourceId", names);
    }

    [Theory]
    [InlineData("none", "none")]
    [InlineData("atRisk", "none")]
    [InlineData("confirmedCompromised", "none")]
    [InlineData("confirmedSafe", "adminConfirmedSigninSafe")]
    public void Device_Code_Use_Without_Admin_Confirmed_Compromise_Is_Not_Abuse(
        string riskState, string riskDetail)
    {
        var fields = Valid();
        fields["RiskState"] = riskState;
        fields["RiskDetail"] = riskDetail;

        Assert.False(Try(fields, out var observation, out var reason));
        Assert.Null(observation);
        Assert.Equal("COMPROMISE_NOT_ADMIN_CONFIRMED", reason);
    }

    [Theory]
    [InlineData("oAuth2")]
    [InlineData("ropc")]
    [InlineData("none")]
    public void Other_Authentication_Protocols_Are_Rejected(string protocol)
    {
        var fields = Valid();
        fields["AuthenticationProtocol"] = protocol;

        Assert.False(Try(fields, out _, out var reason));
        Assert.Equal("NOT_DEVICE_CODE_SIGNIN", reason);
    }

    [Theory]
    [InlineData("50058")]
    [InlineData("50126")]
    [InlineData("1")]
    public void Failed_Device_Code_Signins_Are_Not_Confirmed_Abuse(string resultType)
    {
        var fields = Valid();
        fields["ResultType"] = resultType;

        Assert.False(Try(fields, out _, out var reason));
        Assert.Equal("SIGNIN_NOT_SUCCESSFUL", reason);
    }

    [Fact]
    public void Extra_Pii_And_Unexpected_Provider_Fields_Are_Rejected()
    {
        foreach (var extra in new[]
        {
            "UserPrincipalName", "UserDisplayName", "UniqueTokenIdentifier",
            "AuthenticationDetails", "RawToken", "DeviceCode"
        })
        {
            var fields = Valid();
            fields[extra] = "sensitive";
            Assert.False(Try(fields, out var observation, out var reason));
            Assert.Null(observation);
            Assert.Equal("INVALID_ENTRA_SIGNIN_SCHEMA", reason);
        }
    }

    [Theory]
    [InlineData("UserId")]
    [InlineData("AppId")]
    [InlineData("ResourceId")]
    [InlineData("HomeTenantId")]
    [InlineData("ResourceTenantId")]
    [InlineData("Id")]
    public void Missing_Required_Identifier_Is_Rejected(string field)
    {
        var fields = Valid();
        Assert.True(fields.Remove(field));
        Assert.False(Try(fields, out _, out var reason));
        Assert.Equal("INVALID_ENTRA_SIGNIN_SCHEMA", reason);
    }

    [Theory]
    [InlineData("UserId")]
    [InlineData("AppId")]
    [InlineData("ResourceId")]
    [InlineData("HomeTenantId")]
    [InlineData("ResourceTenantId")]
    [InlineData("Id")]
    public void Malformed_Required_Identifier_Is_Rejected(string field)
    {
        var fields = Valid();
        fields[field] = "not-a-guid";
        Assert.False(Try(fields, out _, out var reason));
        Assert.Equal("INVALID_ENTRA_SIGNIN_IDENTIFIERS", reason);
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("::1")]
    [InlineData("0.0.0.0")]
    [InlineData("not-an-ip")]
    public void Invalid_Or_Local_Source_Address_Is_Rejected(string source)
    {
        var fields = Valid();
        fields["IPAddress"] = source;
        Assert.False(Try(fields, out _, out var reason));
        Assert.Equal("INVALID_ENTRA_SOURCE_IP", reason);
    }

    [Fact]
    public void Duplicate_Json_Field_Is_Rejected_Instead_Of_Last_Wins()
    {
        var json = JsonSerializer.Serialize(Valid());
        var duplicate = json.Insert(1, "\"ResultType\":\"0\",");
        Assert.False(MicrosoftEntraDeviceCodeAuditIntake.TryInspectUntrustedProjectedJson(
            duplicate, out var observation, out var reason));
        Assert.Null(observation);
        Assert.Equal("INVALID_ENTRA_SIGNIN_SCHEMA", reason);
    }

    [Theory]
    [InlineData("2026-11-03")]
    [InlineData("2026-11-03T21:00:00+01:00")]
    [InlineData("not-a-time")]
    public void Invalid_Timestamp_Is_Rejected(string timestamp)
    {
        var fields = Valid();
        fields["CreatedDateTime"] = timestamp;
        Assert.False(Try(fields, out _, out var reason));
        Assert.Equal("INVALID_ENTRA_TIMESTAMP", reason);
    }
}
