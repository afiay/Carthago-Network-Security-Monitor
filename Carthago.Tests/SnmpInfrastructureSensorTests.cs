// SPDX-License-Identifier: MIT
using System.Net;
using Carthago.Services;
using Carthago.Services.Sensors;
using Lextm.SharpSnmpLib;
using Xunit;

namespace Carthago.Tests;

public sealed class SnmpInfrastructureSensorTests
{
    private static readonly LocalLanInterface Adapter = new("test", IPAddress.Parse("192.168.1.130"), IPAddress.Parse("255.255.255.128"));
    private static readonly IPAddress Target = IPAddress.Parse("192.168.1.131");
    private static List<Variable> Values() => new()
    {
        new(new ObjectIdentifier("1.3.6.1.2.1.1.1.0"), new OctetString("Lab switch")),
        new(new ObjectIdentifier("1.3.6.1.2.1.1.2.0"), new ObjectIdentifier("1.3.6.1.4.1.9")),
        new(new ObjectIdentifier("1.3.6.1.2.1.1.3.0"), new TimeTicks(12345u)),
        new(new ObjectIdentifier("1.3.6.1.2.1.1.5.0"), new OctetString("switch01")),
        new(new ObjectIdentifier("1.3.6.1.2.1.2.1.0"), new Integer32(24))
    };
    [Fact]
    public void FixedReadOnlyObjects()
    {
        Assert.Equal(5, SnmpInfrastructureSensor.RequestedOids.Count);
        Assert.Equal(SnmpInfrastructureSensor.RequestedOids.ToArray(),
            SnmpInfrastructureSensor.BuildVariables().Select(v => v.Id.ToString()).ToArray());
    }
    [Fact]
    public void ExactTypedValuesProjected()
    {
        Assert.True(SnmpInfrastructureSensor.TryProject(Values(), out var evidence));
        Assert.Equal("switch01", evidence!.Name);
        Assert.Equal("Lab switch", evidence.Description);
        Assert.Equal("1.3.6.1.4.1.9", evidence.ObjectId);
        Assert.Equal(12345u, evidence.UptimeCentiseconds);
        Assert.Equal(24, evidence.InterfaceCount);
    }
    [Theory]
    [InlineData("missing")]
    [InlineData("extra")]
    [InlineData("wrong-oid")]
    [InlineData("reordered")]
    public void UnexpectedVariableBindingRejected(string change)
    {
        var values = Values();
        switch (change)
        {
            case "missing": values.RemoveAt(0); break;
            case "extra": values.Add(values[0]); break;
            case "wrong-oid": values[0] = values[1]; break;
            case "reordered": (values[0], values[1]) = (values[1], values[0]); break;
        }
        Assert.False(SnmpInfrastructureSensor.TryProject(values, out var evidence));
        Assert.Null(evidence);
    }
    [Fact]
    public void WrongTypesAndNegativeCountsRemainUnknown()
    {
        var values = Values();
        values[2] = new(values[2].Id, new OctetString("123"));
        values[4] = new(values[4].Id, new Integer32(-1));
        Assert.True(SnmpInfrastructureSensor.TryProject(values, out var evidence));
        Assert.Null(evidence!.UptimeCentiseconds);
        Assert.Null(evidence.InterfaceCount);
    }
    [Fact]
    public void TextIsBoundedAndControlCharactersRemoved()
    {
        var values = Values();
        values[0] = new(values[0].Id, new OctetString(new string('a', 1025)));
        values[3] = new(values[3].Id, new OctetString("switch\r\n01"));
        Assert.True(SnmpInfrastructureSensor.TryProject(values, out var evidence));
        Assert.Null(evidence!.Description);
        Assert.Equal("switch01", evidence.Name);
    }
    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("192.168.1.128")]
    [InlineData("192.168.1.130")]
    [InlineData("192.168.1.255")]
    [InlineData("127.0.0.1")]
    public void OutsideScopeRejected(string address) => Assert.Throws<ArgumentException>(() =>
    { _ = SnmpInfrastructureSensor.CheckAsync(Adapter, IPAddress.Parse(address), "user", "authphrase", "privphrase"); });
    [Theory]
    [InlineData("", "authphrase", "privphrase")]
    [InlineData("user name", "authphrase", "privphrase")]
    [InlineData("user", "short", "privphrase")]
    [InlineData("user", "authphrase", "short")]
    [InlineData("user", "authphrase", "priv\nphrase")]
    public void InvalidCredentialsRejected(string user, string auth, string privacy) =>
        Assert.Throws<ArgumentException>(() => SnmpInfrastructureSensor.ValidateCredentials(user, auth, privacy));
    [Fact]
    public void ValidCredentialsAcceptedWithoutNetwork() =>
        SnmpInfrastructureSensor.ValidateCredentials("operator", "authphrase", "privphrase");
    [Fact]
    public void PreCancelledRequestDoesNotConnect()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() =>
        { _ = SnmpInfrastructureSensor.CheckAsync(Adapter, Target, "user", "authphrase", "privphrase", cts.Token); });
    }
}
