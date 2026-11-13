// SPDX-License-Identifier: MIT
using Carthago.Contracts;
using Xunit;
using System.Text.Json;

namespace Carthago.Cli.Tests;

public sealed class LocalReadProtocolTests
{
    [Fact]
    public void RoundTripAndCorrelation()
    {
        var request = new ReadRequest(ReadCommand.RulesSummary, Guid.NewGuid());
        Assert.Equal(request, LocalReadProtocol.DecodeRequest(LocalReadProtocol.EncodeRequest(request)));
        var response = new ReadResponse(request.Command, request.Correlation, ReadState.Available, 100, 80, 10,
            DateTimeOffset.FromUnixTimeMilliseconds(123456));
        byte[] bytes = LocalReadProtocol.EncodeResponse(response);
        Assert.Equal(response, LocalReadProtocol.DecodeResponse(bytes, request));
        Assert.Throws<InvalidDataException>(() => LocalReadProtocol.DecodeResponse(bytes, request with { Correlation = Guid.NewGuid() }));
    }

    [Theory]
    [InlineData(0, 2)]
    [InlineData(1, 255)]
    public void UnknownVersionOrCommandRejected(int offset, int value)
    {
        var bytes = LocalReadProtocol.EncodeRequest(new(ReadCommand.HostStatus, Guid.NewGuid()));
        bytes[offset] = (byte)value;
        Assert.Throws<InvalidDataException>(() => LocalReadProtocol.DecodeRequest(bytes));
    }

    [Fact]
    public void MalformedAndImpossibleCountsRejected()
    {
        Assert.Throws<InvalidDataException>(() => LocalReadProtocol.DecodeRequest(new byte[17]));
        Assert.Throws<InvalidDataException>(() => LocalReadProtocol.EncodeResponse(new(ReadCommand.RulesSummary,
            Guid.NewGuid(), ReadState.Available, 10, 11, 0, DateTimeOffset.UtcNow)));
        Assert.Throws<InvalidDataException>(() => LocalReadProtocol.EncodeResponse(new(ReadCommand.HostStatus,
            Guid.NewGuid(), ReadState.Available, 1, 0, 0, DateTimeOffset.UtcNow)));
        Assert.Throws<InvalidDataException>(() => LocalReadProtocol.EncodeResponse(new(ReadCommand.RulesSummary,
            Guid.NewGuid(), ReadState.Unavailable, 1, 0, 0, DateTimeOffset.UtcNow)));
    }

    [Fact]
    public async Task RuleSummaryDoesNotClaimValidation()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        int code = await CliApplication.RunAsync(new[] { "rules", "summary", "--json" }, output, error,
            query: (command, _) => Task.FromResult(new ReadResponse(command, Guid.NewGuid(), ReadState.Available,
                100, 80, 10, DateTimeOffset.UtcNow)));
        Assert.Equal(0, code);
        using var doc = JsonDocument.Parse(output.ToString());
        Assert.Equal(100, doc.RootElement.GetProperty("registered").GetInt32());
        Assert.Equal("not_assessed", doc.RootElement.GetProperty("validation").GetString());
        Assert.Empty(error.ToString());
    }

    [Fact]
    public async Task UnavailableSourceDoesNotEmitZeroCounts()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        int code = await CliApplication.RunAsync(new[] { "rules", "summary", "--json" }, output, error,
            query: (command, _) => Task.FromResult(new ReadResponse(command, Guid.NewGuid(), ReadState.Unavailable,
                0, 0, 0, DateTimeOffset.UtcNow)));
        Assert.Equal(3, code);
        Assert.Empty(output.ToString());
        Assert.Contains("source_unavailable", error.ToString());
    }

    [Fact]
    public async Task WindowsLoopbackCandidate()
    {
        if (!OperatingSystem.IsWindows()) return; // Windows-specific runtime gate; not Linux verification.
        string name = "Carthago.Test." + Guid.NewGuid().ToString("N");
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var server = WindowsLocalReadPipe.ServeAsync(r => new ReadResponse(r.Command, r.Correlation,
            ReadState.Available, 9, 8, 1, DateTimeOffset.UtcNow), cts.Token, name);
        try
        {
            var response = await WindowsLocalReadPipe.QueryAsync(ReadCommand.RulesSummary, cts.Token, name);
            Assert.Equal(9, response.Registered);
            var second = await WindowsLocalReadPipe.QueryAsync(ReadCommand.RulesSummary, cts.Token, name);
            Assert.Equal(9, second.Registered);
        }
        finally
        {
            cts.Cancel();
            try { await server; }
            catch (OperationCanceledException) when (cts.IsCancellationRequested) { }
        }
    }
}
