// SPDX-License-Identifier: MIT
// GA Redis Software source adapter — SOURCE CANDIDATE — UNVERIFIED.
// Fixtures are hand-authored notifications from the published schema, not
// external authenticated Redis audit data and not approved holdout captures.
using System;
using System.Text;
using System.Text.Json;
using Carthago.Services.TrustedAudit;
using Xunit;

namespace Carthago.Tests;

public sealed class RedisSoftwareAuditSourceTests
{
    internal const long EventSecond = 1793640000L;
    private static readonly DateTimeOffset EventUtc =
        DateTimeOffset.FromUnixTimeSeconds(EventSecond);

    internal static byte[] Command(string command = "config", int status = 9,
        long sequence = 1, string clientPort = "40000",
        string serverPort = "6379", string client = "10.4.0.9",
        string server = "10.4.0.10", int workerId = 0)
        => JsonSerializer.SerializeToUtf8Bytes(new
        {
            ts = EventSecond,
            action = "command",
            id = 13001000L,
            srcip = client,
            srcp = clientPort,
            trgip = server,
            trgp = serverPort,
            bdb_name = "Redis-test-db",
            bdb_uid = "1",
            status,
            command,
            keys = new[] { "secret-config-parameter" },
            error = "secret-config-error",
            username = "private-username",
            audit_worker_id = workerId,
            audit_seq = sequence
        });

    internal static byte[] Connection(long sequence = 0, int workerId = 0)
        => JsonSerializer.SerializeToUtf8Bytes(new
        {
            ts = EventSecond,
            new_conn = new
            {
                id = 13001000L,
                srcip = "10.4.0.9",
                srcp = "40000",
                trgip = "10.4.0.10",
                trgp = "6379",
                bdb_name = "Redis-test-db",
                bdb_uid = "1"
            },
            audit_worker_id = workerId,
            audit_seq = sequence
        });

    private static RedisSoftwareAuditObservation Decode(byte[] json)
    {
        Assert.True(RedisSoftwareAuditNotificationParser.TryParse(
            json, out var value));
        return Assert.IsType<RedisSoftwareAuditObservation>(value);
    }

    [Fact]
    public void Vendor_Config_Success_Remains_Generic_Not_A_Proven_Config_Set()
    {
        var observation = Decode(Command());
        Assert.Equal(RedisSoftwareAuditEventKind.Command, observation.Kind);
        Assert.Equal(RedisSoftwareCommandClass.GenericConfig, observation.CommandClass);
        Assert.Equal(RedisSoftwareCommandOutcome.Succeeded, observation.CommandOutcome);
        Assert.Equal("10.4.0.9", observation.ClientIp);
        Assert.Equal(40000, observation.ClientPort);
        Assert.Equal("10.4.0.10", observation.ServerIp);
        Assert.Equal(6379, observation.ServerPort);
        Assert.Equal(13001000L, observation.ConnectionId);
        Assert.Equal(EventUtc, observation.OccurredAtUtc);
        Assert.False(observation.ProvesConfigSetSubcommand);
        Assert.False(observation.AuthenticatedProducer);
        Assert.DoesNotContain("secret-config", observation.ToString());
        Assert.DoesNotContain("private-username", observation.ToString());
        Assert.DoesNotContain("Redis-test-db", observation.ToString());
    }

    [Fact]
    public void Vendor_Generic_Config_Error_Remains_Error_Without_Secrets()
    {
        var observation = Decode(Command(status: 10));
        Assert.Equal(RedisSoftwareCommandOutcome.Failed, observation.CommandOutcome);
        Assert.Equal(RedisSoftwareCommandClass.GenericConfig, observation.CommandClass);
        Assert.False(observation.ProvesConfigSetSubcommand);
        Assert.DoesNotContain("secret-config-error", observation.ToString());
    }

    [Theory]
    [InlineData("get")]
    [InlineData("set")]
    [InlineData("CONFIG SET")]
    [InlineData("config-get")]
    public void Noncanonical_Command_Names_Are_Not_Interpreted_As_Config_Set(string command)
    {
        var observation = Decode(Command(command: command));
        Assert.Equal(RedisSoftwareCommandClass.Other, observation.CommandClass);
        Assert.False(observation.ProvesConfigSetSubcommand);
    }

    [Fact]
    public void Connection_Authentication_And_Disconnection_Are_Parsed_For_Sequence_Health()
    {
        var opened = Decode(Connection());
        Assert.Equal(RedisSoftwareAuditEventKind.ConnectionOpened, opened.Kind);
        Assert.Equal(RedisSoftwareCommandClass.None, opened.CommandClass);
        Assert.Equal(RedisSoftwareCommandOutcome.NotACommand, opened.CommandOutcome);

        var authentication = JsonSerializer.SerializeToUtf8Bytes(new
        {
            ts = EventSecond, action = "auth", id = 13001000L,
            srcip = "10.4.0.9", srcp = "40000",
            trgip = "10.4.0.10", trgp = "6379",
            bdb_uid = "1", status = 8, username = "no-retention",
            audit_worker_id = 0, audit_seq = 1L
        });
        Assert.Equal(RedisSoftwareAuditEventKind.Authentication,
            Decode(authentication).Kind);

        var closed = JsonSerializer.SerializeToUtf8Bytes(new
        {
            ts = EventSecond,
            close_conn = new
            {
                id = 13001000L,
                srcip = "10.4.0.9", srcp = "40000",
                trgip = "10.4.0.10", trgp = "6379", bdb_uid = "1"
            },
            audit_worker_id = 0, audit_seq = 3L
        });
        Assert.Equal(RedisSoftwareAuditEventKind.ConnectionClosed,
            Decode(closed).Kind);
    }

    [Fact]
    public void Invalid_Frame_Duplicate_Properties_And_Unknown_Status_Fail_Closed()
    {
        foreach (var bytes in new[]
        {
            Array.Empty<byte>(),
            Encoding.UTF8.GetBytes("{}"),
            Encoding.UTF8.GetBytes("{"),
            Encoding.UTF8.GetBytes(new string('x', 16385)),
            Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(Command())
                .Replace("\"audit_seq\":1", "\"audit_seq\":1,\"audit_seq\":1")),
            Command(status: 8),
            Command(status: 11),
            Command(serverPort: "0"),
            Command(serverPort: "65536"),
            Command(clientPort: "-1"),
            Command(client: "not-an-ip"),
            Command(workerId: -1)
        })
        {
            Assert.False(RedisSoftwareAuditNotificationParser.TryParse(
                bytes, out var ignored));
            Assert.Null(ignored);
        }
    }

    [Fact]
    public void Vendor_Ports_Must_Be_Bounded_But_Numeric_Ports_Are_Accepted()
    {
        var json = Encoding.UTF8.GetString(Command());
        json = json.Replace("\"srcp\":\"40000\"", "\"srcp\":40000")
                   .Replace("\"trgp\":\"6379\"", "\"trgp\":6379");
        var record = Decode(Encoding.UTF8.GetBytes(json));
        Assert.Equal(40000, record.ClientPort);
        Assert.Equal(6379, record.ServerPort);
    }

    [Fact]
    public void Stream_Tracker_Requires_An_Explicit_Source_And_Contiguous_All_Event_Sequence()
    {
        var tracker = new RedisSoftwareAuditContinuityTracker();
        var opened = Decode(Connection(sequence: 0));
        var cmd = Decode(Command(sequence: 1));
        Assert.Equal(RedisAuditDeliveryStatus.InvalidProducerIdentity,
            tracker.Observe(null, opened).Status);
        var first = tracker.Observe("provisioned-redis-1", opened);
        Assert.Equal(RedisAuditDeliveryStatus.FirstObservation, first.Status);
        Assert.False(first.NoGapObserved);
        var next = tracker.Observe("provisioned-redis-1", cmd);
        Assert.Equal(RedisAuditDeliveryStatus.Contiguous, next.Status);
        Assert.True(next.NoGapObserved);
        Assert.False(next.AuthenticityEstablished);
    }

    [Fact]
    public void Gap_Poisons_Only_Affected_Worker_And_Cannot_Be_Silently_Reset()
    {
        var tracker = new RedisSoftwareAuditContinuityTracker();
        var first = Decode(Connection(sequence: 0));
        tracker.Observe("redis-audit-source", first);
        Assert.Equal(RedisAuditDeliveryStatus.SequenceGap,
            tracker.Observe("redis-audit-source", Decode(Command(sequence: 3))).Status);
        Assert.Equal(RedisAuditDeliveryStatus.AlreadyCompromised,
            tracker.Observe("redis-audit-source", Decode(Command(sequence: 4))).Status);

        Assert.Equal(RedisAuditDeliveryStatus.FirstObservation,
            tracker.Observe("redis-audit-source", Decode(Connection(0, workerId: 1))).Status);
        Assert.Equal(RedisAuditDeliveryStatus.Contiguous,
            tracker.Observe("redis-audit-source", Decode(Command(sequence: 1, workerId: 1))).Status);
    }

    [Fact]
    public void Duplicate_And_Rollback_Are_Sticky_And_Not_A_Replay_Bypass()
    {
        var tracker = new RedisSoftwareAuditContinuityTracker();
        tracker.Observe("redis-audit-source", Decode(Connection(sequence: 20)));
        Assert.Equal(RedisAuditDeliveryStatus.DuplicateOrRollback,
            tracker.Observe("redis-audit-source", Decode(Command(sequence: 20))).Status);
        Assert.Equal(RedisAuditDeliveryStatus.AlreadyCompromised,
            tracker.Observe("redis-audit-source", Decode(Command(sequence: 21))).Status);
    }

    [Fact]
    public void Worker_Tracker_Refuses_Unbounded_Identity_Cardinality()
    {
        var tracker = new RedisSoftwareAuditContinuityTracker();
        for (var i = 0; i < 256; i++)
            Assert.Equal(RedisAuditDeliveryStatus.FirstObservation,
                tracker.Observe("redis-audit-source", Decode(Connection(workerId: i))).Status);
        Assert.Equal(RedisAuditDeliveryStatus.CapacityExceeded,
            tracker.Observe("redis-audit-source", Decode(Connection(workerId: 256))).Status);
    }
}
