// SPDX-License-Identifier: MIT
// Pure in-memory R343 IPC contract tests. NO Windows service, listener,
// audit policies, signing keys, real peer credentials or WinRM operations.
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using Carthago.Services.TrustedAudit;
using Xunit;

namespace Carthago.Tests;

public sealed class WinRmTelemetryIpcContractTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 10, 29, 1, 30, 0, TimeSpan.Zero);
    private const string Sid = "S-1-5-80-123-456-789-101";
    private const string Machine = "CARTHAGE";

    private static WinRmTelemetryIpcContract Contract(Func<DateTimeOffset>? clock = null)
        => new(Sid, Machine, clock ?? (() => Now));

    private static WinRmTelemetryTransportPeer Peer(
        string sid = Sid, string machine = Machine, int pid = 701,
        Guid? channel = null)
        => new(sid, machine, pid, channel ?? Guid.NewGuid());

    private static WinRmTelemetryIpcSession Open(
        WinRmTelemetryIpcContract contract, WinRmTelemetryTransportPeer? peer = null)
    {
        Assert.True(contract.TryOpenVerifiedPeer(peer ?? Peer(), out var session,
            out var reason), reason);
        return Assert.IsType<WinRmTelemetryIpcSession>(session);
    }

    private static bool TryAccept(WinRmTelemetryIpcContract contract,
        WinRmTelemetryIpcSession? session, byte[] frame,
        out WinRmTelemetryIpcCandidate? candidate, out string reason)
    {
        // Synthetic transport identity in TESTS ONLY; a real adapter must
        // derive this independently from the Windows OS on every frame.
        var peer = session == null ? null : new WinRmTelemetryTransportPeer(
            Sid, Machine, 701, session.ChannelBinding);
        return contract.TryAcceptFrame(session, peer, frame,
            out candidate, out reason);
    }

    private static Dictionary<string, object?> Payload(
        WinRmTelemetryIpcSession session, long sequence = 1,
        Guid? correlation = null, DateTimeOffset? at = null)
        => new(StringComparer.Ordinal)
        {
            ["Version"] = 1,
            ["Kind"] = "UnsignedWinRmCandidate",
            ["SessionId"] = session.Id.ToString("D"),
            ["CorrelationId"] = (correlation ?? Guid.NewGuid()).ToString("D"),
            ["Sequence"] = sequence,
            ["Machine"] = Machine,
            ["RemoteIp"] = "10.20.30.41",
            ["LogonId"] = 0x12345UL,
            ["LogonRecordId"] = 100L,
            ["ProcessRecordId"] = 101L,
            ["ProcessId"] = 1234U,
            ["ParentProcessId"] = 1222U,
            ["ProcessTimeUtc"] = (at ?? Now).ToString("O")
        };

    private static byte[] Frame(Dictionary<string, object?> fields)
        => FrameText(JsonSerializer.Serialize(fields));

    private static byte[] FrameText(string text)
    {
        var payload = Encoding.UTF8.GetBytes(text);
        var frame = new byte[payload.Length + 4];
        BinaryPrimitives.WriteInt32BigEndian(frame.AsSpan(0, 4), payload.Length);
        payload.CopyTo(frame, 4);
        return frame;
    }

    [Fact]
    public void Authenticated_Transport_Context_Accepts_Only_Unsigned_Metadata()
    {
        var contract = Contract();
        var session = Open(contract);
        Assert.True(TryAccept(contract, session, Frame(Payload(session)),
            out var accepted, out var reason), reason);
        var result = Assert.IsType<WinRmTelemetryIpcCandidate>(accepted);
        Assert.Equal("UNSIGNED_IPC_CANDIDATE_NOT_AUTHORIZED_FOR_ALERT", reason);
        Assert.Equal(session.Id, result.SessionId);
        Assert.Equal(1L, result.Sequence);
        Assert.Equal(Machine, result.Machine);
        Assert.Equal("10.20.30.41", result.RemoteIp);
        Assert.Equal(1234U, result.ProcessId);
        Assert.Equal(100L, result.LogonRecordId);
        Assert.Equal(101L, result.ProcessRecordId);

        var properties = typeof(WinRmTelemetryIpcCandidate)
            .GetProperties().Select(x => x.Name)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var forbidden in new[]
            { "CommandLine", "Payload", "Signature", "Trusted", "Authorized",
              "Outcome", "Verified", "Token", "Sid" })
            Assert.False(properties.Contains(forbidden),
                "Forbidden IPC candidate property: " + forbidden);
    }

    [Fact]
    public void Null_Or_Mismatched_Peer_Is_Not_Authenticated_By_Payload_Claims()
    {
        var contract = Contract();
        Assert.False(contract.TryOpenVerifiedPeer(null, out var missing, out _));
        Assert.Null(missing);
        foreach (var peer in new[]
        {
            Peer(sid: "S-1-5-80-999"),
            Peer(machine: "OTHERHOST"),
            Peer(pid: 0),
            Peer(channel: Guid.Empty),
            Peer(sid: "not-a-sid")
        })
        {
            Assert.False(contract.TryOpenVerifiedPeer(peer, out var session, out _));
            Assert.Null(session);
        }
    }

    [Fact]
    public void Session_Cannot_Be_Used_Across_Gates_Or_After_Close()
    {
        var first = Contract();
        var second = Contract();
        var session = Open(first);
        Assert.False(TryAccept(second, session, Frame(Payload(session)),
            out var foreign, out var foreignReason));
        Assert.Null(foreign);
        Assert.Equal("INVALID_SESSION", foreignReason);
        first.Close(session);
        Assert.False(TryAccept(first, session, Frame(Payload(session)),
            out var closed, out var reason));
        Assert.Null(closed);
        Assert.Equal("SESSION_CLOSED_OR_EXPIRED", reason);
    }

    [Fact]
    public void Each_Frame_Requires_The_Same_Transport_Verified_Sid_Pid_And_Channel()
    {
        var contract = Contract();
        var session = Open(contract);
        var frame = Frame(Payload(session));

        var wrongPeers = new WinRmTelemetryTransportPeer?[]
        {
            null,
            Peer(sid: "S-1-5-80-999", channel: session.ChannelBinding),
            Peer(machine: "OTHERHOST", channel: session.ChannelBinding),
            Peer(pid: 702, channel: session.ChannelBinding),
            Peer(channel: Guid.NewGuid())
        };
        foreach (var peer in wrongPeers)
        {
            Assert.False(contract.TryAcceptFrame(session, peer, frame,
                out var candidate, out var reason));
            Assert.Null(candidate);
            Assert.Equal("TRANSPORT_IDENTITY_MISMATCH", reason);
        }
        // Rejected frames do not advance sequence or burn correlation IDs.
        Assert.True(TryAccept(contract, session, frame, out var valid, out var accepted),
            accepted);
        Assert.NotNull(valid);
    }

    [Fact]
    public void One_Channel_Binding_Cannot_Open_Another_Session()
    {
        var contract = Contract();
        var peer = Peer();
        Open(contract, peer);
        Assert.False(contract.TryOpenVerifiedPeer(peer, out var replay, out var reason));
        Assert.Null(replay);
        Assert.Equal("CHANNEL_REPLAY_OR_CAPACITY", reason);
    }

    [Theory]
    [InlineData("Version", 2)]
    [InlineData("Version", "1")]
    [InlineData("Kind", "SignedWinRmOutcome")]
    [InlineData("Kind", "R343")]
    [InlineData("SessionId", "not-a-guid")]
    [InlineData("CorrelationId", "00000000-0000-0000-0000-000000000000")]
    [InlineData("Sequence", 0)]
    [InlineData("Sequence", "1")]
    [InlineData("Machine", "OTHERHOST")]
    [InlineData("Machine", "CARTHAGE\\bad")]
    [InlineData("RemoteIp", "127.0.0.1")]
    [InlineData("RemoteIp", "::ffff:127.0.0.1")]
    [InlineData("RemoteIp", "0.0.0.0")]
    [InlineData("RemoteIp", "not-an-ip")]
    [InlineData("LogonId", 0)]
    [InlineData("LogonRecordId", 0)]
    [InlineData("ProcessRecordId", 100)]
    [InlineData("ProcessId", 0)]
    [InlineData("ParentProcessId", 0)]
    [InlineData("ParentProcessId", 1234)]
    [InlineData("ProcessTimeUtc", "2026-10-29")]
    [InlineData("ProcessTimeUtc", "2026-10-29T02:30:00.0000000+01:00")]
    public void Corrupt_Or_Unrelated_Claims_Fail_Closed(
        string key, object replacement)
    {
        var contract = Contract();
        var session = Open(contract);
        var fields = Payload(session);
        fields[key] = replacement;
        Assert.False(TryAccept(contract, session, Frame(fields),
            out var candidate, out _));
        Assert.Null(candidate);
        // A rejected frame must not consume the first sequence number.
        Assert.True(TryAccept(contract, session, Frame(Payload(session)),
            out var valid, out var reason), reason);
        Assert.NotNull(valid);
    }

    [Theory]
    [InlineData("CommandLine")]
    [InlineData("EncodedCommand")]
    [InlineData("SignatureBase64")]
    [InlineData("BearerToken")]
    [InlineData("Authenticated")]
    [InlineData("Authorized")]
    [InlineData("Outcome")]
    [InlineData("SourceSid")]
    [InlineData("Provider")]
    [InlineData("RuleId")]
    public void Extra_Claims_Including_Authentication_And_Secrets_Are_Rejected(
        string extra)
    {
        var contract = Contract();
        var session = Open(contract);
        var fields = Payload(session);
        fields[extra] = "attacker-controlled";
        Assert.False(TryAccept(contract, session, Frame(fields),
            out var candidate, out var reason));
        Assert.Null(candidate);
        Assert.Equal("INVALID_CANDIDATE_SCHEMA", reason);
    }

    [Fact]
    public void Duplicate_Json_Fields_Are_Rejected_Instead_Of_Last_Wins()
    {
        var contract = Contract();
        var session = Open(contract);
        var serialized = JsonSerializer.Serialize(Payload(session));
        var spoofed = serialized.Insert(1, "\"Version\":1,");
        Assert.False(TryAccept(contract, session, FrameText(spoofed),
            out var candidate, out var reason));
        Assert.Null(candidate);
        Assert.Equal("INVALID_CANDIDATE_SCHEMA", reason);
    }

    [Fact]
    public void Frames_Reject_Truncation_Padding_Invalid_Utf8_And_Excessive_Size()
    {
        var contract = Contract();
        var session = Open(contract);
        var valid = Frame(Payload(session));
        var truncated = valid[..^1];
        var padded = valid.Concat(new byte[] { 0 }).ToArray();
        var malformed = (byte[])valid.Clone();
        malformed[0] = 0x7f;
        var invalidUtf8 = new byte[] { 0, 0, 0, 2, 0xC3, 0x28 };
        var tooLarge = new byte[WinRmTelemetryIpcContract.MaxFrameBytes + 1];
        foreach (var frame in new[]
        {
            Array.Empty<byte>(), truncated, padded, malformed, invalidUtf8,
            tooLarge, FrameText("{}"), FrameText("[]"),
            FrameText("{\"Version\":1,}"), FrameText("{\"Version\":1}//comment"),
            FrameText("\uFEFF" + JsonSerializer.Serialize(Payload(session)))
        })
        {
            Assert.False(TryAccept(contract, session, frame,
                out var candidate, out _));
            Assert.Null(candidate);
        }
    }

    [Fact]
    public void Strict_Sequence_Prevents_Skips_Duplicates_And_Out_Of_Order_Frames()
    {
        var contract = Contract();
        var session = Open(contract);
        Assert.False(TryAccept(contract, session, Frame(Payload(session, 2)),
            out _, out _));
        Assert.True(TryAccept(contract, session, Frame(Payload(session, 1)),
            out _, out _));
        Assert.False(TryAccept(contract, session, Frame(Payload(session, 1)),
            out _, out _));
        Assert.False(TryAccept(contract, session, Frame(Payload(session, 3)),
            out _, out _));
        Assert.True(TryAccept(contract, session, Frame(Payload(session, 2)),
            out _, out _));
    }

    [Fact]
    public void Replayed_Correlation_Id_Is_Rejected_Across_Different_Sessions()
    {
        var contract = Contract();
        var first = Open(contract);
        var second = Open(contract);
        var id = Guid.NewGuid();
        Assert.True(TryAccept(contract, first,
            Frame(Payload(first, correlation: id)), out _, out _));
        Assert.False(TryAccept(contract, second,
            Frame(Payload(second, correlation: id)), out var candidate,
            out var reason));
        Assert.Null(candidate);
        Assert.Equal("OUT_OF_ORDER_OR_REPLAY", reason);
    }

    [Fact]
    public void Bound_Session_Id_Cannot_Be_Replaced_By_Another_Authenticated_Session()
    {
        var contract = Contract();
        var first = Open(contract);
        var second = Open(contract);
        var forged = Payload(first);
        Assert.False(TryAccept(contract, second, Frame(forged),
            out var candidate, out var reason));
        Assert.Null(candidate);
        Assert.Equal("CHANNEL_OR_MACHINE_MISMATCH", reason);
    }

    [Theory]
    [InlineData(-180)]
    [InlineData(31)]
    public void Stale_Or_Future_Observations_Are_Rejected(int offsetSeconds)
    {
        var contract = Contract();
        var session = Open(contract);
        var when = Now.AddSeconds(offsetSeconds);
        Assert.False(TryAccept(contract, session,
            Frame(Payload(session, at: when)), out var candidate, out var reason));
        Assert.Null(candidate);
        Assert.Equal("STALE_OR_FUTURE_CANDIDATE", reason);
    }

    [Fact]
    public void Expired_Transport_Session_Cannot_Accept_Fresh_Frame()
    {
        var clock = Now;
        var contract = Contract(() => clock);
        var session = Open(contract);
        clock = Now.AddMinutes(16);
        Assert.False(TryAccept(contract, session,
            Frame(Payload(session, at: clock)), out var candidate, out var reason));
        Assert.Null(candidate);
        Assert.Equal("SESSION_CLOSED_OR_EXPIRED", reason);
    }

    [Fact]
    public void Concurrent_Session_Limit_Is_Fail_Closed_But_Closed_Slots_Reopen()
    {
        var contract = Contract();
        var sessions = new List<WinRmTelemetryIpcSession>();
        for (var i = 0; i < WinRmTelemetryIpcContract.MaxSessions; i++)
            sessions.Add(Open(contract));

        Assert.False(contract.TryOpenVerifiedPeer(Peer(), out var denied,
            out var reason));
        Assert.Null(denied);
        Assert.Equal("CHANNEL_REPLAY_OR_CAPACITY", reason);

        contract.Close(sessions[0]);
        var replacement = Open(contract);
        Assert.NotEqual(sessions[0].Id, replacement.Id);
    }

    [Fact]
    public void Replay_Cache_Saturates_Fail_Closed_Without_Evicting_Old_Ids()
    {
        var contract = Contract();
        var session = Open(contract);
        for (var sequence = 1; sequence <= WinRmTelemetryIpcContract.MaxAcceptedMessages;
            sequence++)
        {
            Assert.True(TryAccept(contract, session,
                Frame(Payload(session, sequence)), out _, out var reason), reason);
        }

        Assert.False(TryAccept(contract, session,
            Frame(Payload(session, WinRmTelemetryIpcContract.MaxAcceptedMessages + 1)),
            out var rejected, out var rejection));
        Assert.Null(rejected);
        Assert.Equal("REPLAY_CACHE_CAPACITY", rejection);
    }

    [Fact]
    public void Malformed_Operator_Configuration_Fails_Before_Sessions_Open()
    {
        Assert.Throws<ArgumentException>(() => new WinRmTelemetryIpcContract(
            "not-a-sid", Machine));
        Assert.Throws<ArgumentException>(() => new WinRmTelemetryIpcContract(
            Sid, "CARTHAGE/other"));
    }
}
