// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using Lextm.SharpSnmpLib.Security;

namespace Carthago.Services.Sensors;

public enum SnmpInfrastructureStatus { Observed, Partial, InvalidResponse, AgentReport, AgentError, TimedOut, TransportError }
public sealed record SnmpInfrastructureEvidence(string? Description, string? ObjectId, uint? UptimeCentiseconds,
    string? Name, int? InterfaceCount);
public sealed record SnmpInfrastructureObservation(IPAddress Source, IPAddress Target,
    SnmpInfrastructureStatus Status, SnmpInfrastructureEvidence? Evidence, DateTimeOffset ObservedUtc, TimeSpan Duration);

/// <summary>One source-bound SNMPv3 USM authPriv GET after engine discovery. No fallback or SET.</summary>
public static class SnmpInfrastructureSensor
{
    private static readonly string[] Oids = { "1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.2.0",
        "1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.2.1.0" };
    public static IReadOnlyList<string> RequestedOids { get; } = Array.AsReadOnly(Oids);
    public static TimeSpan Timeout { get; } = TimeSpan.FromSeconds(5);
    private const int MaxDatagram = 8192;

    internal static void ValidateCredentials(string user, string auth, string privacy)
    {
        // Restrict to ASCII USM credentials to avoid library/agent encoding ambiguity.
        if (user is null || user.Length is < 1 or > 32 || user.Any(c => c < 33 || c > 126))
            throw new ArgumentException("Enter an ASCII SNMPv3 user (1–32 characters).");
        if (!ValidPhrase(auth) || !ValidPhrase(privacy))
            throw new ArgumentException("Enter authentication and privacy passphrases of 8–128 printable ASCII characters.");
    }
    private static bool ValidPhrase(string value) => value is not null && value.Length is >= 8 and <= 128 &&
        value.All(c => c >= 32 && c <= 126);

    public static Task<SnmpInfrastructureObservation> CheckAsync(LocalLanInterface adapter,
        IPAddress target, string user, string auth, string privacy, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(adapter);
        ArgumentNullException.ThrowIfNull(target);
        token.ThrowIfCancellationRequested();
        if (!LocalLanDiscovery.PlanProbeTargets(new[] { adapter }).Contains(target))
            throw new ArgumentException("Agent must be another host in the selected local IPv4 scope.", nameof(target));
        ValidateCredentials(user, auth, privacy);
        return CheckEndpointAsync(adapter.Address, target, user, auth, privacy, Timeout, token);
    }

    internal static List<Variable> BuildVariables() => Oids.Select(oid => new Variable(new ObjectIdentifier(oid))).ToList();

    internal static bool TryProject(IList<Variable> variables, out SnmpInfrastructureEvidence? evidence)
    {
        evidence = null;
        if (variables.Count != Oids.Length) return false;
        for (int i = 0; i < Oids.Length; i++)
            if (variables[i].Id.ToString() != Oids[i]) return false;
        string? Text(int i) => variables[i].Data is OctetString s && s.GetRaw().Length <= 1024
            ? new string(s.ToString().Where(c => !char.IsControl(c)).ToArray()) : null;
        var obj = variables[1].Data is ObjectIdentifier oid ? oid.ToString() : null;
        uint? uptime = variables[2].Data is TimeTicks ticks ? ticks.ToUInt32() : null;
        int? interfaces = variables[4].Data is Integer32 count && count.ToInt32() >= 0 ? count.ToInt32() : null;
        evidence = new(Text(0), obj, uptime, Text(3), interfaces);
        return true;
    }

    // The discovery report is unauthenticated and is used only to construct the
    // subsequent USM request. It never supplies device identity evidence.
    internal static bool ValidDiscovery(ISnmpMessage message, int messageId, int requestId) =>
        message.Version == VersionCode.V3 && message.TypeCode() == SnmpType.ReportPdu &&
        message.MessageId() == messageId && message.RequestId() == requestId &&
        (int)message.Header.SecurityLevel == 0 && !message.Parameters.IsInvalid &&
        message.Parameters.EngineId?.GetRaw().Length is >= 5 and <= 32 &&
        message.Parameters.EngineBoots?.ToInt32() is >= 0 and < int.MaxValue &&
        message.Parameters.EngineTime?.ToInt32() is >= 0 &&
        message.Parameters.UserName.Equals(OctetString.Empty) &&
        (message.Parameters.AuthenticationParameters?.GetRaw().Length ?? 0) == 0 &&
        (message.Parameters.PrivacyParameters?.GetRaw().Length ?? 0) == 0 &&
        (Equals(message.Scope.ContextEngineId, OctetString.Empty) ||
            Equals(message.Scope.ContextEngineId, message.Parameters.EngineId)) &&
        message.Pdu().ErrorStatus.ToInt32() == 0 && message.Pdu().ErrorIndex.ToInt32() == 0 &&
        message.Pdu().Variables.Count == 1 &&
        message.Pdu().Variables[0].Id.ToString() == "1.3.6.1.6.3.15.1.1.4.0" &&
        message.Pdu().Variables[0].Data is Counter32;

    internal static bool ValidResponse(ISnmpMessage response, ISnmpMessage request, bool encryptedScope)
    {
        var p = response.Parameters;
        var q = request.Parameters;
        return encryptedScope && response.Version == VersionCode.V3 && response.TypeCode() == SnmpType.ResponsePdu &&
            response.MessageId() == request.MessageId() && response.RequestId() == request.RequestId() &&
            (int)response.Header.SecurityLevel == 3 && !p.IsInvalid &&
            p.AuthenticationParameters?.GetRaw().Length == 24 && p.PrivacyParameters?.GetRaw().Length == 8 &&
            p.EngineId is not null && p.EngineId.Equals(q.EngineId) &&
            p.UserName is not null && p.UserName.Equals(q.UserName) &&
            p.EngineBoots is not null && q.EngineBoots is not null &&
            p.EngineBoots.ToInt32() == q.EngineBoots.ToInt32() && p.EngineBoots.ToInt32() < int.MaxValue &&
            p.EngineTime is not null && q.EngineTime is not null &&
            p.EngineTime.ToInt32() >= 0 && Math.Abs((long)p.EngineTime.ToInt32() - q.EngineTime.ToInt32()) <= 150 &&
            Equals(response.Scope.ContextEngineId, request.Scope.ContextEngineId) &&
            Equals(response.Scope.ContextName, request.Scope.ContextName);
    }

    // Enforce actual USM wire shape before library decoding: an authPriv flag
    // alone is not evidence that the scoped PDU is encrypted.
    internal static bool TryReadEnvelope(ReadOnlyMemory<byte> bytes, out bool encrypted)
    {
        encrypted = false;
        try
        {
            var root = new AsnReader(bytes, AsnEncodingRules.BER);
            var message = root.ReadSequence();
            if (message.ReadInteger() != 3) return false;
            var header = message.ReadSequence();
            header.ReadInteger(); header.ReadInteger();
            var flags = header.ReadOctetString();
            if (flags.Length != 1 || (flags[0] & ~7) != 0 || header.ReadInteger() != 3) return false;
            header.ThrowIfNotEmpty();
            message.ReadOctetString(); // USM security parameters, parsed by library
            var tag = message.PeekTag();
            encrypted = tag.HasSameClassAndValue(Asn1Tag.PrimitiveOctetString) && !tag.IsConstructed;
            if (encrypted) message.ReadOctetString();
            else if (tag.HasSameClassAndValue(Asn1Tag.Sequence)) message.ReadEncodedValue();
            else return false;
            if (encrypted != ((flags[0] & 2) != 0)) return false;
            message.ThrowIfNotEmpty();
            root.ThrowIfNotEmpty();
            return true;
        }
        catch (AsnContentException) { return false; }
    }

    private static async Task<(ISnmpMessage? Message, bool Encrypted)> ExchangeAsync(Socket socket, byte[] bytes, UserRegistry users,
        CancellationToken token)
    {
        await socket.SendAsync(bytes.AsMemory(), SocketFlags.None, token).ConfigureAwait(false);
        var buffer = new byte[MaxDatagram + 1];
        int length = await socket.ReceiveAsync(buffer.AsMemory(), SocketFlags.None, token).ConfigureAwait(false);
        if (length <= 0 || length > MaxDatagram || !TryReadEnvelope(buffer.AsMemory(0, length), out var encrypted)) return (null, false);
        var messages = MessageFactory.ParseMessages(buffer, 0, length, users);
        return (messages.Count == 1 ? messages[0] : null, encrypted);
    }

    internal static async Task<SnmpInfrastructureObservation> CheckEndpointAsync(IPAddress source, IPAddress target,
        string user, string auth, string privacy, TimeSpan timeout, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(token);
        budget.CancelAfter(timeout);
        var watch = Stopwatch.StartNew();
        SnmpInfrastructureObservation Result(SnmpInfrastructureStatus status, SnmpInfrastructureEvidence? evidence = null) =>
            new(source, target, status, evidence, DateTimeOffset.UtcNow, watch.Elapsed);
        try
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.Bind(new IPEndPoint(source, 0));
            await socket.ConnectAsync(new IPEndPoint(target, 161), budget.Token).ConfigureAwait(false);
            int discoveryMessage = RandomNumberGenerator.GetInt32(1, int.MaxValue);
            int discoveryRequest = RandomNumberGenerator.GetInt32(1, int.MaxValue);
            var discovery = new Discovery(discoveryMessage, discoveryRequest, MaxDatagram);
            var (report, discoveryEncrypted) = await ExchangeAsync(socket, discovery.ToBytes(), new UserRegistry(), budget.Token).ConfigureAwait(false);
            if (discoveryEncrypted || report is null || !ValidDiscovery(report, discoveryMessage, discoveryRequest))
                return Result(SnmpInfrastructureStatus.InvalidResponse);
            budget.Token.ThrowIfCancellationRequested();
            var username = new OctetString(user);
            var provider = new AESPrivacyProvider(new OctetString(privacy), new SHA256AuthenticationProvider(new OctetString(auth)));
            var users = new UserRegistry();
            users.Add(username, provider);
            var request = new GetRequestMessage(VersionCode.V3, RandomNumberGenerator.GetInt32(1, int.MaxValue),
                RandomNumberGenerator.GetInt32(1, int.MaxValue), username, OctetString.Empty,
                BuildVariables(), provider, MaxDatagram, report);
            var (response, encryptedScope) = await ExchangeAsync(socket, request.ToBytes(), users, budget.Token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            if (budget.IsCancellationRequested) return Result(SnmpInfrastructureStatus.TimedOut);
            if (response is null) return Result(SnmpInfrastructureStatus.InvalidResponse);
            // Reports (including wrong credentials/time-window) are not authenticated inventory.
            if (response.TypeCode() == SnmpType.ReportPdu)
                return Result(SnmpInfrastructureStatus.AgentReport);
            if (!ValidResponse(response, request, encryptedScope)) return Result(SnmpInfrastructureStatus.InvalidResponse);
            if (response.Pdu().ErrorStatus.ToInt32() != 0) return Result(SnmpInfrastructureStatus.AgentError);
            if (!TryProject(response.Pdu().Variables, out var evidence) || evidence is null)
                return Result(SnmpInfrastructureStatus.InvalidResponse);
            bool complete = evidence.Description is not null && evidence.ObjectId is not null &&
                evidence.UptimeCentiseconds.HasValue && evidence.Name is not null && evidence.InterfaceCount.HasValue;
            return Result(complete ? SnmpInfrastructureStatus.Observed : SnmpInfrastructureStatus.Partial, evidence);
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested && budget.IsCancellationRequested)
        { return Result(SnmpInfrastructureStatus.TimedOut); }
        catch (SocketException)
        {
            token.ThrowIfCancellationRequested();
            return Result(budget.IsCancellationRequested ? SnmpInfrastructureStatus.TimedOut : SnmpInfrastructureStatus.TransportError);
        }
        catch (Exception ex) when (ex is not OperationCanceledException && ex is not OutOfMemoryException)
        {
            // Third-party ASN.1/USM parser and crypto exceptions must not leak credentials or packet text.
            token.ThrowIfCancellationRequested();
            return Result(budget.IsCancellationRequested ? SnmpInfrastructureStatus.TimedOut : SnmpInfrastructureStatus.InvalidResponse);
        }
    }
}
