// SPDX-License-Identifier: MIT
// File: Services/Cisco/SharpSnmpClientAdapter.cs
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Runtime.ExceptionServices;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using SnmpTimeoutException = Lextm.SharpSnmpLib.Messaging.TimeoutException;

namespace Carthago.Services.Cisco
{
    internal enum SnmpBulkRequestStatus
    {
        Success,
        TimedOut,
        Error
    }

    internal sealed record SnmpBulkRequestResult(
        SnmpBulkRequestStatus Status,
        IReadOnlyList<Variable> Variables,
        Exception? TimeoutException = null)
    {
        public static SnmpBulkRequestResult Success(params Variable[] variables)
            => new(SnmpBulkRequestStatus.Success, variables);

        public static SnmpBulkRequestResult TimedOut(Exception timeoutException)
            => new(
                SnmpBulkRequestStatus.TimedOut,
                Array.Empty<Variable>(),
                timeoutException ?? throw new ArgumentNullException(nameof(timeoutException)));

        public static SnmpBulkRequestResult Error()
            => new(SnmpBulkRequestStatus.Error, Array.Empty<Variable>());
    }

    internal interface ISnmpBulkRequestClient
    {
        SnmpBulkRequestResult GetNextPage(
            IPEndPoint endpoint,
            OctetString community,
            ObjectIdentifier seed,
            int timeoutMilliseconds,
            int maxRepetitions);
    }

    internal sealed class SharpSnmpBulkRequestClient : ISnmpBulkRequestClient
    {
        [RequiresUnreferencedCode("SharpSnmpLib synchronous responses are incompatible with trimming.")]
        public SnmpBulkRequestResult GetNextPage(
            IPEndPoint endpoint,
            OctetString community,
            ObjectIdentifier seed,
            int timeoutMilliseconds,
            int maxRepetitions)
        {
            var request = new GetBulkRequestMessage(
                Messenger.RequestCounter.NextId,
                VersionCode.V2,
                community,
                nonRepeaters: 0,
                maxRepetitions,
                new List<Variable> { new(seed) });

            try
            {
                var response = request.GetResponse(timeoutMilliseconds, endpoint);
                var pdu = response.Pdu();
                if (pdu.ErrorStatus.ToErrorCode() != ErrorCode.NoError)
                    return SnmpBulkRequestResult.Error();

                var variables = new Variable[pdu.Variables.Count];
                pdu.Variables.CopyTo(variables, 0);
                return SnmpBulkRequestResult.Success(variables);
            }
            catch (SnmpTimeoutException exception)
            {
                return SnmpBulkRequestResult.TimedOut(exception);
            }
        }
    }

    public sealed class SharpSnmpClientAdapter : ISnmpClientAdapter
    {
        private readonly ISnmpBulkRequestClient _requestClient;

        public SharpSnmpClientAdapter()
            : this(new SharpSnmpBulkRequestClient())
        {
        }

        internal SharpSnmpClientAdapter(ISnmpBulkRequestClient requestClient)
            => _requestClient = requestClient ?? throw new ArgumentNullException(nameof(requestClient));

        [RequiresUnreferencedCode("SharpSnmpLib synchronous responses are incompatible with trimming.")]
        public IReadOnlyList<SnmpWalkVariable> Walk(
            string host,
            int port,
            string community,
            string rootOid,
            int timeoutMilliseconds = 3000,
            int retries = 1,
            int maxRepetitions = 25)
        {
            if (!IPAddress.TryParse(host, out var agentAddress))
                throw new ArgumentException("SNMP host must be an IPv4 or IPv6 address for this adapter.", nameof(host));
            if (port is < 1 or > IPEndPoint.MaxPort)
                throw new ArgumentOutOfRangeException(nameof(port), port, "SNMP port must be between 1 and 65535.");
            if (string.IsNullOrWhiteSpace(community))
                throw new ArgumentException("SNMP community is required.", nameof(community));
            if (string.IsNullOrWhiteSpace(rootOid))
                throw new ArgumentException("SNMP root OID is required.", nameof(rootOid));
            if (timeoutMilliseconds <= 0)
                throw new ArgumentOutOfRangeException(nameof(timeoutMilliseconds), timeoutMilliseconds, "SNMP timeout must be positive.");
            if (retries < 0)
                throw new ArgumentOutOfRangeException(nameof(retries), retries, "SNMP retries cannot be negative.");
            if (maxRepetitions <= 0)
                throw new ArgumentOutOfRangeException(nameof(maxRepetitions), maxRepetitions, "SNMP max repetitions must be positive.");

            var endpoint = new IPEndPoint(agentAddress, port);
            var communityName = new OctetString(community);
            var root = new ObjectIdentifier(rootOid);
            var rootPrefix = root + ".";
            var seed = root;
            var results = new List<SnmpWalkVariable>();

            while (true)
            {
                var page = GetNextPageWithRetries(
                    endpoint,
                    communityName,
                    seed,
                    timeoutMilliseconds,
                    retries,
                    maxRepetitions);

                if (page.Status == SnmpBulkRequestStatus.Error || page.Variables.Count == 0)
                    return results;

                var seedText = seed.ToString();
                foreach (var variable in page.Variables)
                {
                    if (variable.Data.TypeCode == SnmpType.EndOfMibView)
                        return results;

                    var oidText = variable.Id.ToString();
                    if (!oidText.StartsWith(rootPrefix, StringComparison.Ordinal))
                        return results;
                    if (string.Equals(oidText, seedText, StringComparison.Ordinal))
                        return results;

                    results.Add(ConvertVariable(variable));
                }

                seed = page.Variables[^1].Id;
            }
        }

        private SnmpBulkRequestResult GetNextPageWithRetries(
            IPEndPoint endpoint,
            OctetString community,
            ObjectIdentifier seed,
            int timeoutMilliseconds,
            int retries,
            int maxRepetitions)
        {
            for (var attempt = 0; attempt <= retries; attempt++)
            {
                var page = _requestClient.GetNextPage(
                    endpoint,
                    community,
                    seed,
                    timeoutMilliseconds,
                    maxRepetitions);

                if (page.Status != SnmpBulkRequestStatus.TimedOut)
                    return page;

                if (attempt == retries)
                    ExceptionDispatchInfo.Capture(page.TimeoutException!).Throw();
            }

            throw new InvalidOperationException("SNMP retry loop terminated unexpectedly.");
        }

        internal static SnmpWalkVariable ConvertVariable(Variable variable)
        {
            ArgumentNullException.ThrowIfNull(variable);

            var octetStringBytes = variable.Data is OctetString octetString
                ? (byte[])octetString.GetRaw().Clone()
                : null;

            return new SnmpWalkVariable(
                variable.Id.ToString(),
                variable.Data.ToString(),
                octetStringBytes);
        }
    }
}
