// SPDX-License-Identifier: MIT
// File: Services/Cisco/ISnmpClientAdapter.cs
using System.Collections.Generic;

namespace Carthago.Services.Cisco
{
    public sealed record SnmpWalkVariable(
        string Oid,
        string? ValueText,
        byte[]? OctetStringBytes = null);

    public interface ISnmpClientAdapter
    {
        IReadOnlyList<SnmpWalkVariable> Walk(
            string host,
            int port,
            string community,
            string rootOid,
            int timeoutMilliseconds = 3000,
            int retries = 1,
            int maxRepetitions = 25);
    }
}
