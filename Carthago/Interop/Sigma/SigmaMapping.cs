// SPDX-License-Identifier: MIT
// File: Interop/Sigma/SigmaMapping.cs
namespace Carthago.Interop.Sigma
{
    public static class SigmaMapping
    {
        public static string ToSigmaLevel(string severity) => severity.ToLowerInvariant();
    }
}
