// SPDX-License-Identifier: MIT
// File: Engine/PayloadNormalization/NormalizedPayload.cs
using System.Collections.Generic;

namespace Carthago.Engine.PayloadNormalization
{
    public sealed record NormalizedPayload(
        string Original,
        string Normalized,
        string LowerInvariant,
        IReadOnlyDictionary<string, string> SourceFragments);
}
