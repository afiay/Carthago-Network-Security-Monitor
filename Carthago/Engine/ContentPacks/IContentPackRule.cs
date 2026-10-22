// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/IContentPackRule.cs
using Carthago.Engine.Rules;

namespace Carthago.Engine.ContentPacks
{
    public interface IContentPackRule : IDetectionRule
    {
        string PackId { get; }
        string SourceRuleId { get; }
        bool Deprecated { get; }
    }
}
