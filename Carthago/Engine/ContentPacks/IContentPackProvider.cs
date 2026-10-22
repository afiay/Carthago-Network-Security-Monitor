// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/IContentPackProvider.cs
using System.Collections.Generic;

namespace Carthago.Engine.ContentPacks
{
    public interface IContentPackProvider
    {
        ContentPackManifest Manifest { get; }
        IReadOnlyList<ContentPackRuleRegistration> GetRuleRegistrations();
    }
}
