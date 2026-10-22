// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/CompiledContentPackRegistry.cs
using System;
using System.Collections.Generic;
using System.Linq;

namespace Carthago.Engine.ContentPacks
{
    public sealed class CompiledContentPackRegistry
    {
        private readonly IReadOnlyList<IContentPackProvider> _providers;

        public CompiledContentPackRegistry(IEnumerable<IContentPackProvider>? providers = null)
        {
            _providers = (providers ?? Packs.ContentPackPackCatalog.CreateProviders())
                .OrderBy(static provider => provider.Manifest.PackId, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        public IReadOnlyList<IContentPackProvider> Providers => _providers;

        public IReadOnlyList<ContentPackManifest> GetAvailablePacks()
            => _providers.Select(static provider => provider.Manifest).ToArray();

        public IContentPackProvider? FindProvider(string packId)
            => _providers.FirstOrDefault(provider => string.Equals(provider.Manifest.PackId, packId, StringComparison.OrdinalIgnoreCase));

        public IReadOnlyList<ContentPackRuleRegistration> GetAllRuleRegistrations()
            => _providers.SelectMany(static provider => provider.GetRuleRegistrations())
                .OrderBy(static registration => registration.Rule.RuleId, StringComparer.OrdinalIgnoreCase)
                .ToArray();
    }
}
