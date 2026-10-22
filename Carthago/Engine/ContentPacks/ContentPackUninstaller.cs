// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/ContentPackUninstaller.cs
using System;
using System.Linq;

namespace Carthago.Engine.ContentPacks
{
    public sealed class ContentPackUninstaller
    {
        private readonly ContentPackRegistry _registry;

        public ContentPackUninstaller(ContentPackRegistry? registry = null)
            => _registry = registry ?? new ContentPackRegistry();

        public ContentPackInstallResult Uninstall(string packId)
        {
            var state = _registry.LoadState();
            var installed = state.InstalledPacks.FirstOrDefault(item => string.Equals(item.PackId, packId, StringComparison.OrdinalIgnoreCase));
            if (installed == null)
            {
                return new ContentPackInstallResult
                {
                    PackId = packId,
                    Errors = { $"Pack {packId} is not installed." }
                };
            }

            state.InstalledPacks.Remove(installed);
            _registry.Store.Save(state);
            _registry.Store.DeleteManifest(packId);

            return new ContentPackInstallResult
            {
                PackId = packId,
                Version = installed.Version,
                Plan = new ContentPackInstallPlan
                {
                    PackId = packId,
                    Version = installed.Version,
                    DryRun = false,
                    PlannedChanges =
                    {
                        "Removed pack installation metadata and compiled-rule registrations.",
                        "Preserved historical detections, journals, evidence bundles, incidents, and feedback."
                    }
                },
                Warnings =
                {
                    "Historical incidents may continue to reference this pack's rule IDs.",
                    "Journaled detections and analyst feedback were intentionally preserved."
                }
            };
        }
    }
}
