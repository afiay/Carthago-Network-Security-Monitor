// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/Packs/ContentPackPackCatalog.cs
using System.Collections.Generic;

namespace Carthago.Engine.ContentPacks.Packs
{
    internal static class ContentPackPackCatalog
    {
        public static IReadOnlyList<IContentPackProvider> CreateProviders()
            => new IContentPackProvider[]
            {
                new CloudSaasPackProvider(),
                new ActiveDirectoryPackProvider(),
                new KubernetesPackProvider(),
                new Microsoft365PackProvider(),
                new DevOpsPackProvider(),
                new IoTHomePackProvider(),
                new OTIndustrialPackProvider(),
                new MalwareC2PackProvider(),
                new ExfiltrationPackProvider()
            };
    }
}
