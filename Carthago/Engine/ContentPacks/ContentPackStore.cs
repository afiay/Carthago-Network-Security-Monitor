// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/ContentPackStore.cs
using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Carthago.Engine.ContentPacks
{
    public sealed class ContentPackStore
    {
        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            WriteIndented = true,
            PropertyNameCaseInsensitive = true,
            Converters = { new JsonStringEnumConverter() }
        };

        public ContentPackStore(string? rootDirectory = null)
        {
            RootDirectory = string.IsNullOrWhiteSpace(rootDirectory)
                ? ContentPackConstants.DefaultRootDirectory
                : rootDirectory!;
        }

        public string RootDirectory { get; }
        public string StatePath => Path.Combine(RootDirectory, "content-pack-state.json");
        public string ManifestDirectory => Path.Combine(RootDirectory, "manifests");

        public ContentPackInstallState Load()
        {
            EnsureDirectories();
            if (!File.Exists(StatePath))
                return new ContentPackInstallState();

            try
            {
                using var stream = File.Open(StatePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                return JsonSerializer.Deserialize<ContentPackInstallState>(stream, JsonOptions) ?? new ContentPackInstallState();
            }
            catch (JsonException)
            {
                return new ContentPackInstallState();
            }
            catch (IOException)
            {
                return new ContentPackInstallState();
            }
        }

        public void Save(ContentPackInstallState state)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            EnsureDirectories();
            File.WriteAllText(StatePath, JsonSerializer.Serialize(state, JsonOptions));
        }

        public void SaveManifest(ContentPackManifest manifest)
        {
            if (manifest == null) throw new ArgumentNullException(nameof(manifest));
            EnsureDirectories();
            File.WriteAllText(GetManifestPath(manifest.PackId), JsonSerializer.Serialize(manifest, JsonOptions));
        }

        public ContentPackManifest? LoadManifest(string packId)
        {
            EnsureDirectories();
            var path = GetManifestPath(packId);
            if (!File.Exists(path))
                return null;

            try
            {
                using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                return JsonSerializer.Deserialize<ContentPackManifest>(stream, JsonOptions);
            }
            catch (JsonException)
            {
                return null;
            }
            catch (IOException)
            {
                return null;
            }
        }

        public void DeleteManifest(string packId)
        {
            var path = GetManifestPath(packId);
            if (File.Exists(path))
                File.Delete(path);
        }

        public string GetManifestPath(string packId)
            => Path.Combine(ManifestDirectory, SanitizeFileName(packId) + ".json");

        private void EnsureDirectories()
        {
            Directory.CreateDirectory(RootDirectory);
            Directory.CreateDirectory(ManifestDirectory);
        }

        private static string SanitizeFileName(string value)
        {
            var safe = value ?? string.Empty;
            foreach (var ch in Path.GetInvalidFileNameChars())
                safe = safe.Replace(ch, '-');
            return safe.Replace('.', '-');
        }
    }
}
