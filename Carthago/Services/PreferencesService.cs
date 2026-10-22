// SPDX-License-Identifier: MIT
// File: Services/PreferencesService.cs
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using Carthago.Models;

namespace Carthago.Services
{
    /// <summary>
    /// App-wide preferences (now full-object + versioning).
    /// - File: %APPDATA%\Carthago\preferences.json (atomic save, hot-reload)
    /// - Overrides: CLI: --sensitivity=Aggressive or -s Aggressive
    ///              ENV: CARTHAGO_SENSITIVITY
    /// - Events: PreferencesChanged (full object) and SensitivityChanged (compat)
    /// - Backward compatible with older { Sensitivity, Version, UpdatedUtc } layout
    /// </summary>
    public static class PreferencesService
    {
        private const string AppFolderName = "Carthago";
        private const string FileName = "preferences.json";
        private const string EnvVar = "CARTHAGO_SENSITIVITY";

        // ---- state ----
        private static readonly object _lock = new();
        private static FileSystemWatcher? _watcher;
        private static DateTime _lastWriteUtc;      // debounce FS events
        private static string? _filePathOverride;

        // Full current preferences (disk + optional overrides layered)
        private static AppPreferences _current = new();

        // Override state (CLI/ENV)
        private static volatile bool _overrideSensitivityActive;
        private static Sensitivity _overrideSensitivity = Sensitivity.Balanced;

        // JSON options (stable casing; keep file human-friendly)
        private static readonly JsonSerializerOptions _json = new()
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            PropertyNamingPolicy = null // keep PascalCase for back-compat readability
        };

        /// <summary>Full, effective preferences object (read-only snapshot).</summary>
        public static AppPreferences Current
        {
            get
            {
                lock (_lock)
                {
                    // Present a defensive copy so callers can’t mutate in place
                    return CreateEffectiveSnapshotLocked();
                }
            }
        }

        /// <summary>
        /// Effective sensitivity (applies CLI/ENV override if present).
        /// Backward-compatible property consumed by RuleEngine, etc.
        /// </summary>
        public static Sensitivity Sensitivity
        {
            get
            {
                if (_overrideSensitivityActive) return _overrideSensitivity;
                lock (_lock) return _current.Sensitivity;
            }
        }

        /// <summary>Raised when any preferences change (file edit, Set/Update, or overrides).</summary>
        public static event Action<AppPreferences>? PreferencesChanged;

        /// <summary>Raised when effective Sensitivity changes (compat convenience).</summary>
        public static event Action<Sensitivity>? SensitivityChanged;

        /// <summary>
        /// Load preferences (priority: CLI &gt; ENV &gt; file).
        /// Installs the file watcher (hot reload) and emits change events.
        /// Safe to call multiple times.
        /// </summary>
        public static void Load()
        {
            lock (_lock)
            {
                // 1) CLI override wins
                if (TryGetCliOverride(out var cliSens))
                {
                    _overrideSensitivityActive = true;
                    _overrideSensitivity = cliSens;
                    // still load disk to populate other fields
                    _current = LoadFromDiskOrDefault();
                    EmitChanged();
                    EnsureWatcher();
                    return;
                }

                // 2) ENV override
                var envVal = Environment.GetEnvironmentVariable(EnvVar);
                if (SensitivityExtensions.TryParse(envVal, out var envSens))
                {
                    _overrideSensitivityActive = true;
                    _overrideSensitivity = envSens;
                    _current = LoadFromDiskOrDefault();
                    EmitChanged();
                    EnsureWatcher();
                    return;
                }

                // 3) disk only
                _overrideSensitivityActive = false;
                _current = LoadFromDiskOrDefault();
                EmitChanged();
                EnsureWatcher();
            }
        }

        /// <summary>
        /// Set sensitivity and persist to disk. Clears CLI/ENV override for the running session.
        /// </summary>
        public static void SetSensitivity(Sensitivity s)
        {
            lock (_lock)
            {
                var before = Sensitivity;
                _overrideSensitivityActive = false; // explicit user choice takes precedence
                _current.Sensitivity = s;
                _current.UpdatedUtc = DateTime.UtcNow;
                SaveInternal(_current);
                if (before != Sensitivity) EmitChanged();
            }
        }

        /// <summary>
        /// Update multiple preferences atomically and persist (lambda receives a mutable copy).
        /// Clears CLI/ENV sensitivity override only if you change Sensitivity explicitly.
        /// </summary>
        public static void Update(Action<AppPreferences> mutate)
        {
            if (mutate is null) return;

            lock (_lock)
            {
                var oldEffectiveSensitivity = GetEffectiveSensitivityLocked();
                var previousStoredSensitivity = _current.Sensitivity;

                // Work on a copy of the persisted state so unrelated settings survive updates.
                var next = _current.Clone();
                mutate(next);

                // If sensitivity changed explicitly, drop runtime override
                if (next.Sensitivity != previousStoredSensitivity)
                    _overrideSensitivityActive = false;

                NormalizePreferences(next);
                _current = next;
                _current.UpdatedUtc = DateTime.UtcNow;
                SaveInternal(_current);

                // fire changes if effective sensitivity or any field meaningfully changed
                EmitChanged(oldEffectiveSensitivity);
            }
        }

        /// <summary>Reset preferences to sane defaults and persist.</summary>
        public static void Reset()
        {
            lock (_lock)
            {
                var oldEffectiveSensitivity = GetEffectiveSensitivityLocked();
                _overrideSensitivityActive = false;
                _current = new AppPreferences { UpdatedUtc = DateTime.UtcNow };
                SaveInternal(_current);
                EmitChanged(oldEffectiveSensitivity);
            }
        }

        /// <summary>Return the full path to preferences.json.</summary>
        public static string GetFilePath()
        {
            if (!string.IsNullOrWhiteSpace(_filePathOverride))
                return _filePathOverride!;

            var dir = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            if (!string.IsNullOrWhiteSpace(dir))
                return Path.Combine(dir, AppFolderName, FileName);
            return Path.Combine(AppContext.BaseDirectory, FileName);
        }

        /// <summary>Return the directory that contains preferences.json.</summary>
        public static string GetDirectoryPath() => Path.GetDirectoryName(GetFilePath())!;

        public static void SetFilePathOverride(string? path)
        {
            lock (_lock)
            {
                _filePathOverride = string.IsNullOrWhiteSpace(path) ? null : path;
                _watcher?.Dispose();
                _watcher = null;
            }
        }

        /// <summary>Export a snapshot to a custom path (e.g., for support bundles).</summary>
        public static void Export(string destinationPath)
        {
            if (string.IsNullOrWhiteSpace(destinationPath)) return;
            var json = JsonSerializer.Serialize(Current, _json);
            Directory.CreateDirectory(Path.GetDirectoryName(destinationPath)!);
            File.WriteAllText(destinationPath, json);
        }

        // =================================================================
        // internals
        // =================================================================

        private static bool TryGetCliOverride(out Sensitivity s)
        {
            try
            {
                string[] args = Environment.GetCommandLineArgs();
                for (int i = 0; i < args.Length; i++)
                {
                    var a = args[i] ?? string.Empty;

                    if (a.StartsWith("--sensitivity=", StringComparison.OrdinalIgnoreCase))
                    {
                        var val = a[(a.IndexOf('=') + 1)..]; // <-- fix: range operator
                        return SensitivityExtensions.TryParse(val, out s);
                    }

                    if ((a.Equals("-s", StringComparison.OrdinalIgnoreCase) ||
                         a.Equals("--sensitivity", StringComparison.OrdinalIgnoreCase)) &&
                        i + 1 < args.Length &&
                        SensitivityExtensions.TryParse(args[i + 1], out s))
                    {
                        return true;
                    }
                }
            }
            catch { /* ignore */ }

            s = Sensitivity.Balanced;
            return false;
        }

        private static AppPreferences LoadFromDiskOrDefault()
        {
            try
            {
                var path = GetFilePath();
                if (!File.Exists(path))
                {
                    var def = new AppPreferences(); // defaults
                    SaveInternal(def);              // create file on first run
                    return def;
                }

                // Tolerate transient locks by opening shared
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                var json = sr.ReadToEnd();

                // Try v2 (AppPreferences) first
                var prefs = JsonSerializer.Deserialize<AppPreferences>(json, _json);
                if (prefs is not null)
                {
                    NormalizePreferences(prefs);
                    _lastWriteUtc = File.GetLastWriteTimeUtc(path);
                    return prefs;
                }

                // Fallback: legacy DTO { Sensitivity, Version, UpdatedUtc }
                var legacy = JsonSerializer.Deserialize<LegacyPrefs>(json, _json) ?? new LegacyPrefs();
                var migrated = new AppPreferences
                {
                    Sensitivity = TryParseWithFallback(legacy.Sensitivity, Sensitivity.Balanced),
                    UpdatedUtc = legacy.UpdatedUtc == default ? DateTime.UtcNow : legacy.UpdatedUtc
                };
                NormalizePreferences(migrated);
                _lastWriteUtc = File.GetLastWriteTimeUtc(path);
                // Write back in new shape so we stop hitting the legacy path
                SaveInternal(migrated);
                return migrated;
            }
            catch (Exception ex)
            {
                // Return safe defaults if file is corrupt/inaccessible
                Console.Error.WriteLine($"[Preferences] Load failed: {ex.Message}");
                return new AppPreferences();
            }
        }

        private static Sensitivity TryParseWithFallback(string? s, Sensitivity fallback)
            => SensitivityExtensions.TryParse(s, out var parsed) ? parsed : fallback;

        private static void SaveInternal(AppPreferences prefs)
        {
            try
            {
                NormalizePreferences(prefs);
                var path = GetFilePath();
                var dir = Path.GetDirectoryName(path)!;
                Directory.CreateDirectory(dir);

                var json = JsonSerializer.Serialize(prefs, _json);

                // Atomic-ish save: write temp then move
                var tmp = path + ".tmp";
                File.WriteAllText(tmp, json);

#if NET8_0_OR_GREATER
                File.Move(tmp, path, overwrite: true);
#else
                if (File.Exists(path)) File.Delete(path);
                File.Move(tmp, path);
#endif
                if (File.Exists(tmp)) { try { File.Delete(tmp); } catch { /* ignore */ } }

                _lastWriteUtc = File.GetLastWriteTimeUtc(path);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[Preferences] Save failed: {ex.Message}");
            }
        }

        private static void EnsureWatcher()
        {
            try
            {
                var path = GetFilePath();
                var dir = Path.GetDirectoryName(path)!;
                var file = Path.GetFileName(path);

                _watcher ??= new FileSystemWatcher(dir)
                {
                    Filter = file,
                    NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.FileName | NotifyFilters.CreationTime,
                    IncludeSubdirectories = false,
                    EnableRaisingEvents = true
                };

                // Deduplicate handlers if Load() is called again
                _watcher.Changed -= OnPrefsFileChanged;
                _watcher.Created -= OnPrefsFileChanged;
                _watcher.Renamed -= OnPrefsFileChanged;

                _watcher.Changed += OnPrefsFileChanged;
                _watcher.Created += OnPrefsFileChanged;
                _watcher.Renamed += OnPrefsFileChanged;
            }
            catch
            {
                // Non-fatal
            }
        }

        private static void OnPrefsFileChanged(object? sender, FileSystemEventArgs e)
        {
            // Ignore disk edits if runtime override is in effect; user asked for that precedence.
            // However, we still reload the *other* fields for display accuracy.
            var overrideWasActive = _overrideSensitivityActive;

            // Debounce bursty events (and ignore our own writes right away)
            var now = DateTime.UtcNow;
            if ((now - _lastWriteUtc).TotalMilliseconds < 150) return;

            for (int attempt = 0; attempt < 3; attempt++)
            {
                try
                {
                    var loaded = LoadFromDiskOrDefault();
                    lock (_lock)
                    {
                        // Preserve the override relationship
                        var oldEffectiveSensitivity = Sensitivity;
                        _current = loaded;
                        if (overrideWasActive) _overrideSensitivityActive = true;
                        EmitChanged(oldEffectiveSensitivity);
                    }
                    break;
                }
                catch
                {
                    Thread.Sleep(80);
                }
            }
        }

        /// <summary>
        /// Emit change events in correct order and only when effective sensitivity changed.
        /// </summary>
        private static void EmitChanged(Sensitivity? previousEffective = null)
        {
            AppPreferences snapshot;
            Sensitivity eff;
            lock (_lock)
            {
                snapshot = CreateEffectiveSnapshotLocked();
                eff = snapshot.Sensitivity;
            }

            try
            {
                PreferencesChanged?.Invoke(snapshot);
            }
            catch { /* ignore listeners */ }

            if (previousEffective is null || previousEffective.Value != eff)
            {
                try { SensitivityChanged?.Invoke(eff); } catch { /* ignore listeners */ }
            }
        }

        // legacy DTO (for migration)
        private sealed class LegacyPrefs
        {
            public int Version { get; set; } = 1;
            public string? Sensitivity { get; set; } = nameof(Models.Sensitivity.Balanced);
            public DateTime UpdatedUtc { get; set; } = DateTime.UtcNow;
        }

        private static AppPreferences CreateEffectiveSnapshotLocked()
        {
            var snapshot = _current.Clone();
            snapshot.Sensitivity = GetEffectiveSensitivityLocked();
            return snapshot;
        }

        private static Sensitivity GetEffectiveSensitivityLocked()
            => _overrideSensitivityActive ? _overrideSensitivity : _current.Sensitivity;

        private static void NormalizePreferences(AppPreferences prefs)
        {
            if (prefs.Version <= 0)
                prefs.Version = new AppPreferences().Version;

            prefs.BlockedCountries ??= new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (!ReferenceEquals(prefs.BlockedCountries.Comparer, StringComparer.OrdinalIgnoreCase))
                prefs.BlockedCountries = new HashSet<string>(prefs.BlockedCountries, StringComparer.OrdinalIgnoreCase);

            prefs.Dashboard ??= new DashboardPreferences();
            prefs.Dashboard.Normalize();
        }
    }
}
