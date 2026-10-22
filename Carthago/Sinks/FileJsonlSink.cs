// SPDX-License-Identifier: MIT
// File: Sinks/FileJsonlSink.cs
using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using Carthago.Models;

namespace Carthago.Sinks
{
    /// <summary>
    /// Durable JSON Lines sink. Writes one JSON event per line.
    /// - Creates today's file immediately on initialization
    /// - Daily roll (optional)
    /// - Size-based roll with compression of rolled files (optional)
    /// - Falls back to %LOCALAPPDATA% if %PROGRAMDATA% is not writable
    /// - Synchronous writes inside SinkManager worker thread for backpressure safety
    /// </summary>
    public sealed class FileJsonlSink : IDetectionSink
    {
        private string _baseDir;
        private readonly long _maxBytes;
        private readonly bool _rollDaily;
        private readonly bool _compressOnRotate;

        private readonly object _gate = new();
        private readonly JsonSerializerOptions _json = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = false,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
        };

        private DateTime _currentDateUtc = DateTime.MinValue;
        private string? _currentPath;
        private FileStream? _stream;
        private StreamWriter? _writer;
        private long _written;

        public FileJsonlSink(
            string? directory = null,
            int maxSizeMB = 100,
            bool rollDaily = true,
            bool compressOnRotate = true)
        {
            // Prefer ProgramData for shared agents; fall back to LocalAppData if not writable.
            _baseDir = directory ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Carthago", "detections");

            if (!TryEnsureDirectory(_baseDir))
            {
                // Fallback to LOCALAPPDATA (user-writable)
                _baseDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Carthago", "detections");
                TryEnsureDirectory(_baseDir); // last-ditch; if this fails, we will throw later on open
            }

            _maxBytes = Math.Max(1, maxSizeMB) * 1024L * 1024L;
            _rollDaily = rollDaily;
            _compressOnRotate = compressOnRotate;

            // Create/open today's file immediately so users see the file after enabling the sink.
            lock (_gate)
            {
                EnsureFileLocked();
            }
        }

        public void Dispose()
        {
            lock (_gate)
            {
                try { _writer?.Flush(); } catch { }
                try { _writer?.Dispose(); } catch { }
                try { _stream?.Dispose(); } catch { }
                _writer = null;
                _stream = null;
                _currentPath = null;
            }
        }

        public System.Threading.Tasks.Task EmitAsync(DetectionEvent evt, System.Threading.CancellationToken ct = default)
        {
            var line = JsonSerializer.Serialize(evt, _json) + "\n";
            var bytes = Encoding.UTF8.GetByteCount(line);

            lock (_gate)
            {
                EnsureFileLocked();
                if (_written + bytes > _maxBytes)
                {
                    RotateLocked(); // size-based
                    EnsureFileLocked();
                }

                _writer!.Write(line);
                _written += bytes;
            }

            return System.Threading.Tasks.Task.CompletedTask;
        }

        // ===== internals =====

        private static bool TryEnsureDirectory(string path)
        {
            try
            {
                Directory.CreateDirectory(path);
                // quick write test to catch brittle ACLs
                var probe = Path.Combine(path, ".write_test");
                File.WriteAllText(probe, "ok");
                File.Delete(probe);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private void EnsureFileLocked()
        {
            var today = DateTime.UtcNow.Date;

            if (_writer == null || _stream == null || _currentPath == null)
            {
                OpenNewLocked(today);
                return;
            }

            if (_rollDaily && today != _currentDateUtc.Date)
            {
                RotateLocked(); // day changed
                OpenNewLocked(today);
            }
        }

        private void OpenNewLocked(DateTime dateUtc)
        {
            _currentDateUtc = dateUtc;
            var baseName = $"detections_{dateUtc:yyyy-MM-dd}.jsonl";
            var path = Path.Combine(_baseDir, baseName);

            // Open append to keep a single current file per day.
            _stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read);
            _writer = new StreamWriter(_stream, new UTF8Encoding(false)) { AutoFlush = false };
            _currentPath = path;
            _written = _stream.Length;
        }

        private void RotateLocked()
        {
            if (_writer == null || _stream == null || _currentPath == null)
                return;

            try { _writer.Flush(); } catch { }
            try { _writer.Dispose(); } catch { }
            try { _stream.Dispose(); } catch { }

            // Create an archived name with timestamp to avoid collisions
            var ts = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
            var dir = Path.GetDirectoryName(_currentPath)!;
            var name = Path.GetFileNameWithoutExtension(_currentPath);
            var ext = Path.GetExtension(_currentPath);
            var archived = Path.Combine(dir, $"{name}.{ts}{ext}");

            try
            {
                File.Move(_currentPath, archived, overwrite: false);
                if (_compressOnRotate)
                {
                    CompressGzip(archived);
                }
            }
            catch
            {
                // If move fails, keep writing to current to avoid data loss; try a new file next time.
            }

            _writer = null;
            _stream = null;
            _currentPath = null;
            _written = 0;
        }

        private static void CompressGzip(string path)
        {
            try
            {
                var gz = path + ".gz";
                using (var src = File.OpenRead(path))
                using (var dst = File.Create(gz))
                using (var gzOut = new GZipStream(dst, CompressionLevel.Optimal, leaveOpen: false))
                {
                    src.CopyTo(gzOut);
                }
                File.Delete(path);
            }
            catch
            {
                // Best-effort compression; if it fails, keep original file.
            }
        }
    }
}
