// File: Services/DotEnv.cs
// SPDX-License-Identifier: MIT

using System;
using System.IO;

namespace Carthago.Services
{
    /// <summary>
    /// Minimal .env loader for desktop apps.
    /// Walks parent folders from the current base directory,
    /// finds the first ".env", parses KEY=VALUE, and sets environment variables if not already set.
    /// </summary>
    public static class DotEnv
    {
        public static void Load(string? startDirectory = null, string fileName = ".env")
        {
            var dir = new DirectoryInfo(startDirectory ?? AppContext.BaseDirectory);
            while (dir != null)
            {
                var path = Path.Combine(dir.FullName, fileName);
                if (File.Exists(path))
                {
                    LoadFile(path);
                    return;
                }
                dir = dir.Parent;
            }
        }

        private static void LoadFile(string path)
        {
            foreach (var raw in File.ReadAllLines(path))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("#")) continue;

                var hash = line.IndexOf('#');
                if (hash >= 0) line = line[..hash].Trim();
                if (line.Length == 0) continue;

                var eq = line.IndexOf('=');
                if (eq <= 0) continue;

                var key = line[..eq].Trim();
                var value = line[(eq + 1)..].Trim();

                if ((value.StartsWith('"') && value.EndsWith('"')) ||
                    (value.StartsWith('\'') && value.EndsWith('\'')))
                {
                    value = value[1..^1];
                }

                value = value.Replace("\\n", "\n").Replace("\\r", "\r").Replace("\\t", "\t");

                if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable(key)))
                {
                    Environment.SetEnvironmentVariable(key, value);
                }
            }
        }
    }
}
