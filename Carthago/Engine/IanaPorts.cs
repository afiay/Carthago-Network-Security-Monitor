// SPDX-License-Identifier: MIT
// File: Engine/IanaPorts.cs
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;

namespace Carthago.Services
{
    /// <summary>
    /// Minimal, dependency-free loader for the official IANA "service-names-port-numbers.csv".
    /// Tolerant to column order/names and port ranges (e.g., "17599-17609").
    /// </summary>
    public static class IanaPorts
    {
        private static readonly Dictionary<(int port, string proto), string> _byPortProto = new();
        private static readonly Dictionary<string, List<(int port, string proto)>> _byService = new(StringComparer.OrdinalIgnoreCase);
        private static bool _loaded;

        public static bool IsLoaded => _loaded;

        public static void Load(string csvPath)
        {
            if (!File.Exists(csvPath))
                throw new FileNotFoundException($"IANA CSV not found: {csvPath}");

            _byPortProto.Clear();
            _byService.Clear();

            using var sr = new StreamReader(csvPath);
            string? header = sr.ReadLine();
            if (header is null)
                throw new InvalidDataException("IANA CSV header missing");

            // Flexible header resolution
            var cols = header.Split(',').Select((h, i) => (h: h.Trim().ToLowerInvariant(), i)).ToArray();
            int idxService = Find(cols, "service name");
            int idxPort = Find(cols, "port number");
            int idxProto = Find(cols, "transport protocol");
            if (idxService < 0 || idxPort < 0 || idxProto < 0)
                throw new InvalidDataException("IANA CSV missing required columns (service name / port number / transport protocol)");

            string? line;
            while ((line = sr.ReadLine()) != null)
            {
                // very tolerant CSV split: only split on commas not inside double quotes
                var fields = SplitCsv(line);
                if (fields.Length <= Math.Max(idxProto, Math.Max(idxPort, idxService)))
                    continue;

                string name = (fields[idxService] ?? "").Trim();
                string portCell = (fields[idxPort] ?? "").Trim();
                string protoCell = (fields[idxProto] ?? "").Trim().ToLowerInvariant();

                if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(portCell) || string.IsNullOrEmpty(protoCell))
                    continue;

                // Normalize protocol
                if (protoCell is not ("tcp" or "udp" or "sctp" or "dccp"))
                    continue;

                foreach (var p in ExpandPorts(portCell))
                {
                    var key = (p, protoCell);
                    if (!_byPortProto.ContainsKey(key))
                        _byPortProto[key] = name;

                    if (!_byService.TryGetValue(name, out var list))
                    {
                        list = new List<(int, string)>();
                        _byService[name] = list;
                    }
                    list.Add((p, protoCell));
                }
            }

            _loaded = true;

            static int Find((string h, int i)[] cols, string needle)
                => Array.FindIndex(cols, c => c.h.Contains(needle, StringComparison.Ordinal));

            static IEnumerable<int> ExpandPorts(string cell)
            {
                // Cells are usually: "5353" or "17599-17609"
                cell = cell.Trim();
                if (cell.Length == 0) yield break;

                foreach (var token in cell.Split(new[] { ';', ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    var s = token.Trim().Trim('"');
                    if (s.Contains('-', StringComparison.Ordinal))
                    {
                        var parts = s.Split('-', 2);
                        if (int.TryParse(parts[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out int a) &&
                            int.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out int b) &&
                            a > 0 && b > 0 && b >= a && b <= 65535)
                        {
                            for (int x = a; x <= b; x++) yield return x;
                        }
                    }
                    else if (int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out int p) && p > 0 && p <= 65535)
                    {
                        yield return p;
                    }
                }
            }

            static string[] SplitCsv(string input)
            {
                var res = new List<string>(16);
                var cur = new System.Text.StringBuilder();
                bool inQ = false;

                for (int i = 0; i < input.Length; i++)
                {
                    char c = input[i];
                    if (c == '"')
                    {
                        if (inQ && i + 1 < input.Length && input[i + 1] == '"') { cur.Append('"'); i++; }
                        else inQ = !inQ;
                    }
                    else if (c == ',' && !inQ)
                    {
                        res.Add(cur.ToString());
                        cur.Clear();
                    }
                    else cur.Append(c);
                }
                res.Add(cur.ToString());
                return res.ToArray();
            }
        }

        public static string? ServiceNameFor(int port, string proto)
        {
            if (PortServiceResolver.TryGetServiceInfo(port, proto, out var info) &&
                !string.Equals(info.Source, "Heuristic", StringComparison.OrdinalIgnoreCase))
                return info.Name;

            proto = (proto ?? "tcp").Trim().ToLowerInvariant();
            return _byPortProto.TryGetValue((port, proto), out var name) ? name : null;
        }

        public static IEnumerable<int> PortsForService(string serviceName, params string[] protocols /* e.g. "udp","tcp" */)
        {
            var resolved = PortServiceResolver.GetPortsForService(serviceName);
            if (resolved.Count > 0)
            {
                HashSet<string> resolvedProtocols = protocols.Length == 0
                    ? new HashSet<string>(new[] { "tcp", "udp" })
                    : new HashSet<string>(protocols.Select(p => p.Trim().ToLowerInvariant()));
                foreach (var (port, proto) in resolved)
                    if (resolvedProtocols.Contains(proto.Trim().ToLowerInvariant()))
                        yield return port;
                yield break;
            }

            if (!_byService.TryGetValue(serviceName, out var list)) yield break;
            HashSet<string> protos = protocols.Length == 0
                ? new HashSet<string>(new[] { "tcp", "udp" })
                : new HashSet<string>(protocols.Select(p => p.Trim().ToLowerInvariant()));
            foreach (var (p, proto) in list)
                if (protos.Contains(proto)) yield return p;
        }
    }
}
