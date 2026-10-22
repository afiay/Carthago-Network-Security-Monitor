// SPDX-License-Identifier: MIT
// File: Services/Cisco/IncidentRulesEngine.cs

using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Carthago.Services.Cisco
{
    /// <summary>
    /// Lightweight rules engine for Cisco incident tagging/escalation/runbooks.
    /// Supports JSON and a small YAML subset (mappings, sequences, scalars).
    /// </summary>
    public sealed class IncidentRulesEngine
    {
        private readonly List<IncidentRule> _rules = new();
        public IReadOnlyList<IncidentRule> Rules => _rules;
        public string? SourcePath { get; private set; }

        public void Clear()
        {
            _rules.Clear();
            SourcePath = null;
        }

        public int LoadFromFile(string path)
        {
            if (!File.Exists(path))
                throw new FileNotFoundException("Rules file not found.", path);

            string text = File.ReadAllText(path);
            List<IncidentRule> parsed;

            if (LooksLikeJson(text))
            {
                parsed = JsonSerializer.Deserialize<List<IncidentRule>>(text, JsonOptions())
                         ?? new List<IncidentRule>();
            }
            else
            {
                // YAML -> object -> JSON -> IncidentRule[]
                var yamlObj = YamlLite.Parse(text);
                var json = JsonSerializer.Serialize(yamlObj, JsonOptions());
                parsed = JsonSerializer.Deserialize<List<IncidentRule>>(json, JsonOptions())
                         ?? new List<IncidentRule>();
            }

            Normalize(parsed);

            _rules.Clear();
            _rules.AddRange(parsed);
            _rules.Sort((a, b) => b.Priority.CompareTo(a.Priority)); // higher first
            SourcePath = path;
            return _rules.Count;
        }

        public void ApplyRules(IncidentContext ctx, IncidentFacts facts)
        {
            foreach (var rule in _rules)
            {
                if (!rule.When.Matches(facts))
                    continue;

                rule.Then.Apply(ctx, facts);

                if (rule.StopProcessing)
                    break;
            }
        }

        public void ApplyRulesToAll(IEnumerable<IncidentContext> allContexts, Func<IncidentContext, IncidentFacts> factsFactory)
        {
            foreach (var ctx in allContexts)
            {
                var facts = factsFactory(ctx);
                ApplyRules(ctx, facts);
            }
        }

        // ---- helpers ----

        private static JsonSerializerOptions JsonOptions()
        {
            return new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                ReadCommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
            };
        }

        private static void Normalize(List<IncidentRule> rules)
        {
            foreach (var r in rules)
            {
                r.Id ??= Guid.NewGuid().ToString("n");
                r.When ??= new RuleCriteria();
                r.Then ??= new RuleActions();
            }
        }

        private static bool LooksLikeJson(string text)
        {
            for (int i = 0; i < text.Length; i++)
            {
                char c = text[i];
                if (char.IsWhiteSpace(c)) continue;
                return c == '{' || c == '[';
            }
            return false;
        }
    }

    // -------- Model --------

    public sealed class IncidentRule
    {
        public string? Id { get; set; }
        public string? Description { get; set; }
        public int Priority { get; set; } = 0;
        public bool StopProcessing { get; set; } = false;
        public RuleCriteria When { get; set; } = new();
        public RuleActions Then { get; set; } = new();
    }

    public sealed class RuleCriteria
    {
        public string? DevicePattern { get; set; }            // regex or glob (supports * and ?)
        public string? Category { get; set; }                 // exact or regex:/.../
        public string? CiscoCode { get; set; }                // exact or regex:/.../
        public string? SeverityAtLeast { get; set; }          // Information/Warning/Error/Critical
        public List<string>? MessageContains { get; set; }    // all terms must be present
        public string? MessageRegex { get; set; }             // regex
        public int? CountAtLeast { get; set; }                // within window (if provided)
        public string? Within { get; set; }                   // e.g., "5m","1h","30s"

        public bool Matches(IncidentFacts f)
        {
            if (!string.IsNullOrWhiteSpace(DevicePattern))
            {
                if (!MatchPattern(DevicePattern!, f.DeviceLabel))
                    return false;
            }

            if (!MatchValue(Category, f.Category))
                return false;

            if (!MatchValue(CiscoCode, f.CiscoCode))
                return false;

            if (!string.IsNullOrWhiteSpace(SeverityAtLeast))
            {
                if (SeverityRank(f.SeverityName) < SeverityRank(SeverityAtLeast!))
                    return false;
            }

            if (MessageContains is { Count: > 0 })
            {
                var msg = f.ExampleMessage ?? "";
                foreach (var term in MessageContains)
                {
                    if (string.IsNullOrWhiteSpace(term)) continue;
                    if (msg.IndexOf(term, StringComparison.OrdinalIgnoreCase) < 0)
                        return false;
                }
            }

            if (!string.IsNullOrWhiteSpace(MessageRegex))
            {
                if (!Regex.IsMatch(f.ExampleMessage ?? "", AsRegex(MessageRegex!), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                    return false;
            }

            if (CountAtLeast.HasValue)
            {
                TimeSpan window = ParseWindow(Within) ?? TimeSpan.FromMinutes(30);
                if (f.CountInWindow(window) < CountAtLeast.Value)
                    return false;
            }

            return true;
        }

        private static bool MatchValue(string? ruleValue, string actual)
        {
            if (string.IsNullOrWhiteSpace(ruleValue))
                return true;

            if (ruleValue.StartsWith("regex:/", StringComparison.OrdinalIgnoreCase) && ruleValue.EndsWith("/"))
            {
                var pat = ruleValue[6..^1];
                return Regex.IsMatch(actual ?? "", pat, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            }

            return string.Equals(ruleValue, actual ?? "", StringComparison.OrdinalIgnoreCase);
        }

        private static bool MatchPattern(string pattern, string candidate)
        {
            if (string.IsNullOrEmpty(pattern)) return true;
            if (pattern.StartsWith("regex:/", StringComparison.OrdinalIgnoreCase) && pattern.EndsWith("/"))
            {
                var pat = pattern[6..^1];
                return Regex.IsMatch(candidate ?? "", pat, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            }
            // glob -> regex
            var rx = "^" + Regex.Escape(pattern).Replace(@"\*", ".*").Replace(@"\?", ".") + "$";
            return Regex.IsMatch(candidate ?? "", rx, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        }

        private static int SeverityRank(string s) => (s ?? "").Trim().ToLowerInvariant() switch
        {
            "critical" => 3,
            "error" => 2,
            "warning" => 1,
            _ => 0
        };

        private static string AsRegex(string input)
        {
            if (input.StartsWith("regex:/") && input.EndsWith("/"))
                return input[6..^1];
            return input;
        }

        private static TimeSpan? ParseWindow(string? s)
        {
            if (string.IsNullOrWhiteSpace(s)) return null;
            s = s.Trim().ToLowerInvariant();
            try
            {
                if (s.EndsWith("ms")) return TimeSpan.FromMilliseconds(double.Parse(s[..^2], CultureInfo.InvariantCulture));
                if (s.EndsWith("s")) return TimeSpan.FromSeconds(double.Parse(s[..^1], CultureInfo.InvariantCulture));
                if (s.EndsWith("m")) return TimeSpan.FromMinutes(double.Parse(s[..^1], CultureInfo.InvariantCulture));
                if (s.EndsWith("h")) return TimeSpan.FromHours(double.Parse(s[..^1], CultureInfo.InvariantCulture));
                if (s.EndsWith("d")) return TimeSpan.FromDays(double.Parse(s[..^1], CultureInfo.InvariantCulture));
                // raw seconds
                if (double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var sec))
                    return TimeSpan.FromSeconds(sec);
            }
            catch { }
            return null;
        }
    }

    public sealed class RuleActions
    {
        public List<string>? AddTags { get; set; }
        public string? Hint { get; set; }
        public string? RunbookUrl { get; set; }
        public string? EscalateTo { get; set; }     // Warning/Error/Critical
        public bool? Suppress { get; set; }
        public List<string>? Assign { get; set; }   // owners, teams

        public void Apply(IncidentContext ctx, IncidentFacts facts)
        {
            if (AddTags is { Count: > 0 })
                foreach (var t in AddTags)
                    ctx.AddTag(t);

            if (!string.IsNullOrWhiteSpace(Hint))
                ctx.SetHint(Hint!);

            if (!string.IsNullOrWhiteSpace(RunbookUrl))
                ctx.SetRunbook(RunbookUrl!);

            if (!string.IsNullOrWhiteSpace(EscalateTo))
                ctx.Escalate(EscalateTo!);

            if (Suppress == true)
                ctx.Suppress();

            if (Assign is { Count: > 0 })
                ctx.AssignTo(Assign!);
        }
    }

    // -------- Bridge from engine to host app --------

    /// <summary>
    /// Facts made available to the rule evaluation for an incident.
    /// </summary>
    public sealed class IncidentFacts
    {
        public string DeviceLabel { get; init; } = "";
        public string Category { get; init; } = "";
        public string CiscoCode { get; init; } = "";
        public string SeverityName { get; init; } = "";
        public string? ExampleMessage { get; init; }
        public Func<TimeSpan, int> CountInWindow { get; init; } = _ => 0; // supplied by host
    }

    /// <summary>
    /// Host-provided operations that mutate the incident.
    /// </summary>
    public sealed class IncidentContext
    {
        private readonly Action<string> _addTag;
        private readonly Action<string> _setHint;
        private readonly Action<string> _setRunbook;
        private readonly Action<string> _escalate;
        private readonly Action _suppress;
        private readonly Action<IEnumerable<string>> _assign;

        public IncidentContext(Action<string> addTag,
                               Action<string> setHint,
                               Action<string> setRunbook,
                               Action<string> escalate,
                               Action suppress,
                               Action<IEnumerable<string>> assign)
        {
            _addTag = addTag;
            _setHint = setHint;
            _setRunbook = setRunbook;
            _escalate = escalate;
            _suppress = suppress;
            _assign = assign;
        }

        public void AddTag(string tag) => _addTag(tag);
        public void SetHint(string hint) => _setHint(hint);
        public void SetRunbook(string url) => _setRunbook(url);
        public void Escalate(string severity) => _escalate(severity);
        public void Suppress() => _suppress();
        public void AssignTo(IEnumerable<string> owners) => _assign(owners);
    }

    // -------- Minimal YAML reader (subset) --------
    // Supports:
    //  - mappings: key: value
    //  - nested mappings via indentation (2+ spaces)
    //  - sequences via "- item" or "- key: value" blocks
    //  - scalars: strings, bool, int/float
    // This is intentionally small and tailored for rules files.

    internal static class YamlLite
    {
        private sealed class Node
        {
            public object Value;
            public int Indent;
            public Node(object v, int i) { Value = v; Indent = i; }
        }

        public static object Parse(string yaml)
        {
            var root = new List<object>();
            var stack = new Stack<Node>();
            stack.Push(new Node(root, -1));

            var lines = yaml.Replace("\r\n", "\n").Replace("\r", "\n").Split('\n');
            for (int ln = 0; ln < lines.Length; ln++)
            {
                var raw = lines[ln];
                var line = StripComment(raw).TrimEnd();
                if (string.IsNullOrWhiteSpace(line)) continue;

                int indent = CountIndent(raw);
                while (stack.Peek().Indent >= indent) stack.Pop();

                var parent = stack.Peek().Value;

                if (line.TrimStart().StartsWith("-", StringComparison.Ordinal))
                {
                    // sequence item
                    var content = line.TrimStart().Substring(1).TrimStart();
                    if (parent is not IList list)
                    {
                        // convert mapping to list if needed
                        var newList = new List<object>();
                        if (parent is IDictionary) throw new FormatException("Sequence under mapping key must be introduced after key:");
                        stack.Peek().Value = newList;
                        parent = newList;
                    }

                    if (content.Length == 0)
                    {
                        var newMap = new Dictionary<string, object>();
                        ((IList)parent).Add(newMap);
                        stack.Push(new Node(newMap, indent));
                    }
                    else if (content.Contains(":"))
                    {
                        // inline mapping start
                        var map = new Dictionary<string, object>();
                        ((IList)parent).Add(map);
                        stack.Push(new Node(map, indent));
                        AddMapping(map, content);
                    }
                    else
                    {
                        ((IList)parent).Add(ParseScalar(content));
                    }
                }
                else
                {
                    // mapping entry
                    if (parent is IList)
                    {
                        // A mapping begins after list item with newline
                        var map = new Dictionary<string, object>();
                        ((IList)parent).Add(map);
                        parent = map;
                        stack.Push(new Node(parent, indent));
                    }

                    var dict = parent as IDictionary ?? throw new FormatException("Mapping expected");
                    if (line.EndsWith(":"))
                    {
                        var key = line[..^1].Trim();
                        var newMap = new Dictionary<string, object>();
                        dict[key] = newMap;
                        stack.Push(new Node(newMap, indent));
                    }
                    else
                    {
                        AddMapping((IDictionary)dict, line);
                    }
                }
            }

            // if root is a single mapping or list, return it; else return list
            if (root.Count == 1) return root[0];
            return root;
        }

        private static void AddMapping(IDictionary dict, string content)
        {
            int idx = content.IndexOf(':');
            if (idx < 0) throw new FormatException("Invalid mapping line: " + content);
            var key = content[..idx].Trim();
            var value = content[(idx + 1)..].Trim();
            dict[key] = ParseValue(value);
        }

        private static object ParseValue(string s)
        {
            if (s.Length == 0) return string.Empty;

            // inline sequence [a, b, c]
            if (s.StartsWith("[") && s.EndsWith("]"))
            {
                var inner = s[1..^1];
                var parts = inner.Split(',');
                var list = new List<object>();
                foreach (var p in parts)
                {
                    list.Add(ParseScalar(p.Trim()));
                }
                return list;
            }

            // quoted string
            if ((s.StartsWith("\"") && s.EndsWith("\"")) || (s.StartsWith("'") && s.EndsWith("'")))
            {
                return s[1..^1];
            }

            return ParseScalar(s);
        }

        private static object ParseScalar(string s)
        {
            if (string.Equals(s, "true", StringComparison.OrdinalIgnoreCase)) return true;
            if (string.Equals(s, "false", StringComparison.OrdinalIgnoreCase)) return false;

            if (int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var i)) return i;
            if (double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var d)) return d;

            return s; // raw string
        }

        private static string StripComment(string s)
        {
            var i = s.IndexOf('#');
            return i >= 0 ? s[..i] : s;
        }

        private static int CountIndent(string s)
        {
            int n = 0;
            foreach (var c in s)
            {
                if (c == ' ') n++;
                else if (c == '\t') n += 2; // soft-tab
                else break;
            }
            return n;
        }
    }
}
