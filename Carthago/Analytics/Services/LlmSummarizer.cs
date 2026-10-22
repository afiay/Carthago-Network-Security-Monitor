// SPDX-License-Identifier: MIT
// File: Analytics/Services/LlmSummarizer.cs
using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Analytics.Models;

namespace Carthago.Analytics.Services
{
    /// <summary>
    /// Simple LLM client. Default is Ollama at 127.0.0.1:11434 with qwen2.5:7b.
    /// Emits progress states so the UI can show a progress bar.
    /// </summary>
    public sealed class LlmSummarizer : IDisposable
    {
        public enum Backend { None, Ollama }

        private readonly Backend _backend;
        private readonly string _baseUrl;
        private readonly string _model;
        private readonly TimeSpan _timeout;
        private readonly HttpClient? _http;

        public LlmSummarizer(
            Backend backend = Backend.None,
            string baseUrl = "http://127.0.0.1:11434",
            string model = "qwen2.5:7b",
            TimeSpan? timeout = null)
        {
            _backend = backend;
            _baseUrl = baseUrl;
            _model = model;
            _timeout = timeout ?? TimeSpan.FromSeconds(20);

            if (_backend == Backend.Ollama)
                _http = new HttpClient { Timeout = _timeout };
        }

        public void Dispose() => _http?.Dispose();

        /// <summary>Raised as (incidentId, state) at milestones: "started" | "llm" | "done" | "failed: ...".</summary>
        public event Action<string, string>? Progress;

        /// <summary>
        /// Try to summarize an incident. Returns a string always (fallback summary on errors).
        /// </summary>
        public async Task<string> TrySummarizeAsync(
            Incident incident,
            Action<string>? progress = null,
            CancellationToken ct = default)
        {
            var id = incident.Id ?? Guid.NewGuid().ToString("N");

            void Report(string s)
            {
                try { progress?.Invoke(s); } catch { }
                try { Progress?.Invoke(id, s); } catch { }
            }

            try
            {
                Report("started");

                 if (_backend == Backend.None)
                 {
                     var fallback = FallbackSummary(incident);
                     Report("done");
                     return fallback;
                 }

                if (_backend == Backend.Ollama && _http != null)
                {
                    Report("llm");

                    // Build a compact prompt from the Incident details we _know_ you have.
                    var prompt = BuildPrompt(incident);

                    var payload = new
                    {
                        model = _model,
                        stream = false,
                        messages = new[]
                        {
                            new { role = "system", content = "You are a SOC analyst. Be precise and concise." },
                            new { role = "user", content = prompt }
                        }
                    };

                    using var req = new HttpRequestMessage(HttpMethod.Post, $"{_baseUrl.TrimEnd('/')}/api/chat")
                    {
                        Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json")
                    };

                    using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                    resp.EnsureSuccessStatusCode();

                    // { "message": { "role":"assistant", "content":"..." }, "done":true, ... }
                    using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
                    var content = doc.RootElement.GetProperty("message").GetProperty("content").GetString();

                    var result = string.IsNullOrWhiteSpace(content) ? FallbackSummary(incident) : content!;
                    Report("done");
                    return result;
                }

                 // Unknown backend
                 var defaultFallback = FallbackSummary(incident);
                 Report("done");
                 return defaultFallback;
            }
            catch (Exception ex)
            {
                Report("failed: " + ex.Message);
                return FallbackSummary(incident);
            }
        }

        private static string BuildPrompt(Incident inc)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Summarize this security incident using only the supplied evidence.");
            sb.AppendLine("Do not invent facts. Do not change the incident severity or risk score. Do not decide whether the activity is malicious.");
            sb.AppendLine("Produce a concise analyst-facing summary and recommended investigation focus.");
            sb.AppendLine();
            sb.AppendLine($"Title: {inc.Title ?? "N/A"}");
            sb.AppendLine($"Severity: {inc.Severity}");
            sb.AppendLine($"Risk score: {inc.RiskScore}");
            sb.AppendLine($"Created (UTC): {inc.CreatedUtc:u}");
            sb.AppendLine($"Category: {inc.Category}");
            sb.AppendLine($"Source: {inc.PrimarySourceIp ?? "N/A"}");
            sb.AppendLine($"Destination: {inc.PrimaryDestinationHost ?? inc.PrimaryDestinationIp ?? "N/A"}");
            sb.AppendLine($"Status: {inc.Status}");

            if (inc.Evidence.Count > 0)
            {
                sb.AppendLine("Evidence:");
                foreach (var line in inc.Evidence.Take(6))
                    sb.AppendLine($"- {line}");
            }

            if (inc.RiskReasons.Count > 0)
            {
                sb.AppendLine("Risk reasons:");
                foreach (var line in inc.RiskReasons.Take(6))
                    sb.AppendLine($"- {line}");
            }

            if (inc.TimelineItems.Count > 0)
            {
                sb.AppendLine("Timeline highlights:");
                foreach (var item in inc.TimelineItems
                             .OrderBy(item => item.TimestampUtc)
                             .Take(8))
                {
                    sb.AppendLine($"- {item.TimestampUtc:u} [{item.Type}] {item.Title}: {item.Description}");
                }
            }

            if (inc.RecommendedActions.Count > 0)
            {
                sb.AppendLine("Recommended actions:");
                foreach (var line in inc.RecommendedActions.Take(5))
                    sb.AppendLine($"- {line}");
            }

            return sb.ToString();
        }

        private static string FallbackSummary(Incident inc)
        {
            var actor = string.IsNullOrWhiteSpace(inc.PrimarySourceIp) ? "A host" : $"Host {inc.PrimarySourceIp}";
            var target = inc.PrimaryDestinationHost ?? inc.PrimaryDestinationIp;
            var title = string.IsNullOrWhiteSpace(inc.Title) ? "Suspicious activity" : inc.Title.Trim();
            var evidence = inc.Evidence.Take(3).ToArray();
            var reasons = inc.RiskReasons.Take(3).ToArray();
            var actions = inc.RecommendedActions.Take(2).ToArray();
            var timeline = inc.TimelineItems
                .OrderBy(item => item.TimestampUtc)
                .Select(item => item.Title)
                .Where(title => !string.IsNullOrWhiteSpace(title))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(3)
                .ToArray();

            var sb = new StringBuilder();
            sb.Append($"{title} was detected");
            if (!string.IsNullOrWhiteSpace(target))
                sb.Append($" involving {actor} and {target}");
            else
                sb.Append($" for {actor}");
            sb.Append(". ");

            if (evidence.Length > 0)
                sb.Append($"Evidence includes {JoinForSentence(evidence)}. ");
            else if (reasons.Length > 0)
                sb.Append($"Key risk reasons include {JoinForSentence(reasons)}. ");

            if (timeline.Length > 0)
                sb.Append($"Timeline highlights include {JoinForSentence(timeline)}. ");

            if (actions.Length > 0)
                sb.Append($"Recommended next steps: {JoinForSentence(actions)}.");
            else
                sb.Append("Recommended next steps: review the responsible process, validate destination context, and collect supporting telemetry.");

            return sb.ToString();
        }

        private static string JoinForSentence(IReadOnlyList<string> items)
        {
            if (items.Count == 0) return "";
            if (items.Count == 1) return items[0];
            if (items.Count == 2) return $"{items[0]} and {items[1]}";
            return $"{items[0]}, {items[1]}, and {items[2]}";
        }
    }
}
