// File: Sinks/ElasticSink.cs
using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;

namespace Carthago.Sinks
{
    public sealed class ElasticSink : IDetectionSink
    {
        private readonly HttpClient _http = new();
        private readonly Uri _bulk;
        private readonly string _index;

        public ElasticSink(string baseUrl, string index, string? apiKey = null)
        {
            _bulk = new Uri(new Uri(baseUrl.TrimEnd('/')), $"/{index}/_bulk");
            _index = index;
            if (!string.IsNullOrWhiteSpace(apiKey))
                _http.DefaultRequestHeaders.Authorization =
                    new System.Net.Http.Headers.AuthenticationHeaderValue("ApiKey", apiKey);
        }

        public async Task EmitAsync(DetectionEvent evt, CancellationToken ct = default)
        {
            // Bulk NDJSON: action line + source line
            var action = $"{{\"index\":{{\"_index\":\"{_index}\"}}}}\n";
            var doc = JsonSerializer.Serialize(evt) + "\n";
            var ndjson = action + doc;

            using var content = new StringContent(ndjson, Encoding.UTF8, "application/x-ndjson");
            using var resp = await _http.PostAsync(_bulk, content, ct).ConfigureAwait(false);
            resp.EnsureSuccessStatusCode();
        }

        public void Dispose() => _http.Dispose();
    }
}
