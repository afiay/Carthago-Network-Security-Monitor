// File: Sinks/SplunkHecSink.cs
// SPDX-License-Identifier: MIT
using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;

namespace Carthago.Sinks
{
    public sealed class SplunkHecSink : IDetectionSink
    {
        private readonly HttpClient _http = new();
        private readonly Uri _endpoint;
        private readonly string? _source, _sourcetype, _index, _host;

        public SplunkHecSink(string baseUrl, string token,
                             string? source = null, string? sourcetype = "carthago:detection",
                             string? index = null, string? host = null)
        {
            // baseUrl e.g. "https://splunk.example:8088"
            _endpoint = new Uri(new Uri(baseUrl.TrimEnd('/')), "/services/collector/event");
            _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Splunk", token);
            _source = source; _sourcetype = sourcetype; _index = index; _host = host;
        }

        public async Task EmitAsync(DetectionEvent evt, CancellationToken ct = default)
        {
            var payload = new
            {
                time = new DateTimeOffset(evt.Timestamp).ToUnixTimeSeconds(),
                host = _host,
                source = _source,
                sourcetype = _sourcetype,
                index = _index,
                @event = evt // serialize the full structured event
            };
            using var req = new HttpRequestMessage(HttpMethod.Post, _endpoint)
            {
                Content = new StringContent(JsonSerializer.Serialize(payload))
            };
            req.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
            using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
            resp.EnsureSuccessStatusCode();
        }

        public void Dispose() => _http.Dispose();
    }
}
