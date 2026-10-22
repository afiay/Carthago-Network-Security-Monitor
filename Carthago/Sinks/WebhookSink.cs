// SPDX-License-Identifier: MIT
// File: Sinks/WebhookSink.cs
using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;

namespace Carthago.Sinks
{
    public sealed class WebhookSink : IDetectionSink
    {
        private readonly HttpClient _http = new();
        private readonly Uri _uri;

        public WebhookSink(string url)
        {
            if (string.IsNullOrWhiteSpace(url)) throw new ArgumentNullException(nameof(url));
            _uri = new Uri(url);
        }

        public async Task EmitAsync(DetectionEvent evt, CancellationToken ct = default)
        {
            // Serialize the event and POST as application/json (no dependency on System.Net.Http.Json)
            var json = JsonSerializer.Serialize(evt);
            using var content = new StringContent(json, Encoding.UTF8, "application/json");
            using var resp = await _http.PostAsync(_uri, content, ct).ConfigureAwait(false);
            resp.EnsureSuccessStatusCode();
        }

        public void Dispose() => _http.Dispose();
    }
}
