// SPDX-License-Identifier: MIT
// File: Sinks/AzureLogsSink.cs
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Azure;
using Azure.Core;              // RequestContext
using Azure.Identity;
using Azure.Monitor.Ingestion;
using Carthago.Models;

namespace Carthago.Sinks
{
    public sealed class AzureLogsSink : IDetectionSink
    {
        private readonly LogsIngestionClient _client;
        private readonly string _ruleId;
        private readonly string _stream;

        // dceUri: e.g., "https://<dce-name>.<region>-ingest.monitor.azure.com"
        // ruleId: DCR immutableId (GUID), stream: e.g., "Custom-CarthagoDetections_CL"
        public AzureLogsSink(string dceUri, string ruleId, string stream)
        {
            _client = new LogsIngestionClient(new Uri(dceUri), new DefaultAzureCredential());
            _ruleId = ruleId;
            _stream = stream;
        }

        public async Task EmitAsync(DetectionEvent evt, CancellationToken ct = default)
        {
            // Azure ingestion expects an array of objects serialized as JSON
            var item = new Dictionary<string, object?>
            {
                ["TimeGenerated"] = evt.Timestamp, // Azure convention
                ["ruleId"] = evt.RuleId,
                ["description"] = evt.Description,
                ["severity"] = evt.Severity.ToString(),
                ["srcIp"] = evt.SourceIp,
                ["dstIp"] = evt.DestinationIp,
                ["dstPort"] = evt.DestinationPort,
                ["proto"] = evt.Protocol,
                ["count"] = evt.Count,
                ["windowSeconds"] = evt.WindowSeconds,
                ["sensitivity"] = evt.SensitivityAtTrigger.ToString()
            };

            var payload = new[] { item };
            using RequestContent content = RequestContent.Create(BinaryData.FromObjectAsJson(payload));

            // NOTE: This SDK overload uses RequestContext for cancellation, not a named 'cancellationToken'
            var ctx = new RequestContext { CancellationToken = ct };
            await _client.UploadAsync(_ruleId, _stream, content, contentEncoding: null, context: ctx).ConfigureAwait(false);
        }

        public void Dispose() { }
    }
}
