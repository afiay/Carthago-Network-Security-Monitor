// File: Sinks/KafkaSink.cs
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;
using Confluent.Kafka;

namespace Carthago.Sinks
{
    public sealed class KafkaSink : IDetectionSink
    {
        private readonly IProducer<string, string> _producer;
        private readonly string _topic;

        public KafkaSink(string bootstrapServers, string topic, string? saslUser = null, string? saslPass = null)
        {
            var cfg = new ProducerConfig { BootstrapServers = bootstrapServers };
            if (!string.IsNullOrEmpty(saslUser))
            {
                cfg.SaslUsername = saslUser;
                cfg.SaslPassword = saslPass;
                cfg.SecurityProtocol = SecurityProtocol.SaslSsl;
                cfg.SaslMechanism = SaslMechanism.Plain;
            }
            _producer = new ProducerBuilder<string, string>(cfg).Build();
            _topic = topic;
        }

        public async Task EmitAsync(DetectionEvent evt, CancellationToken ct = default)
        {
            var json = JsonSerializer.Serialize(evt);
            // key by SourceIp to keep ordering per source
            await _producer.ProduceAsync(_topic, new Message<string, string> { Key = evt.SourceIp ?? "", Value = json }, ct)
                           .ConfigureAwait(false);
        }

        public void Dispose() => _producer.Dispose();
    }
}
