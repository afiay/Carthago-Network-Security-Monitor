# Replay Testing

Replay samples live under:

```text
Tests/RuleReplaySamples/
```

Each sample defines:

```json
{
  "Name": "log4shell-basic-jndi",
  "Records": [],
  "ExpectedMatches": ["R084"],
  "ExpectedNonMatches": ["R085"],
  "ExpectedMinimumConfidence": 0.8
}
```

Initial replay coverage includes:

- Log4Shell/JNDI
- SQL injection
- path traversal
- DNS tunneling via long labels
- MQTT external broker
- Modbus outside segment
- benign DNS
- benign HTTP

Replay tests should grow with every new or revised rule.
