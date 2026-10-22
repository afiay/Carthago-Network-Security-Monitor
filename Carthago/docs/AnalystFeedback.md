# Analyst Feedback

Feedback is an annotation layer. It must not modify or delete the original `DetectionEvent`.

Feedback is persisted under:

```text
%ProgramData%\Carthago\feedback\feedback-YYYY-MM.jsonl
```

Supported verdicts:

- Unknown
- TruePositive
- FalsePositive
- ExpectedActivity
- NeedsReview
- SuppressSimilar

Feedback can later drive:

- false-positive rate
- rule tuning suggestions
- suppression recommendations
- maturity promotion/demotion
