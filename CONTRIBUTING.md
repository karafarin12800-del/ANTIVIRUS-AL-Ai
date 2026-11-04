# Contributing

- Keep scanning and parsing defensive. Never execute or install a file being inspected.
- Add tests for every detection rule, including benign cases that must not be flagged.
- Include provenance, rationale, test coverage, and expiry/version metadata for future threat indicators.
- Never commit API keys, signing keys, private certificates, user files, or malware samples.
- Preserve the distinction between confirmed hash indicators, heuristic warnings, and unknown results.
- Do not add broad Android permissions without a documented requirement and policy review.
