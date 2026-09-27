# Security policy

## Scope

This project is an experimental, dependency-light text scanner. It is not a sandbox, model firewall at the network layer, secrets manager, or guarantee that an LLM application is safe. It does not inspect images, tool calls, retrieved documents unless the caller passes their text, or model internals.

## Reporting a vulnerability

Please do not publish working credentials or sensitive personal data in an issue. Report a security concern privately to the repository owner through GitHub's private vulnerability reporting feature when available. Include a minimal reproduction with synthetic data, the affected rule or API, and the expected behavior.

## Safe handling

Findings do not include the matched secret value, but offsets and input length can still be sensitive. The CLI reads standard input and prints generic detections. The optional example API is for local demonstration only and should not be exposed to the public internet without authentication, rate limiting, and a data-retention policy.
