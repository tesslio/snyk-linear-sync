# External failure diagnostics, version 1

Each instrumented failed boundary emits an ERROR log with message `external
operation failed` and a `diagnostic_json` string containing one JSON object.
The normal CLI uses Go slog text format: unquote the field as a Go/JSON string,
then decode the contained JSON. With a JSON slog handler, decode the outer JSON
and then the `diagnostic_json` string. Only this object is the contract; ordinary
logs, envelope attributes and returned errors are **not safe retained evidence**.

Consumers must reject unsupported versions, extra keys, wrong types, out-of-range
numbers and unknown enum values (the literal `unknown` is valid). Retain only a
bounded number of validated objects, never raw lines on parsing failure. Validation,
retention limits, final-run outcome and alert delivery belong to the consumer.

All keys are mandatory; nullable fields use JSON `null`, never missing keys:

| Key | Type / allowed values |
| --- | --- |
| `version` | integer `1` |
| `provider` | `snyk`, `linear`, `unknown` |
| `stage` | `snyk_oauth`, `snyk_rest`, `snyk_v1`, `snyk_sdk`, `linear_graphql`, `unknown` |
| `endpoint` | One of the templates below, or `unknown` |
| `method` | `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS`, `unknown` |
| `phase` | `transport`, `response_read`, `response_validation`, `operation`, `unknown` |
| `status` | integer 100–599, or null |
| `family` | `http_status`, `graphql`, `canceled`, `timeout`, `truncated_response`, `invalid_response`, `network`, `unknown` |
| `attempt_scope` | `transport`, `graphql_execute`, `token_source`, `sdk_call`, `unknown` |
| `attempts` | integer 0–1000, or null |
| `retry_exhausted` | boolean, or null |
| `elapsed_ms` | integer 0–9223372036854, or null |

Endpoint allowlist:

- `/oauth2/token`
- `/graphql`
- `/rest/orgs/{org}`
- `/rest/orgs/{org}/projects`
- `/rest/orgs/{org}/issues`
- `/v1/org/{org}/project/{project}`
- `/v1/org/{org}/project/{project}/ignores`

These are labels, not URLs. There are no hosts, dynamic path segments, queries,
request/response bodies, exception messages, headers, correlation IDs, GraphQL
variables or operation text in this contract. The emitter reprojects string fields
onto closed allowlists even when callers provide unexpected strings.

## Meaning and limits

- A record is a failure at one boundary, **not** a final-run failure or a claim
  that a mutation did not land. An outer retry may recover. The same failure may
  emit transport, read and operation records; do not sum them as separate outages.
- `transport` attempts count actual calls to the base RoundTripper within one
  AdaptiveTransport call, including the initial attempt. Zero means cancellation
  or request cloning failed before dispatch. `retry_exhausted=true` means the
  existing retry limit stopped that scope; disabled retries or unreplayable
  bodies report false. No retry conditions, delays or limits change.
- `graphql_execute` counts calls to gqlclient.Execute in one existing Linear
  execute loop; it is not a network-attempt count. `sdk_call` counts one SDK call,
  whose internal network count is unknown. A separate transport record carries
  observed dispatch counts. OAuth acquisition occurs outside AdaptiveTransport;
  `token_source` attempts and exhaustion are null because a TokenSource can cache,
  retry or perform multiple internal requests. Its status is read only from a
  typed OAuth retrieval error, never parsed from text.
- Elapsed time covers the emitting boundary, including waits. Response records
  inherit the transport's start and attempt evidence when available. With an
  uninstrumented client, response-only elapsed time, attempts and exhaustion are
  unknown. OAuth measures the Token call, Linear the execute loop, and SDK the single List call. Durations are not additive.
- Transport failures, failed HTTP statuses, non-EOF body read errors, Snyk JSON
  decode/fresh-response validation and v1 ignore validation, SDK List failures,
  and Linear Execute failures are covered. This is not exhaustive coverage of
  every higher-level pagination, acknowledgment or reconciliation validation.
- Wrapped/joined typed errors classify cancellation before timeout, truncation,
  JSON validation, then network errors. Plain arbitrary errors remain unknown.
  Some SDK/library errors flatten nested errors into strings; the operation
  record remains unknown rather than guessing. Lower-level transport/read records
  can still supply evidence. Linear typed HTTP and GraphQL failures are classified
  without copying their text. Unknown status is null, not zero or an inferred 503.
- Existing return values/errors, source completeness checks, write authorization,
  lineage and cache behavior remain unchanged. Existing raw error logs can contain
  sensitive data; this feature does not make them safe for public retention.

[Consumer fixtures](fixtures/failure-diagnostics-v1.json) contain synthetic
records with known elapsed time normalized to zero. Tests exercise real boundaries
with synthetic secret-bearing URLs, bodies, headers, nested errors and GraphQL details.
No production integration or deployment is implied by these fixtures.
