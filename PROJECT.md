# Project Overview

## Purpose

This project exists to keep Linear aligned with Snyk.

Canonical module path:

```text
github.com/tesslio/snyk-linear-sync
```

This repository is a detached operational copy of
github.com/RichardoC/snyk-linear-sync; fixes are contributed back upstream.

The intended outcome is:

- every relevant Snyk finding has a corresponding Linear issue
- the Linear issue stays current as the Snyk finding changes
- resolved or ignored findings move to the correct Linear workflow state
- repeated runs become cheap by skipping unchanged records

This is an operational sync tool, not a generic library.

## Core Contract

The project treats Snyk as the source of truth for security finding data and Linear as the execution surface for tracking and triage.

It is responsible for:

- reading Snyk findings
- deciding the desired Linear representation
- reconciling the current Linear state to that desired state

It is not responsible for:

- writing back to Snyk
- preserving arbitrary manual edits inside the managed section of the Linear description
- syncing comments or custom fields beyond the currently managed issue body, title, priority, due date, workflow state, and managed automation label

## Identity Model

Each Snyk finding is identified by:

```text
snyk:<project-id>:<issue-id>
```

That fingerprint is embedded in the Linear description metadata block and is the durable join key between systems.

Without that fingerprint, the sync cannot safely deduplicate or update issues.

## Issue Lifecycle

### Create

Create a Linear issue when:

- a Snyk finding exists
- no Linear issue with the same fingerprint exists

### Update

Update the Linear issue when managed fields differ:

- title
- description
- due date
- priority
- mapped state
- managed automation label

### Resolve

When a previously tracked finding no longer exists in Snyk but its Snyk project still exists, move the Linear issue to the resolved state.

When a previously tracked finding no longer exists because its Snyk project no longer exists, cancel the Linear issue instead.

### Conflict

If multiple Linear issues share the same fingerprint, the sync treats that as a conflict:

- it logs the conflict
- it skips automatic mutation for that fingerprint

## Description Strategy

The Linear issue description is intentionally structured for fast triage first, deep debugging second.

It includes:

- heading with vulnerability title and severity
- Kubernetes cluster and namespace near the top for findings whose project
  origin is `kubernetes` (cluster from the Snyk v1 project detail's
  `imageCluster` field — the REST project resource does not expose it and
  the v1 projects list endpoint is deprecated — namespace parsed from the
  project name, which the Snyk Kubernetes integration builds as
  `<namespace>/<kind>.<group>/<workload>:<target>`)
- repository context near the top
- branch/reference and commit context when available
- source file or project target file context near the top
- human-usable Snyk UI link
- Snyk REST API link
- package/version details
- fix availability, CVSS, CWE class(es), and CVE identifier(s) when Snyk reports them
- vulnerability description and remediation guidance sections when Snyk reports them
- project identifiers
- issue identifiers
- GitHub repository links when `SOURCE_PROVIDER=github`
- GitHub source file and commit links when `SOURCE_PROVIDER=github`
- GitHub project target file links when `SOURCE_PROVIDER=github` and no precise source location is available
- metadata block

The synced title is also structured for scanability. It includes the best available source context:

- repository for code and repository-backed findings
- branch/image/reference for non-GitHub target-file findings such as Kubernetes or container scans

The subject portion then uses this preference:

1. source file basename
2. package name
3. project target file
4. project name

The metadata block also records the managed automation label name when label management is enabled.

Linear may rewrite parts of the description body when rendering or storing markdown. The sync therefore normalizes known Linear formatting changes during compare and cache hashing.

## Source Hosting

`SOURCE_PROVIDER` controls how source references are rendered.

- `unknown` leaves source references as plain text
- `github` renders public GitHub links for:
  - repositories
  - source files, pinned to the reported commit
  - source commits
  - project target files, pinned to the reported branch/reference when no source commit/file is available

If repository, file, or commit data is missing, the sync falls back to plain text.

## Managed Labels

`LINEAR_MANAGED_LABEL` controls the label this tool manages on synced issues.

- default: `snyk-automation`
- `off`: disables label management
- any other value: the exact Linear label name to manage

Behavior:

- the configured managed label is added to new synced issues
- unrelated existing labels are preserved
- if the configured managed label changes, the old managed label is removed and the new one is applied
- if label management is disabled, the previously managed label is removed

The configured label must already exist in Linear. If it does not, the run fails with a clear operator-facing error.

`LINEAR_TOOL_LABELS` optionally maps Snyk issue `type` values to additional managed Linear labels.

- format: comma-separated `issue_type:label` pairs
- example: `code:snyk-code,package_vulnerability:snyk-open-source`

`LINEAR_TOOL_LABEL_DEFAULT` controls the fallback label for unmapped issue types.

- default: `snyk-automation`
- `off`: disables the fallback

`LINEAR_ORIGIN_LABELS` optionally maps Snyk project `origin` values to additional managed Linear labels.

- format: comma-separated `origin:label` pairs
- example: `github:snyk-github,kubernetes:snyk-kubernetes`

`LINEAR_ORIGIN_LABEL_DEFAULT` controls the fallback label for unmapped project origins.

- default: `off`
- `off`: disables the fallback

`LINEAR_AWAITING_FIX_LABEL` controls the label applied to issues where Snyk reports the ignore as "until fix is available" (disregardIfFixable).

- default: `triage-dependency`
- `off`: disables the awaiting-fix label
- any other value: the exact Linear label name to apply
- the label must already exist in Linear

When an issue is in the awaiting-fix state, the sync adds the configured label. When the fix becomes available and the issue moves to `Todo`, the label is removed. The label is tracked in the metadata block alongside tool and origin labels.

The metadata block stores the full managed label set so the sync can remove stale tool-derived, origin-derived, and awaiting-fix labels while preserving unrelated manual labels.

`LINEAR_UNSUBSCRIBE_ACTOR` is an optional operator control for notification behavior.

- default: `true`
- when enabled, the sync creates issues without subscribing the Linear API actor
- update operations preserve the current subscriber list exactly as it already exists

This only affects the persisted subscriber list. Linear still records the API user as the issue creator, which is separate from `subscribers` and can make the UI look like the creator is still "following" the issue even when the stored subscriber list is empty.

## Snapshot Scope

Each run loads a snapshot of the sync's own Linear tickets. The query is scoped
by team, then by an archive window, then by identity:

```text
team = LINEAR_TEAM_ID
  AND (not auto-archived OR auto-archived within the lookback window)
  AND (title starts with "Snyk:" OR carries LINEAR_MANAGED_LABEL)
```

Both identity predicates are exact -- a title prefix and a label name -- and
either alone identifies a managed ticket, since the sync builds every title with
the prefix and re-asserts the managed label on every update. Keeping both means a
retitled ticket, or one whose label was removed by hand, is still found rather
than being invisible and duplicated. With `LINEAR_MANAGED_LABEL=off` the label
clause is omitted rather than matching nothing.

This matters because the Linear team is shared with `snyk-dast-linear-sync`: the
scope must exclude the other tool's tickets. The fingerprint metadata block is
deliberately **not** used as a query predicate -- `description: { contains: ... }`
does not bound the result set (the DAST sync, using this same filter shape
against this same team, loaded 59,866 issues for 7 findings), and Linear does not
document `description` as supporting the string comparators at all. The metadata
block remains the authority for identity once an issue is loaded; it just cannot
be trusted to select which issues to load.

## State Mapping

The current workflow mapping is:

- `open` -> `Todo`
- `ignored until fix available` (disregardIfFixable) -> `Backlog` (no due date, `triage-dependency` label)
- `temporarily ignored` (snoozed with future expiry) -> `Todo`
- `permanently ignored` -> `Cancelled`
- `fixed` (or `resolved`/disappeared) -> `Done`
- missing finding in an existing active Snyk project -> `Done`
- missing finding because the Snyk project no longer exists -> `Cancelled`
- Snyk project is inactive (de-activated) -> `Cancelled`

The sync also normalizes workflow naming differences such as `Canceled` vs `Cancelled`.

Resolution takes precedence over ignore state: if Snyk reports a finding as resolved (status `resolved`/`fixed`, resolution `fixed`, or all coordinates resolved), it maps to `Done` even when the finding still carries an ignore. The ignore branches (`until fix available`, `temporarily ignored`, `permanently ignored`) apply only to findings that still exist in Snyk. Without this precedence, a resolved finding that still has an active or expired ignore would map to a non-terminal state and resurface as a permanently-open, birth-overdue ticket for a vulnerability that no longer exists.

The `ignored until fix available` state is distinct from other ignored states because the ignore is conditional on an upstream fix. These issues are placed in `Backlog` with no due date and the `triage-dependency` label (configurable via `LINEAR_AWAITING_FIX_LABEL`). The description renders `Status: ignored (no fix available)` so the Snyk-side reality is visible in Linear. When a fix becomes available, Snyk flips `ignored=false` and the next run moves the issue to `Todo` with a recalculated due date.

### Manual Backlog Override

When a user manually moves a managed open ticket from `Todo` to `Backlog` in Linear, subsequent syncs preserve the `Backlog` state instead of overriding it back to `Todo`. This prevents the automation from fighting intentional user triage decisions. The override matches the configured `LINEAR_STATE_BACKLOG` value with case-insensitive normalization.

### Manual Non-Terminal State Override

When a user manually moves a managed issue to any non-terminal Linear workflow state that differs from what the sync would set, subsequent syncs preserve the user's chosen state. This generalises the previous Backlog-only and hardcoded "Todo" overrides.

This covers:

- a user moving an open issue from the configured open state (e.g. `Triage`) to `Todo` or `In Progress`
- a user moving an awaiting-fix issue from `Backlog` to `Todo`
- any other non-terminal state that differs from the configured state for the desired model state

Terminal states (`Done`, `Cancelled`) are never preserved: the sync always transitions to a terminal state when the Snyk finding is fixed or ignored, even if a user manually moved the issue to a terminal state.

### Due Dates

Due dates are normally derived from the Snyk issue creation timestamp, not from when the issue first appears in Linear. For temporarily ignored issues, the due date is instead calculated from the ignore expiry date so the SLA extends to the normal severity offset from when the ignore expires.

Issues ignored "until fix is available" have no due date. The SLA clock is paused while the issue is blocked on an upstream fix. When a fix becomes available, Snyk flips `ignored=false` and the next run recalculates the due date from fix availability (today + severity offset), moving the issue to `Todo`.

Default offsets:

- critical: 15 days
- high: 30 days
- medium: 45 days
- low: 90 days

## Performance Model

The project is designed for thousands of issues.

It uses:

- concurrent Snyk and Linear snapshot loading
- worker-based reconciliation
- batched Linear mutations
- rate-limit backoff
- SQLite caching

The cache is critical for steady-state performance. A healthy steady-state run should do little or no work when nothing has changed.

## SQLite Cache

The SQLite cache stores:

- Snyk-side normalized hashes keyed by fingerprint
- Linear-side normalized hashes keyed by fingerprint
- a schema signature for the managed issue format

The cache is used only as an optimization. It should never be the only source used to infer real current state.

Normal behavior:

1. Read live Snyk data.
2. Read live Linear data.
3. Compare both against the last successful cached hashes.
4. Skip unchanged fingerprints.
5. After successful writes, refresh the cache from the live post-write Linear snapshot.

The post-write refresh matters because Linear may rewrite markdown bodies after mutation.

## Safety Assumptions

- The metadata block must remain intact.
- The managed description body is owned by this tool.
- Linear issue history matters, so deleting and recreating all issues is a last resort, not a normal repair path.
- Cache bypass is the correct operator action when the rendering schema or compare logic changes.

## Operator Guidance

After any code change, run the full verification suite (see README for the
rationale behind the ordering):

```bash
go mod tidy && git diff --exit-code go.mod go.sum
go fix ./... && git diff --exit-code
go fmt ./...
go build ./...
go vet ./...
go test ./...
```

Use a normal run for day-to-day sync:

```bash
go run ./cmd/snyk-linear-sync --env-file .env
```

Use a dry run to inspect planned changes:

```bash
go run ./cmd/snyk-linear-sync --env-file .env --dry-run
```

Use cache bypass when you intentionally changed the managed rendering or need a full live reconciliation:

```bash
go run ./cmd/snyk-linear-sync --env-file .env --bypass-cache
```

## Design Boundaries

If this project grows further, the next reasonable extensions would be:

- stronger incremental Snyk fetching using server timestamps where available
- more selective Linear snapshot loading if the API surface allows it safely
- richer cache statistics and observability
- explicit conflict reporting output

The current implementation is intentionally optimized for correctness first, then steady-state efficiency.
