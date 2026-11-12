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
snyk:<project-id>:<issue-id>[:<location>]
```

That fingerprint is embedded in the Linear description metadata block and is the durable join key between systems. `<location>` (source file for code issues, `package@version` for dependencies) separates occurrences that share a Snyk issue ID.

Without that fingerprint, the sync cannot safely deduplicate or update issues.

The metadata block also carries a project-independent `identity`: a hash of the project's origin, name, target file, target reference, repository and Kubernetes cluster, the issue key, and the location. The cluster is included because Snyk's Kubernetes project names carry no cluster, so the same workload in staging and prod would otherwise share an identity. It exists because Snyk sometimes recreates a project under a new project ID, which changes every fingerprint for findings that are otherwise the same. Identity is used only to decide which existing ticket a finding is matched to; ticket content and state still derive only from current Snyk data.

Matching order for each finding:

1. exact fingerprint
2. coarse fingerprint (migration of pre-location tickets; open tickets only)
3. identity rebind: a ticket with the same identity whose project is not active, and which is either open or `Cancelled` with a sync-recorded `closed_reason` of `project-missing`/`project-deactivated`. Never a ticket of an active project, one closed by a fix or a person, or an archived one. Each candidate is used once; open tickets are preferred, then the most recently created.

A failed Kubernetes cluster lookup makes the cluster unknown (not "no cluster"): those findings get no identity for the run, keep their tickets' stored identity and Cluster line, never rebind, and defer creating a new ticket only when a rebind candidate could be theirs and is still open or was closed less than 24 hours ago (so a persistent failure hides a finding for at most about a day).

Linear is the only durable state: identity and `closed_reason` live in the metadata block, not in the SQLite cache. Tickets written before the identity line existed gain it on their next update, which on the first run after upgrading is a one-time, metadata-only update of every matched ticket.

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

When a previously tracked finding no longer exists because its Snyk project no longer exists, cancel the Linear issue instead. When the sync itself closes an open ticket this way it records `closed_reason: project-missing` (or `project-deactivated`) in the metadata block, so a later run can tell the closure was machine-made and rebind the ticket if the project is recreated. A ticket that is already closed keeps its state and records no `closed_reason`: a `Done` ticket stays `Done`, because the project going away says nothing about how the ticket was closed.

### Reopen Guard

A terminal ticket is not reopened when Snyk reports its finding as open again; a fresh ticket is created instead, because Snyk reuses issue IDs across different code (#28). Two exceptions:

- a rebind of a sync-cancelled ticket after project recreation (see Identity Model);
- an exact, location-bearing fingerprint match whose ticket has known creation and closed times in Linear, where Snyk's `last_resolved_at` (the latest across the issue's coordinates) is empty or earlier than the ticket's creation. The finding was then open for the ticket's whole life, so the closure was premature (for example an automation) and the ticket is reopened (among several closed copies with that fingerprint, the most recently created one is checked and becomes canonical) with the reason "Snyk still reports this finding as open; reopened instead of creating a duplicate". This cannot reintroduce #28: an issue-ID reuse starts with Snyk resolving the old occurrence, which shows as a `last_resolved_at` after the ticket's creation. The comparison is deliberately against creation rather than closure, because the sync closes a ticket on a run after Snyk's resolution, so the resolution always predates the closure. An unparsable `last_resolved_at` or a missing timestamp keeps the default behavior.

A reopened ticket (by either exception) moves to the last open workflow state its Linear history shows it in before it was closed, so triage done before the closure (moving it from Triage to Todo, or into progress) survives. Only states of the team qualify. When the history yields none or cannot be read, the reopen still happens, into the configured open state.

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

Linear may rewrite parts of the description body when rendering or storing markdown. The sync therefore normalizes known Linear formatting changes during compare and cache hashing, including the blank lines Linear inserts after headings.

The compare and the cache hash also ignore the scanned commit and the flagged line region in the `Ref`, `Commit` and `File` lines. Snyk reports a new commit, and often new line numbers, for every Snyk Code finding of a repository on each rescan of its branch, with nothing else changed. A ticket therefore keeps the commit and line links it was last written with; they are permalinks to that commit, and are refreshed whenever anything else about the finding changes.

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

When an issue is in the awaiting-fix state, the sync adds the configured label. When the fix becomes available and the issue moves to `Todo`, the label is removed. The label is tracked in the metadata block alongside tool and origin labels. The metadata block also carries an `awaiting_fix: yes` marker, written whenever the finding is in the awaiting-fix state regardless of the label configuration, and cleared when the state ends.

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

The `ignored until fix available` state is distinct from other ignored states because the ignore is conditional on an upstream fix. These issues are placed in `Backlog` with no due date and the `triage-dependency` label (configurable via `LINEAR_AWAITING_FIX_LABEL`). The description renders `Status: ignored (no fix available)` so the Snyk-side reality is visible in Linear. When a fix becomes available, Snyk flips `ignored=false` and the next run moves the issue to `Todo` with a due date based on the day the ignore ended (see Due Dates).

### Manual Backlog Override

When a user manually moves a managed open ticket from `Todo` to `Backlog` in Linear, subsequent syncs preserve the `Backlog` state instead of overriding it back to `Todo`. This prevents the automation from fighting intentional user triage decisions. The override matches the configured `LINEAR_STATE_BACKLOG` value with case-insensitive normalization.

A ticket in `Backlog` that was previously awaiting a fix moves to `Todo` when Snyk reports `ignored=false`, with a recalculated due date and a change comment explaining the move. The detection reads the `awaiting_fix` marker in the metadata block or, for legacy tickets, the configured awaiting-fix label recorded in the managed labels. The marker is written regardless of the label configuration, so the transition also works with `LINEAR_AWAITING_FIX_LABEL=off`.

Legacy tickets with a usable configured label are recognized even without the marker. A ticket lacking both signals stays in `Backlog` when the fix arrives, unless an earlier awaiting-fix run first adds the marker. The first upgraded run backfills the marker on matched, non-archived tickets that are still awaiting a fix, even if nothing else changed. This is a one-time metadata-only update, without a change comment; subsequent unchanged runs do not repeat it.

The marker and label record awaiting-fix history, not who selected `Backlog`. Consequently, a manual `Backlog` placement made before or during that awaiting-fix period can also move to `Todo` when the fix arrives. Other manually chosen non-terminal states, such as `In Progress`, remain preserved. Distinguishing manual and sync-owned `Backlog` placements requires additional ownership tracking.

### Manual Non-Terminal State Override

When a user manually moves a managed issue to any non-terminal Linear workflow state that differs from what the sync would set, subsequent syncs preserve the user's chosen state. This generalises the previous Backlog-only and hardcoded "Todo" overrides.

This covers:

- a user moving an open issue from the configured open state (e.g. `Triage`) to `Todo` or `In Progress`
- a user moving an awaiting-fix issue from `Backlog` to `Todo`
- any other non-terminal state that differs from the configured state for the desired model state

Terminal states (`Done`, `Cancelled`) are never preserved: the sync always transitions to a terminal state when the Snyk finding is fixed or ignored, even if a user manually moved the issue to a terminal state.

### Due Dates

Due dates are normally derived from the Snyk issue creation timestamp, not from when the issue first appears in Linear. For temporarily ignored issues, the due date is instead calculated from the ignore expiry date so the SLA extends to the normal severity offset from when the ignore expires. The expiry keeps being the base after the ignore has lapsed, including once Snyk itself no longer reports the ignore: the sync remembers it (see Ignore Memory under SQLite Cache).

Issues ignored "until fix is available" have no due date. The SLA clock is paused while the issue is blocked on an upstream fix. When a fix becomes available, Snyk flips `ignored=false`; the sync records the day it first saw that in its ignore memory, and from then on the due date is that day + severity offset ("fix availability"), so every run computes the same date. An ignore of this kind that reaches its own expiry with no fix is treated as an expired snooze: the expiry stays the base and the reason says so. A revoked ignore until fix available is dated the same way as a fix arrival, from the day the sync first saw it un-ignored.

Every base is taken as a UTC calendar date, so the result does not depend on the host's time zone.

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
- the sync's memory of Snyk v1 ignores, per project and issue key (below)

The hashes are used only as an optimization and are never the only source used to infer real current state. The ignore memory is the one exception, by necessity: it holds what Snyk reported and has since stopped reporting.

Normal behavior:

1. Read live Snyk data.
2. Read live Linear data.
3. Compare both against the last successful cached hashes.
4. Skip unchanged fingerprints.
5. After successful writes, refresh the cache from the live post-write Linear snapshot. When several tickets share a fingerprint, the cached Linear hash is that of the ticket the finding was matched to, so the next run's comparison against the same ticket can hit.

The post-write refresh matters because Linear may rewrite markdown bodies after mutation.

### Ignore Memory

The Snyk v1 ignores endpoint stops returning an expired ignore after an undocumented period, while the expiry is the base of the ticket's due date for good. The `snyk_ignores` table remembers, per project and issue key, the expiry, the disregard-if-fixable flag, when the v1 API last confirmed the ignore (`updated_at`), and when an ignore until fix available stopped applying (`unignored_at`). Nothing is aged out on read. Snyk stays authoritative: which rows survive a run is decided once every REST issue of the project has been seen, so a row is only forgotten when Snyk contradicts it.

Per project and key, at the end of the Snyk snapshot load:

- a key the v1 API returned this run is stored as the summary of the union of API and cached entries (the latest created entry decides, a permanent ignore zeroes the expiry, the expiry is a high-water mark) and its confirmation time is refreshed;
- a key the API did not return is kept while any REST issue it can apply to still reports `ignored=true` (Snyk asserts the ignore; this wins over an un-ignored sibling under a rule key), while its expiry has passed (it is the due-date base), while it is an ignore until fix available (its end is the due-date base), and while no open un-ignored REST issue matches it (resolved or disappeared: the row is inert);
- an active snooze (expiry ahead) whose finding Snyk reports open and not ignored is kept for seven days of grace against partial v1 responses, then dropped and logged: Snyk revoked it.

A failed or 404ing v1 fetch falls back to the cached rows and never ages one into a drop. A row written before `updated_at` existed, or whose value cannot be parsed, is kept with an unknown confirmation time; its grace clock starts on the next write.

The `unignored_at` stamp is set on a disregard-if-fixable row the first run on which every REST issue carrying the ignore reports `ignored=false`, kept from then on, and cleared while the issue is ignored again. Findings carry it as `IgnoreEndedAt`. A newer ignore creation resets a direct key's old end even if its whole lifecycle occurred between snapshots; the next observation is the known end, not a claimed actual lift time.

The `observed_issues` column also preserves the effective metadata and first observed end per REST finding seen ignored under a key. Historical rule-key lookup requires that evidence, because v1 rule keys can include path-scoped ignores and never-ignored siblings must keep their own SLA. A newer rule ignore for a sibling does not replace an already actionable finding's observed metadata. Superseding or revoking a newer rule ignore preserves older expired-snooze or until-fix observations belonging to other findings. Cached-only rule metadata cannot establish a new finding association, and a newer direct-key ignore prevents attributing an older rule ignore to that finding. Legacy rule rows have no recoverable per-finding scope. For an open, unignored occurrence, ignore metadata predating a known resolution of every coordinate is excluded so issue-ID reuse does not carry an old ignore deadline forward.

When a configured ignore-memory store cannot be read or written, snapshot loading fails before any Linear reconciliation. Newly observed ignore ends must be persisted before they can become SLA bases; a retry reuses only durable history rather than publishing a date that would be forgotten after a failed write.

### Cold-Start Guard

With an empty ignore memory, the sync cannot tell an earlier due date that is a real change from one that merely reflects an expiry it no longer knows about. A run that starts with no cached ignore rows while the Linear snapshot holds managed open tickets with due dates therefore engages a guard: for a matched open ticket whose desired due date is earlier than its current one, the current date is kept this run (the reason says why) and the run warns with the count, reported as `held_due_dates`. Later dates still apply. Before loading can populate the cache, `ignores_memory_state` in `sync_meta` records a pending empty start. Both sync and diagnostic Snyk loads preserve this evidence across failures or interruptions, even when rows were already committed. After a successful pair of snapshots, an open dated ticket promotes that pending state to the `ignores_cold_start_at` guard; otherwise memory is marked trusted and no guard is engaged. The guard holds until `--clear-ignores-cold-start` records trusted memory and removes the marker. Trust persists even when the table stays empty, including on subsequent normal runs. Deleting only the guard key does not release pending memory; use the flag.

## Dry-Run Plan Export

`--dry-run --plan-json <new-private-file>` exports versioned JSON from the same
reconciliation decisions as a normal run. It does not recompute a parallel plan,
reorder matching inputs, reload either initial snapshot, or invoke mutation-time
state/label resolution. The exporter is disabled by default, rejects non-dry-run
use before loading, and returns a complete plan only after successful source
loading and reconciliation. The CLI creates an exclusive `0600` file; existing
paths and final-component symlinks are refused. Consumers must require successful
process exit and the complete flag.

Coverage includes every initial finding and ticket, with a matched pair in one
record and explicit records for superseded source fingerprints, deferred creates,
archived/unchanged/cache-suppressed tickets, terminal duplicates and rejected
reopens. One-based input indexes allow coverage checks. Selected mutation totals
must match the existing dry-run counters. Export rejects missing or repeated
Linear issue IDs rather than claiming untrustworthy per-row decision provenance;
this validation does not change the ordinary sync path. Each mutation is
`not_attempted`, never
reported as successful; no Linear writes or sync-hash saves are performed.
Read-only reopen history requests remain part of planning, and lookup errors are
reported without exporting their potentially sensitive error text.

The sanitized schema records due-date inputs, the raw SLA deadline before
sticky/cold-start overrides, proposed/planned dates, reasons, held status,
state/reopen/history intent, requested labels and change flags. It does not export
ticket prose, URLs, source paths, credentials or raw location-bearing fingerprints.
Raw SLA dates are empty while awaiting a fix. A non-mutation record keeps its old
planned date; candidate change flags may still show a cache-suppressed difference.
State/label resolution is explicitly unattempted: actual writes resolve workflow
states and label IDs/groups, reread live labels, preserve unmanaged labels and
apply protected/exclusive-group rules. The export must not be treated as final
mutation payloads or as a prediction of write success.

Full ordered snapshots and an explicit credential-free configuration allowlist
are hashed separately from the sync cache and selected decisions. Sorting output
records provides stable serialization for identical ordered inputs without
changing input-order-sensitive matching. The tool revision and exact cache file
must be bound separately when approving a later run. Source drift and concurrent
Linear edits can still change a live result.

Dry run retains existing local ignore-memory and cold-start/trust metadata
writes, including clear-marker behavior. Operators must use a disposable cache
copy and retain the untouched candidate separately when collecting previews. The
artifact itself remains private operational data (ticket IDs, state/label names
and timestamps), even though sensitive prose and raw source identities are omitted.

## Reviewed Reconciliation Preflight

The optional paired `--reviewed-plan-json` and `--reviewed-plan-sha256` flags
require live mode. The reader pins exact accepted artifact bytes, strictly validates
version, completeness, input/record digests, coverage, operation totals and history
status, and loads the file only once. A guarded run buffers the entire fresh
reconciliation after overrides and history reads, validates the finished plan
against all accepted fields, and only then invokes Linear mutation methods for
that same buffer. A mismatch, cancellation before dispatch or incomplete required
history read results in zero Linear mutation attempts. Guarded jobs run serially,
stop on partial/uncertain failure, and disable replay in the service, GraphQL
client and HTTP transport. Missing mutation acknowledgments or generated IDs
stop guarded dispatch, as does failed post-create subscription cleanup. The
ordinary unguarded retry and best-effort cleanup behavior remains unchanged.
Dispatch errors preserve their client cause and operation/batch context,
including returned failed-item indexes, without retrying or continuing writes.
Guarded execution requires an immutable configured Linear team UUID, rather than
a workspace-relative team key. Its exact value is already included in the
settings digest, and the Linear client uses that same UUID directly as the
mutation destination. A preview generated with a team key must be regenerated
and reviewed with the UUID. No credential hash is used as destination identity.
Guarded HTTP calls do not follow redirects, including mutation-body-preserving
307/308 redirects. Ordinary calls retain the default ten-redirect limit.

This is input/decision equivalence only. The executable/build must be externally
pinned: version 1 does not bind generator code or final mutation payloads. Its
snapshot hashes do not include raw history events or the workflow inventory;
history is bound through successful complete reads and the selected restore-state
decision. Workflow
and label resolution, live-label rereads, generated comments, and create cleanup
remain in the ordinary mutation client. Remote systems expose no transaction or
compare-and-swap through this path. State can change after the check, and a late
failure can leave earlier writes committed. This does not satisfy an exact-payload
or all-or-nothing apply contract; those require a separately versioned prepared
operation format and prepare/execute boundary, and still cannot eliminate remote
races without server support. Local ignore/cache metadata is not rolled back.

History and workflow inventory reads fail when responses omit required
containers, nodes, fields or page data, or when continuation cursors are absent,
empty, repeated or exceed the page limit. Partial workflow inventories are not
installed in the client cache.
Each retried read decodes into a fresh response and publishes it only on success,
so data from a failed earlier attempt cannot supply fields omitted by the retry.
The Linear issue snapshot also requires a complete issue connection/page marker
and identified non-null rows. Missing, empty or repeated continuation cursors
and snapshots exceeding 10,000 pages fail instead of returning partial data.
A complete history containing no prior open state remains a valid fallback case.


## Replay-safe Observation Input

The opt-in version-2 plan contract requires validated fresh Snyk reads and
canonicalizes full snapshots before both matching and hashing. It retains all
raw field values and duplicate semantic-set entries, rejects ambiguous source
fingerprints and JSON field aliases, and makes buffered reconciliation order
deterministic. Case-distinct map identities remain separate; project-only metadata
reads exclude non-project scan items. Matching
semantics can differ from version 1, including canonical duplicate selection for
coarse migration; a new plan and independent review are mandatory. Version 1 is
not silently normalized or upgraded.

An observation-only checkpoint is a separate preparation boundary, not a normal
preview database promoted for execution. It starts from checksum-pinned trusted
source bytes, runs only the Snyk loader with strict source reads, and emits a new
private candidate plus a complete hash-bound receipt only after SQLite closes.
Candidate and receipt creation and cleanup are leaf-only operations relative to
a retained private parent-directory handle. Replacement of the parent or candidate
refuses publication; cleanup does not follow a replaced pathname. SQLite still
reopens the absolute candidate pathname, so its directories must remain
single-writer throughout preparation.
Protected reconciliation hashes and prior cold-start provenance must remain
unchanged. Schema is preserved except for the reviewed nullable `unignored_at`
and `observed_issues` additions to supported legacy ignore tables; the receipt
binds the final schema and every other schema change is rejected. An empty-start
pending marker is preserved. The command does not construct a Linear client,
reconcile, save sync hashes, or authorize writes.

Observation timestamps become durable inputs to subsequent fresh preview and
reviewed execution, each on independent untouched checkpoint copies. Real-time
expiry, revocation grace and deferral behavior stays current; new transitions and
drift still refuse exact replay. Source provenance checks reject unavailable
required reads even when cache fallback would produce identical findings.
Received response validation cannot establish an atomic remote snapshot or detect
truthful-looking server omissions.

Consumers remain responsible for authenticating and accepting receipt/candidate/
plan bytes, pinning the executable and destination, limiting review age, rejecting
future timestamps, and holding a single-writer cache-generation lease through
execution/publication. The receipt records a read interval, not one event time.
This interface does not remove remote races or freeze mutation-time metadata/API
payloads. See README for the command contract and remaining integration gates.

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

Cache bypass does not touch the ignore memory. After a run has warned that the ignore cache was cold, release the held due dates once the cache is trusted (for example after the ignores have been re-seeded from Snyk and checked):

```bash
go run ./cmd/snyk-linear-sync --env-file .env --clear-ignores-cold-start
```

## Design Boundaries

If this project grows further, the next reasonable extensions would be:

- stronger incremental Snyk fetching using server timestamps where available
- more selective Linear snapshot loading if the API surface allows it safely
- richer cache statistics and observability
- explicit conflict reporting output

The current implementation is intentionally optimized for correctness first, then steady-state efficiency.

## Single-Snapshot Bounded Reconciliation

The explicit `--plan-and-execute-bound --replay-safe` live mode accepts operator
bounds rather than an independently reviewed prior snapshot. It requires all of
`--max-creates`, `--max-updates`, `--max-resolves`, `--max-cancel-duplicates`
(canonical decimal integers in `[0, 999999]`), an immutable destination team
UUID, and a new `--plan-json` file. Reopens consume update capacity; duplicate
cancellations have an independent bound. Dry-run, reviewed-plan and checkpoint
modes and clearing cold-start protection cannot be combined with this mode.

It reserves a new private `PLAN_PATH.receipts` directory under a physical,
mode-0700 parent before loading. The service loads source snapshots once,
buffers every job, finishes the complete v2 plan, validates coverage, actions
and reopen history, verifies exact job/record correspondence, and enforces
aggregate limits. Before dispatch it exclusively creates and fsyncs the
requested plan file and `attempt.json` in the receipt directory (mode 0600),
then fsyncs their directories. The attempt binds exact plan-file bytes and a
digest of the full buffered job payloads, with aggregate counts, limits and a
start timestamp. Exactly one `bound plan written` message carries the raw
plan-file SHA-256 after binding and before dispatch. Raw source snapshots and
payloads remain in memory. Receipt paths cannot overwrite existing attempts or
follow symlinks, and retained directory handles prevent renamed parents from
redirecting receipt writes. Artifact and payload tampering is checked before
dispatch. The operator controls and protects the private parent against
concurrent modification; receipts are local evidence, not signatures.

A validated plan and matching buffered jobs that exceed any limit instead
produce a private, exclusively created and fsynced `refusal.json` (at most
4 KiB). Its version-1 schema contains status `limits_exceeded`, the four
aggregate counts and configured maxima, and the exact nonempty `exceeded`
category list in creates/updates/resolves/cancel_duplicates order. No source
payloads, identifiers or hashes are included. The returned typed `BoundLimitError`
also exposes these aggregates. Malformed plan/job evidence is rejected before
emitting this diagnostic. Refusal persistence errors remain fatal. Rejection
writes no plan or attempt, attempts no Linear mutations, and saves no sync
hashes; the final result remains `failed_before_writes` with zero batches and
`not_saved`. Refusal evidence neither authorizes execution nor allows directory
reuse, and consumers must validate its schema and consistency with the result.

Execution sends those same jobs sequentially through the existing no-retry
guarded dispatch path. A partial or uncertain response, cancellation, or receipt
verification failure stops subsequent jobs; no sync hashes are saved on an
incomplete execution. Follow-on writes and mutation-time metadata resolution
remain non-atomic. `PLAN_PATH.receipts/result.json` separately records
conservative attempted and acknowledged batch counts, write-attempt status,
bound hashes, completion time, cache status and final success/failure, without
private API error text. Death before a final receipt leaves a consumed,
potentially uncertain attempt, never a successful one. Output failures fail the
process and never erase the reservation.

Only complete execution saves sync hashes. A configured cache requires nonempty
Snyk hashes before the write gate. After executing all buffered jobs, bounded
mode performs one mandatory post-write Linear read solely for cache evidence. It
cannot replan, enqueue jobs or trigger another mutation. Failed, empty or
malformed reads stop without saving hashes; bounded mode never substitutes
pre-write hashes. Successful refresh saves nonempty current Linear hashes using
the existing canonical matched-ticket cache selection. Ordinary and
reviewed-mode refresh behavior remains unchanged. Cache-save failure cannot
claim success.

Loader observation and cold-start metadata may already have changed, so callers
must isolate the cache and publish only after successful exact readback. Callers
also own source/executable provenance, freshness, single-writer exclusion and a
durable attempt-one guard across paths. Retain the exact plan, hash-bound
attempt, any refusal diagnostic and any final result privately for at most seven days, including on
partial or uncertain failure, before cleanup removes job scratch; do not retain
raw API logs or databases as receipt artifacts. Existing ordinary and
independently reviewed-plan behavior is preserved, including strict
JSON/input/decision equivalence for reviewed execution.

### Strict settings-bound execution

For callers that bind execution to previously validated settings, bounded mode
accepts `--expected-settings-sha256` with exactly 64 lowercase hexadecimal
characters. It requires `--plan-and-execute-bound` and refuses an explicitly
empty or malformed digest. Before writing the plan or attempt receipt and before
any Linear mutation, the generated plan must match the expected settings digest
and contain no deferred creates. A mismatch or deferral fails without executing
any buffered jobs. The result receipt retains the existing failed-before-writes
status. Omitting this option preserves existing manual bounded behavior. The
option does not change the settings digest, count limits, job binding, retry
policy or cache-publication requirements.

### Bounded drain protocol primitives

The drain protocol uses a separate `<managed-schema>+drain-v1` cache signature
and the `bounded_drain_pending` and `bounded_drain_hash_evidence` metadata rows.
Both rows, the signature, and both hash tables are committed in one SQLite
transaction. A legacy save cannot overwrite a drain generation, including a
partially damaged generation. This does not retrofit fences into older binaries;
callers must isolate the drain cache namespace and reject it in legacy routes.

The selector validates the complete plan and its jobs before selecting whole
causal groups. Work keys are `issue:<id>` or `create:<fingerprint-sha256>`.
Duplicate issue targets refuse. Duplicate cancellation follows its canonical
copy's mutation; an identity rebind follows creates that lost the same nonempty
identity. Shared coarse fingerprints alone do not create dependencies. Groups
are ordered by oldest pending generation then smallest work key. The total
budget is at most 100 and independent per-kind ceilings still apply. Selected
jobs are rebuilt in stable batches of at most ten and revalidated.

Deferred and unverified operations retain their first pending generation and
withhold every affected fingerprint. Three consecutive unverified generations
refuse further progress. Disappeared work is removed, so genuinely new work gets
a new age. Verification uses freshly read issue IDs and desired managed fields;
create acknowledgements preserve those IDs even on partial errors. An unchanged
retained terminal copy is allowed when the newly created ticket is canonical.

Evidence is built after matched and acknowledged-create ID hash overrides. It
contains only pre-write keys and keys selected operations may introduce.
Concurrent arrivals are counted but omitted from saved hashes. Deferred,
unverified and unrelated drifted keys are withheld, and saved hashes are exactly
the refreshed evidence minus the withheld set. An evidence-backed empty map is
valid. Entry and byte bounds are checked before dispatch, with a no-save,
uncertain-result overflow backstop after writes.

These protocol primitives are not yet connected to an execution flag. Producer
artifact admission, version-2 receipt integration, and generation initialization
must be completed and reviewed before drain execution is available. Structural
cache validation alone does not prove producer provenance. Missing producer
receipts must refuse without resetting pending ages or initializing a new cache.

### Acknowledged create outcomes

Create batches return one indexed outcome per input, retaining acknowledged IDs
and identifiers even when another alias or response processing fails. Each
create mutation request is sent once. Guarded execution never retries partial
or uncertain outcomes. Ordinary execution retries only explicitly rejected
aliases from a complete error-free response, once; missing aliases, empty IDs,
transport errors and partial GraphQL errors stop without retrying the batch.

The cap counts issue reconciliation operations, not every API mutation.
Subscription cleanup after creates and auxiliary comments are separate effects;
future execution receipts must report them explicitly. Before runtime wiring,
the evidence contract must also represent same-fingerprint membership drift:
matched-ID hash overrides alone can hide a new competing copy even when the
canonical issue hash did not change. This remains a required integration gate,
not a case that the current collapsed hash evidence can prove safe.
