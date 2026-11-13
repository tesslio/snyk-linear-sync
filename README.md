# snyk-linear-sync

Sync Snyk findings with Linear issues since there isn't an official integration.

Repo:

```text
github.com/tesslio/snyk-linear-sync
```

## What It Does

- Authenticates to Snyk with OAuth client credentials.
- Reads all projects in one configured Snyk org.
- Normalizes Snyk findings into one Linear issue per `project + issue`.
- Stores a stable fingerprint in a hidden metadata block in the Linear issue description.
- Embeds Snyk issue details (fix availability, CVSS, CWE class(es), CVE identifier(s), vulnerability description, and remediation guidance) in the Linear ticket body so consumers do not each need Snyk API credentials.
- Optionally renders GitHub source file and commit links when source hosting is configured as `github`.
- Enriches tickets for Kubernetes-integration projects (`origin: kubernetes`) with the cluster (from the Snyk v1 project detail's `imageCluster`) and namespace (parsed from the `<namespace>/<kind>.<group>/<workload>:<target>` project name; only the segment before the first `/` is used) at the top of the description.
- Creates missing Linear issues.
- Updates existing Linear issues when managed fields change.
- Ensures a configurable managed label is applied to all managed issues, unless label management is explicitly turned off.
- Moves stale issues to the configured resolved state when the finding is no longer present but the Snyk project still exists.
- Cancels managed Linear issues when their Snyk project no longer exists, such as after project deletion.
- Rebinds a ticket to its finding when Snyk recreates the project under a new project ID (see [Project Recreation](#project-recreation)), instead of cancelling it and creating a copy.
- Reopens a ticket that was closed while Snyk kept reporting the exact same occurrence as open, instead of creating a duplicate (see [Reopen Guard](#reopen-guard)).
- Uses a local SQLite cache to skip unchanged findings and unchanged Linear issues on steady-state runs, and as its memory of Snyk ignores that Snyk has since stopped reporting (see [Cache Behavior](#cache-behavior)).
- Sets Linear due dates from Snyk issue creation time using configurable per-severity offsets, or from the ignore expiry or the day an ignore until fix available ended (see [Due Dates](#due-dates)).

The fingerprint format is:

```text
snyk:<project-id>:<issue-id>[:<location>]
```

`<location>` is the source file path for code issues or `package@version` for dependency issues. It is omitted when Snyk reports no coordinates.

## Running

Quickstart without cloning:

Create a local `.env`, then run directly with the repo path:

```bash
go run github.com/tesslio/snyk-linear-sync/cmd/snyk-linear-sync@latest --env-file .env --dry-run
```

Or install the binary:

```bash
go install github.com/tesslio/snyk-linear-sync/cmd/snyk-linear-sync@latest
snyk-linear-sync --env-file .env --dry-run
```

Default usage is to pass a dotenv file explicitly:

```bash
go run ./cmd/snyk-linear-sync --env-file .env --dry-run
```

That avoids shell-specific `source` behavior and is the recommended way to run the tool.

Dry run:

```bash
go run ./cmd/snyk-linear-sync --env-file .env --dry-run
```

Export a private per-ticket dry-run plan to a **new** file:

```bash
go run ./cmd/snyk-linear-sync --env-file .env --dry-run --plan-json private-plan.json
```

`--plan-json` requires `--dry-run`. It writes JSON with file mode `0600` and
refuses to overwrite an existing path (including a symlink). The plan is emitted
only after both source snapshots and reconciliation complete successfully. A
failed or interrupted process does not supply a usable plan: require exit code
zero and `complete: true` before consuming an artifact.

The versioned plan covers each source finding and each ticket in the initial
Linear snapshot, including creates, updates, resolutions, duplicate cancellation,
cache hits, unchanged or archived tickets, deferred creates, and closed tickets
retained by the reopen guard. One-based snapshot indexes account for coverage;
a matched finding and ticket share a record. Repeated source fingerprints that
were overwritten during reconciliation have an explicit superseded record.
Mutation counts are checked against the normal dry-run counters.
Snapshots with missing or repeated Linear issue IDs fail export without producing
a complete plan: ambiguous rows cannot be assigned trustworthy per-row decisions.
This validation is export-only and does not change the ordinary sync path.

Records include old, calculated and proposed/planned due dates, the raw SLA
deadline before sticky-date/cold-start overrides, source timestamps, reasons and
held-date status. They also include state-preservation and reopen/history intent,
requested managed/create-only labels, snapshot label names, and sanitized change
flags (including metadata-only changes). `candidate_diff` describes the candidate
fields even if a cache hit suppresses an operation. `planned` due dates remain
unchanged for non-mutation records. Raw SLA deadlines are empty while awaiting a
fix. State names/IDs and labels are **intent**, not fully resolved mutation input:
real writes resolve workflow states and label IDs/groups and reread live labels.
Protected-label and exclusive-group rules still apply at mutation time.

All operations say `execution_status: not_attempted`. No Linear writes, comments,
label creation, or sync-hash saves occur. This does not predict whether a later
live operation will succeed. Reopen history may require read-only requests;
`reopen_history_status: partial_or_failed` reports a history lookup error, and a
record without a restored state uses the normal configured-state fallback.

**Dry runs still update local ignore memory and cold-start/trust metadata.** Use
a disposable copy of the intended cache when comparing plans, including when
using `--bypass-cache` or `--clear-ignores-cold-start`. Keep an untouched candidate
cache separately. The export contains private ticket IDs/identifiers, state and
label names and timestamps; keep it private. It omits titles, descriptions, URLs,
source paths, credentials and raw Snyk fingerprints. Fingerprint identities and
full source/configuration/sync-cache inputs are SHA-256 digests. Input hashes
preserve snapshot order because matching can depend on that order. Output record
ordering is stable for identical inputs; this does not change the matching order
or promise identical decisions for reordered/changing snapshots. Bind an approval
to the exact tool revision and cache artifact separately; the plan is not a lock
on either service.

Normal run:

```bash
go run ./cmd/snyk-linear-sync --env-file .env
```

Installed binary:

```bash
snyk-linear-sync --env-file .env
```

Bypass cache:

```bash
go run ./cmd/snyk-linear-sync --env-file .env --bypass-cache
```

Release due dates held back by the ignore-cache cold-start guard (see [Cache Behavior](#cache-behavior)):

```bash
go run ./cmd/snyk-linear-sync --env-file .env --clear-ignores-cold-start
```

`--env-file` uses `github.com/joho/godotenv`, so the file can be a normal dotenv file and does not need to be sourced by your shell.

### Reviewed reconciliation guard (preflight only)

An opt-in live run can require the exact input and decision plan accepted by an
operator. Supply the private artifact and its independently reviewed file-byte
SHA-256 together:

```bash
go run ./cmd/snyk-linear-sync --env-file .env --reviewed-plan-json private-plan.json --reviewed-plan-sha256 <reviewed-file-sha256>
```

Use the same externally pinned executable/build, configuration, and untouched
candidate cache for preview and guarded execution. The accepted digest must come
from the actual review, not be calculated automatically from a replacement plan.
Guarded execution requires `LINEAR_TEAM_ID` to be the immutable team UUID, not
a symbolic team key. Generate the reviewed preview with that same UUID. Team
keys can resolve to a different team after credentials or workspace changes;
changing a key-based preview to a UUID at execution changes the settings digest
and requires regenerating and reviewing the preview. Credentials are never hashed.
The process reads accepted bytes once, rejects malformed/incomplete plans or
incomplete reopen history, and recomputes the entire reconciliation from fresh
snapshots. All input hashes, records, totals, guard and history status must match
before any Linear mutation method is called. Jobs are buffered until this check
passes and that same buffer is executed serially. A partial or uncertain mutation
response stops subsequent jobs without an automatic retry in the service,
GraphQL client or HTTP transport. Missing mutation acknowledgments or generated
IDs, and failed post-create subscription cleanup, also stop guarded dispatch.
HTTP redirects are not followed during guarded calls, including 307/308 POST
redirects which would otherwise replay the mutation body.
Read retries never merge data from failed attempts into a later response.
The Linear snapshot reader rejects missing connection/page data, null or
unidentified issue rows, missing or repeated continuation cursors, and snapshots
exceeding 10,000 pages rather than treating partial data as an empty import.
Review actual remote state before attempting another run.
Stopped-run errors retain the client cause, operation, batch size and available
failed-item indexes so operators can investigate without automatically retrying.

**This is a reconciliation preflight, not exact payload approval or an atomic
transaction.** Version 1 does not commit final title/description/comment contents,
resolved workflow/label IDs and groups, final replacement label sets, subscription
cleanup, or mutation order. The Linear client resolves metadata and rereads labels
later; its create path may perform unsubscribe cleanup. Source and Linear state
can change during and after snapshot loading. No compare-and-swap or rollback is
provided, so earlier operations can succeed before a later failure. Exact ordered
snapshot hashes deliberately reject even a benign row reorder or timestamp change.
Raw history events and the workflow inventory are not hashed; history commits
to a successful complete read and the selected restore-state decision only.
A passing guard is not proof that writes succeeded or that remote state remained
unchanged. It is insufficient on its own to authorize a production cutover whose
contract requires frozen final payloads or no post-check drift.

Local ignore-cache and trust metadata may change even when the guard rejects a
run. Keep the source candidate cache immutable and use a disposable copy. The
ordinary unguarded mode retains its existing behavior; these options do not make
all live runs guarded. Successful guarded live runs do not export a dry-run plan
as an execution receipt.


### Replay-safe plans and observation checkpoints

`--replay-safe` opts plan export and reviewed execution into version 2. It
requires complete validated fresh Snyk reads, including readable ignore metadata
for project scan items and known cluster context for included findings, then
canonicalizes source and ticket ordering before both matching and hashing.
Excluded non-project scan items do not require project-only metadata reads. Unavailable required reads,
malformed or repeated pages, ambiguous JSON field aliases or source fingerprints,
and missing required context fail closed. Case-distinct map identities remain
separate rather than being folded together.
Legitimate retained historical ignore memory remains an explicit input. This
validates received response completeness, not an atomic server snapshot.

Version 2 sorts semantic sets without removing duplicate entries or changing raw
values. It also makes buffered job production deterministic and chooses the final
canonical duplicate before coarse migration. These changes can select different
matches from version 1. Generate and review a **new** version-2 plan; never convert
an accepted version-1 artifact. Versions must match the selected mode. Ordinary
version-1 behavior and its order-sensitive comparison remain available unchanged.

A preview can discover a first-observed ignore ending that is not present in the
source database. Repeating from that unmodified database observes a different
wall-clock time. To prepare deterministic observation input separately, use:

```sh
mkdir -m 700 private-observation
go run ./cmd/snyk-linear-sync --env-file .env \
  --observation-checkpoint private-observation/candidate.db \
  --observation-source-sha256 <accepted-source-file-sha256>
```

`CACHE_DB_FILE` names the existing trusted source. The command requires the exact
source digest and an immutable `LINEAR_TEAM_ID` for settings binding, but does not
require a Linear API key or construct a Linear client. It creates a new private
DB and a matching `.json` receipt, refuses overwrites and SQLite sidecars, and runs
only the strict Snyk loader. It preserves reconciliation hashes and prior
cold-start metadata. The sole permitted schema changes add missing nullable
`unignored_at` and `observed_issues` columns to supported six- or seven-column
legacy ignore tables; all other schema changes are rejected. The receipt binds
the resulting schema. Seeding an untrusted empty source preserves `pending` rather
than making the cache trusted. Failed or incomplete preparation discards its new
candidate. The original source is not opened for writing. Source paths are
operator-selected; reads open only a single leaf inside an opened parent directory
and reject symlinks, sidecars, and replacement during the read. Both relative and
absolute checkpoint paths address the same file during SQLite inspection.
Output paths containing `?` are rejected before creation because SQLite interprets
that character as DSN query syntax rather than part of the filename. Candidate and
receipt creation, directory sync, and failure cleanup retain the same private
parent-directory handle. Parent or candidate replacement fails preparation. Keep
the source and output directories single-writer throughout preparation: SQLite
reopens the candidate by pathname between identity checks.

The completed receipt binds source/output hashes, protected logical state,
version-2 settings digest and read provenance. `started_at` is a conservative
freshness-age origin; `completed_at` is not the time of every stored observation.
The receipt is not authentication or an execution authorization. Separately bind
its exact bytes, checkpoint bytes, tool revision/build and complete plan to an
independent review. Keep the source under an external single-writer lease; local
before/after digest checks cannot prevent a later concurrent write. Use trusted
source bytes and a private owned output directory. Schema inspection verifies
preservation and rejects extra objects, not every possible malicious schema.

Generate a version-2 preview with `--dry-run --plan-json <new-file> --replay-safe`
from a disposable copy of the completed checkpoint. Execute with both reviewed
plan flags and `--replay-safe` from a different untouched copy. Never substitute
a normal preview's mutated database. A new lifecycle, source content change,
revocation-grace/expiry boundary or guard change still invalidates the exact plan.
No global clock is frozen. Choose an explicit maximum review age and reject stale
or future receipts in the consuming workflow.

This upstream interface does not implement artifact distribution, trusted receipt
acceptance, cache-generation locking, or workflow activation. A consumer must
provide those and validate representative read-only API responses first. Unknown
cluster context intentionally blocks strict mode. Version 2 is still a
reconciliation preflight, not frozen final payloads, server-side compare-and-swap,
rollback, or a per-ticket execution receipt. Existing no-retry behavior after
partial or uncertain mutations remains essential.

## Validation

Run these before every commit, in order. Each step catches a different class
of issue and some depend on earlier steps being clean.

```bash
# 1. Reconcile module dependencies first — go fmt/build/vet/test can all
#    fail with a stale go.mod even when the code is correct.
go mod tidy
git diff --exit-code go.mod go.sum

# 2. Apply go fix (may rewrite code, e.g. modernising loop syntax). Review
#    the diff and include any changes in the same commit. Repeat until clean.
go fix ./...
git diff --exit-code

# 3. Format — must come after go fix so you don't re-diff what fix touched.
#    go fmt ./... loads the full module graph and exits non-zero if go.mod
#    needs tidying, which is why step 1 comes first.
go fmt ./...

# 4. Compile, vet, and test.
go build ./...
go vet ./...
go test ./...
```

CI enforces all of these: `gofmt -l`, `go fix` + `git diff --exit-code`,
`go vet`, and `go test` (including `-race`).

## Current Behavior

- Uses `github.com/guillermo/linear/linear-api` plus direct GraphQL mutations for Linear.
- Uses `github.com/pavel-snyk/snyk-sdk-go/v2` where useful, with direct REST calls for issue retrieval.
- Stores a human-facing Snyk UI link in the Linear description.
- Keeps the Snyk REST API link as a secondary reference.
- Includes repository, project reference, target file, and source location details when Snyk provides them.
- Batches Linear create and update mutations to reduce request pressure.
- Retries and backs off on Linear rate limiting.
- Normalizes common Linear markdown rewrites when comparing descriptions so steady-state runs do not churn, and ignores the scanned commit and line numbers of Snyk Code findings, so a rescan that changes nothing else does not rewrite every ticket of the repository. The commit and line links on a ticket are refreshed when anything else about its finding changes.

## Linear Permissions

This project is designed to work with:

- `Read`
- `Create issues`
- `Update issues`

It does not require label creation permissions.
If `LINEAR_MANAGED_LABEL` is enabled, the configured label must already exist in Linear.

## Managed Linear Description

Each managed issue contains:

- a heading with vulnerability title and severity
- repo, ref, and file or target-file context near the top
- Snyk UI and API links grouped together
- package/version details when available
- fix availability, CVSS, CWE class(es), and CVE identifier(s) when Snyk reports them
- vulnerability description and remediation guidance sections when Snyk reports them, so ticket consumers do not each need Snyk API credentials
- project and issue identifiers lower in the body
- GitHub repository, source file, and commit links when `SOURCE_PROVIDER=github` and the finding includes repository, file, and commit data
- GitHub project target file links when `SOURCE_PROVIDER=github` and Snyk provides repository, branch/reference, and target file data but not a precise source location
- hidden metadata block

The metadata block is required for deduplication and safe updates:

```text
<!-- snyk-linear-sync
fingerprint: snyk:proj-123:issue-456:lodash@4.17.20
identity: 3f0c9a1e5b7d2c4a8e6f1b3d5a7c9e0f
managed_labels: snyk-automation,snyk-code
closed_reason: project-missing
-->
```

- `fingerprint` is the exact join key to the Snyk finding.
- `identity` is a project-independent hash of the finding (project origin, name, target file, target reference, repository and Kubernetes cluster, issue key, and location). It is written on every create and update and lets the sync find the ticket again if Snyk recreates the project under a new project ID. Tickets created before this line existed gain it on their next update; the first run after upgrading therefore updates every matched ticket once (a metadata-only change, so no change comment is posted).
- `closed_reason` is present only on tickets the sync cancelled because their Snyk project went missing (`project-missing`) or was deactivated (`project-deactivated`). It marks the closure as machine-made, not a fix or a human decision. It is dropped as soon as the ticket tracks a live finding again.

Changing or removing that block can cause duplicate issues or prevent updates from matching the correct Linear issue.

## Source Links

Use `SOURCE_PROVIDER` to control source-link rendering:

- `unknown` keeps plain-text source file and commit fields
- `github` renders repository, source file, and commit links to public GitHub

For `github`, the file link is commit-pinned and includes line anchors when Snyk provides line numbers.
If Snyk does not provide a source file/commit but does provide `Repository + Project reference + Project target file`, the sync links the project target file in GitHub without line anchors.

## Issue Format

The synced issue body is optimized for fast developer triage:

- heading first: vulnerability title plus severity
- repo, ref, and file or target file immediately below
- Snyk UI and API links grouped together
- package and fix context next, plus fix availability, CVSS, CWE class(es), and CVE identifier(s) when Snyk reports them
- vulnerability description and remediation guidance sections lower in the body when Snyk reports them, so consumers do not need Snyk API credentials to triage
- project and issue IDs lower in the body for debugging and API work

The synced title includes the most useful source context when Snyk provides it:

- repository for code and repository-backed findings
- branch/image/reference for non-GitHub target-file findings such as Kubernetes or container scans

The subject portion then uses this preference:

1. source file basename
2. package name
3. project target file
4. project name

## Managed Labels

`LINEAR_MANAGED_LABEL` controls the automation label applied to managed issues:

- default: `snyk-automation`
- set to another label name to use that label instead
- set to `off` to disable label management

When label management is enabled, the sync:

- adds the configured label to newly created managed issues
- preserves unrelated existing labels
- removes the previously managed label if the configured label changes
- removes the previously managed label if label management is turned off

If the configured label does not exist in Linear, the run fails with a clear message telling the operator to create the label or disable label management.

`LINEAR_TOOL_LABELS` optionally maps Snyk issue `type` values to additional managed Linear labels:

- format: comma-separated `issue_type:label` pairs
- example: `code:snyk-code,package_vulnerability:snyk-open-source,cloud:snyk-cloud`
- labels must already exist in Linear

`LINEAR_TOOL_LABEL_DEFAULT` controls the fallback label for issue types without an explicit mapping:

- default: `snyk-automation`
- set to `off` to disable the fallback

`LINEAR_ORIGIN_LABELS` optionally maps Snyk project `origin` values to additional managed Linear labels:

- format: comma-separated `origin:label` pairs
- example: `github:snyk-github,kubernetes:snyk-kubernetes`
- labels must already exist in Linear

`LINEAR_ORIGIN_LABEL_DEFAULT` controls the fallback label for project origins without an explicit mapping:

- default: `off`
- set to another label name to apply a shared fallback origin label

`LINEAR_AWAITING_FIX_LABEL` controls the label applied to issues where Snyk reports the ignore as "until fix is available" (disregardIfFixable):

- default: `triage-dependency`
- set to another label name to use that label instead
- set to `off` to disable the awaiting-fix label
- the label must already exist in Linear

When an issue is in the awaiting-fix state, the sync:
- places the issue in `Backlog` with no due date
- adds the configured awaiting-fix label
- renders `Status: ignored (no fix available)` in the description
- writes an `awaiting_fix: yes` marker into the metadata block
- removes the awaiting-fix label and clears the marker when a fix becomes available and the issue moves to `Todo`

The `awaiting_fix` marker records awaiting-fix history regardless of the label configuration, so the transition back to `Todo` also works with `LINEAR_AWAITING_FIX_LABEL=off`. Legacy tickets with the configured awaiting-fix label recorded in their managed labels are recognized without a marker. A ticket lacking both signals stays in `Backlog` when the fix arrives, unless an earlier awaiting-fix run first adds the marker.

The first upgraded run backfills the marker on matched, non-archived tickets that are still awaiting a fix, even if nothing else changed. This is a one-time metadata-only update, without a change comment; subsequent unchanged runs do not repeat it. Keep the label enabled (the default) to make these tickets filterable. The marker and label only drive the state move; the due date of a ticket whose fix arrived comes from the sync's ignore memory (see [Due Dates](#due-dates)), label or no label.

When tool, origin, or awaiting-fix label mapping is enabled, the sync manages the global automation label plus the derived label set recorded in the metadata block.

### Label ownership

Linear's `issueUpdate` mutation replaces an issue's label set wholesale rather
than applying a delta, so every update this sync performs has to restate the
labels the issue should end up with.

This sync owns only its own managed labels — the global automation label plus
the tool, origin, severity, and awaiting-fix labels recorded in the
`managed_labels:` metadata block. Every other label on a ticket belongs to
someone else (a person, or another automation) and is carried forward untouched.

To make that safe against edits made mid-run, each update batch re-reads the
current labels of the issues it is about to write, immediately before the write.
That live read — not the board snapshot taken at the start of the run — is the
authority for which labels the ticket carries. The board snapshot can be minutes
old, so a label another system added after it is absent from the snapshot;
restating the snapshot would delete that label. Reading live avoids it:

- a label added since the snapshot (managed or not) survives the update
- a label removed since the snapshot is not re-added
- if an issue's live labels cannot be read, its update fails rather than
  proceeding — writing a label set that might drop a label the sync does not own
  is worse than deferring the update to the next run. The caller retries the
  batch item by item, so one unreadable issue does not block the rest.

`LINEAR_PROTECTED_LABELS` lists labels this sync must never *assert* from its
managed set — a guard against a misconfiguration that puts a control label into
the managed set stamping it onto a ticket that does not carry it:

- default: `df:kikimora-snyk,df:kikimora-snyk-complete,df:kikimora-snyk-invalid`
- set to `off` to disable the guard
- a protected label already on the ticket is still carried forward like any
  other unmanaged label; protection only stops the sync *adding* one

These three labels belong to the kikimora Dark Factory harness, which uses them
as dispatch control state: `df:kikimora-snyk` enrols a finding for automated
assessment, and the `-complete` / `-invalid` variants are terminal gates that
stop a finding being re-assessed. Deleting one silently re-opens work that was
already done.

`LINEAR_CREATE_ONLY_LABELS` lists labels stamped once, when the issue is
created, and never reconciled afterwards:

- default: none
- labels must already exist in Linear (the run fails loudly if one does not)
- create-only labels are deliberately not part of the managed set: they never
  enter the `managed_labels:` metadata block and never appear in a desired
  label set, so nothing later tries to re-assert or remove them
- because updates carry forward every label the sync does not own, a create-only
  label already on a ticket is preserved without further configuration

The Tessl deployment sets `LINEAR_CREATE_ONLY_LABELS=df:kikimora-snyk` so every
newly synced finding carries the enrolment label from birth and kikimora does
not need to write it itself.

`LINEAR_UNSUBSCRIBE_ACTOR` controls whether the Linear API actor should be kept off the subscriber list for managed issue creates and updates:

- default: `true`
- `true`: create issues without subscribing the actor, and preserve the current subscriber list unchanged on updates
- `false`: let Linear use its default subscriber behavior

This setting only controls the issue subscriber list. Linear will still record the API user as the issue creator, and the create mutation response may briefly include that creator in `subscribers` even when the persisted issue subscriber list is empty after a refresh.

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

- open -> `Todo`
- ignored until fix available (disregardIfFixable) -> `Backlog` (no due date, `triage-dependency` label)
- temporarily ignored (snoozed with future expiry) -> `Todo`
- permanently ignored -> `Cancelled`
- fixed (or resolved/disappeared) -> `Done`
- missing finding in an existing active Snyk project -> `Done`
- missing finding because the Snyk project no longer exists -> `Cancelled`
- Snyk project is inactive (de-activated) -> `Cancelled`

The configured Linear state names are resolved by name first, then by workflow type where possible.

These distinctions are intentional:

- Issues ignored "until fix is available" are placed in `Backlog` with no due date because the team cannot act on them until an upstream fix ships. The `triage-dependency` label (configurable via `LINEAR_AWAITING_FIX_LABEL`) makes them filterable. When a fix becomes available, Snyk flips `ignored=false` and the next run moves the issue to `Todo` with a due date based on the day the ignore ended.
- Temporarily ignored issues (those with a scheduled expiry) are kept open in `Todo` rather than cancelled, because they require attention once the ignore expires. This applies only while the finding still exists in Snyk: a finding Snyk reports as resolved is treated as `Done` regardless of any ignore (active, expired, or "until fix available") still attached to it, so a vulnerability that no longer exists never lingers as an open or overdue ticket.
- If a Snyk issue disappears but the project still exists and is active, the tool treats that as the issue being resolved and moves the Linear ticket to `Done`.
- If the Snyk project itself is gone or has been de-activated (inactive), the tool treats the managed Linear ticket as no longer actionable and moves it to `Cancelled`. A ticket that was already closed keeps its state: a `Done` ticket stays `Done`, because the project going away says nothing about how the finding was closed.

### Reopen Guard

A closed (`Done`/`Cancelled`) ticket is normally never reopened when Snyk reports its finding as open again: Snyk reuses an issue ID when the same problem type reappears on different code, so the sync creates a fresh ticket instead. There are two exceptions, both derived from Snyk data:

- **Closed while still open in Snyk.** When the fingerprint matches exactly and includes a location, the ticket has recorded creation and closed times in Linear, and Snyk's `last_resolved_at` shows no resolution since the ticket was created (empty, or earlier than the ticket's creation), the finding has been open for the ticket's whole life. The closure was premature (for example an automation marked it `Done`), so the sync reopens the ticket (when earlier runs already left several closed copies with that fingerprint, the check runs against the most recently created one, which then becomes the canonical ticket; older copies are left untouched) instead of minting a duplicate with the same fingerprint. An issue ID reused for a new occurrence always shows a later `last_resolved_at`, because Snyk resolved the old occurrence first, so this cannot reopen the tickets the guard exists to protect. An unparsable `last_resolved_at`, a coarse fingerprint, an archived ticket, or a missing Linear timestamp keeps the default behavior.
- **Project recreation.** See below.

A reopened ticket goes back to the open state it was in before it was closed (for example `Todo` or `In Progress` after triage), read from its Linear history, rather than the configured open state; the change comment names the state. When the history has no usable open state (it was in another team's state, or that state has been archived) or cannot be read, the ticket reopens in the configured open state.

### Project Recreation

Snyk sometimes recreates a project (same name and target) under a new project ID, which also gives every issue a new ID, so no fingerprint matches. When a finding has no exact or coarse match, the sync looks for a ticket with the same `identity` whose project is no longer active and rebinds it: the ticket's fingerprint, description, links, and state are rewritten from the new finding through the normal update path. Only these tickets qualify:

- open tickets (their project vanished in this run), and
- `Cancelled` tickets carrying a sync-recorded `closed_reason` (`project-missing` or `project-deactivated`), which are reopened.

If the Kubernetes cluster lookup for a project fails (after retries), its findings have no identity for that run: they still match their tickets by fingerprint, the ticket's stored identity and Cluster line are kept unchanged, and no rebind happens. When such a finding has no ticket but a rebind candidate could be its own under the cluster that candidate records, and that candidate is still open or was closed less than 24 hours ago, creating the ticket is deferred to the next run so a successful lookup can rebind it. Otherwise the ticket is created without an identity, so a persistent lookup failure never hides a finding for more than about a day.

A ticket whose project is still active is never taken (two live projects scanning the same target keep separate tickets), nor is a ticket closed by a fix or a person, nor an archived one. Each ticket is rebound at most once per run; with several candidates the sync prefers open tickets, then the most recently created.

### Manual Backlog Override

If a user manually moves a managed open ticket from `Todo` to `Backlog` in Linear, subsequent syncs will preserve the `Backlog` state instead of overriding it back to `Todo`. This prevents the automation from fighting intentional user triage decisions. The override applies when the existing Linear issue state matches the configured `LINEAR_STATE_BACKLOG` value.

A `Backlog` ticket recognized as previously awaiting a fix moves to `Todo` when Snyk reports `ignored=false`, with a recalculated due date and a change comment explaining the move. The marker or recorded configured label provides that history. These signals do not establish who selected `Backlog`, so a manual `Backlog` placement made before or during the awaiting-fix period can also move to `Todo` when the fix arrives. Distinguishing those placements requires additional ownership tracking. Other manually chosen non-terminal states, such as `In Progress`, remain preserved.

### Manual Non-Terminal State Override

If a user manually moves a managed issue to any non-terminal Linear state that differs from what the sync would set (e.g. `Todo` or `In Progress` when the configured open state is `Triage`, or `Todo` when the finding is awaiting fix and the sync would set `Backlog`), subsequent syncs will preserve the user's chosen state. This prevents the automation from dragging issues back to the configured state after intentional triage decisions.

Terminal states (`Done`, `Cancelled`) are never preserved — the sync always transitions to a terminal state when the Snyk finding is fixed or ignored.

### Due Dates

Default due date offsets:

- critical -> 15 days
- high -> 30 days
- medium -> 45 days
- low -> 90 days

The base date is normally the Snyk issue `created_at` timestamp. For temporarily ignored issues, the base date is the ignore expiry date, so the due date extends to the normal severity SLA calculated from when the ignore expires. That stays true after the ignore has lapsed, and after Snyk's v1 ignores endpoint has stopped returning the expired record: the sync remembers the expiry in its cache (see [Cache Behavior](#cache-behavior)), so the due date does not regress to `created_at` + SLA.

Issues ignored "until fix is available" have no due date. The SLA clock is paused while the issue is blocked on an upstream fix. When a fix becomes available, Snyk flips `ignored=false`; the sync records the day it first sees that, and the due date is that day + severity offset from then on, so it is the same on every later run. An ignore of this kind that reaches its own expiry with no fix is dated from the expiry, like any expired snooze, and the change comment names the ignore expiry rather than fix availability. A revoked ignore until fix available is dated like a fix arrival.

All bases are UTC calendar dates, whatever the host's time zone.

## Cache Behavior

The cache lives in SQLite and stores:

- a schema signature for the managed issue format
- a normalized hash for each Snyk finding
- a normalized hash for each managed Linear issue
- the sync's memory of Snyk v1 ignores, per project and issue key

On a normal run:

1. Load Snyk findings.
2. Load the current Linear snapshot.
3. Skip fingerprints whose Snyk hash and Linear hash both match the last successful run.
4. Apply creates, updates, and resolves for the rest.
5. Refresh the cache from the live post-write Linear snapshot.

Use `--bypass-cache` to ignore the hashes for a run and rebuild them from live data. It does not touch the ignore memory.

### Ignore memory

Snyk's v1 ignores endpoint stops returning an expired ignore after a while, but the expiry stays the base of the ticket's due date. The sync therefore remembers each ignore it has seen (expiry, the until-fix-available flag, when the v1 API last confirmed it, and when an until-fix-available ignore stopped applying) and keeps a row until Snyk contradicts it, judged at the end of each Snyk load against the REST issues:

- an ignore the v1 API still returns is refreshed as before (latest entry wins, a permanent ignore drops the expiry, the expiry only moves forward);
- an ignore the API no longer returns is kept while Snyk still reports a finding it applies to as ignored, while its expiry has passed, while it is an until-fix-available ignore, or while no open un-ignored finding matches it;
- an active snooze whose finding Snyk reports open and not ignored is kept for seven days (partial v1 responses happen) and then dropped as revoked, with a log line.

A v1 request that fails or 404s after its retries falls back to the cached rows and never drops one. Rows written by older versions are kept too.

Rule-keyed ignores may cover only some findings. The cache records each finding observed ignored under a rule, with its own expiry and first observed end, so that history remains available after the finding becomes actionable without changing a never-ignored sibling's SLA. Superseding or revoking a newer rule ignore preserves older expired-snooze or until-fix observations belonging to other findings. Cached-only rule metadata cannot establish a new finding association, and a newer direct-key ignore prevents attributing an older rule ignore to that finding. Legacy rule rows without these observations cannot reconstruct which findings were ignored. A newer direct-key ignore starts a new lifecycle; if it is already lifted when first seen, that observation starts its SLA. An open, unignored occurrence does not inherit an ignore that predates a known resolution of every coordinate.

When a configured ignore-memory store cannot be read or written, snapshot loading fails before any Linear reconciliation. Newly observed ignore ends must be persisted before they can become SLA bases; a retry reuses only durable history rather than publishing a date that would be forgotten after a failed write.

### Cold-start guard

A run that starts with an empty ignore memory (a new or lost cache file) while Linear already holds open tickets with due dates cannot tell an earlier due date that is a real change from one that only reflects an expiry it no longer remembers. Such a run keeps the current due date of any matched open ticket whose desired date is earlier, logs a warning with the count (`held_due_dates` in the summary), and leaves an `ignores_cold_start_at` marker in the cache so later runs keep holding too. Later due dates still apply. Once the ignore memory is trusted again, release the held dates with:

```bash
go run ./cmd/snyk-linear-sync --env-file .env --clear-ignores-cold-start
```

The cache records a pending empty start under the `ignores_memory_state` key in `sync_meta` before any snapshot loader can seed rows, including diagnostic loads. Failed or interrupted loads keep that evidence for the next run. A successful load with no open dated tickets marks the memory trusted without engaging the guard.

The clear flag records that the memory is trusted and removes the cold-start marker. This release persists even when there are no cacheable ignores, so the next normal run stays released. Deleting only `ignores_cold_start_at` does not release pending memory; use the flag.

## Configuration

Required:

- `SNYK_CLIENT_ID`
- `SNYK_CLIENT_SECRET`
- `SNYK_ORG_ID`
- `LINEAR_API_KEY`
- `LINEAR_TEAM_ID`

Optional:

- `--env-file`
- `--dry-run`
- `--plan-json <new-private-file>` (requires `--dry-run`)
- `--reviewed-plan-json <private-plan>` with `--reviewed-plan-sha256 <reviewed-digest>` (live reconciliation preflight only)
- `--bypass-cache`
- `--clear-ignores-cold-start`
- `SNYK_REGION`
- `SNYK_OAUTH_SCOPES`
- `SOURCE_PROVIDER`
- `LINEAR_STATE_TODO`
- `LINEAR_STATE_BACKLOG`
- `LINEAR_STATE_DONE`
- `LINEAR_STATE_CANCELLED`
- `LINEAR_MANAGED_LABEL`
- `LINEAR_TOOL_LABELS`
- `LINEAR_TOOL_LABEL_DEFAULT`
- `LINEAR_ORIGIN_LABELS`
- `LINEAR_ORIGIN_LABEL_DEFAULT`
- `LINEAR_AWAITING_FIX_LABEL`
- `LINEAR_CREATE_ONLY_LABELS`
- `LINEAR_PROTECTED_LABELS`
- `LINEAR_DUE_DAYS_CRITICAL`
- `LINEAR_DUE_DAYS_HIGH`
- `LINEAR_DUE_DAYS_MEDIUM`
- `LINEAR_DUE_DAYS_LOW`
- `LINEAR_ARCHIVE_LOOKBACK_DAYS`
- `SYNC_WORKERS`
- `SNYK_HTTP_CONCURRENCY`
- `LINEAR_HTTP_CONCURRENCY`
- `ERROR_LOG_FILE`
- `CACHE_DB_FILE`

See [.env.example](/workspace/.env.example).


## Logs

- Console logs show startup, load progress, work progress, cache refresh, and final summary.
- The final `sync complete` line reports `findings`, `existing_issues`, `active_projects`, `inactive_projects`, `cluster_lookup_failures`, `conflicts`, `rebound`, `reopened`, `deferred_creates`, `held_due_dates`, `planned_creates`, `planned_updates`, `planned_resolves`, `cancelled_duplicates`, and `failed_ops`. Each rebind is also logged individually with the old and new project ID and the Linear identifier. A dropped cached ignore and an engaged cold-start guard are logged too.
- Error logs are appended to `ERROR_LOG_FILE`.
- Default error log path: `logs/snyk-linear-sync-errors.log`

## More Detail

See [PROJECT.md](/workspace/PROJECT.md) for the project intent, architecture, sync rules, and operational model.

### Single-snapshot bounded execution

`--plan-and-execute-bound` is an explicit alternative authorization mode to the
independently reviewed-plan guard. It requires `--replay-safe`, an immutable
`LINEAR_TEAM_ID` UUID, and all four integer limits:

```sh
./snyk-linear-sync --plan-and-execute-bound --replay-safe \
  --max-creates 5 --max-updates 10 --max-resolves 2 --max-cancel-duplicates 0 \
  --plan-json /physical/private-parent/new-plan.json
```

Each limit must be a canonical decimal integer in `[0, 999999]`; omitted,
negative, overflowing or malformed limits fail closed. Reopens count as updates.
Duplicate cancellations have their own required limit. Limits apply to the
complete plan, including every batch, before the first Linear mutation. This
mode cannot be combined with dry-run, reviewed-plan execution, observation
checkpoint creation, or clearing cold-start protection.

The parent directory must already exist with mode `0700`. Use its physical path:
symlinks in the path are rejected. The plan file and adjacent `PATH.receipts`
directory must not exist. The directory is reserved with mode `0700` before
loading sources and is never automatically removed, even after failure. Files
are created exclusively with mode `0600`:

- `PATH` (the `--plan-json` file): complete v2 reconciliation intent from one validated fresh Snyk
  load, one Linear planning load and complete required reopen history. The exact
  file, including its trailing newline, must fit within 32 MiB before dispatch. This file remains
  an unattempted plan, not an execution receipt.
- `PATH.receipts/attempt.json`: schema version `1`, status `attempt_started`, `started_at`, exact
  file-byte `plan_sha256`, full buffered-payload `jobs_sha256`, `creates`,
  `updates`, `resolves`, `cancel_duplicates`, the four `max_*` limits and
  `batches`. The receipt is capped at 4 KiB. The plan and receipt files and directory entries are synced before
  dispatch. Exactly one `msg="bound plan written" plan_sha256=<raw file hash>`
  line is logged after binding and before dispatch. Raw source snapshots and buffered payloads are not persisted.
- `PATH.receipts/refusal.json`: emitted only when a complete, validated plan and
  its buffered jobs exceed one or more limits. Schema version `1`, status
  `limits_exceeded`, the four aggregate counts (`creates`, `updates`, `resolves`,
  `cancel_duplicates`), their four `max_*` limits, and `exceeded`: the nonempty
  list of over-limit categories in that order. It is capped at 4 KiB, contains
  no identifiers, hashes or raw source data, and is not an execution attempt.
  Rejection creates no plan or attempt file, performs no Linear writes and saves
  no sync hashes. The error also reports the counts and limits. Invalid plan or
  job evidence fails without this diagnostic. A refusal write failure still
  fails closed and is reported alongside the limit error.
- `PATH.receipts/result.json`: schema version `1`, `finished_at`, the same plan/job hashes,
  `status`, `linear_writes_attempted`, `batches_attempted`,
  `batches_acknowledged`, and `cache_status`. It is capped at 4 KiB and contains
  no raw API error text.

`status` is `success`, `failed_before_writes`, or `partial_or_uncertain`.
`cache_status` is `not_saved`, `refresh_failed_or_uncertain`, `saved`, or
`save_failed_or_uncertain`. With no cache store, `not_saved` also applies to
successful execution. Acknowledgement means all mutation and applicable
follow-on comment responses in that batch succeeded; it does not imply atomicity
or independently verified remote state. No mutations are retried. A failed or
uncertain batch stops later batches and skips sync-cache saving. Cache saving or
result persistence failure also makes the process fail. Missing, incomplete or
mismatched receipts are never evidence of success.

When a cache is configured, bounded execution requires nonempty Snyk hashes
before the write gate. After all buffered jobs succeed, it loads Linear once
more solely to build fresh cache hashes. That read never replans, adds jobs or
triggers mutations. Missing, malformed, empty or failed refresh results fail
closed without saving sync hashes or falling back to pre-write hashes.
Successful execution saves nonempty Snyk and freshly read Linear hashes and
emits the existing cache-refresh and completion messages. This read is cache
evidence, not independent verification of every remote outcome.

Loader ignore memory and cold-start metadata can change before the write gate,
as in preview mode. Always run on a disposable copy of the trusted cache and
publish nothing on failure. Retain the exact plan, `PATH.receipts/attempt.json`
and any `PATH.receipts/refusal.json` or `PATH.receipts/result.json` privately for at most seven days, including
on failure, before removing job scratch. Retain no database or raw log as a plan
artifact. A missing final receipt means an interrupted or uncertain attempt.
Keep the completed cache separately and publish it only after independent exact
readback validation.

The caller owns executable/source provenance, freshness policy, a single-writer
lease, a durable attempt-one gate across different output paths, private receipt
retention (at most seven days), and exact cache readback before publication.
Never retry an interrupted or uncertain attempt by choosing another directory:
inspect remote state and explicitly authorize a new reconciliation first. The
existing reviewed-plan mode still requires its independent digest and exact
input/decision comparison; this mode does not relax that contract.

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

### Create response safety

Create requests are never automatically repeated after a transport or partial
GraphQL failure. Acknowledged issue IDs survive partial responses so callers can
inspect what landed. Guarded execution stops on every partial or uncertain
outcome; ordinary execution retries only explicitly rejected aliases from a
complete error-free response, once. An uncertain create stops the ordinary run
without stranding blocked queue sends or publishing its cache.

### Bounded drain development

See the [offline interchange contract](docs/BOUNDED_DRAIN_SCHEMA.md) for the
retained full plan, canonical receipt bytes, initialization types and evidence
sets. It is an offline compatibility contract, not an enabled execution route.

The separate drain protocol primitives support deterministic whole-group
selection of at most 100 total issue mutations, persistent pending ages, fresh
ID-based effect verification, and atomic hash evidence. They are exposed only through
the explicit opt-in drain execution mode described below. Existing bounded mode
still refuses an oversized complete plan; existing workflows remain unchanged. Drain caches
use a separate signature and cannot be overwritten by this version's legacy
cache writer. Consumer provenance checks and namespace fences remain required.
Preflight bounds all potentially pending work entries and their encoded size,
not only distinct fingerprints, since selected effects may remain unverified.

The proposed 100-operation cap counts creates, updates (including reopens),
resolves and duplicate cancellations. It does not mean 100 API mutations:
subscription cleanup and optional comments are additional effects. Runtime
integration also requires evidence for changed same-fingerprint membership,
which a matched issue's unchanged hash cannot detect by itself.

Pending ages and unverified counters survive deferral. Missing restored work
refuses rather than silently resetting its age; only a create-to-issue handoff
can transfer ownership through a fingerprint. Three unverified selections while
work remains pending stop further progress, even with intervening deferrals.

### Opt-in drain execution (not deployed)

`--plan-and-execute-drain` selects at most 100 total issue operations from the
complete fresh plan rather than rejecting an oversized plan. This is a separate,
explicit execution mode. No existing workflow or default enables it. It requires
`--replay-safe`, a cache already initialized and independently admitted under the
separate drain protocol, an immutable team UUID, a new private `--plan-json`
path, all four per-kind ceilings, and these explicit options:

- `--max-issue-changes` from 1 through 100;
- `--drain-run-id`, a positive canonical decimal string of at most twenty digits;
- `--drain-run-attempt 1`;
- `--drain-prior-evidence-sha256` and `--drain-prior-pending-sha256`, obtained from
  the caller's authenticated admission of the exact restored cache;
- `--expected-settings-sha256`, binding the reviewed reconciliation settings.

The supplied hashes bind the local state to that admission; they do not prove
its origin. The caller must authenticate producer receipts, full plan, exact
cache bytes and destination, enforce freshness and a durable single-writer and
attempt-one guard, and retain receipts privately. There is no automatic
initialization, legacy fallback, generation reset or retry by using a new output
path. The mode refuses dry-run, the older bounded/reviewed modes, bypassing the
cache and clearing cold-start protection. `LINEAR_UNSUBSCRIBE_ACTOR` must be
explicitly false: hidden create-cleanup mutations are not supported by this
execution contract. This requirement does not change ordinary-mode defaults.

Whole causal groups are selected oldest pending first, with deterministic ties.
Creates, updates (including reopens), resolves and duplicate cancellations all
consume the same budget; optional comments are separate effects. A group that
cannot fit the total or its kind ceiling refuses instead of being starved.
Deferred aliases are withheld from the saved Linear hashes, so an unchanged
source on the next run still plans their work. Missing pending work refuses;
a no-op replan is not independent proof that an uncertain old effect finished.

The exact full plan and canonical version-2 attempt are durably written before
dispatch. Only selected payloads execute, once, in batches of at most ten.
Partial or uncertain mutations stop later batches without retry. A fresh Linear
read then verifies effects by issue ID and can commit a conservative partial
checkpoint. The process still exits unsuccessfully for an uncertain outcome or
unverified effects; only the caller's admission of a complete saved receipt may
authorize publishing that checkpoint. A missing result is never publishable.

Unexplained membership changes for known fingerprints refuse cache publication,
including competing tickets hidden by canonical-ID hash overrides. Only
acknowledged selected creates and independently verified selected rebinds may
explain membership changes. Unrelated new fingerprints are excluded as arrivals.
The prior checkpoint remains authoritative after a failed refresh or cache save.
Pending ages, counters, hash evidence and sync hashes commit in one transaction;
the third unverified checkpoint is retained and subsequent execution refuses.

Optional comments use `auxiliary_comments.policy: per-batch-once`: update-batch
comment calls and complete acknowledgements are counted separately from issue
batches. A failed or uncertain comment is never retried, including in a later
generation whose issue effect already verified. When comments are disabled,
the policy is `disabled` with zero counters. These counters describe calls to
the batched comment interface; that interface can omit comments with no diff.
No durable comment retry queue is implied.

This implementation does not supply the caller's provenance admission,
initialization route, production namespace, single-writer lease or activation
workflow. Those gates must be implemented and reviewed before deployment.

An attempted create without a complete, valid acknowledged ID mapping refuses
checkpoint publication even if a fresh read could show no new issue. Absence
is not proof of non-creation. The caller must retain the failed attempt and
require reconciliation before another attempt; it must not replay the old cache
automatically. Fully acknowledged creates may advance only after the normal
fresh effect and membership checks.

If a comment was attempted but its underlying issue update remains unverified,
checkpoint publication also refuses. Reconciliation is required rather than
allowing a later generation to repeat that comment with the update.
