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
- Creates missing Linear issues.
- Updates existing Linear issues when managed fields change.
- Ensures a configurable managed label is applied to all managed issues, unless label management is explicitly turned off.
- Moves stale issues to the configured resolved state when the finding is no longer present but the Snyk project still exists.
- Cancels managed Linear issues when their Snyk project no longer exists, such as after project deletion.
- Uses a local SQLite cache to skip unchanged findings and unchanged Linear issues on steady-state runs.
- Sets Linear due dates from Snyk issue creation time using configurable per-severity offsets.

The fingerprint format is:

```text
snyk:<project-id>:<issue-id>
```

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

`--env-file` uses `github.com/joho/godotenv`, so the file can be a normal dotenv file and does not need to be sourced by your shell.

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
- Normalizes common Linear markdown rewrites when comparing descriptions so steady-state runs do not churn.

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
fingerprint: snyk:proj-123:issue-456
managed_labels: snyk-automation,snyk-code
-->
```

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
- removes the awaiting-fix label when a fix becomes available and the issue moves to `Todo`

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

```
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

- Issues ignored "until fix is available" are placed in `Backlog` with no due date because the team cannot act on them until an upstream fix ships. The `triage-dependency` label (configurable via `LINEAR_AWAITING_FIX_LABEL`) makes them filterable. When a fix becomes available, Snyk flips `ignored=false` and the next run moves the issue to `Todo` with a due date.
- Temporarily ignored issues (those with a scheduled expiry) are kept open in `Todo` rather than cancelled, because they require attention once the ignore expires. This applies only while the finding still exists in Snyk: a finding Snyk reports as resolved is treated as `Done` regardless of any ignore (active, expired, or "until fix available") still attached to it, so a vulnerability that no longer exists never lingers as an open or overdue ticket.
- If a Snyk issue disappears but the project still exists and is active, the tool treats that as the issue being resolved and moves the Linear ticket to `Done`.
- If the Snyk project itself is gone or has been de-activated (inactive), the tool treats the managed Linear ticket as no longer actionable and moves it to `Cancelled`.

### Manual Backlog Override

If a user manually moves a managed open ticket from `Todo` to `Backlog` in Linear, subsequent syncs will preserve the `Backlog` state instead of overriding it back to `Todo`. This prevents the automation from fighting intentional user triage decisions. The override applies when the existing Linear issue state matches the configured `LINEAR_STATE_BACKLOG` value.

### Manual Non-Terminal State Override

If a user manually moves a managed issue to any non-terminal Linear state that differs from what the sync would set (e.g. `Todo` or `In Progress` when the configured open state is `Triage`, or `Todo` when the finding is awaiting fix and the sync would set `Backlog`), subsequent syncs will preserve the user's chosen state. This prevents the automation from dragging issues back to the configured state after intentional triage decisions.

Terminal states (`Done`, `Cancelled`) are never preserved — the sync always transitions to a terminal state when the Snyk finding is fixed or ignored.

### Due Dates

Default due date offsets:

- critical -> 15 days
- high -> 30 days
- medium -> 45 days
- low -> 90 days

The base date is normally the Snyk issue `created_at` timestamp. For temporarily ignored issues, the base date is the ignore expiry date, so the due date extends to the normal severity SLA calculated from when the ignore expires.

Issues ignored "until fix is available" have no due date. The SLA clock is paused while the issue is blocked on an upstream fix. When a fix becomes available, Snyk flips `ignored=false` and the next run recalculates the due date from fix availability (today + severity offset), moving the issue to `Todo`.

## Cache Behavior

The cache lives in SQLite and stores:

- a schema signature for the managed issue format
- a normalized hash for each Snyk finding
- a normalized hash for each managed Linear issue

On a normal run:

1. Load Snyk findings.
2. Load the current Linear snapshot.
3. Skip fingerprints whose Snyk hash and Linear hash both match the last successful run.
4. Apply creates, updates, and resolves for the rest.
5. Refresh the cache from the live post-write Linear snapshot.

Use `--bypass-cache` to ignore the cache for a run and rebuild it from live data.

## Configuration

Required:

- `SNYK_CLIENT_ID`
- `SNYK_CLIENT_SECRET`
- `SNYK_ORG_ID`
- `LINEAR_API_KEY`
- `LINEAR_TEAM_ID`

Optional:

- `--env-file`
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
- Error logs are appended to `ERROR_LOG_FILE`.
- Default error log path: `logs/snyk-linear-sync-errors.log`

## More Detail

See [PROJECT.md](/workspace/PROJECT.md) for the project intent, architecture, sync rules, and operational model.
