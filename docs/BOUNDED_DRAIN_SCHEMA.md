# Bounded drain offline interchange contract

This document freezes the proposed producer/consumer interchange for offline
validation. It does not enable drain execution, authorize initialization or
publication, or establish producer provenance. Shared fixtures prove byte and
semantic agreement only. Runtime wiring must separately authenticate producer
artifacts, pin the executable and destination, enforce freshness and a durable
single-writer/attempt-one guard, and verify publication.

## Versions and bytes

Pending and evidence rows use version 1 and the cache signature suffix
`+drain-v1`. Execution and initialization receipts use version 2; a legacy
bounded receipt reader must refuse them. Unknown fields, duplicate JSON keys,
field aliases, invalid UTF-8, noninteger numbers and mismatched versions refuse.

Canonical drain JSON recursively sorts object keys, uses UTF-8, has no whitespace
or trailing newline, and uses Go `encoding/json` escaping, including `<`, `>`,
`&`, U+2028 and U+2029. Empty drain-row, receipt and operation collections are `[]` or `{}`, never
`null`. The retained reconciliation plan preserves its existing v2 field
representation, including any nullable nested plan arrays; do not rewrite it.
Digests are lowercase hexadecimal SHA-256. Fingerprint digests hash the raw
fingerprint's UTF-8 bytes, without JSON quoting or normalization. Canonical rows
and operation arrays are hashed over their canonical bytes. A retained plan is
hashed over its exact file bytes, not a consumer's reserialization.

All run-ID fields, including initialization's source and authorizing run IDs,
are strings matching `[1-9][0-9]{0,19}` (at most twenty digits). Numbers, zero, leading zeros, signs and
whitespace refuse. `producer_run_attempt` is a positive JSON integer.
Generations and counts are nonnegative JSON integers. Cross-language numeric
values must be below 2^53. Run IDs are never converted to floating point.

## Limits

Limits are inclusive and checked on exact encoded bytes before dispatch:

- Each attempt, result, pending row and evidence row: 32 MiB.
- The retained full plan: 128 MiB. This is a drain-specific ceiling, not a
  change to the ordinary bounded-plan limit.
- Full operations, pending entries and each fingerprint map: 100,000 entries.
- A raw fingerprint: 1 through 4,096 UTF-8 bytes.
- An issue ID: `[A-Za-z0-9_-]{1,64}`; the `issue:` prefix is additional.
- Selected issue operations: 1 through 100 configured maximum, with independent
  nonnegative per-kind ceilings; selection may be empty for an empty plan.
- Dispatch batches: at most ten issue operations, grouped in create, update,
  resolve, cancel-duplicate order, with work keys sorted within each kind.

Size preflight must include all operations potentially becoming pending,
including selected operations whose effect verification could fail. It must not
collapse distinct pending work keys just because they share fingerprints. A
post-write overflow means an uncertain failure and no cache publication. A
receipt byte ceiling is not permission to retain raw payloads or API logs.

## Retained full plan and operation partition

Retain the existing complete `ReconciliationPlan` version-2 artifact, including
inputs, coverage, summary, records and decision digest. Do not replace it with
an `operations`-only object. Validate the existing v2 plan contract before
projecting operations. `full_plan_sha256` binds the exact retained bytes;
`settings_sha256` equals `inputs.settings_sha256`.

For every record with `mutation_planned: true`:

1. `kind` is its action, one of `create`, `update`, `resolve`,
   `cancel-duplicate`; reopens count as updates.
2. For create, `work_key` is `create:<fingerprint_sha256>` and the alias array
   contains exactly that digest. For other actions it is `issue:<issue_id>`.
3. For issue work, `fingerprint_sha256s` is the sorted unique union of the
   current fingerprint digest and nonempty `previous_fingerprint_sha256`.
   Identity rebind therefore binds both old and new aliases. An unchanged old
   digest is deduplicated, not counted twice.

Operations have exactly `work_key`, `kind`, `fingerprint_sha256s`. Reject
repeated work keys. Do not infer a repeated target merely from overlapping
fingerprints: legitimate duplicate cancellation can share a fingerprint with
canonical work. A consumer cannot invent stronger exclusions than the producer.

Let M be the full projection, S selected and D deferred. Each array is sorted by
work key. S and D must be disjoint and their complete operation values must
partition M exactly. Count objects have exactly `creates`, `updates`,
`resolves`, `cancel_duplicates`, each recomputed from the respective array.
`selected_ops_sha256` and `deferred_ops_sha256` hash the canonical arrays.
The jobs digest binds the actual buffered payloads; an offline consumer cannot
reconstruct those private payloads from the redacted plan.

## Evidence sets

Use P for `pre_write`: canonical pre-write Linear hashes after matched-ID
overrides. Let A be fingerprint keys selected operations may introduce, derived
from their desired fingerprints: use the current `fingerprint_sha256` of each
selected mutation record, not its `previous_fingerprint_sha256` or all aliases.
The retained full plan supplies this distinction without exposing raw payloads. Let Q be the complete mandatory fresh post-write
read after matched-ID and acknowledged-create-ID overrides. Define:

- R (`refreshed`) = Q restricted to keys(P) union A.
- arrivals = keys(Q) minus (keys(P) union A).
- W (`withheld`) is a subset of keys(R).
- saved = R minus W, exactly by both key and value.

Concurrent arrivals are counted but never included in the saved hash map.
A selected create is not a concurrent arrival. A disappeared pre-write key is
absent from R, W and saved; do not invent an empty hash or tombstone. Pending
work can remain even when its alias is absent from R.

For every key in R, withhold it when any deferred or selected-unverified
operation names its fingerprint digest. `work_keys` is the sorted unique list
of all such operations. The reason is `deferred` if any are deferred, otherwise
`unverified`. If no full-plan operation touches a key and its P hash differs
from its R hash, withhold it as `drift` with an empty `work_keys` array.
Precedence is deferred, then unverified, then drift. This is content drift,
not merely disagreement between receipt set digests.

R must be nonempty. An empty saved map is valid when R is nonempty and W covers
R completely with valid explanations. Empty R is not evidence of a complete
empty remote snapshot in this protocol and refuses publication.

Result `refreshed`, `withheld`, `saved` and `arrivals` use the grouped shape
`{count, sha256}`. For each, hash canonical JSON of the sorted array of raw-key
fingerprint digests. The empty set hashes `[]`. Arrivals' count and digest bind
the producer's observation; they cannot independently prove exclusion from Q
without the full post-read snapshot. The retained R map intentionally excludes
them, so a consumer must not compute arrivals as R minus P.

Hash overrides can hide same-fingerprint membership changes. Before runtime
activation, the producer must bind before/after membership evidence or an
explicit conservative withholding proof for changed membership. Unchanged
canonical content alone is not proof that no competing issue appeared.

## Normal execution receipts

`DrainAttempt` and `DrainResult` define the strict normal-generation field sets.
Their version is 2; a normal attempt has status `attempt_started` and generation
at least 1. It restores exactly generation minus one and binds the admitted
previous evidence and pending digests. Attempt, result and evidence agree on
run ID, run attempt, generation, full plan, selected/deferred and settings
hashes. Attempt and result also agree on the jobs digest.

`verified` and `unverified` are sorted disjoint arrays partitioning S's work
keys. `created` maps selected create work keys to acknowledged issue IDs;
every verified create has an ID, but an acknowledged ID is not itself proof of
the desired effect. Batch acknowledgments cannot exceed attempted batches or
the attempt's planned batches. The planned batch count is exactly the sum,
over the four kinds, of ceil(selected count for that kind / 10). Private payloads
are not needed to recompute this. An empty selection has zero batches.
For normal receipts, `linear_writes_attempted` equals
`batches_attempted > 0` for issue dispatch; auxiliary effects remain separately
accounted for by the auxiliary policy described below. Cache admission requires a saved result whose
status is success or partial_or_uncertain and fully consistent evidence.
Failures that lack committed evidence do not authorize a new generation.

Auxiliary comments and create subscription cleanup are additional API effects,
not issue operations. The opt-in runtime policy below specifies their retry and receipt accounting; the issue cap does not bound every API mutation.

## Generation zero: distinct initialization receipts

Use `attempt.json` and `result.json`, but decode into separate strict
`DrainInitializationAttempt` and `DrainInitializationResult` types. Both have
`kind: "initialization"`, version 2 and generation 0. Normal receipt schemas
have no `kind` field. Reject hybrid shapes. Do not manufacture empty jobs or
plan hashes, or use null values as substitutes for absent execution fields.

Initialization attempt fields are exactly:

- `version`, `kind`, `status` (exactly `initialization_started`), `started_at`;
- `producer_run_id`, `producer_run_attempt`, `generation`;
- `initialization`: exactly `source_cache_key`, `source_cache_sha256`,
  `v2_producer_run_id`, `authorizing_run_id`.

Initialization result fields are exactly:

- `version`, `kind`, `status` (`success` or `failed_before_writes`), `finished_at`;
- `producer_run_id`, `producer_run_attempt`, `generation`;
- `initialization_attempt_sha256` (exact attempt bytes),
  `pending_after_sha256`, `hash_evidence_sha256`;
- `cache_status` (`saved`, `not_saved` or `save_failed_or_uncertain`);
- `linear_writes_attempted` (always false);
- grouped `refreshed`, `withheld`, `saved`, `arrivals` keysets.

Only success plus saved admits generation zero. Its pending entries are empty;
P equals nonempty R; W is empty; saved equals R; arrivals is empty. Its evidence
contains the initialization block instead of execution-plan digests. Run ID,
run attempt and generation agree across the receipts and evidence. The result
binds the exact pending/evidence row bytes. The initialization block agrees
between attempt and evidence. Its authorizing run ID is the initializer's
producer run ID, not the old source producer's ID.

The source cache key must not contain `-v3-drain-`. The source cache must be an
explicitly admitted non-drain cache, bound by exact
key and byte hash and the authenticated source producer's receipt. Initialization
is an explicit boundary, never a fallback for missing/expired drain receipts,
missing pending rows, damaged generations or an empty restore.

## Pending continuity and admission boundaries

Pending records retain their original age. Selection without effect verification
increments the unverified counter; deferral preserves it. Never silently reset
age or counter while work remains. Only a create-to-issue handoff may inherit
ownership through a shared fingerprint; two unrelated issue IDs must not borrow
each other's age. Missing restored work must refuse rather than silently vanish
without a separately specified verified completion proof. Three unverified
selections while pending prevent further progress, including deferrals between
them; the stall rule must not be described as consecutive wall-clock runs. Persist
and admit the third unverified checkpoint (counter 3), so its failure history
is durable. It is the subsequent selection/attempt from that restored state
that must refuse. Retention of the third checkpoint must not be confused with
authorization to dispatch another generation.

A self-consistent cache or fixture is not authenticated producer evidence.
Missing producer receipts always refuse, with no generation reset or legacy
fallback. Artifact availability is separate from age: future timestamps and an
expired acceptance window must be rejected by the runtime admission boundary.
Exact freshness thresholds, receipt-retention policy, external provenance,
destination identity and the admission CLI remain runtime integration gates,
not facts established by this offline schema.

## Shared wire fixtures

The checked-in files under `internal/sync/testdata/drain-v1/` are generated
directly by Go types and helpers in `drain_contract_fixture_test.go`. Each
bundle has `row` (pending/evidence canonical strings and saved Linear map),
`receipts` (attempt/result and exact retained-plan strings), `valid`, and an
optional `restored` generation-zero bundle. An empty plan string denotes no
plan artifact for initialization, not an empty normal plan.

Regenerate only when intentionally changing this contract:

```sh
UPDATE_DRAIN_FIXTURES=1 go test ./internal/sync -run TestDrainProducerWireFixtures
go test ./internal/sync -run TestDrainProducerWireFixtures
python3 scripts/check-drain-fixtures.py /path/to/infra/scripts/snyk_linear_drain_receipts.py
```

The ordinary Go test checks that fixture bytes have not drifted. It validates
positive row admission, operation projection and partition, and refuses negative
row fixtures. The Python harness checks exact canonical agreement and both
consumer admission and retention. Positive cases include generation zero,
success, mixed deferred/unverified/drift with an empty saved map, an absent
pre-write key, and an excluded concurrent arrival. Negative cases reject number
or leading-zero run IDs, empty refreshed evidence, and withholding outside R.
This is an offline compatibility suite, not an authenticated producer, runtime
integration test, or complete test of every future receipt failure mode.

## Opt-in producer implementation

The explicit, undeployed `--plan-and-execute-drain` producer preserves the field
sets above. It binds supplied admitted prior-row digests and expected settings;
external authenticated provenance, exact-cache binding, freshness and durable
single-writer/attempt-one enforcement are still caller gates. There is no
producer initialization route or implicit fallback.

For membership safety this implementation refuses publication when the known
fingerprint member sets change without an acknowledged selected create or a
verified selected rebind explaining the change. It does not add a new W reason
or silently admit a competing issue through a canonical hash override.

`auxiliary_comments.policy` is `disabled` (zero counters) or `per-batch-once`.
Counters describe update-batch comment-interface invocations and their complete
acknowledgements, separately from issue batch acknowledgements. The interface
can omit items without a meaningful diff. An uncertain comment stops later
issue dispatch and is not retried in this or later generations. Create
subscription cleanup is unsupported and must be disabled explicitly for this
mode; ordinary-mode behavior is unchanged. Consumers must keep auxiliary
uncertainty visible even when all issue effects verified and cache status saved.

An attempted create without a complete, valid acknowledged ID mapping refuses
checkpoint publication even if a fresh read could show no new issue. Absence
is not proof of non-creation. The caller must retain the failed attempt and
require reconciliation before another attempt; it must not replay the old cache
automatically. Fully acknowledged creates may advance only after the normal
fresh effect and membership checks.

If a comment was attempted but its underlying issue update remains unverified,
checkpoint publication also refuses. Reconciliation is required rather than
allowing a later generation to repeat that comment with the update.
