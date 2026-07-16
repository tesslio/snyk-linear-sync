package linear

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"

	gqlclient "git.sr.ht/~emersion/gqlclient"

	"github.com/RichardoC/snyk-linear-sync/internal/config"
	"github.com/RichardoC/snyk-linear-sync/internal/model"
)

func TestDesiredLabelIDsReplacesPreviousManagedLabel(t *testing.T) {
	client := &Client{
		cfg: config.LinearConfig{
			Labels: config.LabelConfig{
				Managed: "snyk-automation",
			},
		},
		managedLabelIDs: map[string]string{
			"snyk-automation": "label-new",
			"snyk-code":       "label-code",
		},
	}

	existing := model.ExistingIssue{
		ManagedLabels: []string{"old-managed"},
		Labels: []model.IssueLabel{
			{ID: "label-unrelated", Name: "customer-visible"},
			{ID: "label-old", Name: "old-managed"},
		},
	}
	desired := model.DesiredIssue{
		ManagedLabels: []string{"snyk-automation", "snyk-code"},
	}

	labelIDs, err := client.desiredLabelIDs(existing, desired)
	if err != nil {
		t.Fatalf("desiredLabelIDs() error = %v", err)
	}
	if len(labelIDs) != 3 {
		t.Fatalf("labelIDs len = %d, want 3", len(labelIDs))
	}
	if !containsString(labelIDs, "label-unrelated") {
		t.Fatalf("labelIDs = %#v, want unrelated label preserved", labelIDs)
	}
	if !containsString(labelIDs, "label-new") {
		t.Fatalf("labelIDs = %#v, want new managed label present", labelIDs)
	}
	if !containsString(labelIDs, "label-code") {
		t.Fatalf("labelIDs = %#v, want tool label present", labelIDs)
	}
	if containsString(labelIDs, "label-old") {
		t.Fatalf("labelIDs = %#v, want old managed label removed", labelIDs)
	}
}

func TestDesiredLabelIDsRemovesManagedLabelWhenDisabled(t *testing.T) {
	client := &Client{}
	existing := model.ExistingIssue{
		ManagedLabels: []string{"snyk-automation", "snyk-code"},
		Labels: []model.IssueLabel{
			{ID: "label-unrelated", Name: "customer-visible"},
			{ID: "label-managed", Name: "snyk-automation"},
			{ID: "label-tool", Name: "snyk-code"},
		},
	}

	labelIDs, err := client.desiredLabelIDs(existing, model.DesiredIssue{})
	if err != nil {
		t.Fatalf("desiredLabelIDs() error = %v", err)
	}
	if len(labelIDs) != 1 || labelIDs[0] != "label-unrelated" {
		t.Fatalf("labelIDs = %#v, want only unrelated label", labelIDs)
	}
}

// TestIssueUpdateInputSerializesEmptyLabelIdsAsArray guards against a regression
// where an empty LabelIds slice was omitted from the update mutation via
// `omitempty`. When an issue carried only managed labels and they are all
// being removed (no unrelated labels to preserve), desiredLabelIDs returns a
// non-nil empty slice. With omitempty that slice was dropped from the payload,
// so Linear never received a labelIds field and left the stale managed labels
// on the issue. The JSON must serialize as "labelIds":[] so Linear clears them.
func TestIssueUpdateInputSerializesEmptyLabelIdsAsArray(t *testing.T) {
	input := issueUpdateInput{
		LabelIds: make([]string, 0, 4), // non-nil empty slice, as desiredLabelIDs returns
	}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if !strings.Contains(string(raw), `"labelIds":[]`) {
		t.Fatalf("issueUpdateInput JSON must include \"labelIds\":[] for an empty slice so Linear clears labels, got: %s", raw)
	}
}

// TestUpdateIssuesClearsManagedLabelsWhenNoneDesired verifies the end-to-end
// behavior: an issue that had only managed labels, with label management now
// disabled, must send labelIds:[] in the update mutation so Linear removes them.
func TestUpdateIssuesClearsManagedLabelsWhenNoneDesired(t *testing.T) {
	var capturedInput map[string]any
	client := &Client{
		cfg: config.LinearConfig{
			TeamID: "team-1",
			States: config.StateConfig{
				Todo: "Todo",
			},
		},
		gql: gqlclient.New("http://linear.test/graphql", &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				var payload struct {
					Query     string         `json:"query"`
					Variables map[string]any `json:"variables"`
				}
				body, _ := io.ReadAll(req.Body)
				if err := json.Unmarshal(body, &payload); err != nil {
					t.Fatalf("json.Unmarshal() error = %v", err)
				}
				if strings.Contains(payload.Query, "mutation issueUpdateBatch") {
					for key, val := range payload.Variables {
						if strings.HasPrefix(key, "input") {
							capturedInput, _ = val.(map[string]any)
						}
					}
					return jsonResponse(t, `{"data":{"issueUpdate0":{"success":true}}}`), nil
				}
				t.Fatalf("unexpected GraphQL query: %s", payload.Query)
				return nil, nil
			}),
		}),
		log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		resolvedTeam: "team-1",
		statesByName: map[string]string{"todo": "state-1"},
		statesByType: map[string]string{"unstarted": "state-1"},
	}

	err := client.UpdateIssues(t.Context(), []model.IssueUpdate{{
		Existing: model.ExistingIssue{
			ID:            "issue-1",
			Identifier:    "SNYK-1",
			ManagedLabels: []string{"snyk-automation"},
			Labels:        []model.IssueLabel{{ID: "label-1", Name: "snyk-automation"}},
		},
		Desired: model.DesiredIssue{
			Fingerprint:   "snyk:proj-1:issue-1",
			Title:         "Snyk: title",
			Description:   "body",
			State:         model.StateTodo,
			ManagedLabels: nil, // label management off / none desired
			Priority:      2,
		},
	}})
	if err != nil {
		t.Fatalf("UpdateIssues() error = %v", err)
	}
	if capturedInput == nil {
		t.Fatal("no update input captured")
	}
	rawLabelIds, has := capturedInput["labelIds"]
	if !has {
		t.Fatalf("update mutation must include labelIds to clear managed labels, got: %#v", capturedInput)
	}
	arr, ok := rawLabelIds.([]any)
	if !ok || len(arr) != 0 {
		t.Fatalf("labelIds must be an empty array to clear labels, got: %#v", rawLabelIds)
	}
}

// TestLoadSnapshotArchiveFilterMatchesNotArchivedIssues guards against a
// regression where the "not archived" OR clauses in loadIssues' filter used
// AutoArchivedAt.Null: false instead of true. Per Linear's
// NullableDateComparator, "null: false" matches non-null values (i.e.
// archived issues) while "null: true" matches null values (i.e. NOT
// archived issues). With the inverted boolean, the first two OR clauses
// matched only archived tickets -- the opposite of their intent -- so the
// snapshot silently dropped every non-archived managed ticket outside the
// lookback window's Gte clauses, and the sync created duplicate tickets for
// issues that already had an open Linear ticket.
func TestLoadSnapshotArchiveFilterMatchesNotArchivedIssues(t *testing.T) {
	var capturedFilter map[string]any

	client := &Client{
		cfg: config.LinearConfig{
			TeamID:              "11111111-1111-1111-1111-111111111111",
			ArchiveLookbackDays: 21,
		},
		gql: gqlclient.New("http://linear.test/graphql", &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				var payload struct {
					Query     string         `json:"query"`
					Variables map[string]any `json:"variables"`
				}
				body, err := io.ReadAll(req.Body)
				if err != nil {
					t.Fatalf("ReadAll() error = %v", err)
				}
				if err := json.Unmarshal(body, &payload); err != nil {
					t.Fatalf("json.Unmarshal() error = %v", err)
				}

				switch {
				case strings.Contains(payload.Query, "query teamStates"):
					return jsonResponse(t, `{"data":{"team":{"states":{"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}}`), nil
				case strings.Contains(payload.Query, "query existingIssues"):
					filter, ok := payload.Variables["filter"].(map[string]any)
					if !ok {
						t.Fatalf("filter variable missing or wrong type: %#v", payload.Variables["filter"])
					}
					capturedFilter = filter
					return jsonResponse(t, `{"data":{"issues":{"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}`), nil
				default:
					t.Fatalf("unexpected GraphQL query: %s", payload.Query)
					return nil, nil
				}
			}),
		}),
		log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		statesByName: map[string]string{},
		statesByType: map[string]string{},
	}

	if _, err := client.LoadSnapshot(t.Context()); err != nil {
		t.Fatalf("LoadSnapshot() error = %v", err)
	}
	if capturedFilter == nil {
		t.Fatal("no filter captured for the existingIssues query")
	}

	orClauses, ok := capturedFilter["or"].([]any)
	if !ok {
		t.Fatalf("filter.or missing or wrong type: %#v", capturedFilter["or"])
	}
	if len(orClauses) != 4 {
		t.Fatalf("filter.or len = %d, want 4", len(orClauses))
	}

	var nullTrueCount, gteCount int
	for _, raw := range orClauses {
		clause, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("OR clause has wrong type: %#v", raw)
		}
		autoArchivedAt, ok := clause["autoArchivedAt"].(map[string]any)
		if !ok {
			t.Fatalf("OR clause missing autoArchivedAt: %#v", clause)
		}
		if nullVal, has := autoArchivedAt["null"]; has {
			if nullVal != true {
				t.Fatalf("autoArchivedAt.null = %#v, want true (matches NOT-archived issues); "+
					"null:false would match only archived issues, hiding open managed tickets", nullVal)
			}
			nullTrueCount++
			continue
		}
		if gte, has := autoArchivedAt["gte"]; has {
			gteStr, ok := gte.(string)
			if !ok || gteStr == "" {
				t.Fatalf("autoArchivedAt.gte = %#v, want a non-empty cutoff timestamp", gte)
			}
			gteCount++
			continue
		}
		t.Fatalf("OR clause autoArchivedAt has neither null nor gte: %#v", autoArchivedAt)
	}

	if nullTrueCount != 2 {
		t.Fatalf("clauses with autoArchivedAt.null=true = %d, want 2", nullTrueCount)
	}
	if gteCount != 2 {
		t.Fatalf("clauses with autoArchivedAt.gte = %d, want 2", gteCount)
	}
}

func TestExtractFingerprintPrefersMetadataBlock(t *testing.T) {
	description := "## Example\n\n<!-- snyk-linear-sync\nfingerprint: snyk:project-a:issue-1\nmanaged_labels: snyk-automation,snyk-code\n-->"

	got := extractFingerprint(description)

	if got != "snyk:project-a:issue-1" {
		t.Fatalf("extractFingerprint() = %q, want %q", got, "snyk:project-a:issue-1")
	}
}

// TestExtractFingerprintCanonicalizesLinearMangledMarkdown reproduces the
// stored form observed via the live Linear API: the sync wrote a fingerprint
// containing "__main__.py" and Linear's editor re-serialized it inside the
// metadata comment as "**main**.py". Extraction must return the canonical
// form or the ticket can never be matched again (hourly close-and-recreate
// flapping).
func TestExtractFingerprintCanonicalizesLinearMangledMarkdown(t *testing.T) {
	description := "## Path Traversal [LOW]\n\nFile: [sim/**main**.py (line 92:17-21)](<https://github.com/example/repo/blob/abc/sim/__main__.py#L92>)\n\n<!-- snyk-linear-sync\nfingerprint: snyk:project-a:issue-1:sim/**main**.py\nmanaged_labels: snyk-automation,snyk-code\n-->"

	got := extractFingerprint(description)

	if want := "snyk:project-a:issue-1:sim/__main__.py"; got != want {
		t.Fatalf("extractFingerprint() = %q, want %q", got, want)
	}
}

func TestExtractManagedLabelsSupportsLegacyAndNewMetadata(t *testing.T) {
	if got := extractManagedLabels("<!-- snyk-linear-sync\nmanaged_label: snyk-automation\n-->"); !slices.Equal(got, []string{"snyk-automation"}) {
		t.Fatalf("extractManagedLabels(legacy) = %#v", got)
	}
	if got := extractManagedLabels("<!-- snyk-linear-sync\nmanaged_labels: snyk-automation,snyk-code\n-->"); !slices.Equal(got, []string{"snyk-automation", "snyk-code"}) {
		t.Fatalf("extractManagedLabels(new) = %#v", got)
	}
}

// TestExtractFingerprintIgnoresLinesOutsideMetadataBlock verifies that a
// "Fingerprint:" line appearing in user-written body text is not extracted as
// the managed fingerprint. Only the fingerprint inside the line-anchored
// metadata block counts. This mirrors the line-boundary hardening applied to
// upsertManagedMetadata so user text cannot spoof deduplication.
func TestExtractFingerprintIgnoresLinesOutsideMetadataBlock(t *testing.T) {
	description := "Notes\nFingerprint: fake-from-user-text\n\n<!-- snyk-linear-sync\nfingerprint: snyk:project-a:issue-1\nmanaged_labels: snyk-automation\n-->"

	if got := extractFingerprint(description); got != "snyk:project-a:issue-1" {
		t.Fatalf("extractFingerprint() = %q, want the metadata-block fingerprint", got)
	}
}

// TestExtractFingerprintIgnoresInlineMarker verifies that an inline marker
// (mid-sentence) is not treated as a metadata block, so no fingerprint is
// extracted from a description that has no real line-anchored block.
func TestExtractFingerprintIgnoresInlineMarker(t *testing.T) {
	description := "See <!-- snyk-linear-sync notes --> for context\nFingerprint: not-a-real-block"

	if got := extractFingerprint(description); got != "" {
		t.Fatalf("extractFingerprint() = %q, want empty (no line-anchored block)", got)
	}
	if got := extractManagedLabels(description); got != nil {
		t.Fatalf("extractManagedLabels() = %#v, want nil (no line-anchored block)", got)
	}
}

// TestExtractManagedLabelsIgnoresLinesOutsideMetadataBlock verifies that a
// "managed_labels:" line in user body text does not override the real
// metadata block value.
func TestExtractManagedLabelsIgnoresLinesOutsideMetadataBlock(t *testing.T) {
	description := "managed_labels: fake-from-user\n\n<!-- snyk-linear-sync\nmanaged_labels: snyk-automation,snyk-code\n-->"

	if got := extractManagedLabels(description); !slices.Equal(got, []string{"snyk-automation", "snyk-code"}) {
		t.Fatalf("extractManagedLabels() = %#v, want the metadata-block labels", got)
	}
}

// TestFindMetadataBlockStartReturnsLastOccurrence guards against a
// regression where findMetadataBlockStart returned the FIRST line-anchored
// "<!-- snyk-linear-sync" marker instead of the LAST. Ticket descriptions
// can embed free-form Snyk-controlled prose (issue description/remediation
// text) above the real metadata block, since the sync always appends its
// managed block last. If that prose happens to contain its own line-anchored
// marker (e.g. quoted from elsewhere), the first-occurrence behavior would
// hijack fingerprint/label extraction and break ticket matching, causing
// duplicate ticket creation.
func TestFindMetadataBlockStartReturnsLastOccurrence(t *testing.T) {
	cases := []struct {
		name        string
		description string
		wantIdx     int
	}{
		{
			name:        "single block unchanged",
			description: "Some text\n<!-- snyk-linear-sync\nfingerprint: test\n-->",
			wantIdx:     10, // after "Some text\n"
		},
		{
			name:        "fake block before real block: last wins",
			description: "<!-- snyk-linear-sync\nfingerprint: fake\n-->\nSome text\n<!-- snyk-linear-sync\nfingerprint: real\n-->",
			wantIdx:     54, // index of the second marker
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := findMetadataBlockStart(tc.description)
			if got != tc.wantIdx {
				t.Fatalf("findMetadataBlockStart() = %d, want %d", got, tc.wantIdx)
			}
		})
	}
}

// TestExtractMetadataUsesLastBlockWhenFakeBlockPrecedesReal verifies that
// when a fake, line-anchored "<!-- snyk-linear-sync ... -->" block appears
// before the real one (e.g. embedded in Snyk-controlled prose above the
// sync-managed block), extractFingerprint and extractManagedLabels return
// the values from the LAST (real) block, not the first (fake) one.
func TestExtractMetadataUsesLastBlockWhenFakeBlockPrecedesReal(t *testing.T) {
	description := "<!-- snyk-linear-sync\n" +
		"fingerprint: fake-from-embedded-prose\n" +
		"managed_labels: fake-label\n" +
		"-->\n\n" +
		"## Remediation\n\nSome Snyk-controlled prose describing the finding.\n\n" +
		"<!-- snyk-linear-sync\n" +
		"fingerprint: snyk:project-a:issue-1\n" +
		"managed_labels: snyk-automation,snyk-code\n" +
		"-->"

	if got := extractFingerprint(description); got != "snyk:project-a:issue-1" {
		t.Fatalf("extractFingerprint() = %q, want the last (real) block's fingerprint", got)
	}
	if got := extractManagedLabels(description); !slices.Equal(got, []string{"snyk-automation", "snyk-code"}) {
		t.Fatalf("extractManagedLabels() = %#v, want the last (real) block's labels", got)
	}
}

// TestExtractMetadataUsesLastBlockWhenFakeBlockInsideFencedCode verifies
// that a fake metadata block embedded inside a fenced code block (still
// line-anchored, since fences don't change line-boundary semantics) does
// not win over the real, sync-appended block that follows it.
func TestExtractMetadataUsesLastBlockWhenFakeBlockInsideFencedCode(t *testing.T) {
	description := "```\n" +
		"<!-- snyk-linear-sync\n" +
		"fingerprint: fake-in-code-block\n" +
		"-->\n" +
		"```\n\n" +
		"<!-- snyk-linear-sync\n" +
		"fingerprint: snyk:project-a:issue-2\n" +
		"-->"

	if got := extractFingerprint(description); got != "snyk:project-a:issue-2" {
		t.Fatalf("extractFingerprint() = %q, want the last (real) block's fingerprint", got)
	}
}

func TestActorSubscriberIDsForCreateEnabledEncodesEmptyList(t *testing.T) {
	client := &Client{
		cfg: config.LinearConfig{
			UnsubscribeActor: true,
		},
	}

	input := issueCreateInput{
		SubscriberIds: client.actorSubscriberIDsForCreate(),
	}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if string(raw) != `{"subscriberIds":[],"teamId":""}` {
		t.Fatalf("json.Marshal() = %s, want subscriberIds empty list", raw)
	}
}

// TestIssueUpdateInputNeverContainsSubscriberIds guards against regressions where
// subscriberIds is added back to issueUpdateInput. Linear's IssueUpdateInput GraphQL
// type does not have a subscriberIds field; sending it causes an Argument Validation Error.
func TestIssueUpdateInputNeverContainsSubscriberIds(t *testing.T) {
	input := issueUpdateInput{
		Title:       new("title"),
		Description: new("body"),
		StateId:     new("state-1"),
		LabelIds:    []string{"label-1"},
		DueDate:     new("2026-04-07"),
	}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if strings.Contains(string(raw), "subscriberIds") || strings.Contains(string(raw), "subscriberId") {
		t.Fatalf("issueUpdateInput JSON must not contain subscriberIds, got: %s", raw)
	}
}

//go:fix inline
func strPtr(s string) *string { return new(s) }

// TestUpdateIssuesDoesNotSendSubscriberIdsInPayload verifies that UpdateIssues never
// includes subscriberIds in the GraphQL mutation variables, even when UnsubscribeActor is true.
func TestUpdateIssuesDoesNotSendSubscriberIdsInPayload(t *testing.T) {
	client := &Client{
		cfg: config.LinearConfig{
			TeamID:           "team-1",
			UnsubscribeActor: true,
			States: config.StateConfig{
				Todo: "Todo",
			},
		},
		gql: gqlclient.New("http://linear.test/graphql", &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				var payload struct {
					Query     string         `json:"query"`
					Variables map[string]any `json:"variables"`
				}
				body, err := io.ReadAll(req.Body)
				if err != nil {
					t.Fatalf("ReadAll() error = %v", err)
				}
				if err := json.Unmarshal(body, &payload); err != nil {
					t.Fatalf("json.Unmarshal() error = %v", err)
				}
				if strings.Contains(payload.Query, "mutation issueUpdateBatch") {
					for key, val := range payload.Variables {
						if !strings.HasPrefix(key, "input") {
							continue
						}
						input, ok := val.(map[string]any)
						if !ok {
							continue
						}
						if _, has := input["subscriberIds"]; has {
							t.Fatalf("issueUpdate mutation must not include subscriberIds in %s, got: %#v", key, input)
						}
					}
					return jsonResponse(t, `{"data":{"issueUpdate0":{"success":true}}}`), nil
				}
				t.Fatalf("unexpected GraphQL query: %s", payload.Query)
				return nil, nil
			}),
		}),
		log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		resolvedTeam: "team-1",
		statesByName: map[string]string{"todo": "state-1"},
		statesByType: map[string]string{"unstarted": "state-1"},
		managedLabelIDs: map[string]string{
			"snyk-automation": "label-1",
		},
	}

	err := client.UpdateIssues(t.Context(), []model.IssueUpdate{{
		Existing: model.ExistingIssue{
			ID:            "issue-1",
			Identifier:    "SNYK-1",
			ManagedLabels: []string{"snyk-automation"},
			Labels:        []model.IssueLabel{{ID: "label-1", Name: "snyk-automation"}},
		},
		Desired: model.DesiredIssue{
			Fingerprint:   "snyk:proj-1:issue-1",
			Title:         "Snyk: updated title",
			Description:   "updated body",
			State:         model.StateTodo,
			ManagedLabels: []string{"snyk-automation"},
			Priority:      2,
		},
	}})
	if err != nil {
		t.Fatalf("UpdateIssues() error = %v", err)
	}
}

// TestDesiredLabelIDsPreservesManuallyAddedLabels verifies that labels added manually
// (not tracked in managed_labels metadata) are preserved when an issue is updated.
func TestDesiredLabelIDsPreservesManuallyAddedLabels(t *testing.T) {
	client := &Client{
		managedLabelIDs: map[string]string{
			"snyk-automation": "label-managed",
		},
	}

	existing := model.ExistingIssue{
		ManagedLabels: []string{"snyk-automation"},
		Labels: []model.IssueLabel{
			{ID: "label-managed", Name: "snyk-automation"},
			{ID: "label-manual-1", Name: "needs-review"},
			{ID: "label-manual-2", Name: "team-platform"},
		},
	}
	desired := model.DesiredIssue{
		ManagedLabels: []string{"snyk-automation"},
	}

	labelIDs, err := client.desiredLabelIDs(existing, desired)
	if err != nil {
		t.Fatalf("desiredLabelIDs() error = %v", err)
	}
	if !containsString(labelIDs, "label-manual-1") {
		t.Fatalf("labelIDs = %#v, want manually-added label 'needs-review' preserved", labelIDs)
	}
	if !containsString(labelIDs, "label-manual-2") {
		t.Fatalf("labelIDs = %#v, want manually-added label 'team-platform' preserved", labelIDs)
	}
	if !containsString(labelIDs, "label-managed") {
		t.Fatalf("labelIDs = %#v, want managed label preserved", labelIDs)
	}
	if len(labelIDs) != 3 {
		t.Fatalf("labelIDs len = %d, want 3", len(labelIDs))
	}
}

func TestCreateIssuesRemovesActorAfterCreateWhenLinearAutoSubscribesThem(t *testing.T) {
	var requests []struct {
		Query     string
		Variables map[string]any
	}

	client := &Client{
		cfg: config.LinearConfig{
			TeamID:           "team-1",
			UnsubscribeActor: true,
			States: config.StateConfig{
				Todo: "Todo",
			},
		},
		gql: gqlclient.New("http://linear.test/graphql", &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				var payload struct {
					Query     string         `json:"query"`
					Variables map[string]any `json:"variables"`
				}
				body, err := io.ReadAll(req.Body)
				if err != nil {
					t.Fatalf("ReadAll() error = %v", err)
				}
				if err := json.Unmarshal(body, &payload); err != nil {
					t.Fatalf("json.Unmarshal() error = %v", err)
				}
				requests = append(requests, struct {
					Query     string
					Variables map[string]any
				}{
					Query:     payload.Query,
					Variables: payload.Variables,
				})

				switch {
				case strings.Contains(payload.Query, "mutation issueCreateBatch"):
					input0 := payload.Variables["input0"].(map[string]any)
					if subscriberIDs := input0["subscriberIds"]; !slices.Equal(anyStrings(subscriberIDs), []string{}) {
						t.Fatalf("create subscriberIds = %#v, want empty list", subscriberIDs)
					}
					return jsonResponse(t, `{"data":{"issueCreate0":{"success":true,"issue":{"id":"issue-1","identifier":"ENG-1"}}}}`), nil
				case strings.Contains(payload.Query, "mutation issueUnsubscribeBatch"):
					if got := payload.Variables["id0"]; got != "issue-1" {
						t.Fatalf("issueUnsubscribe id0 = %#v, want issue-1", got)
					}
					return jsonResponse(t, `{"data":{"issueUnsubscribe0":{"success":true}}}`), nil
				default:
					t.Fatalf("unexpected GraphQL query: %s", payload.Query)
					return nil, nil
				}
			}),
		}),
		log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		resolvedTeam: "team-1",
		statesByName: map[string]string{"todo": "state-1"},
		statesByType: map[string]string{"unstarted": "state-1"},
	}

	failed, err := client.CreateIssues(t.Context(), []model.DesiredIssue{{
		Fingerprint: "snyk:project-1:issue-1",
		Title:       "Snyk: example",
		Description: "body",
		State:       model.StateTodo,
		Priority:    3,
	}})
	if err != nil {
		t.Fatalf("CreateIssues() error = %v", err)
	}
	if len(failed) != 0 {
		t.Fatalf("CreateIssues() failed indices = %v, want none", failed)
	}

	if len(requests) != 2 {
		t.Fatalf("request count = %d, want 2", len(requests))
	}
}

func containsString(values []string, want string) bool {
	return slices.Contains(values, want)
}

func anyStrings(value any) []string {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			continue
		}
		out = append(out, s)
	}
	return out
}

func jsonResponse(t *testing.T, body string) *http.Response {
	t.Helper()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(bytes.NewBufferString(body)),
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// TestUpdateIssuesOmitsStateIdWhenPreserveStateTrue verifies that UpdateIssues
// does not include stateId in the GraphQL mutation payload when
// Desired.PreserveState is true, preventing the sync tool from fighting
// manual state moves (e.g. human triage from Triage → Todo).
func TestUpdateIssuesOmitsStateIdWhenPreserveStateTrue(t *testing.T) {
	var requests []struct {
		Query     string
		Variables map[string]any
	}

	client := &Client{
		cfg: config.LinearConfig{
			TeamID: "team-1",
			States: config.StateConfig{
				Todo: "Todo",
			},
		},
		gql: gqlclient.New("http://linear.test/graphql", &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				var payload struct {
					Query     string         `json:"query"`
					Variables map[string]any `json:"variables"`
				}
				body, err := io.ReadAll(req.Body)
				if err != nil {
					t.Fatalf("ReadAll() error = %v", err)
				}
				if err := json.Unmarshal(body, &payload); err != nil {
					t.Fatalf("json.Unmarshal() error = %v", err)
				}
				requests = append(requests, struct {
					Query     string
					Variables map[string]any
				}{
					Query:     payload.Query,
					Variables: payload.Variables,
				})

				if strings.Contains(payload.Query, "mutation issueUpdateBatch") {
					return jsonResponse(t, `{"data":{"issueUpdate0":{"success":true}}}`), nil
				}
				t.Fatalf("unexpected GraphQL query: %s", payload.Query)
				return nil, nil
			}),
		}),
		log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		resolvedTeam: "team-1",
		statesByName: map[string]string{"todo": "state-todo"},
		statesByType: map[string]string{"unstarted": "state-todo"},
		managedLabelIDs: map[string]string{
			"snyk-automation": "label-1",
		},
	}

	err := client.UpdateIssues(t.Context(), []model.IssueUpdate{{
		Existing: model.ExistingIssue{
			ID:            "issue-1",
			Identifier:    "SEC-1",
			StateID:       "state-todo",
			StateName:     "Todo",
			ManagedLabels: []string{"snyk-automation"},
			Labels:        []model.IssueLabel{{ID: "label-1", Name: "snyk-automation"}},
		},
		Desired: model.DesiredIssue{
			Fingerprint:   "snyk:proj-1:issue-1",
			Title:         "updated title",
			Description:   "updated body",
			State:         model.StateTodo,
			PreserveState: true,
			ManagedLabels: []string{"snyk-automation"},
			Priority:      2,
		},
	}})
	if err != nil {
		t.Fatalf("UpdateIssues() error = %v", err)
	}

	if len(requests) != 1 {
		t.Fatalf("request count = %d, want 1", len(requests))
	}

	input0 := requests[0].Variables["input0"].(map[string]any)
	if _, has := input0["stateId"]; has {
		t.Fatalf("issueUpdate mutation must omit stateId when PreserveState=true, got: %#v", input0)
	}
	if input0["title"] != "updated title" {
		t.Fatalf("title = %v, want 'updated title'", input0["title"])
	}
}

func TestBuildChangeCommentGeneratesSummary(t *testing.T) {
	update := model.IssueUpdate{
		Existing: model.ExistingIssue{
			ID:            "issue-1",
			Identifier:    "SEC-1",
			Title:         "old title",
			Description:   "old body",
			DueDate:       "2026-04-01",
			StateName:     "Todo",
			Priority:      3,
			ManagedLabels: []string{"snyk-automation"},
			Labels:        []model.IssueLabel{{ID: "l1", Name: "snyk-automation"}},
		},
		Desired: model.DesiredIssue{
			Title:         "new title",
			Description:   "new body",
			DueDate:       "2026-05-01",
			State:         model.StateBacklog,
			StateReason:   "Snyk reports this issue as ignored until a fix is available",
			DueDateReason: "high severity SLA: 30 days from issue creation",
			Priority:      1,
			ManagedLabels: []string{"snyk-automation", "snyk-code"},
			LabelReasons:  map[string]string{"snyk-code": "Snyk issue type is code"},
		},
		Diff: &model.IssueDiff{
			TitleChanged:       true,
			TitleFrom:          "old title",
			TitleTo:            "new title",
			DescriptionChanged: true,
			DueDateChanged:     true,
			DueDateFrom:        "2026-04-01",
			DueDateTo:          "2026-05-01",
			StateChanged:       true,
			StateFrom:          "Todo",
			StateTo:            "backlog",
			PriorityChanged:    true,
			PriorityFrom:       3,
			PriorityTo:         1,
			LabelsAdded:        []string{"snyk-code"},
		},
	}

	comment := buildChangeComment(update)

	if comment == "" {
		t.Fatal("expected non-empty comment")
	}
	if !strings.Contains(comment, "**snyk-linear-sync**") {
		t.Fatalf("comment missing header: %s", comment)
	}
	// State comment explains why, not just what
	if !strings.Contains(comment, "Moved to **backlog** — Snyk reports this issue as ignored until a fix is available") {
		t.Fatalf("comment missing state change with reason: %s", comment)
	}
	// Due date comment explains the SLA basis
	if !strings.Contains(comment, "Due date set to **2026-05-01** — high severity SLA: 30 days from issue creation") {
		t.Fatalf("comment missing due date with reason: %s", comment)
	}
	// Description explains the driver
	if !strings.Contains(comment, "Description updated — Snyk finding data changed") {
		t.Fatalf("comment missing description reason: %s", comment)
	}
	// Title explains the driver
	if !strings.Contains(comment, "Title updated — Snyk finding data changed") {
		t.Fatalf("comment missing title reason: %s", comment)
	}
	// Priority uses human-readable name and explains the driver
	if !strings.Contains(comment, "Priority set to **Urgent** — Snyk severity changed") {
		t.Fatalf("comment missing priority with reason: %s", comment)
	}
	// Added label includes reason from LabelReasons
	if !strings.Contains(comment, "Added **snyk-code** — Snyk issue type is code") {
		t.Fatalf("comment missing label with reason: %s", comment)
	}
}

func TestBuildChangeCommentReturnsEmptyWhenNoChanges(t *testing.T) {
	update := model.IssueUpdate{
		Existing: model.ExistingIssue{
			Title:       "title",
			Description: "desc",
			DueDate:     "2026-04-01",
			StateName:   "Todo",
			Priority:    2,
		},
		Desired: model.DesiredIssue{
			Title:       "title",
			Description: "desc",
			DueDate:     "2026-04-01",
			State:       model.StateTodo,
			Priority:    2,
		},
		Diff: &model.IssueDiff{},
	}

	comment := buildChangeComment(update)

	if comment != "" {
		t.Fatalf("expected empty comment, got: %s", comment)
	}
}

func TestBuildChangeCommentDueDateClearedWithReason(t *testing.T) {
	update := model.IssueUpdate{
		Existing: model.ExistingIssue{
			DueDate:   "2026-04-01",
			StateName: "Todo",
		},
		Desired: model.DesiredIssue{
			DueDate:       "",
			DueDateReason: "awaiting upstream fix, SLA paused",
			State:         model.StateBacklog,
		},
		Diff: &model.IssueDiff{
			DueDateChanged: true,
			DueDateFrom:    "2026-04-01",
			DueDateTo:      "",
		},
	}

	comment := buildChangeComment(update)
	if !strings.Contains(comment, "Due date cleared — awaiting upstream fix, SLA paused") {
		t.Fatalf("comment missing cleared due date with reason: %s", comment)
	}
}

func TestBuildChangeCommentRemovedLabels(t *testing.T) {
	update := model.IssueUpdate{
		Existing: model.ExistingIssue{
			ManagedLabels: []string{"snyk-automation", "triage-dependency"},
			Labels: []model.IssueLabel{
				{ID: "l1", Name: "snyk-automation"},
				{ID: "l2", Name: "triage-dependency"},
			},
			StateName: "Backlog",
		},
		Desired: model.DesiredIssue{
			State:         model.StateTodo,
			ManagedLabels: []string{"snyk-automation"},
		},
		Diff: &model.IssueDiff{
			StateChanged:     true,
			StateFrom:        "Backlog",
			StateTo:          "todo",
			LabelsRemoved:    []string{"triage-dependency"},
			LabelsNeedUpdate: true,
		},
	}

	comment := buildChangeComment(update)
	if !strings.Contains(comment, "Removed **triage-dependency** — no longer applicable") {
		t.Fatalf("comment missing removed label: %s", comment)
	}
}

func TestBuildChangeCommentStateChangeWithoutReason(t *testing.T) {
	update := model.IssueUpdate{
		Existing: model.ExistingIssue{
			StateName: "Todo",
		},
		Desired: model.DesiredIssue{
			State:       model.StateDone,
			StateReason: "", // no reason provided
		},
		Diff: &model.IssueDiff{
			StateChanged: true,
			StateFrom:    "Todo",
			StateTo:      "done",
		},
	}

	comment := buildChangeComment(update)
	if !strings.Contains(comment, "Moved to **done**") {
		t.Fatalf("comment missing state change: %s", comment)
	}
	// Should NOT contain an em-dash reason when reason is empty
	if strings.Contains(comment, "Moved to **done** —") {
		t.Fatalf("comment should not have reason suffix when empty: %s", comment)
	}
}

func TestBuildChangeCommentReturnsEmptyWhenDiffIsNil(t *testing.T) {
	update := model.IssueUpdate{
		Existing: model.ExistingIssue{
			Title:       "title",
			Description: "desc",
			DueDate:     "2026-04-01",
			StateName:   "Todo",
			Priority:    2,
		},
		Desired: model.DesiredIssue{
			Title:       "new title",
			Description: "new desc",
			DueDate:     "2026-05-01",
			State:       model.StateBacklog,
			Priority:    1,
		},
		Diff: nil,
	}

	comment := buildChangeComment(update)

	if comment != "" {
		t.Fatalf("expected empty comment when diff is nil, got: %s", comment)
	}
}

// TestCreateIssuesPartialAliasFailureReturnsOnlyFailedIndices verifies that
// when one aliased issueCreate in a batched mutation reports success: false
// while its siblings succeed, CreateIssues reports only the failed index
// instead of an error for the whole batch. Treating a partial failure as a
// whole-batch failure made the caller recreate the already-created siblings,
// producing duplicate tickets.
func TestCreateIssuesPartialAliasFailureReturnsOnlyFailedIndices(t *testing.T) {
	client := &Client{
		cfg: config.LinearConfig{
			TeamID: "team-1",
			States: config.StateConfig{Todo: "Todo"},
		},
		gql: gqlclient.New("http://linear.test/graphql", &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return jsonResponse(t, `{"data":{
					"issueCreate0":{"success":true,"issue":{"id":"issue-1","identifier":"ENG-1"}},
					"issueCreate1":{"success":false,"issue":{"id":"","identifier":""}}
				}}`), nil
			}),
		}),
		log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		resolvedTeam: "team-1",
		statesByName: map[string]string{"todo": "state-1"},
		statesByType: map[string]string{"unstarted": "state-1"},
	}

	failed, err := client.CreateIssues(t.Context(), []model.DesiredIssue{
		{
			Fingerprint: "snyk:project-1:issue-1",
			Title:       "Snyk: first",
			Description: "body",
			State:       model.StateTodo,
			Priority:    3,
		},
		{
			Fingerprint: "snyk:project-1:issue-2",
			Title:       "Snyk: second",
			Description: "body",
			State:       model.StateTodo,
			Priority:    3,
		},
	})
	if err != nil {
		t.Fatalf("CreateIssues() error = %v, want nil (partial failure is not a batch error)", err)
	}
	if len(failed) != 1 || failed[0] != 1 {
		t.Fatalf("CreateIssues() failed indices = %v, want [1]", failed)
	}
}

// TestCreateIssuesUnsubscribeFailureDoesNotFailCreates verifies that a
// failure in the best-effort post-create actor-unsubscribe step is not
// reported as a create failure. The issues were already created; returning
// an error here made the caller recreate them, producing duplicate tickets.
func TestCreateIssuesUnsubscribeFailureDoesNotFailCreates(t *testing.T) {
	client := &Client{
		cfg: config.LinearConfig{
			TeamID:           "team-1",
			UnsubscribeActor: true,
			States:           config.StateConfig{Todo: "Todo"},
		},
		gql: gqlclient.New("http://linear.test/graphql", &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				body, err := io.ReadAll(req.Body)
				if err != nil {
					t.Fatalf("ReadAll() error = %v", err)
				}
				payload := string(body)
				switch {
				case strings.Contains(payload, "issueCreateBatch"):
					return jsonResponse(t, `{"data":{"issueCreate0":{"success":true,"issue":{"id":"issue-1","identifier":"ENG-1"}}}}`), nil
				case strings.Contains(payload, "issueUnsubscribeBatch"):
					return jsonResponse(t, `{"errors":[{"message":"unsubscribe exploded"}]}`), nil
				default:
					t.Fatalf("unexpected GraphQL query: %s", payload)
					return nil, nil
				}
			}),
		}),
		log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		resolvedTeam: "team-1",
		statesByName: map[string]string{"todo": "state-1"},
		statesByType: map[string]string{"unstarted": "state-1"},
	}

	failed, err := client.CreateIssues(t.Context(), []model.DesiredIssue{{
		Fingerprint: "snyk:project-1:issue-1",
		Title:       "Snyk: example",
		Description: "body",
		State:       model.StateTodo,
		Priority:    3,
	}})
	if err != nil {
		t.Fatalf("CreateIssues() error = %v, want nil (unsubscribe is best-effort)", err)
	}
	if len(failed) != 0 {
		t.Fatalf("CreateIssues() failed indices = %v, want none", failed)
	}
}

// TestPostCommentsPartialAliasFailureReturnsOnlyFailedIndices verifies the
// PostComments equivalent of the CreateIssues partial-failure contract: only
// the update whose commentCreate alias failed is reported, mapped back to
// its index in the updates slice (accounting for updates that produced no
// comment at all), so the caller does not re-post comments that already
// landed — re-posting spams duplicate notifications to subscribers.
func TestPostCommentsPartialAliasFailureReturnsOnlyFailedIndices(t *testing.T) {
	client := &Client{
		cfg: config.LinearConfig{TeamID: "team-1"},
		gql: gqlclient.New("http://linear.test/graphql", &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return jsonResponse(t, `{"data":{
					"commentCreate0":{"success":true,"comment":{"id":"comment-1"}},
					"commentCreate1":{"success":false,"comment":{"id":""}}
				}}`), nil
			}),
		}),
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	updates := []model.IssueUpdate{
		{
			// No diff: produces no comment and must never appear in the
			// failed list, and must not shift the index mapping.
			Existing: model.ExistingIssue{ID: "existing-0", Identifier: "ENG-10"},
			Desired:  model.DesiredIssue{Fingerprint: "snyk:project-1:issue-10"},
		},
		{
			Existing: model.ExistingIssue{ID: "existing-1", Identifier: "ENG-11"},
			Desired:  model.DesiredIssue{Fingerprint: "snyk:project-1:issue-11"},
			Diff:     &model.IssueDiff{TitleChanged: true},
		},
		{
			Existing: model.ExistingIssue{ID: "existing-2", Identifier: "ENG-12"},
			Desired:  model.DesiredIssue{Fingerprint: "snyk:project-1:issue-12"},
			Diff:     &model.IssueDiff{TitleChanged: true},
		},
	}

	failed, err := client.PostComments(t.Context(), updates)
	if err != nil {
		t.Fatalf("PostComments() error = %v, want nil (partial failure is not a batch error)", err)
	}
	if len(failed) != 1 || failed[0] != 2 {
		t.Fatalf("PostComments() failed indices = %v, want [2] (the second comment maps to updates[2])", failed)
	}
}
