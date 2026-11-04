package snyk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	snyksdk "github.com/pavel-snyk/snyk-sdk-go/v2/snyk"

	"github.com/tesslio/snyk-linear-sync/internal/cache"
	"github.com/tesslio/snyk-linear-sync/internal/model"
)

type projectRef struct {
	ID              string
	Name            string
	Origin          string
	TargetReference string
	TargetFile      string
	Repository      string
	// Namespace is the Kubernetes namespace, populated only for projects
	// with origin "kubernetes" (parsed from the project name).
	Namespace string
	Active    bool
}

type issueListResponse struct {
	Data  []issueResource `json:"data"`
	Links struct {
		Next string `json:"next"`
	} `json:"links"`
}

type issueResource struct {
	ID            string             `json:"id"`
	Type          string             `json:"type"`
	Attributes    issueAttributes    `json:"attributes"`
	Relationships issueRelationships `json:"relationships"`
}

type issueAttributes struct {
	CreatedAt         string          `json:"created_at"`
	UpdatedAt         string          `json:"updated_at"`
	EffectiveSeverity string          `json:"effective_severity_level"`
	Ignored           bool            `json:"ignored"`
	Status            string          `json:"status"`
	Title             string          `json:"title"`
	Key               string          `json:"key"`
	Type              string          `json:"type"`
	ExploitDetails    exploitDetails  `json:"exploit_details"`
	Problems          []problem       `json:"problems"`
	Coordinates       []coordinate    `json:"coordinates"`
	Resolution        resolution      `json:"resolution"`
	Classes           []classEntry    `json:"classes"`
	Description       string          `json:"description"`
	Severities        []severityEntry `json:"severities"`
}

type exploitDetails struct {
	MaturityLevels []maturityLevel `json:"maturity_levels"`
}

type maturityLevel struct {
	Format string `json:"format"`
	Level  string `json:"level"`
}

type problem struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Source   string `json:"source"`
}

// classEntry is a Snyk weakness class attached to an issue. The ID is the
// durable identifier such as "CWE-22" and Source identifies the taxonomy
// (e.g. "CWE"). The Snyk REST schema (Class) exposes id, source, type, and
// url only — there is no title field — so callers should treat the ID as the
// displayable identifier.
type classEntry struct {
	ID     string `json:"id"`
	Source string `json:"source"`
}

// severityEntry is one CVSS score reported for an issue. Snyk can emit
// several entries from different sources (e.g. "Snyk", "NVD", "Red Hat")
// and CVSS versions (3.1, 4.0); selectCVSS picks one for display.
type severityEntry struct {
	Source string   `json:"source"`
	Score  *float64 `json:"score"`
}

type coordinate struct {
	IsFixableManually   bool             `json:"is_fixable_manually"`
	IsFixableSnyk       bool             `json:"is_fixable_snyk"`
	IsFixableUpstream   bool             `json:"is_fixable_upstream"`
	IsPatchable         bool             `json:"is_patchable"`
	IsPinnable          bool             `json:"is_pinnable"`
	IsUpgradeable       bool             `json:"is_upgradeable"`
	State               string           `json:"state"`
	LastResolvedAt      string           `json:"last_resolved_at"`
	LastResolvedDetails string           `json:"last_resolved_details"`
	Remedies            []remedy         `json:"remedies"`
	Representations     []representation `json:"representations"`
}

type remedy struct {
	Description string        `json:"description"`
	Details     remedyDetails `json:"details"`
}

type remedyDetails struct {
	UpgradePackage string `json:"upgrade_package"`
}

type representation struct {
	Dependency     dependencyRepresentation     `json:"dependency"`
	SourceLocation sourceLocationRepresentation `json:"sourceLocation"`
}

type dependencyRepresentation struct {
	PackageName    string `json:"package_name"`
	PackageVersion string `json:"package_version"`
}

type sourceLocationRepresentation struct {
	CommitID string       `json:"commit_id"`
	File     string       `json:"file"`
	Region   sourceRegion `json:"region"`
}

type sourceRegion struct {
	Start sourcePosition `json:"start"`
	End   sourcePosition `json:"end"`
}

type sourcePosition struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

type resolution struct {
	Type    string `json:"type"`
	Details string `json:"details"`
}

type issueRelationships struct {
	ScanItem relationshipData `json:"scan_item"`
}

type relationshipData struct {
	Data relationshipRef `json:"data"`
}

type relationshipRef struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type orgResponse struct {
	Data struct {
		Attributes struct {
			Slug string `json:"slug"`
		} `json:"attributes"`
	} `json:"data"`
}

// v1IgnoreEntry represents a single ignore record from the Snyk v1 API.
// The v1 API returns two different shapes depending on project type:
//
//  1. Flat:   {"created": "...", "expires": "...", ...}
//  2. Nested: {"*": {"created": "...", "expires": "...", ...}}
//
// The custom UnmarshalJSON tries both formats and only extracts the fields
// we need (created, expires, and disregardIfFixable).
type v1IgnoreEntry struct {
	Created            string `json:"created"`
	Expires            string `json:"expires"`
	DisregardIfFixable bool   `json:"disregardIfFixable"`
}

// v1IgnoreFields shares the decoded field schema without the custom unmarshaller.
// Strict validation uses it for either flat or path-wrapped ignore details.
type v1IgnoreFields v1IgnoreEntry

func (e *v1IgnoreEntry) UnmarshalJSON(data []byte) error {
	// Try nested format first: {"*": {...}} or {"path": {...}}
	var nested map[string]v1IgnoreFields
	if err := json.Unmarshal(data, &nested); err == nil && len(nested) > 0 {
		for _, details := range nested {
			e.Created = details.Created
			e.Expires = details.Expires
			e.DisregardIfFixable = details.DisregardIfFixable
			return nil
		}
	}

	// Try flat format: {...}
	var flat v1IgnoreFields
	if err := json.Unmarshal(data, &flat); err == nil {
		e.Created = flat.Created
		e.Expires = flat.Expires
		e.DisregardIfFixable = flat.DisregardIfFixable
		return nil
	}

	return nil
}

// v1ProjectIgnores is the response shape from the Snyk v1 API
// GET /v1/org/{org_id}/project/{project_id}/ignores.
// Top-level keys can be either SNYK-* issue keys or issue UUIDs depending on
// the project type; values are arrays of ignore entries.
type v1ProjectIgnores map[string][]v1IgnoreEntry

// unconfirmedIgnoreGrace is how long an active snooze (expiry still ahead)
// that the v1 ignores API stopped returning is kept while the REST API
// reports its finding as open and not ignored, before the sync concludes the
// ignore was revoked and forgets it. It covers partial v1 responses. It never
// applies to a lapsed snooze (expiry behind): Snyk forgets expired ignores
// after a while, and the cached expiry is then the only record of the date
// the due date is based on. See projectIgnores.revoked for the full rule.
const unconfirmedIgnoreGrace = 7 * 24 * time.Hour

// errIgnoresNotFound reports that every attempt to read a project's v1
// ignores ended in 404, so the API said nothing about the project this run.
var errIgnoresNotFound = errors.New("v1 ignores endpoint returned 404 after all retries")

func (c *Client) LoadSnapshot(ctx context.Context) (model.SnykSnapshot, error) {
	c.sourceReads = SourceReads{}
	if c.cache != nil {
		if _, err := cache.PrepareIgnoreMemory(ctx, c.cache); err != nil {
			return model.SnykSnapshot{}, fmt.Errorf("prepare ignore memory: %w", err)
		}
	}
	orgSlug, err := c.orgSlug(ctx)
	if err != nil {
		return model.SnykSnapshot{}, err
	}

	projects, err := c.listProjects(ctx)
	if err != nil {
		return model.SnykSnapshot{}, err
	}

	projectDetails := make(map[string]projectRef, len(projects))
	projectIDs := make(map[string]struct{}, len(projects))
	inactiveProjectIDs := make(map[string]struct{})
	for _, project := range projects {
		projectDetails[project.ID] = project
		if project.Active {
			projectIDs[project.ID] = struct{}{}
		} else {
			inactiveProjectIDs[project.ID] = struct{}{}
		}
	}

	// v1 ignores are fetched once per project ID that appears in the issues
	// pages. Keying the per-finding lookup off this project-scoped map (rather
	// than a global issueKey map) removes the cross-project collision where
	// the same vulnerability key in two projects with different expiries
	// overwrote each other.
	//
	// We fetch v1 ignore metadata for all projects that appear in the issues
	// pages, not just those with currently-ignored issues. This ensures we
	// preserve the snooze expiry for due date calculation even after a timed
	// ignore expires (the REST API flips ignored=false while the v1 record
	// persists for a while), and also captures disregardIfFixable for "ignore
	// until fix available" ignores.
	//
	// The issues are collected before any finding is built: which cached
	// ignore rows to keep depends on what every REST issue of the project
	// says (see projectIgnores.retain), and the findings must be built from
	// the rows that survive that decision, so a row dropped this run does not
	// feed one last due date.
	ignoresByProject := make(map[string]*projectIgnores)
	var issues []issueResource

	nextCursor := ""
	seenCursors := map[string]bool{}
	seenIssues := map[string]bool{}
	for {
		if c.requireFresh {
			if seenCursors[nextCursor] || c.sourceReads.IssuePages >= freshMaxPages {
				return model.SnykSnapshot{}, fmt.Errorf("Snyk issue pagination repeated or exhausted")
			}
			seenCursors[nextCursor] = true
		}
		page, cursor, err := c.listIssuesPage(ctx, nextCursor)
		if err != nil {
			return model.SnykSnapshot{}, err
		}

		for _, issue := range page {
			if c.requireFresh {
				if seenIssues[issue.ID] {
					return model.SnykSnapshot{}, fmt.Errorf("duplicate Snyk issue id")
				}
				seenIssues[issue.ID] = true
				// Excluded scan-item types have no project-scoped metadata to
				// validate. Do not turn their IDs into bogus v1 project reads.
				if !isProjectIssue(issue) {
					continue
				}
				if _, ok := projectDetails[issue.Relationships.ScanItem.Data.ID]; !ok {
					return model.SnykSnapshot{}, fmt.Errorf("Snyk issue references absent project")
				}
			}
			projectID := issue.Relationships.ScanItem.Data.ID
			if projectID == "" {
				continue
			}
			if _, ok := ignoresByProject[projectID]; ok {
				continue
			}
			state, err := c.fetchProjectIgnores(ctx, projectID)
			if err != nil {
				return model.SnykSnapshot{}, fmt.Errorf("fetch v1 ignores for project %s: %w", projectID, err)
			}
			ignoresByProject[projectID] = state
		}
		issues = append(issues, page...)

		if cursor == "" {
			break
		}
		nextCursor = cursor
	}

	for _, issue := range issues {
		projectID := issue.Relationships.ScanItem.Data.ID
		if !isProjectIssue(issue) {
			continue
		}
		if _, inactive := inactiveProjectIDs[projectID]; inactive {
			continue
		}
		ignoresByProject[projectID].recordIssue(issue)
	}

	now := c.clock()
	for projectID, state := range ignoresByProject {
		if err := c.commitProjectIgnores(ctx, projectID, state, now); err != nil {
			return model.SnykSnapshot{}, err
		}
	}

	// k8sClusterCache holds the cluster name for kubernetes-origin projects,
	// fetched lazily from the v1 project detail endpoint (the REST project
	// resource does not expose it). In-memory only: one GET per kubernetes
	// project per run. A failed fetch is recorded in k8sClusterFailed so we
	// don't retry a broken project for every finding, and so its findings are
	// marked cluster-unknown rather than "no cluster".
	k8sClusterCache := make(map[string]string)
	k8sClusterFailed := make(map[string]struct{})

	findings := make([]model.Finding, 0, len(issues))
	for _, issue := range issues {
		projectID := issue.Relationships.ScanItem.Data.ID
		if !isProjectIssue(issue) {
			continue
		}
		if _, inactive := inactiveProjectIDs[projectID]; inactive {
			continue
		}

		project := projectDetails[projectID]
		issueKey := coalesce(issue.Attributes.Key, firstProblemID(issue.Attributes.Problems), issue.ID)
		// The Snyk UI URL fragment needs a SNYK-* key or issue UUID, not a
		// CVE ID. When issue.Attributes.Key is empty, firstProblemID may
		// return a CVE identifier (e.g. "CVE-2025-7783") which doesn't
		// resolve in the Snyk UI. Prefer issue.ID (always a UUID) for the
		// URL in that case.
		urlKey := issue.Attributes.Key
		if strings.TrimSpace(urlKey) == "" {
			urlKey = issue.ID
		}
		createdAt, err := parseIssueCreatedAt(issue.Attributes.CreatedAt)
		if err != nil {
			return model.SnykSnapshot{}, fmt.Errorf("parse Snyk issue created_at for %s: %w", issue.ID, err)
		}
		updatedAt := parseIssueTimestamp(issue.Attributes.UpdatedAt)

		// Issue keys and UUIDs identify this finding. Rule keys may cover
		// siblings, so current rule metadata requires REST ignored=true;
		// historical rule metadata requires a persisted per-finding observation.
		// Always use the raw issue key, not a coalesced problem/rule fallback.
		projectIgnoreState := ignoresByProject[projectID]
		ignoreKeys := projectIgnoreState.keysForFinding(issue)
		ignoreEntries := projectIgnoreState.entriesForFinding(issue, ignoreKeys)
		ignoreMeta := maxExpiryIgnoreMeta(ignoreEntries)
		if ignoreMeta.DisregardIfFixable {
			ignoreMeta.EndedAt = projectIgnoreState.endedAt(ignoreKeys, issue)
		}
		// Snyk can reuse an issue ID after resolution. An ignore created before
		// that resolution belongs to the old occurrence, not this actionable one.
		if !issue.Attributes.Ignored && !issueResolved(issue.Attributes) &&
			ignorePredatesResolvedOccurrence(ignoreMeta, issue.Attributes.Coordinates) {
			ignoreMeta = ignoreMetadata{}
		}
		ok := len(ignoreEntries) > 0
		// If the issue is ignored but we found no v1 ignore metadata, the
		// key format didn't match either fallback. Log a warning so
		// operators can detect key-format mismatches; without metadata we
		// can't distinguish a temporary snooze from a permanent ignore, so
		// the issue would be treated as permanently ignored (Cancelled).
		if issue.Attributes.Ignored && !ok {
			c.logger.Warn("ignored issue has no v1 ignore metadata; treating as permanent ignore",
				slog.String("issue_id", issue.ID),
				slog.String("issue_key", issueKey),
				slog.String("project_id", projectID),
			)
		}

		cluster := ""
		clusterUnknown := false
		if project.Origin == "kubernetes" {
			var ok bool
			cluster, ok = k8sClusterCache[projectID]
			if !ok {
				cluster, err = c.fetchProjectClusterWithRetry(ctx, projectID, clusterLookupAttempts)
				if err != nil {
					if c.requireFresh {
						return model.SnykSnapshot{}, fmt.Errorf("fresh Snyk cluster read: %w", err)
					}
					// Cluster is ticket enrichment, not sync-critical: log
					// and continue rather than failing the whole run. The
					// findings are marked cluster-unknown, which is not the
					// same as "Snyk reports no cluster": the sync then
					// writes no identity for them this run and keeps the
					// cluster and identity a matched ticket already has.
					c.logger.Warn("could not fetch kubernetes cluster for project; cluster treated as unknown this run",
						slog.String("project_id", projectID),
						slog.String("error", err.Error()),
					)
					cluster = ""
					k8sClusterFailed[projectID] = struct{}{}
				}
				k8sClusterCache[projectID] = cluster
			}
			_, clusterUnknown = k8sClusterFailed[projectID]
		}

		finding := c.findingFromIssue(issue, projectID, project, cluster, orgSlug, issueKey, urlKey, createdAt, updatedAt, ignoreMeta)
		finding.ProjectClusterUnknown = clusterUnknown

		findings = append(findings, finding)
	}

	if c.requireFresh {
		c.sourceReads.Complete = true
	}
	return model.SnykSnapshot{
		Findings:              findings,
		ProjectIDs:            projectIDs,
		InactiveProjectIDs:    inactiveProjectIDs,
		ClusterLookupFailures: len(k8sClusterFailed),
	}, nil
}

// isProjectIssue reports whether a REST issue belongs to a project: it names
// one, and its scan item is a project (or of unstated type).
func isProjectIssue(issue issueResource) bool {
	if issue.Relationships.ScanItem.Data.ID == "" {
		return false
	}
	scanType := issue.Relationships.ScanItem.Data.Type
	return scanType == "" || scanType == "project"
}

// clock returns the current UTC time, from the injected clock when a test
// set one.
func (c *Client) clock() time.Time {
	if c.now != nil {
		return c.now().UTC()
	}
	return time.Now().UTC()
}

func (c *Client) ListFindings(ctx context.Context) ([]model.Finding, error) {
	snapshot, err := c.LoadSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	return snapshot.Findings, nil
}

// findingFromIssue maps a decoded Snyk REST issue resource into the sync's
// model.Finding shape. It is split out from LoadSnapshot so the JSON decode
// → Finding mapping is unit-testable against a response fixture without
// needing a live Snyk org (see TestFindingFromIssueDecodesRealIssueShape).
// createdAt is passed in rather than re-parsed because LoadSnapshot already
// validates it.
func (c *Client) findingFromIssue(
	issue issueResource,
	projectID string,
	project projectRef,
	cluster string,
	orgSlug, issueKey, urlKey string,
	createdAt, updatedAt time.Time,
	ignoreMeta ignoreMetadata,
) model.Finding {
	source := sourceLocation(issue.Attributes.Coordinates)
	lastResolvedAt, lastResolvedAtInvalid := latestResolvedAt(issue.Attributes.Coordinates)
	return model.Finding{
		Fingerprint:           model.Fingerprint(projectID, issue.ID, locationKey(issue.Attributes.Coordinates)),
		SnykIssueID:           issue.ID,
		SnykIssueKey:          issueKey,
		IssueType:             strings.ToLower(strings.TrimSpace(issue.Attributes.Type)),
		CreatedAt:             createdAt,
		UpdatedAt:             updatedAt,
		ProjectID:             projectID,
		ProjectName:           project.Name,
		ProjectOrigin:         project.Origin,
		ProjectReference:      project.TargetReference,
		ProjectTargetFile:     project.TargetFile,
		Repository:            project.Repository,
		ProjectCluster:        cluster,
		ProjectNamespace:      project.Namespace,
		IssueTitle:            coalesce(issue.Attributes.Title, problemTitle(issue.Attributes.Problems), issue.Attributes.Key, issue.ID),
		Severity:              coalesce(issue.Attributes.EffectiveSeverity, firstProblemSeverity(issue.Attributes.Problems), "unknown"),
		CVSS:                  selectCVSS(issue.Attributes.Severities),
		ExploitMaturity:       exploitMaturity(issue.Attributes.ExploitDetails.MaturityLevels),
		PackageName:           packageName(issue.Attributes.Coordinates),
		VulnerableVersion:     vulnerableVersion(issue.Attributes.Coordinates),
		FixedVersion:          fixedVersion(issue.Attributes.Coordinates),
		IssueURL:              c.issueUIURL(orgSlug, projectID, urlKey),
		IssueAPIURL:           c.issueAPIURL(issue.ID),
		Status:                mapStatus(issue.Attributes, ignoreMeta.ExpiresAt, ignoreMeta.DisregardIfFixable),
		IntroducedThrough:     introducedThrough(issue.Attributes.Coordinates),
		SourceFile:            source.File,
		SourceCommitID:        source.CommitID,
		SourceLineStart:       source.Region.Start.Line,
		SourceColumnStart:     source.Region.Start.Column,
		SourceLineEnd:         source.Region.End.Line,
		SourceColumnEnd:       source.Region.End.Column,
		IgnoreExpiresAt:       ignoreMeta.ExpiresAt,
		DisregardIfFixable:    ignoreMeta.DisregardIfFixable,
		IgnoreEndedAt:         ignoreMeta.EndedAt,
		LastResolvedAt:        lastResolvedAt,
		LastResolvedAtInvalid: lastResolvedAtInvalid,
		Classes:               issueClasses(issue.Attributes.Classes),
		CVEs:                  cveIDs(issue.Attributes.Problems),
		Description:           strings.TrimSpace(issue.Attributes.Description),
		Remediation:           remediationDescription(issue.Attributes.Coordinates),
		HasCoordinates:        len(issue.Attributes.Coordinates) > 0,
		IsFixableManually:     anyFixable(issue.Attributes.Coordinates, func(c coordinate) bool { return c.IsFixableManually }),
		IsFixableSnyk:         anyFixable(issue.Attributes.Coordinates, func(c coordinate) bool { return c.IsFixableSnyk }),
		IsFixableUpstream:     anyFixable(issue.Attributes.Coordinates, func(c coordinate) bool { return c.IsFixableUpstream }),
		IsPatchable:           anyFixable(issue.Attributes.Coordinates, func(c coordinate) bool { return c.IsPatchable }),
		IsPinnable:            anyFixable(issue.Attributes.Coordinates, func(c coordinate) bool { return c.IsPinnable }),
		IsUpgradeable:         anyFixable(issue.Attributes.Coordinates, func(c coordinate) bool { return c.IsUpgradeable }),
	}
}

// projectIgnores is what one run knows about a project's v1 ignores: the
// entries the API reported, the rows the cache remembered, and what the REST
// issues of the project say about each ignore key. The retention decision at
// the end of the snapshot load (retain) reads all three.
type projectIgnores struct {
	// api is what the v1 endpoint reported this run (nil when it could not
	// be read); apiConfirmed is its key set.
	api          v1ProjectIgnores
	apiConfirmed map[string]struct{}
	// cached is the rows the cache held at the start of the run.
	cached map[string]cache.IgnoreMeta
	// apiUnavailable is set when the v1 endpoint could not be read this run
	// (every attempt failed or 404ed). The cached rows then stand in for the
	// API, and none of them may be dropped for lack of confirmation: silence
	// from a failed request says nothing about the ignore.
	apiUnavailable bool
	// merged is the union of api and cached, reconstructed as v1 entries.
	// Until retain runs it holds every cached row; afterwards only the
	// retained ones, and findings are built from it.
	merged v1ProjectIgnores
	// rows is what the cache holds after retain: the retained rows, with
	// the unignored_at stamps decided this run. Findings read their
	// IgnoreEndedAt from it.
	rows map[string]cache.IgnoreMeta
	// matches records, per ignore key, what the REST issues of the project
	// that could carry the ignore report. Filled by recordIssue.
	matches map[string]*ignoreKeyMatches
}

// ignoreKeyMatches summarises the REST issues of a project matching one
// ignore key. Every key an issue could be filed under (its issue key, its
// ID, its problem IDs) counts, regardless of the issue.Ignored gate that
// decides which entries a finding consumes: this is about what Snyk asserts
// for the ignore, not about which finding the ignore applies to.
type ignoreKeyMatches struct {
	// total counts the matching issues, whatever they report.
	total int
	// ignored counts matching issues that report ignored=true: Snyk still
	// asserts the ignore for them, whatever the v1 endpoint returns.
	ignored int
	// open is set when a matching issue reports ignored=false and is not
	// resolved: the ignore no longer applies to it, by expiry or revocation.
	open bool
	// issues keeps per-finding evidence; rule matches can include unrelated siblings.
	issues map[string]issueResource
}

// recordIssue notes what a REST issue of the project reports for each ignore
// key it could be filed under. Only keys the run knows an ignore for are
// recorded.
func (p *projectIgnores) recordIssue(issue issueResource) {
	resolved := issueResolved(issue.Attributes)
	for _, key := range ignoreKeysForIssue(issue.Attributes.Key, issue.ID, issue.Attributes.Problems) {
		if _, known := p.merged[key]; !known {
			continue
		}
		m := p.matches[key]
		if m == nil {
			m = &ignoreKeyMatches{issues: make(map[string]issueResource)}
			p.matches[key] = m
		}
		m.issues[issue.ID] = issue
		m.total++
		switch {
		case issue.Attributes.Ignored:
			m.ignored++
		case !resolved:
			m.open = true
		}
	}
}

// retain decides, per ignore key, which rows the cache keeps after this run
// and returns them, with the keys it drops. Snyk is authoritative, and the
// cache is only the sync's memory of what Snyk reported:
//
//   - A key the v1 API returned this run is stored as the summary of the
//     union of API and cached entries (maxExpiryIgnoreMeta: the latest
//     created entry decides, a permanent ignore zeroes the expiry, the
//     expiry is a high-water mark) with its confirmation time refreshed.
//   - A key the API did not return keeps its previous confirmation time and
//     is kept, unless revoked says Snyk has contradicted it.
//
// An ignore-until-fix-available row is also stamped with the time the ignore
// stopped applying (see unignoredAt), which the due date is based on from
// then on.
//
// As before, a summary with no expiry and no disregard-if-fixable flag (a
// plain permanent ignore) is not stored unless it still carries durable
// observations of an older ignore for another finding.
func (p *projectIgnores) retain(now time.Time) (rows map[string]cache.IgnoreMeta, dropped []string) {
	rows = make(map[string]cache.IgnoreMeta, len(p.merged))
	for key, entries := range p.merged {
		meta := maxExpiryIgnoreMeta(entries)
		row := cache.IgnoreMeta{
			IssueKey:           key,
			ExpiresAt:          meta.ExpiresAt,
			DisregardIfFixable: meta.DisregardIfFixable,
			CreatedAt:          meta.CreatedAt,
		}
		row.UpdatedAt = now
		row.UnignoredAt = p.unignoredAt(key, meta, now)
		row.ObservedIssues = make(map[string]cache.IgnoreObservation)
		maps.Copy(row.ObservedIssues, p.cached[key].ObservedIssues)
		if m := p.matches[key]; m != nil {
			for id, issue := range m.issues {
				if issue.Attributes.Ignored {
					if p.canObserveIgnore(key, issue, meta) {
						row.ObservedIssues[id] = cache.IgnoreObservation{ExpiresAt: meta.ExpiresAt, CreatedAt: meta.CreatedAt, DisregardIfFixable: meta.DisregardIfFixable}
					}
				} else if observed, seen := row.ObservedIssues[id]; seen && observed.EndedAt.IsZero() {
					observed.EndedAt = now
					row.ObservedIssues[id] = observed
				}
			}
		}
		if meta.ExpiresAt.IsZero() && !meta.DisregardIfFixable && !hasObservedIgnoreHistory(row.ObservedIssues, now) {
			continue
		}
		if _, confirmed := p.apiConfirmed[key]; !confirmed {
			confirmedAt := p.cached[key].UpdatedAt
			if p.revoked(key, meta, confirmedAt, now) {
				// Revoking a newer rule snooze must not discard a sibling's older,
				// durable deadline. Remove the revoked observations and summary only.
				for id, observed := range row.ObservedIssues {
					if !observed.DisregardIfFixable && observed.ExpiresAt.After(now) {
						delete(row.ObservedIssues, id)
					}
				}
				if !hasObservedIgnoreHistory(row.ObservedIssues, now) {
					dropped = append(dropped, key)
					continue
				}
				row.ExpiresAt = time.Time{}
				row.DisregardIfFixable = false
				row.UnignoredAt = time.Time{}
			}
			// Not refreshed, so the grace is measured from the last real
			// confirmation. A row of unknown confirmation time (written
			// before the column existed, or unparsable) is stamped now, so
			// its grace clock starts this run rather than never.
			if !confirmedAt.IsZero() {
				row.UpdatedAt = confirmedAt
			}
		}
		rows[key] = row
	}
	return rows, dropped
}

// canObserveIgnore avoids attributing a sibling's old rule ignore to a finding
// whose own direct ignore explains REST ignored=true. Cached-only rule data
// can maintain an established association, but cannot establish a new one.
func (p *projectIgnores) canObserveIgnore(key string, issue issueResource, meta ignoreMetadata) bool {
	if key == issue.ID || key == issue.Attributes.Key {
		return true
	}
	if _, confirmed := p.apiConfirmed[key]; !confirmed {
		if _, observed := p.cached[key].ObservedIssues[issue.ID]; !observed {
			return false
		}
	}
	direct := ignoreEntriesForKeys(p.merged, ignoreKeysForIssue(issue.Attributes.Key, issue.ID, nil))
	if len(direct) == 0 {
		return true
	}
	directMeta := maxExpiryIgnoreMeta(direct)
	return !directMeta.CreatedAt.IsZero() && meta.CreatedAt.After(directMeta.CreatedAt)
}

// hasObservedIgnoreHistory identifies observations whose expiry or end is a
// durable due-date base even when the key's current summary is superseded.
func hasObservedIgnoreHistory(observed map[string]cache.IgnoreObservation, now time.Time) bool {
	for _, entry := range observed {
		if entry.DisregardIfFixable || (!entry.ExpiresAt.IsZero() && !entry.ExpiresAt.After(now)) {
			return true
		}
	}
	return false
}

// revoked reports whether an ignore the v1 API did not return this run
// should be forgotten. It is forgotten only when Snyk contradicts it: the API
// was readable, no matching REST issue still reports ignored=true (Snyk
// asserting the ignore wins over an un-ignored sibling under a rule key), a
// matching open issue reports ignored=false, the snooze has not lapsed (an
// expiry that has passed is the base of the due date and is kept for good),
// it is not an ignore-until-fix (its end is the base of the due date too),
// and the grace since the last confirmation has run out. A row whose
// confirmation time is unknown is kept; its clock starts this run.
func (p *projectIgnores) revoked(key string, meta ignoreMetadata, confirmedAt, now time.Time) bool {
	if p.apiUnavailable {
		return false
	}
	m := p.matches[key]
	if m == nil || m.ignored > 0 || !m.open {
		return false
	}
	if meta.DisregardIfFixable {
		return false
	}
	if meta.ExpiresAt.IsZero() || !meta.ExpiresAt.After(now) {
		return false
	}
	if confirmedAt.IsZero() {
		return false
	}
	return now.Sub(confirmedAt) >= unconfirmedIgnoreGrace
}

// unignoredAt returns the time an ignore-until-fix-available ignore stopped
// applying, for the row of the given key: the stamp the cache already holds,
// or now on the first run on which every REST issue the key matches reports
// ignored=false (the fix arrived, or the ignore was revoked; either way the
// finding is actionable from now). The stamp is kept thereafter, since the
// due date is based on it. It is cleared while any matching issue reports
// ignored=true again (a later ignore-until-fix is in force, and its own end
// will be stamped), and left as it was when no REST issue matches the key
// (nothing is known this run). Rows without the flag are never stamped.
func (p *projectIgnores) unignoredAt(key string, meta ignoreMetadata, now time.Time) time.Time {
	if !meta.DisregardIfFixable {
		return time.Time{}
	}
	previous := p.cached[key].UnignoredAt
	// A newer ignore may have both started and ended between snapshots.
	// Its actual end is unknown; start from the first observation, not the
	// previous lifecycle's end.
	cachedCreated := p.cached[key].CreatedAt
	// Older cache versions discarded fractional seconds. A live timestamp in
	// that same second is not evidence of a new ignore lifecycle.
	sameLegacySecond := cachedCreated.Nanosecond() == 0 && meta.CreatedAt.Truncate(time.Second).Equal(cachedCreated)
	if meta.CreatedAt.After(cachedCreated) && !sameLegacySecond {
		previous = time.Time{}
	}
	m := p.matches[key]
	switch {
	case m == nil || m.total == 0:
		return previous
	case m.ignored > 0:
		return time.Time{}
	case !previous.IsZero():
		return previous
	default:
		return now
	}
}

// finalize rebuilds merged from the API entries and the retained rows, so
// findings see exactly what the cache will remember, and keeps the rows for
// the IgnoreEndedAt lookup.
func (p *projectIgnores) finalize(rows map[string]cache.IgnoreMeta) {
	p.rows = rows
	p.merged = mergeIgnores(p.api, cacheIgnoresToV1(rows))
}

// ignorePredatesResolvedOccurrence requires a known post-ignore resolution
// for every coordinate. One resolved sibling must not erase the ignore memory
// of a coordinate that has remained continuously open.
func ignorePredatesResolvedOccurrence(meta ignoreMetadata, coordinates []coordinate) bool {
	if meta.CreatedAt.IsZero() || len(coordinates) == 0 {
		return false
	}
	for _, coord := range coordinates {
		resolvedAt, err := parseTime(coord.LastResolvedAt)
		if err != nil || !resolvedAt.After(meta.CreatedAt) {
			return false
		}
	}
	return true
}

// keysForFinding uses rule history only for findings observed ignored under
// that key. Unignored siblings with no such evidence keep creation-based SLAs.
// Legacy rule rows without associations cannot reconstruct historical scope.
func (p *projectIgnores) keysForFinding(issue issueResource) []string {
	keys := ignoreKeysForIssue(issue.Attributes.Key, issue.ID, gatedProblems(issue.Attributes.Problems, issue.Attributes.Ignored))
	if !issue.Attributes.Ignored {
		for _, key := range ignoreKeysForIssue("", "", issue.Attributes.Problems) {
			if _, seen := p.rows[key].ObservedIssues[issue.ID]; seen && !slices.Contains(keys, key) {
				keys = append(keys, key)
			}
		}
	}
	return keys
}

// entriesForFinding reads historical rule metadata from the observed finding,
// since a newer rule ignore may cover only a different resource path.
func (p *projectIgnores) entriesForFinding(issue issueResource, keys []string) []v1IgnoreEntry {
	var entries []v1IgnoreEntry
	for _, key := range keys {
		if !issue.Attributes.Ignored && key != issue.ID && key != issue.Attributes.Key {
			observed := p.rows[key].ObservedIssues[issue.ID]
			entries = append(entries, cacheIgnoresToV1(map[string]cache.IgnoreMeta{key: {
				ExpiresAt: observed.ExpiresAt, CreatedAt: observed.CreatedAt, DisregardIfFixable: observed.DisregardIfFixable,
			}})[key]...)
		} else {
			entries = append(entries, p.merged[key]...)
		}
	}
	return entries
}

// endedAt returns the latest observed end for this finding. Rule-key history
// uses the finding observation; direct keys can also use the row-level stamp.
func (p *projectIgnores) endedAt(keys []string, issue issueResource) time.Time {
	var latest time.Time
	for _, key := range keys {
		if row, ok := p.rows[key]; ok {
			end := row.UnignoredAt
			if observed, seen := row.ObservedIssues[issue.ID]; seen && key != issue.ID && key != issue.Attributes.Key {
				end = observed.EndedAt
			}
			if end.After(latest) {
				latest = end
			}
		}
	}
	return latest
}

// commitProjectIgnores applies the retention decision for one project: it
// logs the dropped keys, writes the retained rows to the cache, and narrows
// the entries findings are built from to those rows. Persistence must succeed
// before a finding exposes a new SLA base to Linear reconciliation.
func (c *Client) commitProjectIgnores(ctx context.Context, projectID string, state *projectIgnores, now time.Time) error {
	rows, dropped := state.retain(now)
	if c.cache != nil {
		if err := c.cache.SaveIgnores(ctx, projectID, rows); err != nil {
			return fmt.Errorf("persist ignore memory for project %s: %w", projectID, err)
		}
	}
	for _, key := range dropped {
		c.logger.Info("dropping cached ignore the v1 API stopped returning: its finding is open and not ignored while the snooze has not expired, so Snyk revoked it",
			slog.String("project_id", projectID),
			slog.String("issue_key", key),
			slog.Time("expires_at", state.cached[key].ExpiresAt),
			slog.Time("last_confirmed_at", state.cached[key].UpdatedAt),
		)
	}
	state.finalize(rows)
	return nil
}

// fetchProjectIgnores reads a project's v1 ignores and merges them with the
// cached rows. It does not write the cache: which rows survive is decided
// once every REST issue of the project has been seen (commitProjectIgnores).
func (c *Client) fetchProjectIgnores(ctx context.Context, projectID string) (*projectIgnores, error) {
	state := &projectIgnores{
		apiConfirmed: make(map[string]struct{}),
		cached:       make(map[string]cache.IgnoreMeta),
		matches:      make(map[string]*ignoreKeyMatches),
	}
	var cached v1ProjectIgnores
	if c.cache != nil {
		cachedMeta, err := c.cache.LoadIgnores(ctx, projectID)
		if err != nil {
			// API fallback cannot reconstruct forgotten history, and saving
			// that partial view could overwrite the unread durable memory.
			return nil, fmt.Errorf("load cached ignore memory for project %s: %w", projectID, err)
		} else if len(cachedMeta) > 0 {
			state.cached = cachedMeta
			cached = cacheIgnoresToV1(cachedMeta)
		}
	}

	// The Snyk v1 ignores endpoint sometimes returns inconsistent expiry dates
	// for the same ignore. Make several attempts and take the maximum expiry
	// seen across all successful responses so the first run is seeded with the
	// highest reasonable value. This is still Snyk-only data and does not trust
	// mutable Linear state.
	const maxAttempts = 3
	apiIgnores, err := c.fetchProjectIgnoresWithRetry(ctx, projectID, maxAttempts)
	if c.requireFresh && err != nil {
		return nil, fmt.Errorf("fresh Snyk ignores required: %w", err)
	}
	if c.requireFresh {
		c.sourceReads.IgnoreProjects++
	}
	switch {
	case err == nil:
		state.api = apiIgnores
		for issueKey := range apiIgnores {
			state.apiConfirmed[issueKey] = struct{}{}
		}
	case errors.Is(err, errIgnoresNotFound):
		// Already warned by fetchProjectIgnoresWithRetry. Keep the existing
		// non-fatal behavior: the cached rows (if any) stand in for the API.
		state.apiUnavailable = true
	case len(cached) > 0:
		c.logger.Warn("v1 ignores API failed, falling back to cached ignores",
			"project_id", projectID,
			"error", err,
		)
		state.apiUnavailable = true
	default:
		return nil, err
	}

	state.merged = mergeIgnores(state.api, cached)

	if len(cached) == 0 && len(state.merged) > 0 {
		c.logger.Info("seeded v1 ignores cache from API",
			"project_id", projectID,
			"count", len(state.merged),
		)
	} else if len(cached) > 0 {
		cachedMeta := maxExpiryIgnoreMeta(flattenIgnores(cached))
		mergedMeta := maxExpiryIgnoreMeta(flattenIgnores(state.merged))
		if len(state.merged) > len(cached) {
			c.logger.Info("v1 ignores cache gained new keys from API",
				"project_id", projectID,
				"cached_count", len(cached),
				"merged_count", len(state.merged),
			)
		}
		if !mergedMeta.ExpiresAt.IsZero() && !mergedMeta.ExpiresAt.Equal(cachedMeta.ExpiresAt) {
			c.logger.Info("v1 ignores merged expiry changed for project",
				"project_id", projectID,
				"cached_expiry", cachedMeta.ExpiresAt,
				"merged_expiry", mergedMeta.ExpiresAt,
			)
		}
	}

	return state, nil
}

// v1ProjectDetail is the subset of the Snyk v1 API project resource
// (GET /v1/org/{org_id}/project/{project_id}) that the sync needs beyond
// what the REST project resource exposes.
type v1ProjectDetail struct {
	// ImageCluster is the Kubernetes cluster name, reported only for
	// projects imported through the Snyk Kubernetes integration.
	ImageCluster string `json:"imageCluster"`
}

// clusterLookupAttempts bounds fetchProjectClusterWithRetry. The adaptive
// transport already retries 429/502/503/504 with backoff; this covers the
// errors it does not (other 5xx, transient 4xx such as a 404 just after a
// project import, transport errors, and bad bodies).
const clusterLookupAttempts = 3

// clusterLookupBackoff is the delay before the first retry; it grows
// linearly per attempt. A variable so tests can shorten it.
var clusterLookupBackoff = 500 * time.Millisecond

// fetchProjectClusterWithRetry calls fetchProjectCluster up to maxAttempts
// times with a short linear backoff, returning the last error if every
// attempt fails. A failed lookup makes the project's findings lose their
// identity for the run, so one transient error is worth a retry.
func (c *Client) fetchProjectClusterWithRetry(ctx context.Context, projectID string, maxAttempts int) (string, error) {
	var lastErr error
	for attempt := range maxAttempts {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(time.Duration(attempt) * clusterLookupBackoff):
			}
		}
		cluster, err := c.fetchProjectCluster(ctx, projectID)
		if err == nil {
			return cluster, nil
		}
		lastErr = err
		c.logger.Warn("v1 project detail request failed, retrying",
			slog.String("project_id", projectID),
			slog.Int("attempt", attempt+1),
			slog.Int("max_attempts", maxAttempts),
			slog.String("error", err.Error()),
		)
	}
	return "", lastErr
}

// fetchProjectCluster returns the Kubernetes cluster name for a project
// from the v1 project detail endpoint. The REST project resource does not
// expose the cluster, and the v1 projects LIST endpoint is deprecated
// (410 Gone), so this is one GET per kubernetes-origin project per run
// (cached in-memory by the caller). An empty string with nil error means
// Snyk reported no cluster for the project.
func (c *Client) fetchProjectCluster(ctx context.Context, projectID string) (string, error) {
	endpoint, err := c.v1Base.Parse(fmt.Sprintf("org/%s/project/%s", c.orgID, projectID))
	if err != nil {
		return "", fmt.Errorf("build v1 project URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return "", err
	}
	// The v1 API returns 406 Not Acceptable for the JSON:API media type.
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}

	var detail v1ProjectDetail
	if err := c.decodeJSON(resp, &detail); err != nil {
		return "", err
	}
	if c.requireFresh {
		c.sourceReads.ClusterProjects++
	}
	return strings.TrimSpace(detail.ImageCluster), nil
}

// flattenIgnores returns all entries from a v1ProjectIgnores map as a single
// slice so maxExpiryIgnoreMeta can be applied across a whole project.
func flattenIgnores(ignores v1ProjectIgnores) []v1IgnoreEntry {
	var out []v1IgnoreEntry
	for _, entries := range ignores {
		out = append(out, entries...)
	}
	return out
}

// ignoresRetryBackoff is the delay before the first retry of the v1 ignores
// request; it grows linearly per attempt. A variable so tests can shorten it.
var ignoresRetryBackoff = time.Second

func (c *Client) fetchProjectIgnoresWithRetry(ctx context.Context, projectID string, maxAttempts int) (v1ProjectIgnores, error) {
	endpoint, err := c.v1Base.Parse(fmt.Sprintf("org/%s/project/%s/ignores", c.orgID, projectID))
	if err != nil {
		return nil, fmt.Errorf("build v1 ignores URL: %w", err)
	}

	var apiIgnores v1ProjectIgnores
	var lastErr error
	// lastErrNotFound tracks whether the most recent failure was a 404, so
	// that if every attempt exhausts on a 404 we can fall back to the
	// existing non-fatal "ignores unavailable" behavior instead of failing
	// the whole run, while still giving a transient 404 a chance to recover
	// on retry like any other failure.
	lastErrNotFound := false

	for attempt := range maxAttempts {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * ignoresRetryBackoff):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		if err != nil {
			return nil, err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			lastErrNotFound = false
			c.logger.Warn("v1 ignores request failed, retrying",
				"project_id", projectID,
				"attempt", attempt+1,
				"max_attempts", maxAttempts,
				"error", err,
			)
			continue
		}

		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if c.requireFresh && readErr != nil {
			return nil, fmt.Errorf("read complete Snyk ignores response: %w", readErr)
		}

		if resp.StatusCode == http.StatusNotFound {
			// A 404 can be transient (e.g. eventual consistency just after a
			// project is created, or a flaky backend route), so retry it
			// like any other failure instead of accepting it immediately.
			// Previously this returned right away, so a single transient 404
			// erased ignore metadata for the whole run.
			lastErr = fmt.Errorf("snyk v1 ignores API %s %s returned 404",
				resp.Request.Method, resp.Request.URL)
			lastErrNotFound = true
			c.logger.Warn("v1 ignores endpoint returned 404, retrying",
				"project_id", projectID,
				"attempt", attempt+1,
				"max_attempts", maxAttempts,
			)
			continue
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			lastErr = fmt.Errorf("snyk v1 ignores API %s %s failed with %d: %s",
				resp.Request.Method, resp.Request.URL, resp.StatusCode, strings.TrimSpace(string(body)))
			lastErrNotFound = false
			c.logger.Warn("v1 ignores request failed, retrying",
				"project_id", projectID,
				"attempt", attempt+1,
				"max_attempts", maxAttempts,
				"status", resp.StatusCode,
			)
			continue
		}

		if c.requireFresh {
			if err := validateFreshIgnores(body); err != nil {
				return nil, err
			}
		}
		var attemptIgnores v1ProjectIgnores
		if err := json.Unmarshal(body, &attemptIgnores); err != nil {
			lastErr = fmt.Errorf("decode v1 ignores: %w", err)
			lastErrNotFound = false
			c.logger.Warn("v1 ignores decode failed, retrying",
				"project_id", projectID,
				"attempt", attempt+1,
				"max_attempts", maxAttempts,
				"error", err,
			)
			continue
		}

		apiIgnores = mergeIgnores(apiIgnores, attemptIgnores)
		lastErr = nil
		lastErrNotFound = false
	}

	if lastErr != nil {
		if c.requireFresh {
			// A final failure makes the maximum-expiry observation series
			// incomplete, even if an earlier attempt succeeded. Transient
			// HTTP failures followed by a validated final success may pass;
			// malformed successful bodies fail immediately in strict mode.
			return nil, fmt.Errorf("fresh Snyk ignores failed: %w", lastErr)
		}
		if lastErrNotFound {
			// Every attempt (or at least the last one) 404ed. Keep the
			// existing non-fatal behavior: don't fail the run. Return
			// whatever earlier attempts accumulated; when there is nothing,
			// report errIgnoresNotFound so the caller falls back to the
			// cache without treating the API's silence as a statement about
			// the ignores. Warn so operators can see that ignore metadata
			// was unavailable from the API.
			c.logger.Warn("v1 ignores endpoint returned 404 after all retries; ignore metadata unavailable from the API this run",
				"project_id", projectID,
				"attempts", maxAttempts,
			)
			if len(apiIgnores) == 0 {
				return nil, errIgnoresNotFound
			}
			return apiIgnores, nil
		}
		return nil, fmt.Errorf("v1 ignores API failed after %d attempts: %w", maxAttempts, lastErr)
	}

	return apiIgnores, nil
}

// mergeIgnores combines live API ignores with cached ignores for the same
// project. For each issue key, the result is the deduplicated UNION of the
// raw entries from both sides — NOT two independently-summarized metas
// combined afterwards. Summarizing each side separately and then taking
// max(ExpiresAt) and the latest CreatedAt as two independent decisions
// conflates fields from different entries: if the API's latest entry is now
// a permanent ignore (summarized ExpiresAt = zero) but the cache still holds
// an earlier snooze's expiry, an independent max() resurrects that stale
// expiry — and, worse, that conflated result used to get written straight
// back to the cache, so the poison would self-perpetuate across runs.
//
// Instead, maxExpiryIgnoreMeta — which already implements "the latest
// created entry wins, including a permanent ignore overriding an earlier
// snooze" — is left to run once over the whole unioned entry set (callers do
// this, e.g. v1IgnoresToCache and the ignoreMetaByProjectIssue lookup in
// LoadSnapshot), so it always sees every entry from both sources together.
//
// This same function is also used to fold successive retry attempts against
// the live API together inside fetchProjectIgnoresWithRetry (both arguments
// are then "API" data, not one API and one cache) — the union approach works
// identically there.
//
// Cached entries are kept for keys that disappear from the API response so a
// partial response does not wipe stable data.
func mergeIgnores(api, cached v1ProjectIgnores) v1ProjectIgnores {
	allKeys := make(map[string]struct{}, len(api)+len(cached))
	for key := range api {
		allKeys[key] = struct{}{}
	}
	for key := range cached {
		allKeys[key] = struct{}{}
	}

	merged := make(v1ProjectIgnores, len(allKeys))
	for key := range allKeys {
		union := unionIgnoreEntries(api[key], cached[key])
		if len(union) == 0 {
			continue
		}
		merged[key] = union
	}

	return merged
}

// unionIgnoreEntries merges the first-argument and second-argument raw ignore
// entries for a single issue key into a deduplicated union, preserving every
// distinct entry so maxExpiryIgnoreMeta can later decide what they mean
// together. Entries are deduplicated by their full contents (Created,
// Expires, DisregardIfFixable).
//
// The first argument's entries are placed first in the returned slice. This
// matters when two entries share the exact same Created timestamp but
// disagree on other fields (e.g. a previously-poisoned cache entry
// {Created: X, Expires: stale} alongside a clean API entry {Created: X, no
// expiry}): maxExpiryIgnoreMeta only updates its "latest entry" once it sees
// a strictly later Created, so among same-Created entries the one that
// appears first wins the "latest" determination. Since fetchProjectIgnores
// calls mergeIgnores(api, cached), the live API's entry for that moment wins
// over the synthetic cached one, so a poisoned cache entry cannot keep
// resurrecting itself. (We do not additionally drop the conflicting
// lower-priority entry outright — fetchProjectIgnoresWithRetry also uses this
// function to fold successive retry attempts, both genuinely "API" data with
// no priority between them, and dropping on tie there would discard a
// corrected expiry seen only on a later attempt instead of taking the
// maximum, as intended.)
func unionIgnoreEntries(first, second []v1IgnoreEntry) []v1IgnoreEntry {
	out := make([]v1IgnoreEntry, 0, len(first)+len(second))
	seen := make(map[v1IgnoreEntry]struct{}, len(first)+len(second))

	for _, entry := range first {
		if _, dup := seen[entry]; dup {
			continue
		}
		seen[entry] = struct{}{}
		out = append(out, entry)
	}
	for _, entry := range second {
		if _, dup := seen[entry]; dup {
			continue
		}
		seen[entry] = struct{}{}
		out = append(out, entry)
	}

	return out
}

// ignoreEntriesForIssue collects every v1 ignore entry that can apply to a
// single finding. Snyk keys ignore records by issue-key hash, issue UUID, or
// Snyk rule ID depending on project type, and one finding may have records
// under several of these at once. Returning their union lets
// maxExpiryIgnoreMeta weigh them together, so a permanent ignore filed under
// one key is not masked by an expired snooze under another. Keys are
// deduplicated so a value that doubles as more than one identifier (e.g.
// issueKey == issueID for dependency findings) is not counted twice.
//
// The issue-key hash and issue UUID identify exactly this finding, so their
// records always apply. Rule/problem IDs do not: a rule can match several
// findings in one project (one per resource path), and the v1 records under a
// rule key are path-scoped in ways v1IgnoreEntry's parsing discards. Rule-key
// records are therefore consulted only when Snyk itself reports the issue
// ignored — they refine an ignore Snyk asserts (timed snooze vs permanent)
// rather than manufacture one. Without that gate, a sibling finding of the
// same rule that was never ignored could inherit an ExpiresAt and have its
// due-date base silently switched from creation to ignore expiry.
//
// issueKey must be the raw issue.Attributes.Key (empty when Snyk provides
// none), never a coalesced fallback: a fallback derived from a problem ID
// would smuggle a rule key past the ignored gate.
func ignoreEntriesForIssue(projectIgnores v1ProjectIgnores, issueKey, issueID string, problems []problem, ignored bool) []v1IgnoreEntry {
	return ignoreEntriesForKeys(projectIgnores, ignoreKeysForIssue(issueKey, issueID, gatedProblems(problems, ignored)))
}

// gatedProblems applies the issue.Ignored gate of ignoreEntriesForIssue:
// rule/problem keys are consulted only for a finding Snyk reports ignored.
func gatedProblems(problems []problem, ignored bool) []problem {
	if !ignored {
		return nil
	}
	return problems
}

// ignoreEntriesForKeys concatenates the entries filed under the given keys.
func ignoreEntriesForKeys(projectIgnores v1ProjectIgnores, keys []string) []v1IgnoreEntry {
	if len(projectIgnores) == 0 {
		return nil
	}
	var entries []v1IgnoreEntry
	for _, key := range keys {
		entries = append(entries, projectIgnores[key]...)
	}
	return entries
}

// ignoreKeysForIssue returns, deduplicated and without empties, every v1
// ignore key a finding's records can be filed under: its issue key, its
// issue ID, and its problem IDs. Callers that must respect the issue.Ignored
// gate on rule keys pass no problems.
func ignoreKeysForIssue(issueKey, issueID string, problems []problem) []string {
	keys := make([]string, 0, 2+len(problems))
	seen := make(map[string]struct{}, 2+len(problems))
	add := func(key string) {
		if key == "" {
			return
		}
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	add(issueKey)
	add(issueID)
	for _, p := range problems {
		add(p.ID)
	}
	return keys
}

// maxExpiryIgnoreMeta returns the maximum ignore expiry and the metadata of
// the most recently created entry. These may come from different entries, so
// the returned ExpiresAt is the high-water mark while DisregardIfFixable is
// the value from the latest created entry.
func maxExpiryIgnoreMeta(entries []v1IgnoreEntry) ignoreMetadata {
	var meta ignoreMetadata
	var latestCreated time.Time
	var maxExpiry time.Time
	// latestHasExpiry tracks whether the most recently created ignore entry
	// has an expiry date. If the latest entry is a permanent ignore (no
	// expiry), earlier snooze expiries must NOT be used — the user's latest
	// intent is to ignore permanently.
	latestHasExpiry := false
	// anyCreatedParsed / allCreatedParsed track whether we can actually trust
	// "latest" above. If any entry's Created is missing/unparseable, we can't
	// reliably tell which entry is the latest one, so the permanent-override
	// zeroing below must be skipped — otherwise an entry with a missing
	// Created but a legitimate future Expires could be silently outranked and
	// have its expiry zeroed, turning an active snooze into a permanent
	// ignore (and wrongly cancelling the ticket).
	anyCreatedParsed := false
	allCreatedParsed := true

	for _, entry := range entries {
		createdAt, errCreated := parseTime(entry.Created)
		if errCreated == nil {
			anyCreatedParsed = true
			if latestCreated.IsZero() || createdAt.After(latestCreated) {
				latestCreated = createdAt
				meta.CreatedAt = createdAt
				meta.DisregardIfFixable = entry.DisregardIfFixable
				latestHasExpiry = entry.Expires != ""
			}
		} else {
			allCreatedParsed = false
		}

		if entry.Expires == "" {
			continue
		}
		expiresAt, err := parseTime(entry.Expires)
		if err != nil {
			continue
		}
		if expiresAt.After(maxExpiry) {
			maxExpiry = expiresAt
			meta.ExpiresAt = expiresAt
		}
	}

	// If the latest ignore entry is permanent (no expiry), discard any
	// earlier snooze expiry — the user's most recent action overrides the
	// previous temporary ignores. Only do this when every entry's Created
	// timestamp parsed, so "latest" is actually reliable.
	if allCreatedParsed && anyCreatedParsed && !latestHasExpiry {
		meta.ExpiresAt = time.Time{}
	}

	return meta
}

// cacheIgnoresToV1 reconstructs the v1 ignore response shape from cached
// metadata. Each cached issue key becomes a single-entry array so that the
// rest of the sync logic can use maxExpiryIgnoreMeta unchanged.
func cacheIgnoresToV1(cached map[string]cache.IgnoreMeta) v1ProjectIgnores {
	out := make(v1ProjectIgnores, len(cached))
	for issueKey, meta := range cached {
		entry := v1IgnoreEntry{
			DisregardIfFixable: meta.DisregardIfFixable,
		}
		if !meta.ExpiresAt.IsZero() {
			entry.Expires = meta.ExpiresAt.UTC().Format(time.RFC3339Nano)
		}
		if !meta.CreatedAt.IsZero() {
			entry.Created = meta.CreatedAt.UTC().Format(time.RFC3339Nano)
		}
		out[issueKey] = []v1IgnoreEntry{entry}
	}
	return out
}

// ignoreMetadata carries the v1 ignore fields that the sync logic needs:
// the snooze expiry date, whether the ignore is conditional on no fix being
// available (disregardIfFixable), and, for such an ignore, when it stopped
// applying (from the cache; see projectIgnores.unignoredAt).
type ignoreMetadata struct {
	ExpiresAt          time.Time
	DisregardIfFixable bool
	CreatedAt          time.Time
	EndedAt            time.Time
}

func parseTime(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, fmt.Errorf("empty time string")
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, raw)
}

func (c *Client) listProjects(ctx context.Context) ([]projectRef, error) {
	if c.requireFresh {
		return c.listFreshProjects(ctx)
	}
	projects := make([]projectRef, 0, 256)
	opts := &snyksdk.ListProjectsOptions{}

	for {
		page, resp, err := c.sdk.Projects.List(ctx, c.orgID, opts)
		if err != nil {
			return nil, fmt.Errorf("list Snyk projects: %w", err)
		}

		for _, project := range page {
			name := ""
			origin := ""
			targetReference := ""
			targetFile := ""
			status := ""
			if project.Attributes != nil {
				name = project.Attributes.Name
				origin = project.Attributes.Origin
				targetReference = project.Attributes.TargetReference
				targetFile = project.Attributes.TargetFile
				status = project.Attributes.Status
			}
			projects = append(projects, projectRef{
				ID:              project.ID,
				Name:            name,
				Origin:          origin,
				TargetReference: targetReference,
				TargetFile:      targetFile,
				Repository:      projectRepository(name, origin),
				Namespace:       kubernetesNamespace(name, origin),
				Active:          isActiveProjectStatus(status),
			})
		}

		if resp == nil || resp.Links == nil || resp.Links.Next == "" {
			break
		}

		cursor, err := extractCursor(resp.Links.Next)
		if err != nil {
			return nil, err
		}
		if cursor == "" {
			break
		}
		opts.StartingAfter = cursor
	}

	return projects, nil
}

func (c *Client) orgSlug(ctx context.Context) (string, error) {
	endpoint, err := c.restBase.Parse(fmt.Sprintf("orgs/%s", c.orgID))
	if err != nil {
		return "", err
	}

	query := endpoint.Query()
	query.Set("version", issuesAPIVersion)
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.api+json")

	var payload orgResponse
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	if err := c.decodeJSON(resp, &payload); err != nil {
		return "", err
	}

	if c.requireFresh {
		c.sourceReads.Organization = true
	}
	return strings.TrimSpace(payload.Data.Attributes.Slug), nil
}

func (c *Client) listIssuesPage(ctx context.Context, cursor string) ([]issueResource, string, error) {
	endpoint, err := c.restBase.Parse(fmt.Sprintf("orgs/%s/issues", c.orgID))
	if err != nil {
		return nil, "", err
	}

	query := endpoint.Query()
	query.Set("version", issuesAPIVersion)
	query.Set("limit", "100")
	if cursor != "" {
		query.Set("starting_after", cursor)
	}
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "application/vnd.api+json")

	var payload issueListResponse
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	if err := c.decodeJSON(resp, &payload); err != nil {
		return nil, "", err
	}

	if c.requireFresh {
		c.sourceReads.IssuePages++
		next, err := freshCursor(payload.Links.Next)
		return payload.Data, next, err
	}
	nextCursor, err := extractCursor(payload.Links.Next)
	if err != nil {
		return nil, "", err
	}

	return payload.Data, nextCursor, nil
}

func extractCursor(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse pagination link %q: %w", raw, err)
	}
	return parsed.Query().Get("starting_after"), nil
}

func parseIssueCreatedAt(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, fmt.Errorf("missing created_at")
	}
	createdAt, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, err
	}
	return createdAt, nil
}

// parseIssueTimestamp parses a Snyk RFC3339 timestamp, returning the zero
// time if the string is empty. Used for optional fields like updated_at
// where a missing value is acceptable.
func parseIssueTimestamp(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}
	}
	return t
}

// issueResolved reports whether Snyk no longer reports the finding
// (resolved/fixed/disappeared): its status says so, every coordinate is
// resolved, or its resolution is a fix.
func issueResolved(issue issueAttributes) bool {
	status := strings.ToLower(issue.Status)
	return status == "resolved" || status == "fixed" || coordinateResolved(issue.Coordinates) || strings.ToLower(issue.Resolution.Type) == "fixed"
}

func mapStatus(issue issueAttributes, ignoreExpiresAt time.Time, disregardIfFixable bool) model.FindingStatus {
	resolutionType := strings.ToLower(issue.Resolution.Type)
	resolutionDetails := strings.ToLower(issue.Resolution.Details)

	// A finding Snyk no longer reports (resolved/fixed/disappeared) is terminal,
	// full stop — ignores only matter for findings that still exist. This check
	// must precede the ignore handling below: a resolved finding can still carry
	// an ignore (active, expired, or disregard-if-fixable), and letting the
	// ignore branches win would map a vulnerability that is already gone to a
	// non-terminal state, resurrecting it as a permanently-open (and often
	// birth-overdue) ticket.
	resolved := issueResolved(issue)

	if issue.Ignored && !resolved {
		// "Ignore until a fix is available" maps to FindingAwaitingFix so the
		// sync places the issue in Backlog with no due date, signalling that the
		// issue is blocked on an upstream fix. When a fix appears, Snyk flips
		// ignored=false and the next run maps it back to FindingOpen (Todo).
		if disregardIfFixable {
			return model.FindingAwaitingFix
		}
		if !ignoreExpiresAt.IsZero() {
			// Both an active snooze and an expired-but-still-ignored snooze
			// map to FindingOpen (Todo), for two different reasons:
			//   - active snooze: the user intentionally silenced this for
			//     now, so the ticket should stay open rather than cancelled.
			//   - expired snooze: Snyk still reports ignored=true even
			//     though the expiry has passed. Snyk will eventually flip
			//     ignored=false or the user will re-snooze. Mapping to
			//     FindingIgnored (Cancelled) here would trigger the reopen
			//     guard when the snooze lapses or is re-applied, creating
			//     duplicate tickets.
			return model.FindingOpen
		}
		// No expiry metadata — permanent ignore.
		return model.FindingIgnored
	}

	switch {
	case resolved:
		// Resolved wins over a snooze marker: a finding Snyk no longer reports
		// is terminal regardless of any lingering snooze metadata, mirroring the
		// resolved-first gate on the ignore block above.
		return model.FindingFixed
	case strings.Contains(resolutionType, "snooz") || strings.Contains(resolutionDetails, "snooz"):
		return model.FindingSnoozed
	default:
		return model.FindingOpen
	}
}

func fixedVersion(coords []coordinate) string {
	for _, coord := range coords {
		for _, remedy := range coord.Remedies {
			if remedy.Details.UpgradePackage != "" {
				return remedy.Details.UpgradePackage
			}
		}
	}
	return ""
}

func packageName(coords []coordinate) string {
	for _, coord := range coords {
		for _, rep := range coord.Representations {
			if rep.Dependency.PackageName == "" {
				continue
			}
			return rep.Dependency.PackageName
		}
	}
	return ""
}

func vulnerableVersion(coords []coordinate) string {
	for _, coord := range coords {
		for _, rep := range coord.Representations {
			if rep.Dependency.PackageVersion != "" {
				return rep.Dependency.PackageVersion
			}
		}
	}
	return ""
}

func introducedThrough(coords []coordinate) string {
	for _, coord := range coords {
		for _, rep := range coord.Representations {
			if rep.Dependency.PackageName != "" || rep.Dependency.PackageVersion != "" {
				return strings.TrimSpace(rep.Dependency.PackageName + " " + rep.Dependency.PackageVersion)
			}
		}
	}
	return ""
}

func problemTitle(problems []problem) string {
	for _, problem := range problems {
		if problem.Title != "" {
			return problem.Title
		}
	}
	return ""
}

func firstProblemID(problems []problem) string {
	for _, problem := range problems {
		if problem.ID != "" {
			return problem.ID
		}
	}
	return ""
}

func firstProblemSeverity(problems []problem) string {
	for _, problem := range problems {
		if problem.Severity != "" {
			return problem.Severity
		}
	}
	return ""
}

// issueClasses copies Snyk weakness class entries into the model shape,
// dropping empty IDs. Class entries are not deduplicated or sorted here so
// the rendering can preserve Snyk's ordering.
func issueClasses(classes []classEntry) []model.IssueClass {
	out := make([]model.IssueClass, 0, len(classes))
	for _, class := range classes {
		id := strings.TrimSpace(class.ID)
		if id == "" {
			continue
		}
		out = append(out, model.IssueClass{
			ID:     id,
			Source: strings.TrimSpace(class.Source),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// cveIDs extracts CVE identifiers from a Snyk issue's problems list. Snyk
// reports each CVE as a problem whose id is the CVE identifier (e.g.
// "CVE-2025-7783"); the problems[].source field names the reporting database
// (commonly "NVD"), not the literal string "CVE", so matching by source is
// unreliable. We therefore match on a case-insensitive "CVE-" id prefix,
// which is source-agnostic and robust.
func cveIDs(problems []problem) []string {
	seen := make(map[string]struct{}, len(problems))
	out := make([]string, 0, len(problems))
	for _, problem := range problems {
		id := strings.TrimSpace(problem.ID)
		if id == "" || !strings.HasPrefix(strings.ToUpper(id), "CVE-") {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// anyFixable reports whether any coordinate satisfies the predicate. It is
// used to aggregate per-coordinate is_fixable_* flags into a single
// finding-level boolean.
func anyFixable(coords []coordinate, ok func(coordinate) bool) bool {
	return slices.ContainsFunc(coords, ok)
}

// selectCVSS picks a single CVSS score to display from the severities Snyk
// reports for an issue. Snyk may emit several entries from different sources
// (e.g. "Snyk", "NVD", "Red Hat") and CVSS versions (3.1, 4.0). We prefer a
// Snyk score, then Red Hat, then NVD, then any other source; within a source
// we take the highest score so a more severe, well-sourced score wins. 0 is
// returned (and the renderer omits the line) when Snyk reports no scores —
// which is legitimate for non-vulnerability issue types.
func selectCVSS(severities []severityEntry) float64 {
	const (
		scoreSnyk = iota
		scoreRedHat
		scoreNVD
		scoreOther
	)
	rank := func(source string) int {
		switch strings.ToLower(strings.TrimSpace(source)) {
		case "snyk":
			return scoreSnyk
		case "red hat":
			return scoreRedHat
		case "nvd":
			return scoreNVD
		default:
			return scoreOther
		}
	}

	var bestRank = -1
	var best float64
	found := false
	for _, sev := range severities {
		if sev.Score == nil {
			continue
		}
		score := *sev.Score
		r := rank(sev.Source)
		if !found || r < bestRank || (r == bestRank && score > best) {
			bestRank = r
			best = score
			found = true
		}
	}
	return best
}

// remediationDescription aggregates every non-empty remedy description
// across a finding's coordinates. Snyk exposes remediation prose at
// coordinates[].remedies[].description (a markdown string); there is no
// top-level remediation field on the issue resource. Code and cloud findings
// carry prose here; package_vulnerability findings usually carry only a
// details.upgrade_package (already surfaced as Fix version) and no prose.
//
// A finding can carry several distinct remedy descriptions (e.g. a cloud
// finding with Terraform, CloudFormation, and inline-rule messages). Rather
// than dropping all but the first, we collect them in Snyk's order and join
// with a blank line so the Linear ### Remediation section is self-sufficient.
// Descriptions are deduplicated by trimmed content so repeated remedies across
// coordinates collapse to one entry.
func remediationDescription(coords []coordinate) string {
	var out []string
	seen := make(map[string]struct{})
	for _, coord := range coords {
		for _, remedy := range coord.Remedies {
			desc := strings.TrimSpace(remedy.Description)
			if desc == "" {
				continue
			}
			if _, exists := seen[desc]; exists {
				continue
			}
			seen[desc] = struct{}{}
			out = append(out, desc)
		}
	}
	return strings.Join(out, "\n\n")
}

func (c *Client) issueAPIURL(issueID string) string {
	u, err := c.restBase.Parse(fmt.Sprintf("orgs/%s/issues/%s", c.orgID, issueID))
	if err != nil {
		return ""
	}
	query := u.Query()
	query.Set("version", issuesAPIVersion)
	u.RawQuery = query.Encode()
	return u.String()
}

func (c *Client) issueUIURL(orgSlug, projectID, issueKey string) string {
	if strings.TrimSpace(orgSlug) == "" || strings.TrimSpace(projectID) == "" || strings.TrimSpace(issueKey) == "" {
		return ""
	}

	u, err := url.Parse("https://app.snyk.io")
	if err != nil {
		return ""
	}
	u.Path = fmt.Sprintf("/org/%s/project/%s", orgSlug, projectID)
	u.Fragment = "issue-" + issueKey
	return u.String()
}

func coalesce(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func exploitMaturity(levels []maturityLevel) string {
	out := make([]string, 0, len(levels))
	for _, level := range levels {
		value := strings.TrimSpace(level.Level)
		if value == "" {
			continue
		}
		if format := strings.TrimSpace(level.Format); format != "" {
			out = append(out, format+": "+value)
			continue
		}
		out = append(out, value)
	}
	return strings.Join(out, ", ")
}

// latestResolvedAt returns the most recent last_resolved_at across the
// issue's coordinates, the moment Snyk last saw this issue resolved. Snyk
// keeps last_resolved_at on a coordinate after the issue reopens, which is
// how an issue ID reused for a new occurrence shows its earlier resolution.
// invalid reports that some coordinate carried a value that did not parse:
// the resolution history is then unknown and callers must not read the
// zero time as "never resolved".
func latestResolvedAt(coords []coordinate) (latest time.Time, invalid bool) {
	for _, coord := range coords {
		raw := strings.TrimSpace(coord.LastResolvedAt)
		if raw == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			invalid = true
			continue
		}
		if t.After(latest) {
			latest = t
		}
	}
	return latest, invalid
}

func coordinateResolved(coords []coordinate) bool {
	if len(coords) == 0 {
		return false
	}
	for _, coord := range coords {
		if !strings.EqualFold(coord.State, "resolved") {
			return false
		}
	}
	return true
}

func sourceLocation(coords []coordinate) sourceLocationRepresentation {
	for _, coord := range coords {
		for _, rep := range coord.Representations {
			if rep.SourceLocation.File != "" {
				return rep.SourceLocation
			}
		}
	}
	return sourceLocationRepresentation{}
}

// locationKey derives a stable per-instance key from the coordinate
// representations Snyk reports, so that two occurrences of the same
// problem-type-in-project get distinct fingerprints (and thus distinct
// Linear tickets) when they live in different code or dependencies.
//
// For code (SAST) issues it returns the source file path. For dependency
// issues it returns package@version. An empty string means no coordinates
// were available, in which case Fingerprint falls back to the coarse
// 2-segment key for backward compatibility.
//
// Line numbers and commit SHAs are deliberately excluded: they churn on
// every refactor and would orphan tickets. The file path / package identity
// is the stable "occurrence site."
//
// When an issue carries multiple coordinates/representations, Snyk does not
// guarantee their ordering is stable across API calls. Picking "whichever
// comes first" therefore made the fingerprint flip between runs, orphaning
// the old Linear ticket and creating a duplicate. To keep the key
// deterministic we instead collect every candidate location string (still
// preferring a representation's source file over its dependency, as before)
// and pick the lexicographically smallest one. This is a one-time fingerprint
// shift for existing multi-coordinate tickets that happened to be created
// under "first wins" with a non-minimal candidate — acceptable, since the
// vast majority of issues have a single coordinate and are unaffected.
func locationKey(coords []coordinate) string {
	var candidates []string
	for _, coord := range coords {
		for _, rep := range coord.Representations {
			if rep.SourceLocation.File != "" {
				candidates = append(candidates, rep.SourceLocation.File)
				continue
			}
			if rep.Dependency.PackageName != "" {
				if rep.Dependency.PackageVersion != "" {
					candidates = append(candidates, rep.Dependency.PackageName+"@"+rep.Dependency.PackageVersion)
				} else {
					candidates = append(candidates, rep.Dependency.PackageName)
				}
			}
		}
	}
	if len(candidates) == 0 {
		return ""
	}
	slices.Sort(candidates)
	return candidates[0]
}

// isActiveProjectStatus returns true for projects that are being monitored.
// Snyk uses "active" for monitored projects and "inactive" for de-activated ones.
// An empty status is treated as active to be forward-compatible with API responses
// that omit the field.
func isActiveProjectStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "inactive":
		return false
	default:
		return true
	}
}

// kubernetesNamespace extracts the namespace from a kubernetes-origin
// project name. The Snyk Kubernetes integration names projects
// "<namespace>/<kind>.<group>/<workload>:<target>" — e.g.
// "backend/deployment.apps/backend:/app/package.json" — so the namespace is
// the first path segment. Returns "" for other origins or names that don't
// match the shape.
func kubernetesNamespace(name, origin string) string {
	if origin != "kubernetes" {
		return ""
	}
	name = strings.TrimSpace(name)
	namespace, rest, ok := strings.Cut(name, "/")
	if !ok || namespace == "" || rest == "" {
		return ""
	}
	return namespace
}

func projectRepository(name, origin string) string {
	switch origin {
	case "github", "gitlab", "bitbucket", "azure-repos":
	default:
		return ""
	}

	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if idx := strings.Index(name, "("); idx > 0 {
		name = strings.TrimSpace(name[:idx])
	}
	return name
}

// Bound even a server that supplies an endless sequence of distinct cursors.
const freshMaxPages = 10000

type freshProjectsResponse struct {
	Data []struct {
		ID         string `json:"id"`
		Attributes struct {
			Name            string `json:"name"`
			Origin          string `json:"origin"`
			TargetReference string `json:"target_reference"`
			TargetFile      string `json:"target_file"`
			Status          string `json:"status"`
		} `json:"attributes"`
	} `json:"data"`
	Links struct {
		Next string `json:"next"`
	} `json:"links"`
}

func freshCursor(raw string) (string, error) {
	cursor, err := extractCursor(raw)
	if err != nil {
		return "", err
	}
	if raw != "" && strings.TrimSpace(cursor) == "" {
		return "", fmt.Errorf("Snyk continuation missing starting_after")
	}
	return cursor, nil
}

func (c *Client) listFreshProjects(ctx context.Context) ([]projectRef, error) {
	var projects []projectRef
	seenCursors, seenIDs := map[string]bool{}, map[string]bool{}
	cursor := ""
	for {
		if seenCursors[cursor] || c.sourceReads.ProjectPages >= freshMaxPages {
			return nil, fmt.Errorf("Snyk project pagination repeated or exhausted")
		}
		seenCursors[cursor] = true
		endpoint, err := c.restBase.Parse(fmt.Sprintf("orgs/%s/projects", c.orgID))
		if err != nil {
			return nil, err
		}
		query := endpoint.Query()
		query.Set("version", issuesAPIVersion)
		query.Set("limit", "100")
		if cursor != "" {
			query.Set("starting_after", cursor)
		}
		endpoint.RawQuery = query.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/vnd.api+json")
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		var page freshProjectsResponse
		if err := c.decodeJSON(resp, &page); err != nil {
			return nil, err
		}
		c.sourceReads.ProjectPages++
		for _, row := range page.Data {
			if seenIDs[row.ID] {
				return nil, fmt.Errorf("duplicate Snyk project id")
			}
			seenIDs[row.ID] = true
			a := row.Attributes
			projects = append(projects, projectRef{ID: row.ID, Name: a.Name, Origin: a.Origin, TargetReference: a.TargetReference, TargetFile: a.TargetFile, Repository: projectRepository(a.Name, a.Origin), Namespace: kubernetesNamespace(a.Name, a.Origin), Active: isActiveProjectStatus(a.Status)})
		}
		cursor, err = freshCursor(page.Links.Next)
		if err != nil {
			return nil, err
		}
		if cursor == "" {
			return projects, nil
		}
	}
}

func validateFreshIgnores(body []byte) error {
	if err := validateFreshJSON(body, nil); err != nil {
		return err
	}
	var ignores map[string][]json.RawMessage
	if err := json.Unmarshal(body, &ignores); err != nil {
		return err
	}
	for key, entries := range ignores {
		if strings.TrimSpace(key) == "" || entries == nil {
			return fmt.Errorf("invalid Snyk ignore container")
		}
		for _, entry := range entries {
			details := entry
			obj, err := requireJSONObject(entry)
			if err != nil {
				return err
			}
			// Nested path entries must have exactly one path: the legacy decoder
			// selects one map entry, so accepting more would be nondeterministic.
			if _, flat := obj["created"]; !flat {
				if len(obj) != 1 {
					return fmt.Errorf("ambiguous Snyk ignore paths")
				}
				for _, raw := range obj {
					details = raw
					obj, err = requireJSONObject(raw)
					if err != nil {
						return err
					}
				}
			}
			if err := validateFreshJSON(details, (*v1IgnoreFields)(nil)); err != nil {
				return err
			}
			var created string
			if err := json.Unmarshal(obj["created"], &created); err != nil {
				return fmt.Errorf("Snyk ignore missing created")
			}
			if _, err := parseIssueCreatedAt(created); err != nil {
				return err
			}
			if expires, ok := freshIgnoreField(obj, "expires"); ok && string(expires) != "null" {
				var value string
				if err := json.Unmarshal(expires, &value); err != nil {
					return err
				}
				if value != "" {
					if _, err := time.Parse(time.RFC3339, value); err != nil {
						return err
					}
				}
			}
			if flag, ok := freshIgnoreField(obj, "disregardIfFixable"); ok {
				var value bool
				if string(flag) == "null" {
					return fmt.Errorf("null Snyk ignore flag")
				}
				if err := json.Unmarshal(flag, &value); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Fresh ignore details have already been checked for aliases. Match optional
// fields as the custom decoder does, so alternate casing cannot evade validation.
func freshIgnoreField(obj map[string]json.RawMessage, name string) (json.RawMessage, bool) {
	for key, value := range obj {
		if strings.EqualFold(key, name) {
			return value, true
		}
	}
	return nil, false
}
