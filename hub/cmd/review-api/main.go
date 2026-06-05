package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/chip/incident-response-kit/hub/internal/findings"
	"github.com/chip/incident-response-kit/hub/internal/ingest"
	"github.com/chip/incident-response-kit/hub/internal/normalize"
	thruntime "github.com/chip/incident-response-kit/hub/internal/runtime"
	"github.com/chip/incident-response-kit/hub/internal/store/sqlite"
)

func main() {
	layout, err := thruntime.Detect()
	if err != nil {
		log.Fatalf("detect layout: %v", err)
	}
	if err := layout.Ensure(); err != nil {
		log.Fatalf("ensure layout: %v", err)
	}

	var dbPath string
	var addr string
	flag.StringVar(&dbPath, "db", layout.DBPath, "path to the Thoth sqlite database")
	flag.StringVar(&addr, "addr", "127.0.0.1:8080", "listen address")
	flag.Parse()

	store, err := sqlite.Open(dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	if err := store.ApplyMigrations(ctx); err != nil {
		log.Fatalf("apply migrations: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/docs/quick-start" {
			showQuickStart(layout, w, r)
			return
		}
		if r.URL.Path == "/docs/user-guide" {
			showUserGuide(layout, w, r)
			return
		}
		if r.URL.Path == "/ingest" && r.Method == http.MethodPost {
			handleIngest(layout, store, w, r)
			return
		}
		if r.URL.Path == "/export-data" && r.Method == http.MethodPost {
			handleExportData(layout, store, w, r)
			return
		}
		if r.URL.Path == "/clear-data" && r.Method == http.MethodPost {
			handleClearData(layout, store, w, r)
			return
		}
		if r.URL.Path != "/" {
			caseRouter(store, w, r)
			return
		}
		cases, err := store.ListCaseSummaries(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		renderTemplate(w, homeTemplate, map[string]any{"Cases": cases, "Sources": detectMountedSources(), "Message": r.URL.Query().Get("msg"), "Layout": layout})
	})

	log.Printf("Thoth UI listening on http://%s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func caseRouter(store *sqlite.Store, w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] != "cases" {
		http.NotFound(w, r)
		return
	}
	caseUUID := parts[1]

	if len(parts) == 3 && parts[2] == "decision" && r.Method == http.MethodPost {
		handleCaseDecision(store, w, r, caseUUID)
		return
	}
	if len(parts) == 3 && parts[2] == "notes" && r.Method == http.MethodPost {
		handleAddNote(store, w, r, caseUUID)
		return
	}
	if len(parts) == 3 && parts[2] == "field" && r.Method == http.MethodPost {
		handleFieldUpdate(store, w, r, caseUUID)
		return
	}
	if len(parts) == 2 {
		showCase(store, w, r, caseUUID)
		return
	}
	if len(parts) == 3 && (parts[2] == "host-overview" || parts[2] == "host-context") {
		showHostContext(store, w, r, caseUUID)
		return
	}
	if len(parts) == 3 && parts[2] == "network-config" {
		showNetworkConfig(store, w, r, caseUUID)
		return
	}
	if len(parts) == 3 && parts[2] == "processes" {
		showProcesses(store, w, r, caseUUID)
		return
	}
	if len(parts) == 3 && parts[2] == "scheduled-tasks" {
		showScheduledTasks(store, w, r, caseUUID)
		return
	}
	if len(parts) == 3 && parts[2] == "persistence" {
		showPersistence(store, w, r, caseUUID)
		return
	}
	if len(parts) == 3 && parts[2] == "logs" {
		showSystemLogs(store, w, r, caseUUID)
		return
	}
	if len(parts) == 3 && strings.HasPrefix(parts[2], "logs-") {
		showLogView(store, w, r, caseUUID, parts[2])
		return
	}
	if len(parts) == 3 && parts[2] == "network" {
		showNetworkView(store, w, r, caseUUID)
		return
	}
	if len(parts) == 4 && parts[2] == "artifact" {
		showArtifact(store, w, r, caseUUID, parts[3])
		return
	}
	if len(parts) == 4 && parts[2] == "source" {
		showSourceArtifact(store, w, r, caseUUID, parts[3])
		return
	}
	http.NotFound(w, r)
}

func handleCaseDecision(store *sqlite.Store, w http.ResponseWriter, r *http.Request, caseUUID string) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	disposition := normalizeAllowedValue(r.FormValue("disposition"), []string{"", "monitor", "collect_more", "likely_benign", "needs_follow_up", "forensic_escalation"})
	priority := normalizeAllowedValue(r.FormValue("priority"), []string{"", "low", "medium", "high", "urgent"})
	escalated := r.FormValue("escalated") == "on"
	if disposition == "" && priority == "" {
		escalated = false
	}
	if err := store.UpdateCaseDecision(r.Context(), caseUUID, disposition, priority, escalated); err != nil {
		if err == sql.ErrNoRows {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/cases/"+url.PathEscape(caseUUID)+"?msg="+url.QueryEscape("Decision saved."), http.StatusSeeOther)
}

func handleAddNote(store *sqlite.Store, w http.ResponseWriter, r *http.Request, caseUUID string) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	body := strings.TrimSpace(r.FormValue("body"))
	if body == "" {
		http.Redirect(w, r, "/cases/"+url.PathEscape(caseUUID)+"?msg="+url.QueryEscape("Empty note ignored."), http.StatusSeeOther)
		return
	}
	noteType := normalizeAllowedValue(r.FormValue("note_type"), []string{"general", "observation", "decision", "follow_up"})
	if noteType == "" {
		noteType = "general"
	}
	author := strings.TrimSpace(r.FormValue("author"))
	if err := store.AddAnalystNote(r.Context(), caseUUID, noteType, body, author); err != nil {
		if err == sql.ErrNoRows {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/cases/"+url.PathEscape(caseUUID)+"?msg="+url.QueryEscape("Note added."), http.StatusSeeOther)
}

func handleFieldUpdate(store *sqlite.Store, w http.ResponseWriter, r *http.Request, caseUUID string) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	disposition := normalizeAllowedValue(r.FormValue("disposition"), []string{"", "monitor", "collect_more", "likely_benign", "needs_follow_up", "forensic_escalation"})
	priority := normalizeAllowedValue(r.FormValue("priority"), []string{"", "low", "medium", "high", "urgent"})
	escalated := r.FormValue("escalated") == "on"
	if disposition == "" && priority == "" {
		escalated = false
	}
	if err := store.UpdateCaseDecision(r.Context(), caseUUID, disposition, priority, escalated); err != nil {
		if err == sql.ErrNoRows {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	noteAdded := false
	body := strings.TrimSpace(r.FormValue("body"))
	if body != "" {
		noteType := normalizeAllowedValue(r.FormValue("note_type"), []string{"general", "observation", "decision", "follow_up"})
		if noteType == "" {
			noteType = "general"
		}
		author := strings.TrimSpace(r.FormValue("author"))
		if err := store.AddAnalystNote(r.Context(), caseUUID, noteType, body, author); err != nil {
			if err == sql.ErrNoRows {
				http.NotFound(w, r)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		noteAdded = true
	}

	intent := r.FormValue("intent")
	msg := "Decision saved."
	if noteAdded {
		msg = "Decision saved and note added."
	} else if intent == "add_note" {
		msg = "Decision saved; empty note ignored."
	}
	http.Redirect(w, r, "/cases/"+url.PathEscape(caseUUID)+"?msg="+url.QueryEscape(msg), http.StatusSeeOther)
}

func normalizeAllowedValue(value string, allowed []string) string {
	value = strings.TrimSpace(value)
	for _, item := range allowed {
		if value == item {
			return value
		}
	}
	return ""
}

func showCase(store *sqlite.Store, w http.ResponseWriter, r *http.Request, caseUUID string) {
	showAll := r.URL.Query().Get("show") == "all"
	caseSummary, found, err := findCase(store, r.Context(), caseUUID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	artifactSets, err := store.ListArtifactSets(r.Context(), caseUUID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	findings, err := store.ListFindings(r.Context(), caseUUID, showAll)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	findingViews := buildFindingViews(caseUUID, findings)
	allFindings, err := store.ListFindings(r.Context(), caseUUID, true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	notes, err := store.ListAnalystNotes(r.Context(), caseUUID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	suppressedCount := 0
	for _, item := range allFindings {
		if item.Suppressed {
			suppressedCount++
		}
	}
	hostContextArtifact, _ := artifactSetByKey(artifactSets, "host_identity")
	renderTemplate(w, caseTemplate, map[string]any{"Case": caseSummary, "ArtifactSets": buildArtifactSetViews(caseUUID, artifactSets), "Findings": findingViews, "Notes": notes, "Message": r.URL.Query().Get("msg"), "ShowAll": showAll, "SuppressedCount": suppressedCount, "HostContextArtifact": hostContextArtifact})
}

type artifactSetView struct {
	sqlite.ArtifactSetSummary
	SourceRelativePath string
	SourceURL          string
}

func buildArtifactSetViews(caseUUID string, sets []sqlite.ArtifactSetSummary) []artifactSetView {
	views := make([]artifactSetView, 0, len(sets))
	for _, set := range sets {
		views = append(views, artifactSetView{ArtifactSetSummary: set, SourceRelativePath: collectedSourceRelativePath(set.SourcePath), SourceURL: "/cases/" + url.PathEscape(caseUUID) + "/source/" + url.PathEscape(set.ArtifactKey)})
	}
	return views
}

func collectedSourceRelativePath(sourcePath string) string {
	path := filepath.ToSlash(sourcePath)
	if idx := strings.Index(path, "/source/"); idx != -1 {
		return path[idx+len("/source/"):]
	}
	return filepath.Base(sourcePath)
}

type findingView struct {
	sqlite.FindingRecord
	EvidenceURL    string
	EvidenceLabel  string
	EvidenceSource string
}

func buildFindingViews(caseUUID string, findings []sqlite.FindingRecord) []findingView {
	views := make([]findingView, 0, len(findings))
	for _, finding := range findings {
		views = append(views, findingView{FindingRecord: finding, EvidenceURL: evidenceURLForFinding(caseUUID, finding), EvidenceLabel: evidenceLabelForFinding(finding), EvidenceSource: evidenceSourceForFinding(finding)})
	}
	return views
}

func evidenceFields(evidence string) map[string]string {
	fields := map[string]string{}
	for _, part := range strings.Fields(evidence) {
		key, value, ok := strings.Cut(part, "=")
		if !ok || key == "" {
			continue
		}
		fields[key] = strings.Trim(value, `"`)
	}
	return fields
}

func evidenceLabelForFinding(finding sqlite.FindingRecord) string {
	fields := evidenceFields(finding.Evidence)
	if artifact := fields["artifact"]; artifact != "" {
		parts := []string{friendlyArtifactName(artifact)}
		if eventID := fields["event_id"]; eventID != "" {
			parts = append(parts, "Event ID "+eventID)
		}
		if count := fields["count"]; count != "" {
			parts = append(parts, count+" record(s)")
		} else if idx := fields["record_index"]; idx != "" {
			parts = append(parts, "record #"+idx)
		}
		return strings.Join(parts, " · ")
	}
	return finding.Evidence
}

func evidenceSourceForFinding(finding sqlite.FindingRecord) string {
	fields := evidenceFields(finding.Evidence)
	if artifact := fields["artifact"]; artifact != "" {
		return artifact
	}
	return ""
}

func friendlyArtifactName(key string) string {
	switch key {
	case "logs_powershell":
		return "PowerShell Operational Log"
	case "scheduled_tasks":
		return "Scheduled Tasks"
	case "persistence_hkcu_run":
		return "HKCU Run Autoruns"
	case "persistence_startup_folder":
		return "Startup Folder"
	default:
		return key
	}
}

func evidenceURLForFinding(caseUUID string, finding sqlite.FindingRecord) string {
	fields := evidenceFields(finding.Evidence)
	if artifact := fields["artifact"]; artifact != "" {
		switch artifact {
		case "logs_powershell":
			if eventID := fields["event_id"]; eventID != "" {
				return "/cases/" + url.PathEscape(caseUUID) + "/logs-powershell?event_id=" + url.QueryEscape(eventID)
			}
			return "/cases/" + url.PathEscape(caseUUID) + "/logs-powershell"
		case "scheduled_tasks":
			fragment := ""
			if idx := fields["record_index"]; idx != "" {
				fragment = "#record-" + url.PathEscape(idx)
			}
			return "/cases/" + url.PathEscape(caseUUID) + "/scheduled-tasks" + fragment
		case "persistence_hkcu_run", "persistence_startup_folder":
			fragment := ""
			if idx := fields["record_index"]; idx != "" {
				fragment = "#record-" + url.PathEscape(artifact) + "-" + url.PathEscape(idx)
			}
			return "/cases/" + url.PathEscape(caseUUID) + "/persistence" + fragment
		default:
			return "/cases/" + url.PathEscape(caseUUID) + "/artifact/" + url.PathEscape(artifact)
		}
	}
	evidence := strings.ToLower(finding.Evidence)
	title := strings.ToLower(finding.Title)

	if strings.Contains(evidence, "logs_powershell") || strings.Contains(title, "powershell") {
		if strings.Contains(evidence, "event_id=4104") || strings.Contains(title, "script block") {
			return "/cases/" + url.PathEscape(caseUUID) + "/logs-powershell?source=" + url.QueryEscape("4104")
		}
		return "/cases/" + url.PathEscape(caseUUID) + "/logs-powershell"
	}
	if finding.Category == "persistence" && strings.Contains(title, "scheduled task") {
		return "/cases/" + url.PathEscape(caseUUID) + "/scheduled-tasks?q=" + url.QueryEscape(finding.Evidence)
	}
	if finding.Category == "persistence" && strings.Contains(title, "autorun") {
		return "/cases/" + url.PathEscape(caseUUID) + "/artifact/persistence_hkcu_run"
	}
	if finding.Category == "persistence" && strings.Contains(title, "startup-folder") {
		return "/cases/" + url.PathEscape(caseUUID) + "/artifact/persistence_startup_folder"
	}
	return ""
}

func quotedEvidenceValue(evidence, key string) string {
	prefix := key + "=\""
	idx := strings.Index(evidence, prefix)
	if idx == -1 {
		return ""
	}
	start := idx + len(prefix)
	end := strings.Index(evidence[start:], "\"")
	if end == -1 {
		return ""
	}
	return evidence[start : start+end]
}

type hostContextView struct {
	Case                 sqlite.CaseSummary
	Hostname             string
	OSName               string
	OSVersion            string
	OSBuild              string
	Architecture         string
	Username             string
	Domain               string
	Timezone             string
	CollectionTime       string
	LastBootTime         string
	Uptime               string
	SourcePath           string
	OutputPath           string
	RawJSON              string
	PrimaryIPv4          string
	DefaultGateway       string
	DNSServers           string
	AdapterCount         int
	PatchPostureNote     string
	HasNetworkSummary    bool
	HasSecuritySummary   bool
	FirewallSummary      string
	DefenderSummary      string
	SecurityToolsSummary string
	HasSoftwareSummary   bool
	SoftwareSummary      string
	HasDeviceSummary     bool
	DeviceSummary        string
	HasWirelessSummary   bool
	WirelessSummary      string
}

type processRecordView struct {
	ImageName         string
	PID               int
	PIDText           string
	PPIDText          string
	UserName          string
	SessionName       string
	SessionID         string
	ExecutablePath    string
	CommandLine       string
	CPUTime           string
	WindowTitle       string
	Status            string
	MemUsage          string
	PathOrCommand     string
	SuspiciousHint    string
	LikelyInteractive bool
}

type processListView struct {
	Case           sqlite.CaseSummary
	Processes      []processRecordView
	Query          string
	UserFilter     string
	SessionFilter  string
	StatusFilter   string
	SortKey        string
	TotalCount     int
	FilteredCount  int
	UniqueUsers    []string
	UniqueSessions []string
	UniqueStatuses []string
	HasQuery       bool
	PIDFocus       string
}

type scheduledTaskView struct {
	RecordIndex    int
	TaskName       string
	Command        string
	Trigger        string
	RunAsUser      string
	State          string
	Status         string
	LastRunTime    string
	NextRunTime    string
	StartTime      string
	RepeatEvery    string
	StartIn        string
	LastResult     string
	Comment        string
	IsEnabled      bool
	IsHiddenLike   bool
	SuspiciousHint string
	CommandIsPath  bool
}

type scheduledTasksPageView struct {
	Case          sqlite.CaseSummary
	Tasks         []scheduledTaskView
	Query         string
	StateFilter   string
	TriggerFilter string
	RunAsFilter   string
	TimeFilter    string
	SortKey       string
	TotalCount    int
	FilteredCount int
	HasQuery      bool
	States        []string
	Triggers      []string
	RunAsUsers    []string
}

type persistenceItemView struct {
	RecordIndex   int
	ArtifactKey   string
	Source        string
	Name          string
	Command       string
	RegistryPath  string
	FilePath      string
	LastWriteTime string
	Type          string
	ReviewHint    string
	CommandIsPath bool
	UserWritable  bool
}

type persistencePageView struct {
	Case          sqlite.CaseSummary
	Items         []persistenceItemView
	Query         string
	SourceFilter  string
	TotalCount    int
	FilteredCount int
	HasQuery      bool
	Sources       []string
}

type logEventView struct {
	Timestamp      string
	EventID        string
	Source         string
	Channel        string
	Level          string
	Summary        string
	User           string
	RawJSON        string
	CollectionHint string
	NearCollection bool
}

type logPageView struct {
	Case              sqlite.CaseSummary
	ArtifactKey       string
	Title             string
	Events            []logEventView
	TotalCount        int
	FilteredCount     int
	PageSize          int
	Offset            int
	NextOffset        int
	PrevOffset        int
	HasNext           bool
	HasPrev           bool
	CurrentStart      int
	CurrentEnd        int
	LevelFilter       string
	EventIDFilter     string
	SourceQuery       string
	AvailableLevels   []string
	AvailableEventIDs []string
	PathSource        string
	HasFilters        bool
	CollectionNote    string
}

type systemLogLinkView struct {
	Title           string
	URL             string
	Hint            string
	RecordCount     int
	RequestedLimit  string
	SourceCommand   string
	CollectorStatus string
}

type systemLogsPageView struct {
	Case           sqlite.CaseSummary
	Logs           []systemLogLinkView
	CollectionNote string
}

type artifactPageView struct {
	Case         sqlite.CaseSummary
	ArtifactKey  string
	Records      []sqlite.NormalizedRecord
	TotalCount   int
	PageSize     int
	Offset       int
	NextOffset   int
	PrevOffset   int
	HasNext      bool
	HasPrev      bool
	CurrentStart int
	CurrentEnd   int
}

type sourceArtifactPageView struct {
	Case               sqlite.CaseSummary
	ArtifactKey        string
	SourcePath         string
	SourceRelativePath string
	Content            string
	Truncated          bool
}

type networkConnectionView struct {
	Protocol      string
	LocalIP       string
	LocalPort     string
	LocalService  string
	RemoteIP      string
	RemotePort    string
	RemoteService string
	State         string
	StateBucket   string
	PID           string
	ProcessName   string
	RemoteScope   string
	LoopbackOnly  bool
}

type networkPageView struct {
	Case            sqlite.CaseSummary
	Connections     []networkConnectionView
	Query           string
	StatePivot      string
	ProtocolFilter  string
	IPFocus         string
	RemoteFilter    string
	PortFocus       string
	ExternalOnly    bool
	SortKey         string
	TotalCount      int
	FilteredCount   int
	AvailableStates []string
	HasQuery        bool
}

type networkConfigAdapterView struct {
	Name           string
	Description    string
	IPv4           string
	AutoIPv4       string
	IPv6LinkLocal  string
	SubnetMask     string
	Gateway        string
	DNSServers     string
	DHCPEnabled    string
	DHCPServer     string
	LeaseObtained  string
	LeaseExpires   string
	MACAddress     string
	NetBIOS        string
	AdapterContext string
	PrimaryRouted  string
	ReviewHint     string
}

type networkConfigPageView struct {
	Case                sqlite.CaseSummary
	HostName            string
	PrimaryDNSSuffix    string
	DNSSuffixSearchList string
	NodeType            string
	IPRoutingEnabled    string
	WINSProxyEnabled    string
	Adapters            []networkConfigAdapterView
	RawJSON             string
	SourcePath          string
	OutputPath          string
}

func showHostContext(store *sqlite.Store, w http.ResponseWriter, r *http.Request, caseUUID string) {
	caseSummary, found, err := findCase(store, r.Context(), caseUUID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	artifactSets, err := store.ListArtifactSets(r.Context(), caseUUID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	hostArtifact, ok := artifactSetByKey(artifactSets, "host_identity")
	if !ok {
		http.Error(w, "host context artifact not found", http.StatusNotFound)
		return
	}
	records, err := store.ListNormalizedRecords(r.Context(), caseUUID, "host_identity", 1)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(records) == 0 {
		http.Error(w, "host context record not found", http.StatusNotFound)
		return
	}
	var host map[string]any
	if err := json.Unmarshal([]byte(records[0].RawJSON), &host); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	view := hostContextView{
		Case:             caseSummary,
		Hostname:         stringValue(host, "hostname"),
		OSVersion:        stringValue(host, "os_version"),
		Architecture:     stringValue(host, "architecture"),
		Username:         stringValue(host, "username"),
		Domain:           stringValue(host, "domain"),
		Timezone:         stringValue(host, "timezone"),
		CollectionTime:   firstNonEmpty(stringValue(host, "collected_at"), caseSummary.CollectedAt),
		LastBootTime:     firstNonEmpty(bootTimeSummary(host), "Not collected in current baseline"),
		Uptime:           firstNonEmpty(stringValue(host, "uptime_human"), uptimeSummary(host), "Not collected in current baseline"),
		SourcePath:       hostArtifact.SourcePath,
		OutputPath:       hostArtifact.OutputPath,
		RawJSON:          prettyJSON(records[0].RawJSON),
		PatchPostureNote: "Placeholder only — patch posture estimation not implemented yet.",
	}
	view.OSName, view.OSBuild = splitOSVersionParts(view.OSVersion)
	if networkArtifact, ok := artifactSetByKey(artifactSets, "network_ipconfig"); ok {
		view.HasNetworkSummary = true
		view.OutputPath = hostArtifact.OutputPath
		if networkRecords, err := store.ListNormalizedRecords(r.Context(), caseUUID, "network_ipconfig", 1); err == nil && len(networkRecords) > 0 {
			applyNetworkSummary(&view, networkRecords[0].RawJSON)
		}
		_ = networkArtifact
	}
	applySecuritySummary(store, r, caseUUID, &view, artifactSets)
	applySoftwareSummary(store, r, caseUUID, &view, artifactSets)
	applyDeviceSummary(store, r, caseUUID, &view, artifactSets)
	applyWirelessSummary(store, r, caseUUID, &view, artifactSets)
	renderTemplate(w, hostContextTemplate, view)
}

func showProcesses(store *sqlite.Store, w http.ResponseWriter, r *http.Request, caseUUID string) {
	caseSummary, found, err := findCase(store, r.Context(), caseUUID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	records, err := store.ListNormalizedRecords(r.Context(), caseUUID, "processes", 5000)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	userFilter := strings.TrimSpace(r.URL.Query().Get("user"))
	sessionFilter := strings.TrimSpace(r.URL.Query().Get("session"))
	statusFilter := strings.TrimSpace(r.URL.Query().Get("status"))
	sortKey := strings.TrimSpace(r.URL.Query().Get("sort"))
	pidFocus := strings.TrimSpace(r.URL.Query().Get("pid"))
	if sortKey == "" {
		sortKey = "image"
	}
	processes := make([]processRecordView, 0, len(records))
	userSet := map[string]struct{}{}
	sessionSet := map[string]struct{}{}
	statusSet := map[string]struct{}{}
	for _, record := range records {
		var item map[string]any
		if err := json.Unmarshal([]byte(record.RawJSON), &item); err != nil {
			continue
		}
		process := buildProcessRecordView(item)
		if process.UserName != "" && process.UserName != "N/A" {
			userSet[process.UserName] = struct{}{}
		}
		if process.SessionName != "" {
			sessionSet[process.SessionName] = struct{}{}
		}
		if process.Status != "" {
			statusSet[process.Status] = struct{}{}
		}
		processes = append(processes, process)
	}
	totalCount := len(processes)
	filtered := filterProcesses(processes, query, userFilter, sessionFilter, statusFilter, pidFocus)
	sortProcesses(filtered, sortKey)
	view := processListView{
		Case:           caseSummary,
		Processes:      filtered,
		Query:          query,
		UserFilter:     userFilter,
		SessionFilter:  sessionFilter,
		StatusFilter:   statusFilter,
		SortKey:        sortKey,
		TotalCount:     totalCount,
		FilteredCount:  len(filtered),
		UniqueUsers:    sortedKeys(userSet),
		UniqueSessions: sortedKeys(sessionSet),
		UniqueStatuses: sortedKeys(statusSet),
		HasQuery:       query != "" || userFilter != "" || sessionFilter != "" || statusFilter != "" || pidFocus != "",
		PIDFocus:       pidFocus,
	}
	renderTemplate(w, processesTemplate, view)
}

func showScheduledTasks(store *sqlite.Store, w http.ResponseWriter, r *http.Request, caseUUID string) {
	caseSummary, found, err := findCase(store, r.Context(), caseUUID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	records, err := store.ListNormalizedRecords(r.Context(), caseUUID, "scheduled_tasks", 5000)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	stateFilter := strings.TrimSpace(r.URL.Query().Get("state"))
	triggerFilter := strings.TrimSpace(r.URL.Query().Get("trigger"))
	runAsFilter := strings.TrimSpace(r.URL.Query().Get("run_as"))
	timeFilter := strings.TrimSpace(r.URL.Query().Get("time"))
	sortKey := strings.TrimSpace(r.URL.Query().Get("sort"))
	stateSet := map[string]struct{}{}
	triggerSet := map[string]struct{}{}
	runAsSet := map[string]struct{}{}
	tasks := make([]scheduledTaskView, 0, len(records))
	for _, record := range records {
		var item map[string]any
		if err := json.Unmarshal([]byte(record.RawJSON), &item); err != nil {
			continue
		}
		task, ok := buildScheduledTaskView(item)
		if !ok {
			continue
		}
		task.RecordIndex = record.RecordIndex
		if task.State != "" {
			stateSet[task.State] = struct{}{}
		}
		if task.Trigger != "" {
			triggerSet[task.Trigger] = struct{}{}
		}
		if task.RunAsUser != "" {
			runAsSet[task.RunAsUser] = struct{}{}
		}
		tasks = append(tasks, task)
	}
	totalCount := len(tasks)
	filtered := filterScheduledTasks(tasks, query, stateFilter, triggerFilter, runAsFilter, timeFilter)
	sortScheduledTasks(filtered, sortKey)
	view := scheduledTasksPageView{
		Case:          caseSummary,
		Tasks:         filtered,
		Query:         query,
		StateFilter:   stateFilter,
		TriggerFilter: triggerFilter,
		RunAsFilter:   runAsFilter,
		TimeFilter:    timeFilter,
		SortKey:       sortKey,
		TotalCount:    totalCount,
		FilteredCount: len(filtered),
		HasQuery:      query != "" || stateFilter != "" || triggerFilter != "" || runAsFilter != "" || timeFilter != "" || sortKey != "",
		States:        sortedKeys(stateSet),
		Triggers:      sortedKeys(triggerSet),
		RunAsUsers:    sortedKeys(runAsSet),
	}
	renderTemplate(w, scheduledTasksTemplate, view)
}

func showPersistence(store *sqlite.Store, w http.ResponseWriter, r *http.Request, caseUUID string) {
	caseSummary, found, err := findCase(store, r.Context(), caseUUID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	sourceFilter := strings.TrimSpace(r.URL.Query().Get("source"))
	items := []persistenceItemView{}
	sourceSet := map[string]struct{}{}
	for _, spec := range []struct{ key, label string }{
		{"persistence_hkcu_run", "HKCU Run"},
		{"persistence_hkcu_runonce", "HKCU RunOnce"},
		{"persistence_startup_folder", "Startup Folder"},
	} {
		records, err := store.ListNormalizedRecords(r.Context(), caseUUID, spec.key, 5000)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, record := range records {
			var raw map[string]any
			if err := json.Unmarshal([]byte(record.RawJSON), &raw); err != nil {
				continue
			}
			item := buildPersistenceItemView(record.RecordIndex, spec.key, spec.label, raw)
			sourceSet[item.Source] = struct{}{}
			items = append(items, item)
		}
	}
	totalCount := len(items)
	filtered := filterPersistenceItems(items, query, sourceFilter)
	view := persistencePageView{
		Case:          caseSummary,
		Items:         filtered,
		Query:         query,
		SourceFilter:  sourceFilter,
		TotalCount:    totalCount,
		FilteredCount: len(filtered),
		HasQuery:      query != "" || sourceFilter != "",
		Sources:       sortedKeys(sourceSet),
	}
	renderTemplate(w, persistenceTemplate, view)
}

func buildPersistenceItemView(recordIndex int, artifactKey, source string, raw map[string]any) persistenceItemView {
	command := firstNonEmpty(stringValue(raw, "value"), stringValue(raw, "fullname"), stringValue(raw, "full_name"))
	lower := strings.ToLower(command)
	item := persistenceItemView{
		RecordIndex:   recordIndex,
		ArtifactKey:   artifactKey,
		Source:        source,
		Name:          firstNonEmpty(stringValue(raw, "name"), stringValue(raw, "Name")),
		Command:       command,
		RegistryPath:  stringValue(raw, "registry_path"),
		FilePath:      firstNonEmpty(stringValue(raw, "fullname"), stringValue(raw, "full_name")),
		LastWriteTime: firstNonEmpty(stringValue(raw, "lastwritetime"), stringValue(raw, "last_write_time")),
		Type:          firstNonEmpty(stringValue(raw, "type"), stringValue(raw, "mode")),
		CommandIsPath: strings.Contains(command, `:\`) || strings.Contains(command, "%localappdata%"),
		UserWritable:  strings.Contains(lower, `\users\`) || strings.Contains(lower, `\appdata\`) || strings.Contains(lower, `%localappdata%`),
	}
	item.ReviewHint = persistenceReviewHint(item)
	return item
}

func persistenceReviewHint(item persistenceItemView) string {
	lower := strings.ToLower(item.Command)
	if strings.EqualFold(item.Name, "desktop.ini") {
		return "Default/system startup-folder metadata; usually low signal."
	}
	if item.UserWritable {
		return "Launches from a user-writable path — review for persistence abuse or updater noise."
	}
	if strings.Contains(lower, "cmd.exe") || strings.Contains(lower, "powershell") || strings.Contains(lower, "wscript") || strings.Contains(lower, "rundll32") {
		return "Uses a command/script host — review command arguments closely."
	}
	return "Review whether this startup mechanism is expected for the user and host role."
}

func filterPersistenceItems(items []persistenceItemView, query, sourceFilter string) []persistenceItemView {
	query = strings.ToLower(strings.TrimSpace(query))
	var filtered []persistenceItemView
	for _, item := range items {
		if sourceFilter != "" && item.Source != sourceFilter {
			continue
		}
		if query != "" {
			haystack := strings.ToLower(strings.Join([]string{item.Source, item.Name, item.Command, item.RegistryPath, item.FilePath, item.LastWriteTime, item.Type, item.ReviewHint}, " "))
			if !strings.Contains(haystack, query) {
				continue
			}
		}
		filtered = append(filtered, item)
	}
	return filtered
}

func showLogView(store *sqlite.Store, w http.ResponseWriter, r *http.Request, caseUUID, routeKey string) {
	artifactKey := strings.Replace(routeKey, "logs-", "logs_", 1)
	caseSummary, found, err := findCase(store, r.Context(), caseUUID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	pageSize := 100
	offset := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 0 {
			offset = parsed
		}
	}
	levelFilter := strings.TrimSpace(r.URL.Query().Get("level"))
	eventIDFilter := strings.TrimSpace(r.URL.Query().Get("event_id"))
	sourceQuery := strings.TrimSpace(r.URL.Query().Get("source"))
	totalCount, err := store.CountNormalizedRecords(r.Context(), caseUUID, artifactKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	records, err := store.ListNormalizedRecords(r.Context(), caseUUID, artifactKey, 10000)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	artifactSets, err := store.ListArtifactSets(r.Context(), caseUUID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	artifact, _ := artifactSetByKey(artifactSets, artifactKey)
	levels := map[string]struct{}{}
	eventIDs := map[string]struct{}{}
	filteredEvents := make([]logEventView, 0, len(records))
	for _, record := range records {
		var item map[string]any
		if err := json.Unmarshal([]byte(record.RawJSON), &item); err != nil {
			continue
		}
		event := buildLogEventView(item)
		applyCollectionNoiseHint(&event, caseSummary.CollectedAt)
		if event.Level != "" {
			levels[event.Level] = struct{}{}
		}
		if event.EventID != "" {
			eventIDs[event.EventID] = struct{}{}
		}
		if levelFilter != "" && event.Level != levelFilter {
			continue
		}
		if eventIDFilter != "" && event.EventID != eventIDFilter {
			continue
		}
		if sourceQuery != "" {
			haystack := strings.ToLower(event.Source + " " + event.Channel + " " + event.Summary + " " + event.EventID + " " + event.User)
			if !strings.Contains(haystack, strings.ToLower(sourceQuery)) {
				continue
			}
		}
		filteredEvents = append(filteredEvents, event)
	}
	filteredCount := len(filteredEvents)
	if offset > filteredCount {
		offset = 0
	}
	end := offset + pageSize
	if end > filteredCount {
		end = filteredCount
	}
	events := []logEventView{}
	if offset < end {
		events = filteredEvents[offset:end]
	}
	currentStart := 0
	currentEnd := 0
	if filteredCount > 0 {
		currentStart = offset + 1
		currentEnd = end
	}
	view := logPageView{
		Case:              caseSummary,
		ArtifactKey:       artifactKey,
		Title:             logTitleForArtifact(artifactKey),
		Events:            events,
		TotalCount:        totalCount,
		FilteredCount:     filteredCount,
		PageSize:          pageSize,
		Offset:            offset,
		NextOffset:        offset + pageSize,
		PrevOffset:        maxInt(offset-pageSize, 0),
		HasNext:           offset+pageSize < filteredCount,
		HasPrev:           offset > 0,
		CurrentStart:      currentStart,
		CurrentEnd:        currentEnd,
		LevelFilter:       levelFilter,
		EventIDFilter:     eventIDFilter,
		SourceQuery:       sourceQuery,
		AvailableLevels:   sortedKeys(levels),
		AvailableEventIDs: sortedKeys(eventIDs),
		PathSource:        artifact.SourcePath,
		HasFilters:        levelFilter != "" || eventIDFilter != "" || sourceQuery != "",
		CollectionNote:    logCollectionScopeNote(),
	}
	renderTemplate(w, logTemplate, view)
}

func showSystemLogs(store *sqlite.Store, w http.ResponseWriter, r *http.Request, caseUUID string) {
	caseSummary, found, err := findCase(store, r.Context(), caseUUID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	items := []struct{ key, route, title, hint string }{
		{"logs_application", "logs-application", "Application Log", "Application crashes, installer errors, service/app failures, and other app-level clues."},
		{"logs_system", "logs-system", "System Log", "Boot, service, driver, device, network, and OS-level events useful for timeline context."},
		{"logs_powershell", "logs-powershell", "PowerShell Operational Log", "Script block, module, and PowerShell execution activity. Start here for Event ID 4104 pivots."},
		{"logs_defender", "logs-defender", "Defender Operational Log", "Microsoft Defender detections, remediation, exclusions, scan events, and security-tool posture clues."},
	}
	manifestArtifacts := readManifestArtifacts(caseSummary.RawCasePath)
	logs := make([]systemLogLinkView, 0, len(items))
	for _, item := range items {
		count, _ := store.CountNormalizedRecords(r.Context(), caseUUID, item.key)
		manifest := manifestArtifacts[strings.ReplaceAll(item.key, "_", "-")]
		logs = append(logs, systemLogLinkView{Title: item.title, URL: "/cases/" + url.PathEscape(caseUUID) + "/" + item.route, Hint: item.hint, RecordCount: count, RequestedLimit: requestedEventLimit(manifest.SourceCommand), SourceCommand: manifest.SourceCommand, CollectorStatus: manifest.CollectorStatus})
	}
	renderTemplate(w, systemLogsTemplate, systemLogsPageView{Case: caseSummary, Logs: logs, CollectionNote: logCollectionScopeNote()})
}

type manifestArtifactInfo struct {
	ArtifactID      string `json:"artifact_id"`
	SourceCommand   string `json:"source_command"`
	CollectorStatus string `json:"collector_status"`
}

func readManifestArtifacts(rawCasePath string) map[string]manifestArtifactInfo {
	items := map[string]manifestArtifactInfo{}
	content, err := os.ReadFile(filepath.Join(rawCasePath, "manifest.json"))
	if err != nil {
		return items
	}
	var manifest struct {
		Artifacts []manifestArtifactInfo `json:"artifacts"`
	}
	if err := json.Unmarshal(content, &manifest); err != nil {
		return items
	}
	for _, artifact := range manifest.Artifacts {
		items[artifact.ArtifactID] = artifact
	}
	return items
}

func requestedEventLimit(sourceCommand string) string {
	for _, field := range strings.Fields(sourceCommand) {
		if strings.HasPrefix(strings.ToLower(field), "/c:") {
			return strings.TrimPrefix(field, "/c:")
		}
	}
	return ""
}

func logCollectionScopeNote() string {
	return "Log counts are collected-record counts from the SEKER bundle, not the endpoint's full historical Event Log size. Current SEKER builds collect a recent bounded slice per log source; older bundles may contain only the most recent 100 events."
}

func showNetworkView(store *sqlite.Store, w http.ResponseWriter, r *http.Request, caseUUID string) {
	caseSummary, found, err := findCase(store, r.Context(), caseUUID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	connRecords, err := store.ListNormalizedRecords(r.Context(), caseUUID, "network_connections", 5000)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	procRecords, err := store.ListNormalizedRecords(r.Context(), caseUUID, "processes", 5000)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	processByPID := map[string]string{}
	for _, record := range procRecords {
		var item map[string]any
		if err := json.Unmarshal([]byte(record.RawJSON), &item); err != nil {
			continue
		}
		pid := zeroBlank(int(numberValue(item, "pid")))
		if pid == "" {
			continue
		}
		processByPID[pid] = stringValue(item, "image_name")
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	statePivot := strings.TrimSpace(r.URL.Query().Get("state"))
	protocolFilter := strings.TrimSpace(r.URL.Query().Get("protocol"))
	ipFocus := strings.TrimSpace(r.URL.Query().Get("ip"))
	remoteFilter := strings.TrimSpace(r.URL.Query().Get("remote"))
	portFocus := strings.TrimSpace(r.URL.Query().Get("port"))
	externalOnly := r.URL.Query().Get("external") == "1"
	sortKey := strings.TrimSpace(r.URL.Query().Get("sort"))
	states := map[string]struct{}{}
	connections := make([]networkConnectionView, 0, len(connRecords))
	for _, record := range connRecords {
		var item map[string]any
		if err := json.Unmarshal([]byte(record.RawJSON), &item); err != nil {
			continue
		}
		conn := buildNetworkConnectionView(item, processByPID)
		states[conn.StateBucket] = struct{}{}
		connections = append(connections, conn)
	}
	totalCount := len(connections)
	filtered := filterNetworkConnections(connections, query, statePivot, protocolFilter, ipFocus, remoteFilter, portFocus, externalOnly)
	sortNetworkConnections(filtered, sortKey)
	view := networkPageView{
		Case:            caseSummary,
		Connections:     filtered,
		Query:           query,
		StatePivot:      statePivot,
		ProtocolFilter:  protocolFilter,
		IPFocus:         ipFocus,
		RemoteFilter:    remoteFilter,
		PortFocus:       portFocus,
		ExternalOnly:    externalOnly,
		SortKey:         sortKey,
		TotalCount:      totalCount,
		FilteredCount:   len(filtered),
		AvailableStates: sortedKeys(states),
		HasQuery:        query != "" || statePivot != "" || protocolFilter != "" || ipFocus != "" || remoteFilter != "" || portFocus != "" || externalOnly || sortKey != "",
	}
	renderTemplate(w, networkTemplate, view)
}

func showNetworkConfig(store *sqlite.Store, w http.ResponseWriter, r *http.Request, caseUUID string) {
	caseSummary, found, err := findCase(store, r.Context(), caseUUID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	artifactSets, err := store.ListArtifactSets(r.Context(), caseUUID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	artifact, ok := artifactSetByKey(artifactSets, "network_ipconfig")
	if !ok {
		http.Error(w, "network config artifact not found", http.StatusNotFound)
		return
	}
	records, err := store.ListNormalizedRecords(r.Context(), caseUUID, "network_ipconfig", 1)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(records) == 0 {
		http.Error(w, "network config record not found", http.StatusNotFound)
		return
	}
	view, err := buildNetworkConfigPageView(caseSummary, artifact, records[0].RawJSON)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	renderTemplate(w, networkConfigTemplate, view)
}

func buildNetworkConfigPageView(caseSummary sqlite.CaseSummary, artifact sqlite.ArtifactSetSummary, raw string) (networkConfigPageView, error) {
	var payload struct {
		Global   map[string]any `json:"global"`
		Adapters []struct {
			Name   string         `json:"name"`
			Fields map[string]any `json:"fields"`
		} `json:"adapters"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return networkConfigPageView{}, err
	}
	view := networkConfigPageView{
		Case:                caseSummary,
		HostName:            stringFromAny(payload.Global["host_name"]),
		PrimaryDNSSuffix:    stringFromAny(payload.Global["primary_dns_suffix"]),
		DNSSuffixSearchList: stringFromAny(payload.Global["dns_suffix_search_list"]),
		NodeType:            stringFromAny(payload.Global["node_type"]),
		IPRoutingEnabled:    stringFromAny(payload.Global["ip_routing_enabled"]),
		WINSProxyEnabled:    stringFromAny(payload.Global["wins_proxy_enabled"]),
		RawJSON:             prettyJSON(raw),
		SourcePath:          artifact.SourcePath,
		OutputPath:          artifact.OutputPath,
	}
	for _, adapter := range payload.Adapters {
		fields := adapter.Fields
		item := networkConfigAdapterView{
			Name:           adapter.Name,
			Description:    stringFromAny(fields["description"]),
			IPv4:           cleanPreferred(stringFromAny(fields["ipv4_address"])),
			AutoIPv4:       cleanPreferred(stringFromAny(fields["autoconfiguration_ipv4_address"])),
			IPv6LinkLocal:  cleanPreferred(stringFromAny(fields["link_local_ipv6_address"])),
			SubnetMask:     stringFromAny(fields["subnet_mask"]),
			Gateway:        stringFromAny(fields["default_gateway"]),
			DNSServers:     stringFromAny(fields["dns_servers"]),
			DHCPEnabled:    stringFromAny(fields["dhcp_enabled"]),
			DHCPServer:     stringFromAny(fields["dhcp_server"]),
			LeaseObtained:  stringFromAny(fields["lease_obtained"]),
			LeaseExpires:   stringFromAny(fields["lease_expires"]),
			MACAddress:     stringFromAny(fields["physical_address"]),
			NetBIOS:        stringFromAny(fields["netbios_over_tcpip"]),
			AdapterContext: stringFromAny(fields["adapter_context"]),
			PrimaryRouted:  stringFromAny(fields["likely_primary_routed"]),
		}
		item.ReviewHint = networkConfigReviewHint(item)
		view.Adapters = append(view.Adapters, item)
	}
	return view, nil
}

func networkConfigReviewHint(item networkConfigAdapterView) string {
	lowerName := strings.ToLower(item.Name + " " + item.Description)
	if item.AdapterContext != "" {
		return item.AdapterContext + " — treat as context unless routes/connections show external use."
	}
	if strings.EqualFold(item.PrimaryRouted, "true") || item.Gateway != "" {
		return "Likely primary routed adapter — compare with active network connections."
	}
	if item.AutoIPv4 != "" || strings.HasPrefix(item.IPv4, "169.254.") {
		return "Autoconfiguration/link-local address — usually disconnected, isolated, or virtual adapter context."
	}
	if strings.Contains(lowerName, "loopback") || strings.Contains(lowerName, "npcap") {
		return "Loopback/capture adapter — useful context but usually not an external route."
	}
	return "No default gateway captured — likely secondary, virtual, or disconnected adapter."
}

func showArtifact(store *sqlite.Store, w http.ResponseWriter, r *http.Request, caseUUID, artifactKey string) {
	caseSummary, found, err := findCase(store, r.Context(), caseUUID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	pageSize := 100
	offset := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 0 {
			offset = parsed
		}
	}
	totalCount, err := store.CountNormalizedRecords(r.Context(), caseUUID, artifactKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	records, err := store.ListNormalizedRecordsPage(r.Context(), caseUUID, artifactKey, pageSize, offset)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	currentStart := 0
	currentEnd := 0
	if totalCount > 0 {
		currentStart = offset + 1
		currentEnd = offset + len(records)
	}
	renderTemplate(w, artifactTemplate, artifactPageView{Case: caseSummary, ArtifactKey: artifactKey, Records: records, TotalCount: totalCount, PageSize: pageSize, Offset: offset, NextOffset: offset + pageSize, PrevOffset: maxInt(offset-pageSize, 0), HasNext: offset+pageSize < totalCount, HasPrev: offset > 0, CurrentStart: currentStart, CurrentEnd: currentEnd})
}

func showSourceArtifact(store *sqlite.Store, w http.ResponseWriter, r *http.Request, caseUUID, artifactKey string) {
	caseSummary, found, err := findCase(store, r.Context(), caseUUID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	artifactSets, err := store.ListArtifactSets(r.Context(), caseUUID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	artifact, ok := artifactSetByKey(artifactSets, artifactKey)
	if !ok {
		http.NotFound(w, r)
		return
	}
	content, err := os.ReadFile(artifact.SourcePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	truncated := false
	const maxSourceBytes = 256 * 1024
	if len(content) > maxSourceBytes {
		content = content[:maxSourceBytes]
		truncated = true
	}
	renderTemplate(w, sourceArtifactTemplate, sourceArtifactPageView{Case: caseSummary, ArtifactKey: artifactKey, SourcePath: artifact.SourcePath, SourceRelativePath: collectedSourceRelativePath(artifact.SourcePath), Content: string(content), Truncated: truncated})
}

func findCase(store *sqlite.Store, ctx context.Context, caseUUID string) (sqlite.CaseSummary, bool, error) {
	items, err := store.ListCaseSummaries(ctx)
	if err != nil {
		return sqlite.CaseSummary{}, false, err
	}
	for _, item := range items {
		if item.CaseUUID == caseUUID {
			return item, true, nil
		}
	}
	return sqlite.CaseSummary{}, false, nil
}

func renderTemplate(w http.ResponseWriter, tpl string, data any) {
	t := template.Must(template.New("page").Funcs(template.FuncMap{
		"replace": strings.ReplaceAll,
	}).Parse(tpl))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	if err := t.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func artifactSetByKey(items []sqlite.ArtifactSetSummary, key string) (sqlite.ArtifactSetSummary, bool) {
	for _, item := range items {
		if item.ArtifactKey == key {
			return item, true
		}
	}
	return sqlite.ArtifactSetSummary{}, false
}

func stringValue(item map[string]any, key string) string {
	value, ok := item[key]
	if !ok || value == nil {
		return ""
	}
	if typed, ok := value.(string); ok {
		return typed
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func bootTimeSummary(host map[string]any) string {
	bootTime := stringValue(host, "boot_time")
	if strings.TrimSpace(bootTime) == "" {
		return ""
	}
	parts := []string{bootTime}
	metadata := []string{}
	if source := stringValue(host, "boot_time_source"); source != "" {
		metadata = append(metadata, "source: "+source)
	}
	if confidence := stringValue(host, "boot_time_confidence"); confidence != "" {
		metadata = append(metadata, "confidence: "+confidence)
	}
	if len(metadata) > 0 {
		parts = append(parts, "("+strings.Join(metadata, "; ")+")")
	}
	return strings.Join(parts, " ")
}

func uptimeSummary(host map[string]any) string {
	seconds := int64(numberValue(host, "uptime_seconds"))
	if seconds <= 0 {
		return ""
	}
	days := seconds / 86400
	hours := (seconds % 86400) / 3600
	minutes := (seconds % 3600) / 60
	if days > 0 {
		return fmt.Sprintf("%dd %02dh %02dm", days, hours, minutes)
	}
	return fmt.Sprintf("%02dh %02dm", hours, minutes)
}

func splitOSVersionParts(value string) (string, string) {
	if value == "" {
		return "", ""
	}
	buildIndex := strings.Index(strings.ToLower(value), "build ")
	if buildIndex == -1 {
		return value, ""
	}
	return strings.TrimSpace(value[:buildIndex]), strings.TrimSpace(value[buildIndex:])
}

func prettyJSON(raw string) string {
	var payload any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return raw
	}
	formatted, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return raw
	}
	return string(formatted)
}

func applyNetworkSummary(view *hostContextView, raw string) {
	var payload struct {
		Adapters []struct {
			Fields map[string]any `json:"fields"`
		} `json:"adapters"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return
	}
	view.AdapterCount = len(payload.Adapters)
	for _, adapter := range payload.Adapters {
		if view.PrimaryIPv4 == "" {
			view.PrimaryIPv4 = cleanPreferred(stringFromAny(adapter.Fields["ipv4_address"]))
		}
		if view.DefaultGateway == "" {
			view.DefaultGateway = stringFromAny(adapter.Fields["default_gateway"])
		}
		if view.DNSServers == "" {
			view.DNSServers = stringFromAny(adapter.Fields["dns_servers"])
		}
	}
}

func applySecuritySummary(store *sqlite.Store, r *http.Request, caseUUID string, view *hostContextView, artifactSets []sqlite.ArtifactSetSummary) {
	if _, ok := artifactSetByKey(artifactSets, "security_firewall"); ok {
		if records, err := store.ListNormalizedRecords(r.Context(), caseUUID, "security_firewall", 1); err == nil && len(records) > 0 {
			view.FirewallSummary = firewallSummary(records[0].RawJSON)
			view.HasSecuritySummary = true
		}
	}
	if _, ok := artifactSetByKey(artifactSets, "security_defender"); ok {
		if records, err := store.ListNormalizedRecords(r.Context(), caseUUID, "security_defender", 1); err == nil && len(records) > 0 {
			view.DefenderSummary = defenderSummary(records[0].RawJSON)
			view.HasSecuritySummary = true
		}
	}
	if _, ok := artifactSetByKey(artifactSets, "security_products"); ok {
		if records, err := store.ListNormalizedRecords(r.Context(), caseUUID, "security_products", 1); err == nil && len(records) > 0 {
			view.SecurityToolsSummary = securityToolsSummary(records[0].RawJSON)
			view.HasSecuritySummary = true
		}
	}
}

func firewallSummary(raw string) string {
	var payload struct {
		Confidence string              `json:"confidence"`
		Profiles   []map[string]string `json:"profiles"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return "Collected; parse unavailable"
	}
	parts := []string{}
	for _, profile := range payload.Profiles {
		name := firstNonEmpty(profile["profile"], "profile")
		state := firstNonEmpty(profile["state"], profile["firewall_policy"], "unknown")
		parts = append(parts, name+": "+state)
	}
	if len(parts) == 0 {
		parts = append(parts, "No profile rows parsed")
	}
	if payload.Confidence != "" {
		parts = append(parts, "confidence: "+payload.Confidence)
	}
	return strings.Join(parts, " | ")
}

func defenderSummary(raw string) string {
	var payload struct {
		Confidence             string         `json:"confidence"`
		Status                 string         `json:"status"`
		Fields                 map[string]any `json:"fields"`
		WinDefendServiceStatus string         `json:"win_defend_service_status"`
		Error                  string         `json:"error"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return "Collected; parse unavailable"
	}
	parts := []string{}
	for _, key := range []string{"AntivirusEnabled", "RealTimeProtectionEnabled", "BehaviorMonitorEnabled", "IoavProtectionEnabled", "AntivirusSignatureVersion", "AntivirusSignatureLastUpdated"} {
		if value, ok := payload.Fields[key]; ok && value != nil {
			parts = append(parts, key+": "+stringFromAny(value))
		}
	}
	if len(parts) == 0 && payload.Error != "" {
		parts = append(parts, "Get-MpComputerStatus unavailable")
	}
	if payload.Status != "" {
		parts = append(parts, "status: "+payload.Status)
	}
	if payload.Confidence != "" {
		parts = append(parts, "confidence: "+payload.Confidence)
	}
	if payload.WinDefendServiceStatus != "" {
		parts = append(parts, "WinDefend service captured")
	}
	return strings.Join(parts, " | ")
}

func securityToolsSummary(raw string) string {
	var payload struct {
		Confidence string `json:"confidence"`
		Tools      []struct {
			Name string `json:"name"`
			Kind string `json:"kind"`
		} `json:"tools"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return "Collected; parse unavailable"
	}
	if len(payload.Tools) == 0 {
		return "No keyword security-tool hints found (confidence: " + firstNonEmpty(payload.Confidence, "low") + ")"
	}
	parts := make([]string, 0, len(payload.Tools))
	for _, tool := range payload.Tools {
		parts = append(parts, tool.Name+" ("+tool.Kind+")")
	}
	return strings.Join(parts, ", ") + " | confidence: " + firstNonEmpty(payload.Confidence, "low")
}

func applySoftwareSummary(store *sqlite.Store, r *http.Request, caseUUID string, view *hostContextView, artifactSets []sqlite.ArtifactSetSummary) {
	if _, ok := artifactSetByKey(artifactSets, "software_installed_programs"); !ok {
		return
	}
	count, err := store.CountNormalizedRecords(r.Context(), caseUUID, "software_installed_programs")
	if err != nil {
		return
	}
	view.HasSoftwareSummary = true
	machine := 0
	perUser := 0
	flagged := []string{}
	records, err := store.ListNormalizedRecords(r.Context(), caseUUID, "software_installed_programs", 5000)
	if err == nil {
		seenFlagged := map[string]struct{}{}
		for _, record := range records {
			var item map[string]any
			if err := json.Unmarshal([]byte(record.RawJSON), &item); err != nil {
				continue
			}
			scope := strings.ToLower(stringValue(item, "scope"))
			if strings.HasPrefix(scope, "machine") {
				machine++
			} else if strings.Contains(scope, "user") {
				perUser++
			}
			name := stringValue(item, "display_name")
			if name == "" || !softwareReviewHint(name) {
				continue
			}
			key := strings.ToLower(name)
			if _, ok := seenFlagged[key]; !ok {
				flagged = append(flagged, name)
				seenFlagged[key] = struct{}{}
			}
		}
	}
	parts := []string{fmt.Sprintf("%d installed-program entries", count), fmt.Sprintf("machine-wide: %d", machine), fmt.Sprintf("per-user: %d", perUser)}
	if len(flagged) > 0 {
		if len(flagged) > 8 {
			flagged = flagged[:8]
		}
		parts = append(parts, "review hints: "+strings.Join(flagged, ", "))
	}
	parts = append(parts, "install dates labeled per entry")
	view.SoftwareSummary = strings.Join(parts, " | ")
}

func applyDeviceSummary(store *sqlite.Store, r *http.Request, caseUUID string, view *hostContextView, artifactSets []sqlite.ArtifactSetSummary) {
	counts := []string{}
	for _, item := range []struct {
		key   string
		label string
	}{
		{"devices_volumes", "volume/removable entries"},
		{"devices_usb_current", "current USB entries"},
		{"devices_usb_previous", "previous USB evidence entries"},
		{"devices_pnp_summary", "PnP device entries"},
	} {
		if _, ok := artifactSetByKey(artifactSets, item.key); !ok {
			continue
		}
		count, err := store.CountNormalizedRecords(r.Context(), caseUUID, item.key)
		if err != nil {
			continue
		}
		counts = append(counts, fmt.Sprintf("%d %s", count, item.label))
	}
	if len(counts) == 0 {
		return
	}
	view.HasDeviceSummary = true
	view.DeviceSummary = strings.Join(counts, " | ") + " | previous USB language is source-backed context, not a complete forensic history"
}

func applyWirelessSummary(store *sqlite.Store, r *http.Request, caseUUID string, view *hostContextView, artifactSets []sqlite.ArtifactSetSummary) {
	parts := []string{}
	for _, item := range []struct {
		key   string
		label string
	}{
		{"network_wifi_interfaces", "Wi-Fi interface records"},
		{"network_wifi_profiles", "saved Wi-Fi profile names"},
		{"network_bluetooth_devices", "Bluetooth device records"},
		{"network_bluetooth_connected", "connected Bluetooth indicators"},
	} {
		if _, ok := artifactSetByKey(artifactSets, item.key); !ok {
			continue
		}
		count, err := store.CountNormalizedRecords(r.Context(), caseUUID, item.key)
		if err != nil {
			continue
		}
		parts = append(parts, fmt.Sprintf("%d %s", count, item.label))
	}
	if len(parts) == 0 {
		return
	}
	view.HasWirelessSummary = true
	view.WirelessSummary = strings.Join(parts, " | ") + " | no Wi-Fi keys/passwords collected"
}

func softwareReviewHint(name string) bool {
	lower := strings.ToLower(name)
	patterns := []string{"anydesk", "teamviewer", "screenconnect", "connectwise", "splashtop", "logmein", "gotomypc", "vnc", "ultravnc", "realvnc", "tightvnc", "rustdesk", "radmin", "remote utilities", "psexec", "sysinternals", "wireshark", "nmap", "npcap", "crowdstrike", "sentinelone", "carbon black", "cylance", "sophos", "trellix", "mcafee", "symantec", "tanium", "qualys", "rapid7", "nessus", "openvpn", "wireguard", "tailscale", "zerotier"}
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func stringFromAny(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			parts = append(parts, stringFromAny(item))
		}
		return strings.Join(parts, ", ")
	case bool:
		if typed {
			return "true"
		}
		return "false"
	case float64:
		return fmt.Sprintf("%.0f", typed)
	default:
		return fmt.Sprint(typed)
	}
}

func cleanPreferred(value string) string {
	return strings.ReplaceAll(value, "(Preferred)", "")
}

func buildProcessRecordView(item map[string]any) processRecordView {
	pid := int(numberValue(item, "pid"))
	windowTitle := normalizedNA(stringValue(item, "window_title"))
	userName := normalizedNA(stringValue(item, "user_name"))
	pathOrCommand := ""
	suspiciousHint := ""
	executablePath := normalizedNA(stringValue(item, "executable_path"))
	commandLine := normalizedNA(stringValue(item, "command_line"))
	if executablePath != "" {
		pathOrCommand = executablePath
	}
	if commandLine != "" {
		pathOrCommand = commandLine
	}
	if windowTitle != "" && strings.Contains(windowTitle, `:\`) {
		pathOrCommand = windowTitle
		suspiciousHint = "Path-like window title — review execution context"
	}
	return processRecordView{
		ImageName:         stringValue(item, "image_name"),
		PID:               pid,
		PIDText:           zeroBlank(pid),
		PPIDText:          zeroBlank(int(numberValue(item, "ppid"))),
		UserName:          userName,
		SessionName:       stringValue(item, "session_name"),
		SessionID:         zeroBlank(int(numberValue(item, "session_id"))),
		ExecutablePath:    executablePath,
		CommandLine:       commandLine,
		CPUTime:           normalizedNA(stringValue(item, "cpu_time")),
		WindowTitle:       windowTitle,
		Status:            normalizedNA(stringValue(item, "status")),
		MemUsage:          normalizedNA(stringValue(item, "mem_usage")),
		PathOrCommand:     pathOrCommand,
		SuspiciousHint:    suspiciousHint,
		LikelyInteractive: strings.EqualFold(stringValue(item, "session_name"), "Console"),
	}
}

func filterProcesses(items []processRecordView, query, userFilter, sessionFilter, statusFilter, pidFocus string) []processRecordView {
	query = strings.ToLower(strings.TrimSpace(query))
	pidFocus = strings.TrimSpace(pidFocus)
	var filtered []processRecordView
	for _, item := range items {
		if userFilter != "" && item.UserName != userFilter {
			continue
		}
		if sessionFilter != "" && item.SessionName != sessionFilter {
			continue
		}
		if statusFilter != "" && item.Status != statusFilter {
			continue
		}
		if pidFocus != "" && item.PIDText != pidFocus {
			continue
		}
		if query != "" {
			haystack := strings.ToLower(strings.Join([]string{item.ImageName, item.PIDText, item.PPIDText, item.UserName, item.SessionName, item.CPUTime, item.WindowTitle, item.Status, item.ExecutablePath, item.CommandLine, item.PathOrCommand}, " "))
			if !strings.Contains(haystack, query) {
				continue
			}
		}
		filtered = append(filtered, item)
	}
	return filtered
}

func sortProcesses(items []processRecordView, sortKey string) {
	sort.SliceStable(items, func(i, j int) bool {
		left := items[i]
		right := items[j]
		switch sortKey {
		case "pid":
			if left.PID == right.PID {
				return strings.ToLower(left.ImageName) < strings.ToLower(right.ImageName)
			}
			return left.PID < right.PID
		case "user":
			if left.UserName == right.UserName {
				return left.PID < right.PID
			}
			return strings.ToLower(left.UserName) < strings.ToLower(right.UserName)
		case "session":
			if left.SessionName == right.SessionName {
				return left.PID < right.PID
			}
			return strings.ToLower(left.SessionName) < strings.ToLower(right.SessionName)
		case "cpu":
			lc := parseCPUTime(left.CPUTime)
			rc := parseCPUTime(right.CPUTime)
			if lc == rc {
				return left.PID < right.PID
			}
			return lc > rc
		case "status":
			if left.Status == right.Status {
				return left.PID < right.PID
			}
			return strings.ToLower(left.Status) < strings.ToLower(right.Status)
		default:
			if strings.EqualFold(left.ImageName, right.ImageName) {
				return left.PID < right.PID
			}
			return strings.ToLower(left.ImageName) < strings.ToLower(right.ImageName)
		}
	})
}

func parseCPUTime(value string) int64 {
	parts := strings.Split(strings.TrimSpace(value), ":")
	if len(parts) != 3 {
		return 0
	}
	var nums [3]int64
	for i, part := range parts {
		parsed, err := strconv.ParseInt(part, 10, 64)
		if err != nil {
			return 0
		}
		nums[i] = parsed
	}
	return nums[0]*3600 + nums[1]*60 + nums[2]
}

func numberValue(item map[string]any, key string) float64 {
	value, ok := item[key]
	if !ok || value == nil {
		return 0
	}
	switch typed := value.(type) {
	case float64:
		return typed
	case int:
		return float64(typed)
	default:
		return 0
	}
}

func zeroBlank(value int) string {
	if value <= 0 {
		return ""
	}
	return fmt.Sprintf("%d", value)
}

func normalizedNA(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "N/A") {
		return ""
	}
	return value
}

func sortedKeys(set map[string]struct{}) []string {
	items := make([]string, 0, len(set))
	for key := range set {
		items = append(items, key)
	}
	sort.Strings(items)
	return items
}

func buildScheduledTaskView(item map[string]any) (scheduledTaskView, bool) {
	taskName := strings.TrimSpace(stringValue(item, "TaskName"))
	command := strings.TrimSpace(stringValue(item, "Task To Run"))
	if looksLikeScheduledTaskHeader(taskName, command) {
		return scheduledTaskView{}, false
	}
	trigger := normalizedNA(strings.TrimSpace(stringValue(item, "Schedule Type")))
	state := normalizedNA(strings.TrimSpace(stringValue(item, "Scheduled Task State")))
	runAs := normalizedNA(strings.TrimSpace(stringValue(item, "Run As User")))
	startIn := normalizedNA(strings.TrimSpace(stringValue(item, "Start In")))
	comment := normalizedNA(strings.TrimSpace(stringValue(item, "Comment")))
	suspiciousHint := scheduledTaskHint(command, runAs, trigger)
	return scheduledTaskView{
		TaskName:       taskName,
		Command:        command,
		Trigger:        trigger,
		RunAsUser:      runAs,
		State:          state,
		Status:         normalizedNA(strings.TrimSpace(stringValue(item, "Status"))),
		LastRunTime:    normalizedNA(strings.TrimSpace(stringValue(item, "Last Run Time"))),
		NextRunTime:    normalizedNA(strings.TrimSpace(stringValue(item, "Next Run Time"))),
		StartTime:      normalizedNA(strings.TrimSpace(stringValue(item, "Start Time"))),
		RepeatEvery:    normalizedNA(strings.TrimSpace(stringValue(item, "Repeat: Every"))),
		StartIn:        startIn,
		LastResult:     normalizedNA(strings.TrimSpace(stringValue(item, "Last Result"))),
		Comment:        comment,
		IsEnabled:      strings.EqualFold(state, "Enabled"),
		IsHiddenLike:   strings.Contains(strings.ToLower(taskName), "\\microsoft\\windows\\") || strings.EqualFold(runAs, "SYSTEM"),
		SuspiciousHint: suspiciousHint,
		CommandIsPath:  strings.Contains(command, `:\`) || strings.Contains(command, "%windir%") || strings.Contains(command, "%localappdata%"),
	}, true
}

func looksLikeScheduledTaskHeader(taskName, command string) bool {
	return taskName == "" || strings.EqualFold(taskName, "TaskName") || strings.EqualFold(command, "Task To Run")
}

func scheduledTaskHint(command, runAs, trigger string) string {
	lower := strings.ToLower(command)
	if strings.Contains(lower, `c:\users\`) || strings.Contains(lower, `%localappdata%`) {
		return "Runs from user-writable path — review for persistence abuse"
	}
	if strings.Contains(lower, `\\?\c:\`) {
		return "Direct device path execution — uncommon format worth checking"
	}
	if strings.EqualFold(runAs, "SYSTEM") && strings.Contains(strings.ToLower(trigger), "logon") {
		return "SYSTEM task at logon — high-value persistence context"
	}
	return ""
}

func filterScheduledTasks(items []scheduledTaskView, query, stateFilter, triggerFilter, runAsFilter, timeFilter string) []scheduledTaskView {
	query = strings.ToLower(strings.TrimSpace(query))
	timeFilter = strings.ToLower(strings.TrimSpace(timeFilter))
	var filtered []scheduledTaskView
	for _, item := range items {
		if stateFilter != "" && item.State != stateFilter {
			continue
		}
		if triggerFilter != "" && item.Trigger != triggerFilter {
			continue
		}
		if runAsFilter != "" && item.RunAsUser != runAsFilter {
			continue
		}
		if timeFilter != "" {
			timingHaystack := strings.ToLower(strings.Join([]string{item.LastRunTime, item.NextRunTime, item.StartTime}, " "))
			if !strings.Contains(timingHaystack, timeFilter) {
				continue
			}
		}
		if query != "" {
			haystack := strings.ToLower(strings.Join([]string{item.TaskName, item.Command, item.Trigger, item.RunAsUser, item.State, item.Status, item.Comment, item.StartIn, item.LastRunTime, item.NextRunTime, item.StartTime}, " "))
			if !strings.Contains(haystack, query) {
				continue
			}
		}
		filtered = append(filtered, item)
	}
	return filtered
}

func sortScheduledTasks(items []scheduledTaskView, sortKey string) {
	sort.SliceStable(items, func(i, j int) bool {
		if sortKey == "last_run" || sortKey == "next_run" || sortKey == "start_time" {
			leftTime, leftOK := parseFlexibleTaskTime(scheduledTaskSortValue(items[i], sortKey))
			rightTime, rightOK := parseFlexibleTaskTime(scheduledTaskSortValue(items[j], sortKey))
			if leftOK && rightOK {
				if leftTime.Equal(rightTime) {
					return strings.ToLower(items[i].TaskName) < strings.ToLower(items[j].TaskName)
				}
				return leftTime.After(rightTime)
			}
			if leftOK != rightOK {
				return leftOK
			}
		}
		left := scheduledTaskSortValue(items[i], sortKey)
		right := scheduledTaskSortValue(items[j], sortKey)
		if left == right {
			return strings.ToLower(items[i].TaskName) < strings.ToLower(items[j].TaskName)
		}
		return strings.ToLower(left) < strings.ToLower(right)
	})
}

func parseFlexibleTaskTime(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" || value == "—" {
		return time.Time{}, false
	}
	layouts := []string{
		"1/2/2006 3:04:05 PM",
		"1/2/2006 15:04:05",
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02T15:04:05.0000000Z",
		"2006-01-02T15:04:05.000Z07:00",
		"3:04:05 PM",
		"15:04:05",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}

func scheduledTaskSortValue(item scheduledTaskView, sortKey string) string {
	switch sortKey {
	case "last_run":
		return item.LastRunTime
	case "next_run":
		return item.NextRunTime
	case "start_time":
		return item.StartTime
	case "state":
		return item.State
	case "run_as":
		return item.RunAsUser
	default:
		return item.TaskName
	}
}

func buildLogEventView(item map[string]any) logEventView {
	summary := conciseEventSummary(normalizedNA(stringValue(item, "description")))
	if summary == "" {
		summary = firstInterestingValue(item)
	}
	return logEventView{
		Timestamp: stringValue(item, "date"),
		EventID:   stringValue(item, "event_id"),
		Source:    firstNonEmpty(stringValue(item, "source"), stringValue(item, "provider_name")),
		Channel:   firstNonEmpty(stringValue(item, "log_name"), stringValue(item, "channel")),
		Level:     stringValue(item, "level"),
		Summary:   summary,
		User:      normalizedNA(firstNonEmpty(stringValue(item, "user_name"), stringValue(item, "user"))),
		RawJSON:   prettyJSONFromMap(item),
	}
}

func applyCollectionNoiseHint(event *logEventView, collectedAt string) {
	if event.Timestamp == "" || collectedAt == "" {
		return
	}
	eventTime, ok := parseFlexibleTimestamp(event.Timestamp)
	if !ok {
		return
	}
	collectionTime, ok := parseFlexibleTimestamp(collectedAt)
	if !ok {
		return
	}
	delta := eventTime.Sub(collectionTime)
	if delta < 0 {
		delta = -delta
	}
	if delta <= 15*time.Minute || wallClockDeltaWithin(eventTime, collectionTime.In(time.Local), 15*time.Minute) {
		event.NearCollection = true
		event.CollectionHint = "Timestamp is close to the SEKER collection time. This may be collection self-noise; review it in context rather than suppressing it."
	}
}

func wallClockDeltaWithin(left, right time.Time, threshold time.Duration) bool {
	leftWall := time.Date(left.Year(), left.Month(), left.Day(), left.Hour(), left.Minute(), left.Second(), left.Nanosecond(), time.Local)
	rightWall := time.Date(right.Year(), right.Month(), right.Day(), right.Hour(), right.Minute(), right.Second(), right.Nanosecond(), time.Local)
	delta := leftWall.Sub(rightWall)
	if delta < 0 {
		delta = -delta
	}
	return delta <= threshold
}

func parseFlexibleTimestamp(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" || value == "—" {
		return time.Time{}, false
	}
	layouts := []string{
		time.RFC3339Nano,
		"2006-01-02T15:04:05.9999999Z",
		"2006-01-02T15:04:05.9999999",
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02T15:04:05",
		"1/2/2006 3:04:05 PM",
		"1/2/2006 15:04:05",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}

func conciseEventSummary(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	lines := strings.Split(value, "\n")
	var useful []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		useful = append(useful, trimmed)
		if len(useful) >= 8 {
			break
		}
	}
	if len(useful) == 0 {
		return ""
	}
	summary := strings.Join(useful, "\n")
	if len(summary) > 1200 {
		return summary[:1200] + "…"
	}
	return summary
}

func prettyJSONFromMap(item map[string]any) string {
	formatted, err := json.MarshalIndent(item, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(formatted)
}

func firstInterestingValue(item map[string]any) string {
	for key, value := range item {
		switch strings.ToLower(key) {
		case "computer", "date", "event_id", "event_ref", "keyword", "level", "log_name", "opcode", "source", "task", "user", "user_name", "description":
			continue
		}
		if text := stringFromAny(value); strings.TrimSpace(text) != "" {
			return key + ": " + text
		}
	}
	return "No summary text captured"
}

func logTitleForArtifact(key string) string {
	switch key {
	case "logs_application":
		return "Application Log"
	case "logs_system":
		return "System Log"
	case "logs_powershell":
		return "PowerShell Operational Log"
	case "logs_defender":
		return "Defender Operational Log"
	default:
		return key
	}
}

func buildNetworkConnectionView(item map[string]any, processByPID map[string]string) networkConnectionView {
	localIP, localPort := splitHostPort(stringValue(item, "local_address"))
	remoteIP, remotePort := splitHostPort(stringValue(item, "foreign_address"))
	state := strings.ToUpper(normalizedNA(stringValue(item, "state")))
	if state == "" && strings.EqualFold(stringValue(item, "protocol"), "UDP") {
		state = "UNCONNECTED"
	}
	pid := zeroBlank(int(numberValue(item, "pid")))
	return networkConnectionView{
		Protocol:      stringValue(item, "protocol"),
		LocalIP:       localIP,
		LocalPort:     localPort,
		LocalService:  commonServiceLabel(localPort),
		RemoteIP:      remoteIP,
		RemotePort:    remotePort,
		RemoteService: commonServiceLabel(remotePort),
		State:         state,
		StateBucket:   connectionStateBucket(state),
		PID:           pid,
		ProcessName:   processByPID[pid],
		RemoteScope:   ipScope(remoteIP),
		LoopbackOnly:  ipScope(localIP) == "loopback" && ipScope(remoteIP) == "loopback",
	}
}

func splitHostPort(value string) (string, string) {
	value = strings.TrimSpace(value)
	if value == "" || value == "*:*" {
		return value, ""
	}
	if strings.HasPrefix(value, "[") {
		end := strings.LastIndex(value, "]:")
		if end != -1 {
			return value[1:end], value[end+2:]
		}
	}
	idx := strings.LastIndex(value, ":")
	if idx == -1 {
		return value, ""
	}
	return value[:idx], value[idx+1:]
}

func commonServiceLabel(port string) string {
	switch port {
	case "80":
		return "HTTP"
	case "443":
		return "HTTPS"
	case "445":
		return "SMB"
	case "135":
		return "RPC endpoint mapper"
	case "139":
		return "NetBIOS session"
	case "137":
		return "NetBIOS name"
	case "138":
		return "NetBIOS datagram"
	case "53":
		return "DNS"
	case "68":
		return "DHCP client"
	case "161":
		return "SNMP"
	case "500":
		return "IKE"
	case "1900":
		return "SSDP"
	case "5353":
		return "mDNS"
	case "5355":
		return "LLMNR"
	default:
		return ""
	}
}

func connectionStateBucket(state string) string {
	switch state {
	case "LISTENING":
		return "listening"
	case "ESTABLISHED", "SYN_SENT", "SYN_RECEIVED":
		return "active"
	case "TIME_WAIT", "CLOSE_WAIT", "CLOSED", "FIN_WAIT_1", "FIN_WAIT_2", "LAST_ACK", "CLOSING":
		return "closed-ish"
	default:
		return "other"
	}
}

func ipScope(ip string) string {
	ip = strings.Trim(strings.TrimSpace(ip), "[]")
	if ip == "" || ip == "*" || ip == "0.0.0.0" || ip == "::" {
		return "any"
	}
	if strings.HasPrefix(ip, "127.") || ip == "::1" {
		return "loopback"
	}
	if strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "192.168.") {
		return "private"
	}
	if strings.HasPrefix(ip, "172.") {
		parts := strings.Split(ip, ".")
		if len(parts) > 1 {
			if n, err := strconv.Atoi(parts[1]); err == nil && n >= 16 && n <= 31 {
				return "private"
			}
		}
	}
	if strings.HasPrefix(ip, "169.254.") || strings.HasPrefix(strings.ToLower(ip), "fe80:") {
		return "link-local"
	}
	if strings.HasPrefix(strings.ToLower(ip), "fc") || strings.HasPrefix(strings.ToLower(ip), "fd") {
		return "private"
	}
	return "public"
}

func filterNetworkConnections(items []networkConnectionView, query, statePivot, protocolFilter, ipFocus, remoteFilter, portFocus string, externalOnly bool) []networkConnectionView {
	query = strings.ToLower(strings.TrimSpace(query))
	ipFocus = strings.TrimSpace(ipFocus)
	remoteFilter = strings.ToLower(strings.TrimSpace(remoteFilter))
	portFocus = strings.TrimSpace(portFocus)
	var filtered []networkConnectionView
	for _, item := range items {
		if statePivot != "" && item.StateBucket != statePivot {
			continue
		}
		if protocolFilter != "" && !strings.EqualFold(item.Protocol, protocolFilter) {
			continue
		}
		if ipFocus != "" && item.LocalIP != ipFocus && item.RemoteIP != ipFocus {
			continue
		}
		if remoteFilter != "" && !strings.Contains(strings.ToLower(item.RemoteIP), remoteFilter) {
			continue
		}
		if externalOnly && item.RemoteScope != "public" {
			continue
		}
		if portFocus != "" && item.LocalPort != portFocus && item.RemotePort != portFocus {
			continue
		}
		if query != "" {
			haystack := strings.ToLower(strings.Join([]string{item.Protocol, item.LocalIP, item.LocalPort, item.LocalService, item.RemoteIP, item.RemotePort, item.RemoteService, item.State, item.PID, item.ProcessName, item.RemoteScope}, " "))
			if !strings.Contains(haystack, query) {
				continue
			}
		}
		filtered = append(filtered, item)
	}
	return filtered
}

func sortNetworkConnections(items []networkConnectionView, sortKey string) {
	sort.SliceStable(items, func(i, j int) bool {
		switch sortKey {
		case "remote":
			if items[i].RemoteIP != items[j].RemoteIP {
				return items[i].RemoteIP < items[j].RemoteIP
			}
			if items[i].RemotePort != items[j].RemotePort {
				return items[i].RemotePort < items[j].RemotePort
			}
		case "pid":
			if items[i].PID != items[j].PID {
				return items[i].PID < items[j].PID
			}
		case "process":
			if !strings.EqualFold(items[i].ProcessName, items[j].ProcessName) {
				return strings.ToLower(items[i].ProcessName) < strings.ToLower(items[j].ProcessName)
			}
		case "state":
			if items[i].StateBucket != items[j].StateBucket {
				return items[i].StateBucket < items[j].StateBucket
			}
		}
		if items[i].StateBucket != items[j].StateBucket {
			return items[i].StateBucket < items[j].StateBucket
		}
		if items[i].Protocol != items[j].Protocol {
			return items[i].Protocol < items[j].Protocol
		}
		if items[i].LocalPort != items[j].LocalPort {
			return items[i].LocalPort < items[j].LocalPort
		}
		if items[i].RemoteIP != items[j].RemoteIP {
			return items[i].RemoteIP < items[j].RemoteIP
		}
		return items[i].PID < items[j].PID
	})
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func showQuickStart(layout thruntime.Layout, w http.ResponseWriter, r *http.Request) {
	content, err := os.ReadFile(filepath.Join(layout.DocsDir, "thoth-quick-start.md"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	renderTemplate(w, quickStartTemplate, map[string]any{"Content": string(content)})
}

func showUserGuide(layout thruntime.Layout, w http.ResponseWriter, r *http.Request) {
	content, err := os.ReadFile(filepath.Join(layout.DocsDir, "thoth-user-guide.md"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	renderTemplate(w, userGuideTemplate, map[string]any{"Content": string(content)})
}

func handleIngest(layout thruntime.Layout, store *sqlite.Store, w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	source := strings.TrimSpace(r.FormValue("source_path"))
	if source == "" {
		source = strings.TrimSpace(r.FormValue("manual_source_path"))
	}
	if source == "" {
		http.Redirect(w, r, "/?msg="+url.QueryEscape("No source selected."), http.StatusSeeOther)
		return
	}

	analystCaseID := strings.TrimSpace(r.FormValue("analyst_case_id"))
	importer := ingest.Importer{Store: store, DataRoot: layout.DataRoot}
	result, err := importer.ImportPathWithOptions(r.Context(), source, ingest.ImportOptions{AnalystCaseID: analystCaseID})
	if err != nil {
		http.Redirect(w, r, "/?msg="+url.QueryEscape("Ingest failed: "+err.Error()), http.StatusSeeOther)
		return
	}

	summaries, err := store.ListCaseSummaries(r.Context())
	if err != nil {
		http.Redirect(w, r, "/?msg="+url.QueryEscape("Post-ingest refresh failed: "+err.Error()), http.StatusSeeOther)
		return
	}
	for _, summary := range summaries {
		normalized, err := normalize.NormalizeCase(summary)
		if err != nil {
			http.Redirect(w, r, "/?msg="+url.QueryEscape("Normalize failed: "+err.Error()), http.StatusSeeOther)
			return
		}
		if err := normalize.LoadNormalizedArtifacts(r.Context(), store, summary, normalized); err != nil {
			http.Redirect(w, r, "/?msg="+url.QueryEscape("DB load failed: "+err.Error()), http.StatusSeeOther)
			return
		}
		if _, err := findings.GenerateCaseFindings(r.Context(), store, summary); err != nil {
			http.Redirect(w, r, "/?msg="+url.QueryEscape("Findings failed: "+err.Error()), http.StatusSeeOther)
			return
		}
	}

	msg := "Imported " + strconv.Itoa(result.ImportedCases) + " case(s) from " + source + "; normalization and findings completed."
	http.Redirect(w, r, "/?msg="+url.QueryEscape(msg), http.StatusSeeOther)
}

func handleExportData(layout thruntime.Layout, store *sqlite.Store, w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := checkpointSQLite(r.Context(), store); err != nil {
		http.Redirect(w, r, "/?msg="+url.QueryEscape("Export failed during DB checkpoint: "+err.Error()), http.StatusSeeOther)
		return
	}
	destinationDir := strings.TrimSpace(r.FormValue("destination_dir"))
	archivePath, err := exportDataBundle(layout, destinationDir)
	if err != nil {
		http.Redirect(w, r, "/?msg="+url.QueryEscape("Export failed: "+err.Error()), http.StatusSeeOther)
		return
	}
	msg := "Saved investigation bundle: " + archivePath
	http.Redirect(w, r, "/?msg="+url.QueryEscape(msg), http.StatusSeeOther)
}

func handleClearData(layout thruntime.Layout, store *sqlite.Store, w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(r.FormValue("confirm")) != "CLEAR" {
		http.Redirect(w, r, "/?msg="+url.QueryEscape("Clear canceled. Type CLEAR to remove current imported data."), http.StatusSeeOther)
		return
	}
	if err := store.ClearAnalysisState(r.Context()); err != nil {
		http.Redirect(w, r, "/?msg="+url.QueryEscape("Clear failed: "+err.Error()), http.StatusSeeOther)
		return
	}
	if err := clearRuntimeDataDirs(layout); err != nil {
		http.Redirect(w, r, "/?msg="+url.QueryEscape("DB cleared, but file cleanup failed: "+err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?msg="+url.QueryEscape("Cleared current Thoth data. Saved exports were left intact."), http.StatusSeeOther)
}

func checkpointSQLite(ctx context.Context, store *sqlite.Store) error {
	if _, err := store.DB.ExecContext(ctx, `PRAGMA wal_checkpoint(FULL)`); err != nil {
		return fmt.Errorf("checkpoint sqlite WAL: %w", err)
	}
	return nil
}

func exportDataBundle(layout thruntime.Layout, destinationDir string) (string, error) {
	exportsDir := strings.TrimSpace(destinationDir)
	if exportsDir == "" {
		exportsDir = filepath.Join(layout.DataRoot, "exports")
	}
	absExportsDir, err := filepath.Abs(exportsDir)
	if err != nil {
		return "", fmt.Errorf("resolve destination directory: %w", err)
	}
	if err := os.MkdirAll(absExportsDir, 0o755); err != nil {
		return "", fmt.Errorf("create exports directory: %w", err)
	}

	stamp := time.Now().UTC().Format("20060102T150405Z")
	archivePath := filepath.Join(absExportsDir, "thoth-investigation-"+stamp+".tar.gz")
	file, err := os.Create(archivePath)
	if err != nil {
		return "", fmt.Errorf("create archive: %w", err)
	}
	defer file.Close()

	gzipWriter := gzip.NewWriter(file)
	defer gzipWriter.Close()
	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	if err := filepath.WalkDir(layout.DataRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == archivePath {
			return nil
		}
		if path == absExportsDir || strings.HasPrefix(path, absExportsDir+string(os.PathSeparator)) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if path == filepath.Join(layout.DataRoot, "tmp") || strings.HasPrefix(path, filepath.Join(layout.DataRoot, "tmp")+string(os.PathSeparator)) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		return addFileToArchive(tarWriter, layout.DataRoot, path)
	}); err != nil {
		return "", fmt.Errorf("write archive: %w", err)
	}
	return archivePath, nil
}

func addFileToArchive(tarWriter *tar.Writer, root, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil
	}

	relativePath, err := filepath.Rel(root, path)
	if err != nil {
		return fmt.Errorf("relative path for %s: %w", path, err)
	}
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return fmt.Errorf("create tar header for %s: %w", path, err)
	}
	header.Name = filepath.ToSlash(filepath.Join("thoth-data", relativePath))
	if err := tarWriter.WriteHeader(header); err != nil {
		return fmt.Errorf("write tar header for %s: %w", path, err)
	}

	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	if _, err := io.Copy(tarWriter, file); err != nil {
		return fmt.Errorf("copy %s into archive: %w", path, err)
	}
	return nil
}

func clearRuntimeDataDirs(layout thruntime.Layout) error {
	for _, name := range []string{"imports", "cases", "tmp"} {
		path := filepath.Join(layout.DataRoot, name)
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("remove %s: %w", path, err)
		}
		if err := os.MkdirAll(path, 0o755); err != nil {
			return fmt.Errorf("recreate %s: %w", path, err)
		}
	}
	marker := []byte("reset_at=" + time.Now().UTC().Format(time.RFC3339) + "\n")
	if err := os.WriteFile(filepath.Join(layout.DataRoot, ".reset-marker"), marker, 0o644); err != nil {
		return fmt.Errorf("write reset marker: %w", err)
	}
	return nil
}

func detectMountedSources() []string {
	entries, err := os.ReadDir("/Volumes")
	if err != nil {
		return nil
	}
	var sources []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join("/Volumes", entry.Name())
		if dirExists(path) && (dirExists(filepath.Join(path, "collections")) || fileExists(filepath.Join(path, "batch-manifest.json"))) {
			sources = append(sources, path)
		}
	}
	sort.Strings(sources)
	return sources
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

const pageStyle = `<style>
body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;margin:24px;background:#0f172a;color:#e2e8f0}
a{color:#7dd3fc;text-decoration:none} a:hover{text-decoration:underline}
table{border-collapse:collapse;width:100%;margin-top:12px;background:#111827}
th,td{border:1px solid #334155;padding:8px;text-align:left;vertical-align:top}
th{background:#1e293b}
.card{background:#111827;padding:16px;border:1px solid #334155;border-radius:8px;margin:16px 0}
.button-primary{padding:10px 14px;background:#2563eb;color:white;border:0;border-radius:6px;font-weight:600;cursor:pointer}
.button-primary:hover{background:#1d4ed8}
.button-primary[disabled]{background:#475569;cursor:wait}
.status-running{background:#1e293b;border:1px solid #2563eb}
pre{white-space:pre-wrap;background:#020617;padding:12px;border:1px solid #334155;border-radius:6px}
</style>`

const homeTemplate = `<!doctype html><html><head><title>Thoth Cases</title>` + pageStyle + `</head><body>
<h1>Thoth Cases</h1>
<div class="card">` + `{{len .Cases}} case(s) loaded from SQLite.` + `</div>
{{if .Message}}<div class="card"><strong>{{.Message}}</strong></div>{{end}}
<div class="card">
<h2>Runtime</h2>
<div><strong>Mode:</strong> {{.Layout.Mode}}</div>
<div><strong>Root:</strong> <code>{{.Layout.RootDir}}</code></div>
<div><strong>Data root:</strong> <code>{{.Layout.DataRoot}}</code></div>
<div><strong>DB:</strong> <code>{{.Layout.DBPath}}</code></div>
<div><strong>Docs:</strong> <code>{{.Layout.DocsDir}}</code></div>
</div>
<div class="card"><a href="/docs/quick-start">Open quick start guide</a> · <a href="/docs/user-guide" target="_blank" rel="noopener noreferrer">Open user guide ↗</a></div>
<div class="card"><a href="/">Refresh case list</a></div>
<div class="card">
<h2>Investigation Bundle</h2>
<form method="post" action="/export-data" style="margin-bottom:12px;">
<div style="margin-bottom:8px;"><strong>Destination:</strong> <input type="text" name="destination_dir" value="{{.Layout.DataRoot}}/exports" style="width:420px;background:#020617;color:#e2e8f0;border:1px solid #334155;padding:6px;border-radius:4px;"></div>
<button class="button-primary" type="submit">Save Bundle As...</button>
<span style="color:#94a3b8;margin-left:8px;">Exports current cases, notes, decisions, findings, and imported evidence.</span>
</form>
<form method="post" action="/clear-data" onsubmit="return confirm('Clear current imported Thoth data? Saved exports remain, but loaded cases and notes will be removed from this workspace.');">
<input type="text" name="confirm" placeholder="Type CLEAR" style="width:110px;background:#020617;color:#e2e8f0;border:1px solid #334155;padding:6px;border-radius:4px;">
<button type="submit">Clear Current Investigation</button>
<span style="color:#94a3b8;margin-left:8px;">Removes loaded cases from this Thoth workspace. Saved bundles are not deleted.</span>
</form>
</div>
<div class="card">
<h2>Ingest SEKER media</h2>
<form method="post" action="/ingest" onsubmit="document.getElementById('ingest-button').disabled=true;document.getElementById('ingest-button').innerText='Running ingest…';document.getElementById('ingest-status').style.display='block';">
{{if .Sources}}<div><strong>Detected sources:</strong></div>
<div style="margin-top:8px;"><select name="source_path" style="width:380px;background:#020617;color:#e2e8f0;border:1px solid #334155;padding:6px;border-radius:4px;"><option value="">Select a mounted source…</option>{{range .Sources}}<option value="{{.}}">{{.}}</option>{{end}}</select></div>{{else}}<div>No likely SEKER media auto-detected under <code>/Volumes</code>.</div>{{end}}
<div style="margin-top:10px;"><strong>Case ID:</strong> <input type="text" name="analyst_case_id" placeholder="IR-2026-001" style="width:220px;background:#020617;color:#e2e8f0;border:1px solid #334155;padding:6px;border-radius:4px;"> <span style="color:#94a3b8">Optional analyst-facing Case ID override</span></div>
<div style="margin-top:10px;"><strong>Or enter a path:</strong> <input type="text" name="manual_source_path" placeholder="/Volumes/SEKER" style="width:320px;background:#020617;color:#e2e8f0;border:1px solid #334155;padding:6px;border-radius:4px;"></div>
<div id="ingest-status" class="card status-running" style="display:none;margin-top:12px;">Pipeline started. Thoth is ingesting, normalizing, and generating findings for the selected source…</div>
<div style="margin-top:10px;"><button id="ingest-button" class="button-primary" type="submit">Run ingest + normalize + findings</button></div>
</form>
</div>
<table><thead><tr><th>Host</th><th>Host / OS</th><th>Collected</th><th>Decision</th><th>Status</th><th>Integrity</th><th>Warnings</th><th>Errors</th></tr></thead><tbody>
{{range .Cases}}<tr>
<td><a href="/cases/{{.CaseUUID}}">{{.CaseID}}</a><br><span style="color:#94a3b8">{{.Hostname}}</span></td>
<td>{{.Hostname}}<br><span style="color:#94a3b8">{{.OSVersion}}{{if .OSBuild}} ({{.OSBuild}}){{end}}</span></td>
<td>{{.CollectedAt}}</td>
<td>{{if .Disposition}}{{.Disposition}}{{else}}Not set{{end}}{{if .Priority}}<br><span style="color:#94a3b8">{{.Priority}}</span>{{end}}{{if .Escalated}}<br><strong>Escalated</strong>{{end}}</td>
<td>{{.Status}}</td>
<td>{{.IntegrityStatus}}</td>
<td>{{.WarningsCount}}</td>
<td>{{.ErrorsCount}}</td>
</tr>{{end}}
</tbody></table></body></html>`

const caseTemplate = `<!doctype html><html><head><title>Thoth Case</title>` + pageStyle + `</head><body>
<p><a href="/">← Back to cases</a></p>
<h1>{{.Case.CaseID}}</h1>
{{if .Message}}<div class="card"><strong>{{.Message}}</strong></div>{{end}}
<div class="card">
<div><strong>Host:</strong> {{.Case.Hostname}}</div>
<div><strong>OS:</strong> {{.Case.OSVersion}}{{if .Case.OSBuild}} ({{.Case.OSBuild}}){{end}}</div>
<div><strong>Case UUID:</strong> {{.Case.CaseUUID}}</div>
<div><strong>Case ID:</strong> {{.Case.CaseID}}</div>
<div><strong>Collection ID:</strong> {{.Case.CollectionCaseID}}</div>
<div><strong>Batch:</strong> {{.Case.BatchID}}</div>
<div><strong>Collected:</strong> {{.Case.CollectedAt}}</div>
<div><strong>Status:</strong> {{.Case.Status}}</div>
<div><strong>Integrity:</strong> {{.Case.IntegrityStatus}}</div>
<div><strong>Field decision:</strong> {{if .Case.Disposition}}{{.Case.Disposition}}{{else}}Not set{{end}}{{if .Case.Priority}} · Priority: {{.Case.Priority}}{{end}}{{if .Case.Escalated}} · <strong>Forensic escalation</strong>{{end}}</div>
</div>
<form method="post" action="/cases/{{.Case.CaseUUID}}/field">
<h2>Field decision</h2>
<div class="card">
<div style="display:flex;gap:12px;flex-wrap:wrap;align-items:end;">
<label><strong>Disposition</strong><br>
<select name="disposition" style="width:190px;background:#020617;color:#e2e8f0;border:1px solid #334155;padding:6px;border-radius:4px;">
<option value="" {{if eq .Case.Disposition ""}}selected{{end}}>Not set</option>
<option value="monitor" {{if eq .Case.Disposition "monitor"}}selected{{end}}>Monitor</option>
<option value="collect_more" {{if eq .Case.Disposition "collect_more"}}selected{{end}}>Collect more</option>
<option value="likely_benign" {{if eq .Case.Disposition "likely_benign"}}selected{{end}}>Likely benign</option>
<option value="needs_follow_up" {{if eq .Case.Disposition "needs_follow_up"}}selected{{end}}>Needs follow-up</option>
<option value="forensic_escalation" {{if eq .Case.Disposition "forensic_escalation"}}selected{{end}}>Forensic escalation</option>
</select></label>
<label><strong>Priority</strong><br>
<select name="priority" style="width:140px;background:#020617;color:#e2e8f0;border:1px solid #334155;padding:6px;border-radius:4px;">
<option value="" {{if eq .Case.Priority ""}}selected{{end}}>Not set</option>
<option value="low" {{if eq .Case.Priority "low"}}selected{{end}}>Low</option>
<option value="medium" {{if eq .Case.Priority "medium"}}selected{{end}}>Medium</option>
<option value="high" {{if eq .Case.Priority "high"}}selected{{end}}>High</option>
<option value="urgent" {{if eq .Case.Priority "urgent"}}selected{{end}}>Urgent</option>
</select></label>
<label style="padding-bottom:7px;"><input type="checkbox" name="escalated" {{if .Case.Escalated}}checked{{end}}> Mark for forensic escalation</label>
<button class="button-primary" type="submit" name="intent" value="save_decision">Save decision</button>
</div>
</div>
<h2>Analyst notes</h2>
<div class="card">
<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:8px;">
<select name="note_type" style="width:150px;background:#020617;color:#e2e8f0;border:1px solid #334155;padding:6px;border-radius:4px;">
<option value="general">General</option>
<option value="observation">Observation</option>
<option value="decision">Decision</option>
<option value="follow_up">Follow-up</option>
</select>
<input type="text" name="author" placeholder="Analyst" style="width:160px;background:#020617;color:#e2e8f0;border:1px solid #334155;padding:6px;border-radius:4px;">
</div>
<textarea name="body" rows="4" placeholder="Record field observations, collection gaps, decision rationale, or follow-up instructions." style="width:100%;box-sizing:border-box;background:#020617;color:#e2e8f0;border:1px solid #334155;padding:8px;border-radius:4px;"></textarea>
<div style="margin-top:8px;"><button class="button-primary" type="submit" name="intent" value="add_note">Add note</button></div>
</div>
</form>
{{if .Notes}}
{{range .Notes}}<div class="card">
<div><strong>{{.NoteType}}</strong> · {{.CreatedAt}}{{if .Author}} · {{.Author}}{{end}}</div>
<div style="margin-top:8px;white-space:pre-wrap;">{{.Body}}</div>
</div>{{end}}
{{else}}<div class="card">No analyst notes yet.</div>{{end}}
{{if .HostContextArtifact}}<div class="card"><a href="/cases/{{.Case.CaseUUID}}/host-overview">Open Host Overview</a></div>{{end}}
<div class="card"><a href="/cases/{{.Case.CaseUUID}}/processes">Open process list view</a></div>
<div class="card"><a href="/cases/{{.Case.CaseUUID}}/scheduled-tasks">Open scheduled tasks view</a></div>
<div class="card"><a href="/cases/{{.Case.CaseUUID}}/persistence">Open persistence view</a></div>
<div class="card"><a href="/cases/{{.Case.CaseUUID}}/network">Open network view</a></div>
<div class="card"><a href="/cases/{{.Case.CaseUUID}}/logs">Open System Logs</a></div>
<h2>Findings</h2>
<div class="card">
{{if .ShowAll}}Showing all findings, including suppressed known-good noise. <a href="/cases/{{.Case.CaseUUID}}">Hide suppressed</a>{{else}}Showing high-signal findings only. {{if gt .SuppressedCount 0}}<a href="/cases/{{.Case.CaseUUID}}?show=all">Show all ({{.SuppressedCount}} suppressed)</a>{{end}}{{end}}
</div>
{{if .Findings}}
<table><thead><tr><th>Title</th><th>Category</th><th>Severity</th><th>Confidence</th><th>Evidence</th></tr></thead><tbody>
{{range .Findings}}<tr>
<td>{{.Title}}</td><td>{{.Category}}</td><td>{{.Severity}}</td><td>{{.Confidence}}</td><td>{{if .EvidenceURL}}<a href="{{.EvidenceURL}}">{{.EvidenceLabel}}</a>{{else}}{{.EvidenceLabel}}{{end}}{{if .EvidenceSource}}<br><span style="color:#94a3b8">Source: {{.EvidenceSource}}</span>{{end}}</td>
</tr><tr><td colspan="5">{{.Rationale}}{{if .Suppressed}} <br><strong>Suppressed:</strong> {{.SuppressionReason}}{{end}}</td></tr>{{end}}
</tbody></table>
{{else}}<div class="card">No findings generated yet.</div>{{end}}
<h2>Normalized artifact sets</h2>
<table><thead><tr><th>Artifact</th><th>Records</th><th>Status</th><th>Source</th></tr></thead><tbody>
{{range .ArtifactSets}}<tr>
<td><a href="/cases/{{$.Case.CaseUUID}}/artifact/{{.ArtifactKey}}">{{.ArtifactKey}}</a></td>
<td>{{.RecordCount}}</td>
<td>{{.Status}}</td>
<td><a href="{{.SourceURL}}">{{.SourceRelativePath}}</a></td>
</tr>{{end}}
</tbody></table></body></html>`

const artifactTemplate = `<!doctype html><html><head><title>Thoth Artifact</title>` + pageStyle + `</head><body>
<p><a href="/cases/{{.Case.CaseUUID}}">← Back to case</a></p>
<h1>{{.Case.Hostname}} / {{.ArtifactKey}}</h1>
<div class="card">Showing {{.CurrentStart}}-{{.CurrentEnd}} of {{.TotalCount}} normalized record(s).</div>
{{range .Records}}<div class="card" id="record-{{.RecordIndex}}"><div><strong>Record #{{.RecordIndex}}</strong>{{if .PrimaryLabel}} — {{.PrimaryLabel}}{{end}}{{if .SecondaryLabel}} — {{.SecondaryLabel}}{{end}}</div><pre>{{.RawJSON}}</pre></div>{{end}}
<div class="card">
{{if .HasPrev}}<a href="/cases/{{.Case.CaseUUID}}/artifact/{{.ArtifactKey}}?offset={{.PrevOffset}}">← Previous</a>{{end}}
{{if and .HasPrev .HasNext}} · {{end}}
{{if .HasNext}}<a href="/cases/{{.Case.CaseUUID}}/artifact/{{.ArtifactKey}}?offset={{.NextOffset}}">Load more / Next →</a>{{end}}
</div>
</body></html>`

const sourceArtifactTemplate = `<!doctype html><html><head><title>Thoth Collected Source</title>` + pageStyle + `</head><body>
<p><a href="/cases/{{.Case.CaseUUID}}">← Back to case</a></p>
<h1>Collected source — {{.ArtifactKey}}</h1>
<div class="card">
<div><strong>Collected machine path:</strong> <code>{{.SourceRelativePath}}</code></div>
<div><strong>Local imported copy:</strong> <code>{{.SourcePath}}</code></div>
{{if .Truncated}}<div style="margin-top:8px;color:#fbbf24;"><strong>Note:</strong> preview truncated to first 256KB.</div>{{end}}
</div>
<pre>{{.Content}}</pre>
</body></html>`

const hostContextTemplate = `<!doctype html><html><head><title>Thoth Host Overview</title>` + pageStyle + `</head><body>
<p><a href="/cases/{{.Case.CaseUUID}}">← Back to case</a></p>
<h1>Host Overview — {{.Case.CaseID}}</h1>
<div class="card">
<div><strong>Hostname:</strong> {{.Hostname}}</div>
<div><strong>Operating system:</strong> {{.OSName}}{{if .OSBuild}} ({{.OSBuild}}){{end}}</div>
<div><strong>Architecture:</strong> {{.Architecture}}</div>
<div><strong>Username:</strong> {{.Username}}</div>
<div><strong>Domain:</strong> {{if .Domain}}{{.Domain}}{{else}}—{{end}}</div>
<div><strong>Collection time:</strong> {{.CollectionTime}}</div>
<div><strong>Timezone:</strong> {{if .Timezone}}{{.Timezone}}{{else}}—{{end}}</div>
<div><strong>Last boot:</strong> {{.LastBootTime}}</div>
<div><strong>Uptime:</strong> {{.Uptime}}</div>
</div>
{{if .HasNetworkSummary}}<div class="card">
<h2>Network snapshot</h2>
<div><strong>Primary IPv4:</strong> {{if .PrimaryIPv4}}{{.PrimaryIPv4}}{{else}}—{{end}}</div>
<div><strong>Default gateway:</strong> {{if .DefaultGateway}}{{.DefaultGateway}}{{else}}—{{end}}</div>
<div><strong>DNS servers:</strong> {{if .DNSServers}}{{.DNSServers}}{{else}}—{{end}}</div>
<div><strong>Adapters seen:</strong> {{.AdapterCount}}</div>
<div style="margin-top:8px;"><a href="/cases/{{.Case.CaseUUID}}/network-config">Open network configuration details</a></div>
</div>{{end}}
{{if .HasSecuritySummary}}<div class="card">
<h2>Security posture</h2>
<div><strong>Firewall:</strong> {{if .FirewallSummary}}{{.FirewallSummary}}{{else}}—{{end}}</div>
<div><strong>Defender:</strong> {{if .DefenderSummary}}{{.DefenderSummary}}{{else}}—{{end}}</div>
<div><strong>Security-tool hints:</strong> {{if .SecurityToolsSummary}}{{.SecurityToolsSummary}}{{else}}—{{end}}</div>
<div style="margin-top:8px;"><a href="/cases/{{.Case.CaseUUID}}/artifact/security_firewall">Firewall source</a> | <a href="/cases/{{.Case.CaseUUID}}/artifact/security_defender">Defender source</a> | <a href="/cases/{{.Case.CaseUUID}}/artifact/security_products">Tool hints source</a></div>
</div>{{end}}
{{if .HasSoftwareSummary}}<div class="card">
<h2>Installed programs</h2>
<div>{{.SoftwareSummary}}</div>
<div style="margin-top:8px;"><a href="/cases/{{.Case.CaseUUID}}/artifact/software_installed_programs">Open installed-program inventory</a></div>
</div>{{end}}
{{if .HasDeviceSummary}}<div class="card">
<h2>Device / removable-media context</h2>
<div>{{.DeviceSummary}}</div>
<div style="margin-top:8px;"><a href="/cases/{{.Case.CaseUUID}}/artifact/devices_volumes">Volumes</a> | <a href="/cases/{{.Case.CaseUUID}}/artifact/devices_usb_current">Current USB</a> | <a href="/cases/{{.Case.CaseUUID}}/artifact/devices_usb_previous">Previous USB evidence</a> | <a href="/cases/{{.Case.CaseUUID}}/artifact/devices_pnp_summary">PnP summary</a></div>
</div>{{end}}
{{if .HasWirelessSummary}}<div class="card">
<h2>Wi-Fi / Bluetooth context</h2>
<div>{{.WirelessSummary}}</div>
<div style="margin-top:8px;"><a href="/cases/{{.Case.CaseUUID}}/artifact/network_wifi_interfaces">Wi-Fi interfaces</a> | <a href="/cases/{{.Case.CaseUUID}}/artifact/network_wifi_profiles">Wi-Fi profiles</a> | <a href="/cases/{{.Case.CaseUUID}}/artifact/network_bluetooth_devices">Bluetooth devices</a> | <a href="/cases/{{.Case.CaseUUID}}/artifact/network_bluetooth_connected">Bluetooth connected</a></div>
</div>{{end}}
<div class="card">
<h2>Patch posture</h2>
<div>{{.PatchPostureNote}}</div>
</div>
<div class="card">
<h2>Debug / source paths</h2>
<div><strong>Normalized source:</strong> <code>{{.SourcePath}}</code></div>
<div><strong>Normalized output:</strong> <code>{{.OutputPath}}</code></div>
</div>
<div class="card">
<details>
<summary>Show raw normalized host record</summary>
<pre style="margin-top:12px;">{{.RawJSON}}</pre>
</details>
</div>
</body></html>`

const networkConfigTemplate = `<!doctype html><html><head><title>Thoth Network Config</title>` + pageStyle + `</head><body>
<p><a href="/cases/{{.Case.CaseUUID}}/host-overview">← Back to Host Overview</a></p>
<h1>Network Configuration — {{.Case.CaseID}}</h1>
<div class="card">
<div><strong>Host:</strong> {{if .HostName}}{{.HostName}}{{else}}{{.Case.Hostname}}{{end}}</div>
<div><strong>DNS suffix search list:</strong> {{if .DNSSuffixSearchList}}{{.DNSSuffixSearchList}}{{else}}—{{end}}</div>
<div><strong>Primary DNS suffix:</strong> {{if .PrimaryDNSSuffix}}{{.PrimaryDNSSuffix}}{{else}}—{{end}}</div>
<div><strong>Node type:</strong> {{if .NodeType}}{{.NodeType}}{{else}}—{{end}}</div>
<div><strong>IP routing enabled:</strong> {{if .IPRoutingEnabled}}{{.IPRoutingEnabled}}{{else}}—{{end}}</div>
<div><strong>WINS proxy enabled:</strong> {{if .WINSProxyEnabled}}{{.WINSProxyEnabled}}{{else}}—{{end}}</div>
</div>
{{range .Adapters}}<div class="card">
<h2>{{.Name}}</h2>
<div><strong>Description:</strong> {{if .Description}}{{.Description}}{{else}}—{{end}}</div>
<div><strong>IPv4:</strong> {{if .IPv4}}{{.IPv4}}{{else if .AutoIPv4}}{{.AutoIPv4}} <span style="color:#fbbf24">(autoconfig)</span>{{else}}—{{end}} {{if .SubnetMask}}/ {{.SubnetMask}}{{end}}</div>
<div><strong>IPv6 link-local:</strong> {{if .IPv6LinkLocal}}{{.IPv6LinkLocal}}{{else}}—{{end}}</div>
<div><strong>Default gateway:</strong> {{if .Gateway}}{{.Gateway}}{{else}}—{{end}}</div>
<div><strong>Adapter context:</strong> {{if .AdapterContext}}{{.AdapterContext}}{{else if eq .PrimaryRouted "true"}}likely primary routed{{else}}—{{end}}</div>
<div><strong>DNS servers:</strong> {{if .DNSServers}}{{.DNSServers}}{{else}}—{{end}}</div>
<div><strong>DHCP:</strong> {{if .DHCPEnabled}}{{.DHCPEnabled}}{{else}}—{{end}}{{if .DHCPServer}} via {{.DHCPServer}}{{end}}</div>
<div><strong>Lease:</strong> obtained {{if .LeaseObtained}}{{.LeaseObtained}}{{else}}—{{end}} | expires {{if .LeaseExpires}}{{.LeaseExpires}}{{else}}—{{end}}</div>
<div><strong>MAC:</strong> {{if .MACAddress}}{{.MACAddress}}{{else}}—{{end}} | <strong>NetBIOS over TCP/IP:</strong> {{if .NetBIOS}}{{.NetBIOS}}{{else}}—{{end}}</div>
{{if .ReviewHint}}<div style="margin-top:8px;color:#fbbf24;"><strong>Review hint:</strong> {{.ReviewHint}}</div>{{end}}
</div>{{end}}
<div class="card">
<h2>Source</h2>
<div><strong>Normalized source:</strong> <code>{{.SourcePath}}</code></div>
<div><strong>Normalized output:</strong> <code>{{.OutputPath}}</code></div>
<div style="margin-top:8px;"><a href="/cases/{{.Case.CaseUUID}}/artifact/network_ipconfig">Open raw normalized network config</a></div>
</div>
<div class="card"><details><summary>Show raw normalized network config</summary><pre style="margin-top:12px;">{{.RawJSON}}</pre></details></div>
</body></html>`

const processesTemplate = `<!doctype html><html><head><title>Thoth Processes</title>` + pageStyle + `</head><body>
<p><a href="/cases/{{.Case.CaseUUID}}">← Back to case</a></p>
<h1>Process List — {{.Case.CaseID}}</h1>
<div class="card">
<div><strong>Host:</strong> {{.Case.Hostname}}</div>
<div><strong>Showing:</strong> {{.FilteredCount}} of {{.TotalCount}} normalized process records</div>
</div>
<div class="card">
<form method="get" action="/cases/{{.Case.CaseUUID}}/processes">
<div style="display:flex;gap:12px;flex-wrap:wrap;align-items:end;">
<div><strong>Search</strong><br><input type="text" name="q" value="{{.Query}}" placeholder="process, user, command path, PID" style="width:260px;background:#020617;color:#e2e8f0;border:1px solid #334155;padding:6px;border-radius:4px;"></div>
<div><strong>PID</strong><br><input type="text" name="pid" value="{{.PIDFocus}}" placeholder="9588" style="width:100px;background:#020617;color:#e2e8f0;border:1px solid #334155;padding:6px;border-radius:4px;"></div>
<div><strong>User</strong><br><select name="user" style="width:220px;background:#020617;color:#e2e8f0;border:1px solid #334155;padding:6px;border-radius:4px;"><option value="">All users</option>{{range .UniqueUsers}}<option value="{{.}}"{{if eq $.UserFilter .}} selected{{end}}>{{.}}</option>{{end}}</select></div>
<div><strong>Session</strong><br><select name="session" style="width:140px;background:#020617;color:#e2e8f0;border:1px solid #334155;padding:6px;border-radius:4px;"><option value="">All sessions</option>{{range .UniqueSessions}}<option value="{{.}}"{{if eq $.SessionFilter .}} selected{{end}}>{{.}}</option>{{end}}</select></div>
<div><strong>Status</strong><br><select name="status" style="width:180px;background:#020617;color:#e2e8f0;border:1px solid #334155;padding:6px;border-radius:4px;"><option value="">All statuses</option>{{range .UniqueStatuses}}<option value="{{.}}"{{if eq $.StatusFilter .}} selected{{end}}>{{.}}</option>{{end}}</select></div>
<div><strong>Sort</strong><br><select name="sort" style="width:140px;background:#020617;color:#e2e8f0;border:1px solid #334155;padding:6px;border-radius:4px;"><option value="image"{{if eq .SortKey "image"}} selected{{end}}>Process</option><option value="pid"{{if eq .SortKey "pid"}} selected{{end}}>PID</option><option value="user"{{if eq .SortKey "user"}} selected{{end}}>User</option><option value="session"{{if eq .SortKey "session"}} selected{{end}}>Session</option><option value="cpu"{{if eq .SortKey "cpu"}} selected{{end}}>CPU time</option><option value="status"{{if eq .SortKey "status"}} selected{{end}}>Status</option></select></div>
<div><button class="button-primary" type="submit">Apply</button></div>
{{if .HasQuery}}<div><a href="/cases/{{.Case.CaseUUID}}/processes">Clear filters</a></div>{{end}}
</div>
</form>
</div>
<table><thead><tr><th>Process</th><th>PID / PPID</th><th>User</th><th>Session</th><th>CPU</th><th>Status</th><th>Path / Command Line</th></tr></thead><tbody>
{{range .Processes}}<tr>
<td>{{.ImageName}}{{if .LikelyInteractive}}<br><span style="color:#94a3b8">Interactive session</span>{{end}}</td>
<td>{{if .PIDText}}<a href="/cases/{{$.Case.CaseUUID}}/processes?pid={{.PIDText}}">{{.PIDText}}</a>{{else}}—{{end}}{{if .PPIDText}}<br><span style="color:#94a3b8">PPID {{.PPIDText}}</span>{{end}}</td>
<td>{{if .UserName}}{{.UserName}}{{else}}—{{end}}</td>
<td>{{.SessionName}}{{if .SessionID}}<br><span style="color:#94a3b8">Session ID {{.SessionID}}</span>{{end}}</td>
<td>{{if .CPUTime}}{{.CPUTime}}{{else}}—{{end}}<br><span style="color:#94a3b8">{{if .MemUsage}}{{.MemUsage}}{{else}}mem n/a{{end}}</span></td>
<td>{{if .Status}}{{.Status}}{{else}}—{{end}}</td>
<td>{{if .ExecutablePath}}<span style="color:#e2e8f0">{{.ExecutablePath}}</span>{{else if .WindowTitle}}{{.WindowTitle}}{{else}}—{{end}}{{if .CommandLine}}<br><span style="color:#fbbf24">{{.CommandLine}}</span>{{else if .PathOrCommand}}<br><span style="color:#fbbf24">{{.PathOrCommand}}</span>{{end}}{{if .SuspiciousHint}}<br><span style="color:#fca5a5">{{.SuspiciousHint}}</span>{{end}}</td>
</tr>{{end}}
</tbody></table>
<div class="card"><a href="/cases/{{.Case.CaseUUID}}/artifact/processes">Open raw normalized process records</a></div>
</body></html>`

const scheduledTasksTemplate = `<!doctype html><html><head><title>Thoth Scheduled Tasks</title>` + pageStyle + `</head><body>
<p><a href="/cases/{{.Case.CaseUUID}}">← Back to case</a></p>
<h1>Scheduled Tasks — {{.Case.CaseID}}</h1>
<div class="card">
<div><strong>Host:</strong> {{.Case.Hostname}}</div>
<div><strong>Showing:</strong> {{.FilteredCount}} of {{.TotalCount}} normalized scheduled task records</div>
</div>
<div class="card">
<form method="get" action="/cases/{{.Case.CaseUUID}}/scheduled-tasks">
<div style="display:flex;gap:12px;flex-wrap:wrap;align-items:end;">
<div><strong>Search</strong><br><input type="text" name="q" value="{{.Query}}" placeholder="task name, command, user, comment" style="width:280px;background:#020617;color:#e2e8f0;border:1px solid #334155;padding:6px;border-radius:4px;"></div>
<div><strong>State</strong><br><select name="state" style="width:150px;background:#020617;color:#e2e8f0;border:1px solid #334155;padding:6px;border-radius:4px;"><option value="">All states</option>{{range .States}}<option value="{{.}}"{{if eq $.StateFilter .}} selected{{end}}>{{.}}</option>{{end}}</select></div>
<div><strong>Trigger</strong><br><select name="trigger" style="width:220px;background:#020617;color:#e2e8f0;border:1px solid #334155;padding:6px;border-radius:4px;"><option value="">All triggers</option>{{range .Triggers}}<option value="{{.}}"{{if eq $.TriggerFilter .}} selected{{end}}>{{.}}</option>{{end}}</select></div>
<div><strong>Run as</strong><br><select name="run_as" style="width:180px;background:#020617;color:#e2e8f0;border:1px solid #334155;padding:6px;border-radius:4px;"><option value="">All accounts</option>{{range .RunAsUsers}}<option value="{{.}}"{{if eq $.RunAsFilter .}} selected{{end}}>{{.}}</option>{{end}}</select></div>
<div><strong>Time contains</strong><br><input type="text" name="time" value="{{.TimeFilter}}" placeholder="2026, 5/12, 10:" style="width:140px;background:#020617;color:#e2e8f0;border:1px solid #334155;padding:6px;border-radius:4px;"></div>
<div><strong>Sort</strong><br><select name="sort" style="width:150px;background:#020617;color:#e2e8f0;border:1px solid #334155;padding:6px;border-radius:4px;"><option value=""{{if eq .SortKey ""}} selected{{end}}>Task name</option><option value="last_run"{{if eq .SortKey "last_run"}} selected{{end}}>Last run time</option><option value="next_run"{{if eq .SortKey "next_run"}} selected{{end}}>Next run time</option><option value="start_time"{{if eq .SortKey "start_time"}} selected{{end}}>Start time</option><option value="state"{{if eq .SortKey "state"}} selected{{end}}>State</option><option value="run_as"{{if eq .SortKey "run_as"}} selected{{end}}>Run as</option></select></div>
<div><button class="button-primary" type="submit">Apply</button></div>
{{if .HasQuery}}<div><a href="/cases/{{.Case.CaseUUID}}/scheduled-tasks">Clear filters</a></div>{{end}}
</div>
</form>
</div>
{{range .Tasks}}<div class="card" id="record-{{.RecordIndex}}">
<div><strong>{{.TaskName}}</strong> <span style="color:#94a3b8">Record #{{.RecordIndex}}</span></div>
<div style="margin-top:8px;"><strong>Command:</strong> {{.Command}}{{if .CommandIsPath}} <span style="color:#fbbf24">(path-based)</span>{{end}}</div>
<div><strong>Trigger:</strong> {{if .Trigger}}{{.Trigger}}{{else}}—{{end}}{{if .RepeatEvery}} <span style="color:#94a3b8">| repeat {{.RepeatEvery}}</span>{{end}}</div>
<div><strong>Run as:</strong> {{if .RunAsUser}}{{.RunAsUser}}{{else}}—{{end}} <span style="color:#94a3b8">| state {{if .State}}{{.State}}{{else}}—{{end}} | status {{if .Status}}{{.Status}}{{else}}—{{end}}</span></div>
<div><strong>Timing:</strong> last {{if .LastRunTime}}{{.LastRunTime}}{{else}}—{{end}} | next {{if .NextRunTime}}{{.NextRunTime}}{{else}}—{{end}} | start {{if .StartTime}}{{.StartTime}}{{else}}—{{end}}</div>
<div><strong>Start in:</strong> {{if .StartIn}}{{.StartIn}}{{else}}—{{end}} | <strong>Last result:</strong> {{if .LastResult}}{{.LastResult}}{{else}}—{{end}}</div>
{{if .Comment}}<div><strong>Comment:</strong> {{.Comment}}</div>{{end}}
{{if .SuspiciousHint}}<div style="margin-top:8px;color:#fca5a5;"><strong>Review hint:</strong> {{.SuspiciousHint}}</div>{{end}}
</div>{{end}}
<div class="card"><a href="/cases/{{.Case.CaseUUID}}/artifact/scheduled_tasks">Open raw normalized scheduled task records</a></div>
</body></html>`

const persistenceTemplate = `<!doctype html><html><head><title>Thoth Persistence</title>` + pageStyle + `</head><body>
<p><a href="/cases/{{.Case.CaseUUID}}">← Back to case</a></p>
<h1>Persistence — {{.Case.CaseID}}</h1>
<div class="card">
<div><strong>Host:</strong> {{.Case.Hostname}}</div>
<div><strong>Showing:</strong> {{.FilteredCount}} of {{.TotalCount}} normalized persistence record(s)</div>
<div style="margin-top:8px;color:#94a3b8;">Review startup locations that can launch code at user logon or one-time startup. User-writable paths deserve extra attention, but updater noise is common.</div>
</div>
<div class="card">
<form method="get" action="/cases/{{.Case.CaseUUID}}/persistence">
<div style="display:flex;gap:12px;flex-wrap:wrap;align-items:end;">
<div><strong>Search</strong><br><input type="text" name="q" value="{{.Query}}" placeholder="name, command, path, registry" style="width:280px;background:#020617;color:#e2e8f0;border:1px solid #334155;padding:6px;border-radius:4px;"></div>
<div><strong>Source</strong><br><select name="source" style="width:170px;background:#020617;color:#e2e8f0;border:1px solid #334155;padding:6px;border-radius:4px;"><option value="">All sources</option>{{range .Sources}}<option value="{{.}}"{{if eq $.SourceFilter .}} selected{{end}}>{{.}}</option>{{end}}</select></div>
<div><button class="button-primary" type="submit">Apply</button></div>
{{if .HasQuery}}<div><a href="/cases/{{.Case.CaseUUID}}/persistence">Clear filters</a></div>{{end}}
</div>
</form>
</div>
{{range .Items}}<div class="card" id="record-{{.ArtifactKey}}-{{.RecordIndex}}">
<div><strong>{{if .Name}}{{.Name}}{{else}}Unnamed item{{end}}</strong> <span style="color:#94a3b8">{{.Source}} · Record #{{.RecordIndex}}</span></div>
<div style="margin-top:8px;"><strong>Command/path:</strong> {{if .Command}}{{.Command}}{{else}}—{{end}}{{if .CommandIsPath}} <span style="color:#fbbf24">(path-based)</span>{{end}}</div>
{{if .RegistryPath}}<div><strong>Registry path:</strong> <code>{{.RegistryPath}}</code></div>{{end}}
{{if .FilePath}}<div><strong>File path:</strong> <code>{{.FilePath}}</code></div>{{end}}
<div><strong>Type/mode:</strong> {{if .Type}}{{.Type}}{{else}}—{{end}} {{if .LastWriteTime}}| <strong>Last write:</strong> {{.LastWriteTime}}{{end}}</div>
{{if .UserWritable}}<div style="margin-top:8px;color:#fca5a5;"><strong>User-writable path:</strong> yes</div>{{end}}
{{if .ReviewHint}}<div style="margin-top:8px;color:#fbbf24;"><strong>Review hint:</strong> {{.ReviewHint}}</div>{{end}}
</div>{{end}}
<div class="card">
<a href="/cases/{{.Case.CaseUUID}}/artifact/persistence_hkcu_run">Raw HKCU Run</a> ·
<a href="/cases/{{.Case.CaseUUID}}/artifact/persistence_hkcu_runonce">Raw HKCU RunOnce</a> ·
<a href="/cases/{{.Case.CaseUUID}}/artifact/persistence_startup_folder">Raw Startup Folder</a>
</div>
</body></html>`

const logTemplate = `<!doctype html><html><head><title>Thoth Log View</title>` + pageStyle + `</head><body>
<p><a href="/cases/{{.Case.CaseUUID}}/logs">← Back to System Logs</a></p>
<h1>{{.Title}} — {{.Case.CaseID}}</h1>
<div class="card">
<div><strong>Host:</strong> {{.Case.Hostname}}</div>
<div><strong>Showing:</strong> {{.CurrentStart}}-{{.CurrentEnd}} of {{if .HasFilters}}{{.FilteredCount}} filtered / {{end}}{{.TotalCount}} collected event records</div>
<div><strong>Source artifact:</strong> <code>{{.PathSource}}</code></div>
</div>
<div class="card" style="border-left:4px solid #38bdf8;"><strong>Collection scope:</strong> {{.CollectionNote}}</div>
<div class="card">
<form method="get" action="/cases/{{.Case.CaseUUID}}/{{replace .ArtifactKey "_" "-"}}">
<input type="hidden" name="offset" value="0">
<div style="display:flex;gap:12px;flex-wrap:wrap;align-items:end;">
<div><strong>Search source/summary</strong><br><input type="text" name="source" value="{{.SourceQuery}}" placeholder="provider, event text, event ID" style="width:280px;background:#020617;color:#e2e8f0;border:1px solid #334155;padding:6px;border-radius:4px;"></div>
<div><strong>Event ID</strong><br><select name="event_id" style="width:140px;background:#020617;color:#e2e8f0;border:1px solid #334155;padding:6px;border-radius:4px;"><option value="">All IDs</option>{{range .AvailableEventIDs}}<option value="{{.}}"{{if eq $.EventIDFilter .}} selected{{end}}>{{.}}</option>{{end}}</select></div>
<div><strong>Level</strong><br><select name="level" style="width:180px;background:#020617;color:#e2e8f0;border:1px solid #334155;padding:6px;border-radius:4px;"><option value="">All levels</option>{{range .AvailableLevels}}<option value="{{.}}"{{if eq $.LevelFilter .}} selected{{end}}>{{.}}</option>{{end}}</select></div>
<div><button class="button-primary" type="submit">Apply</button></div>
<div><a href="/cases/{{.Case.CaseUUID}}/{{replace .ArtifactKey "_" "-"}}">Clear filters</a></div>
</div>
</form>
</div>
{{range .Events}}<div class="card">
<div><strong>{{if .Timestamp}}{{.Timestamp}}{{else}}—{{end}}</strong> <span style="color:#94a3b8;">Event ID {{if .EventID}}{{.EventID}}{{else}}—{{end}} | {{if .Level}}{{.Level}}{{else}}Unknown level{{end}}</span></div>
{{if .NearCollection}}<div style="margin-top:8px;padding:8px;border-left:4px solid #f59e0b;background:#451a03;color:#fde68a;"><strong>Collection-time hint:</strong> {{.CollectionHint}}</div>{{end}}
<div><strong>Provider / channel:</strong> {{if .Source}}{{.Source}}{{else}}—{{end}} / {{if .Channel}}{{.Channel}}{{else}}—{{end}}</div>
<div><strong>Summary:</strong> {{.Summary}}</div>
{{if .User}}<div><strong>User:</strong> {{.User}}</div>{{end}}
<details style="margin-top:8px;"><summary>Show raw event record</summary><pre style="margin-top:12px;">{{.RawJSON}}</pre></details>
</div>{{end}}
<div class="card">
{{if .HasPrev}}<a href="/cases/{{.Case.CaseUUID}}/{{replace .ArtifactKey "_" "-"}}?offset={{.PrevOffset}}{{if .LevelFilter}}&level={{.LevelFilter}}{{end}}{{if .EventIDFilter}}&event_id={{.EventIDFilter}}{{end}}{{if .SourceQuery}}&source={{.SourceQuery}}{{end}}">← Previous</a>{{end}}
{{if and .HasPrev .HasNext}} · {{end}}
{{if .HasNext}}<a href="/cases/{{.Case.CaseUUID}}/{{replace .ArtifactKey "_" "-"}}?offset={{.NextOffset}}{{if .LevelFilter}}&level={{.LevelFilter}}{{end}}{{if .EventIDFilter}}&event_id={{.EventIDFilter}}{{end}}{{if .SourceQuery}}&source={{.SourceQuery}}{{end}}">Load more / Next →</a>{{end}}
</div>
<div class="card"><a href="/cases/{{.Case.CaseUUID}}/artifact/{{.ArtifactKey}}">Open raw normalized log records</a></div>
</body></html>`

const systemLogsTemplate = `<!doctype html><html><head><title>Thoth System Logs</title>` + pageStyle + `</head><body>
<p><a href="/cases/{{.Case.CaseUUID}}">← Back to case</a></p>
<h1>System Logs — {{.Case.CaseID}}</h1>
<div class="card">
<div><strong>Host:</strong> {{.Case.Hostname}}</div>
<div>Use these logs for timeline context, event-ID pivots, script execution review, and security-tool clues.</div>
</div>
<div class="card" style="border-left:4px solid #38bdf8;"><strong>Collection scope:</strong> {{.CollectionNote}}</div>
{{range .Logs}}<div class="card">
<h2><a href="{{.URL}}">{{.Title}}</a></h2>
<div>{{.Hint}}</div>
<div style="margin-top:8px;color:#94a3b8;">{{.RecordCount}} collected record(s){{if .RequestedLimit}} from a request for up to {{.RequestedLimit}}{{end}}{{if .CollectorStatus}} · collector status: {{.CollectorStatus}}{{end}}</div>
{{if .SourceCommand}}<div style="margin-top:6px;color:#94a3b8;"><strong>Source command:</strong> <code>{{.SourceCommand}}</code></div>{{end}}
</div>{{end}}
</body></html>`

const networkTemplate = `<!doctype html><html><head><title>Thoth Network View</title>` + pageStyle + `</head><body>
<p><a href="/cases/{{.Case.CaseUUID}}">← Back to case</a></p>
<h1>Network View — {{.Case.CaseID}}</h1>
<div class="card">
<div><strong>Host:</strong> {{.Case.Hostname}}</div>
<div><strong>Showing:</strong> {{.FilteredCount}} of {{.TotalCount}} normalized network records</div>
</div>
<div class="card">
<form method="get" action="/cases/{{.Case.CaseUUID}}/network">
<div style="display:flex;gap:12px;flex-wrap:wrap;align-items:end;">
<div><strong>Search</strong><br><input type="text" name="q" value="{{.Query}}" placeholder="IP, port, process, protocol, service" style="width:260px;background:#020617;color:#e2e8f0;border:1px solid #334155;padding:6px;border-radius:4px;"></div>
<div><strong>IP</strong><br><input type="text" name="ip" value="{{.IPFocus}}" placeholder="54.224.94.179" style="width:170px;background:#020617;color:#e2e8f0;border:1px solid #334155;padding:6px;border-radius:4px;"></div>
<div><strong>Remote IP</strong><br><input type="text" name="remote" value="{{.RemoteFilter}}" placeholder="54.224" style="width:150px;background:#020617;color:#e2e8f0;border:1px solid #334155;padding:6px;border-radius:4px;"></div>
<div><strong>Port</strong><br><input type="text" name="port" value="{{.PortFocus}}" placeholder="443" style="width:100px;background:#020617;color:#e2e8f0;border:1px solid #334155;padding:6px;border-radius:4px;"></div>
<div><strong>State pivot</strong><br><select name="state" style="width:150px;background:#020617;color:#e2e8f0;border:1px solid #334155;padding:6px;border-radius:4px;"><option value="">All states</option>{{range .AvailableStates}}<option value="{{.}}"{{if eq $.StatePivot .}} selected{{end}}>{{.}}</option>{{end}}</select></div>
<div><strong>Protocol</strong><br><select name="protocol" style="width:120px;background:#020617;color:#e2e8f0;border:1px solid #334155;padding:6px;border-radius:4px;"><option value="">All</option><option value="TCP"{{if eq .ProtocolFilter "TCP"}} selected{{end}}>TCP</option><option value="UDP"{{if eq .ProtocolFilter "UDP"}} selected{{end}}>UDP</option></select></div>
<div><strong>Sort</strong><br><select name="sort" style="width:140px;background:#020617;color:#e2e8f0;border:1px solid #334155;padding:6px;border-radius:4px;"><option value=""{{if eq .SortKey ""}} selected{{end}}>Default</option><option value="remote"{{if eq .SortKey "remote"}} selected{{end}}>Remote IP</option><option value="pid"{{if eq .SortKey "pid"}} selected{{end}}>PID</option><option value="process"{{if eq .SortKey "process"}} selected{{end}}>Process</option><option value="state"{{if eq .SortKey "state"}} selected{{end}}>State</option></select></div>
<div><label><input type="checkbox" name="external" value="1"{{if .ExternalOnly}} checked{{end}}> Public remote only</label></div>
<div><button class="button-primary" type="submit">Apply</button></div>
{{if .HasQuery}}<div><a href="/cases/{{.Case.CaseUUID}}/network">Clear filters</a></div>{{end}}
</div>
</form>
</div>
<table><thead><tr><th>Protocol</th><th>Local</th><th>Remote</th><th>State</th><th>PID / process</th><th>Remote scope</th></tr></thead><tbody>
{{range .Connections}}<tr>
<td>{{.Protocol}}</td>
<td>{{.LocalIP}}{{if .LocalPort}}:{{.LocalPort}}{{end}}{{if .LocalService}}<br><span style="color:#94a3b8">{{.LocalService}}</span>{{end}}</td>
<td>{{.RemoteIP}}{{if .RemotePort}}:{{.RemotePort}}{{end}}{{if .RemoteService}}<br><span style="color:#94a3b8">{{.RemoteService}}</span>{{end}}</td>
<td>{{if .State}}{{.State}}{{else}}—{{end}}<br><span style="color:#94a3b8">{{.StateBucket}}</span></td>
<td>{{if .PID}}<a href="/cases/{{$.Case.CaseUUID}}/processes?pid={{.PID}}">{{.PID}}</a>{{else}}—{{end}}{{if .ProcessName}}<br><a style="color:#94a3b8" href="/cases/{{$.Case.CaseUUID}}/processes?q={{.ProcessName}}">{{.ProcessName}}</a>{{end}}</td>
<td>{{.RemoteScope}}{{if .LoopbackOnly}}<br><span style="color:#94a3b8">loopback only</span>{{end}}</td>
</tr>{{end}}
</tbody></table>
<div class="card"><a href="/cases/{{.Case.CaseUUID}}/artifact/network_connections">Open raw normalized network records</a></div>
</body></html>`

const quickStartTemplate = `<!doctype html><html><head><title>Thoth Quick Start</title>` + pageStyle + `</head><body>
<p><a href="/">← Back to home</a></p>
<h1>Thoth Quick Start</h1>
<div class="card">Operator guide loaded from <code>docs/thoth-quick-start.md</code>.</div>
<pre>{{.Content}}</pre>
</body></html>`

const userGuideTemplate = `<!doctype html><html><head><title>Thoth User Guide</title>` + pageStyle + `</head><body>
<p><a href="/">← Back to home</a></p>
<h1>Thoth User Guide</h1>
<div class="card">Analyst guide loaded from <code>docs/thoth-user-guide.md</code>. This page opens in a separate tab from the dashboard link so it can stay visible while reviewing a case.</div>
<pre>{{.Content}}</pre>
</body></html>`
