package adjacency

import (
	"strings"
	"testing"
	"time"

	"threatgraph/pkg/models"
)

func TestMapProcessAccessIncludesImageMappingsAndAccessData(t *testing.T) {
	m := NewMapper(MapperOptions{WriteVertexRows: true, IncludeEdgeData: false})
	e := &models.Event{
		Timestamp: time.Date(2026, 3, 5, 13, 0, 0, 0, time.UTC),
		EventID:   10,
		AgentID:   "agent-1",
		RecordID:  "rec-1",
		Fields: map[string]interface{}{
			"SourceProcessGuid": "{SRC}",
			"TargetProcessGuid": "{DST}",
			"SourceImage":       `C:\ProgramData\src.exe`,
			"TargetImage":       `C:\Windows\System32\lsass.exe`,
			"GrantedAccess":     "0x1fffff",
			"CallTrace":         "ntdll.dll+0x1",
		},
	}

	rows := m.Map(e)
	if len(rows) == 0 {
		t.Fatalf("expected mapped rows, got 0")
	}

	var processAccessEdge *models.AdjacencyRow
	edgeCount := 0
	for _, r := range rows {
		if r.RecordType == "edge" {
			edgeCount++
		}
		if r.RecordType == "edge" && r.Type == "ProcessAccessEdge" {
			processAccessEdge = r
		}
	}

	if processAccessEdge == nil {
		t.Fatalf("expected ProcessAccessEdge in mapped rows")
	}
	if edgeCount != 1 {
		t.Fatalf("expected exactly 1 edge row, got %d", edgeCount)
	}
	if processAccessEdge.Data == nil {
		t.Fatalf("expected ProcessAccessEdge data to include source/target image")
	}
	if processAccessEdge.Data["source_image"] != `C:\ProgramData\src.exe` {
		t.Fatalf("unexpected source_image: %v", processAccessEdge.Data["source_image"])
	}
	if processAccessEdge.Data["target_image"] != `C:\Windows\System32\lsass.exe` {
		t.Fatalf("unexpected target_image: %v", processAccessEdge.Data["target_image"])
	}
}

func TestMapParentEdgeKeepsIOATags(t *testing.T) {
	m := NewMapper(MapperOptions{WriteVertexRows: false, IncludeEdgeData: false})
	e := &models.Event{
		Timestamp: time.Date(2026, 3, 6, 2, 0, 0, 0, time.UTC),
		EventID:   1,
		AgentID:   "agent-1",
		RecordID:  "rec-2",
		IoaTags: []models.IoaTag{{
			Name:      "test-ioa",
			Severity:  "low",
			Tactic:    "execution",
			Technique: "T1059",
		}},
		Fields: map[string]interface{}{
			"ProcessGuid":       "{PROC}",
			"ParentProcessGuid": "{PARENT}",
			"Image":             `C:\ProgramData\sample.exe`,
			"CommandLine":       `C:\ProgramData\sample.exe -x`,
			"ParentImage":       `C:\Windows\explorer.exe`,
		},
	}

	rows := m.Map(e)
	if len(rows) == 0 {
		t.Fatalf("expected mapped rows, got 0")
	}

	var parentEdge *models.AdjacencyRow
	for _, r := range rows {
		if r == nil || r.RecordType != "edge" {
			continue
		}
		if r.Type == "ParentOfEdge" {
			parentEdge = r
		}
	}

	if parentEdge == nil {
		t.Fatalf("expected ParentOfEdge to be mapped")
	}
	if len(parentEdge.IoaTags) == 0 {
		t.Fatalf("expected ParentOfEdge to retain ioa tags")
	}
}

func TestMapOfflineEDRNoticeOnlyKeepsCreateProcess(t *testing.T) {
	m := NewMapper(MapperOptions{WriteVertexRows: false, IncludeEdgeData: false})

	noticeCreate := &models.Event{
		Timestamp: time.Date(2026, 3, 4, 15, 49, 3, 0, time.UTC),
		AgentID:   "agent-edr",
		RecordID:  "notice-create-1",
		IoaTags: []models.IoaTag{{
			Name:      "offline-edr-ioa",
			Severity:  "high",
			Tactic:    "persistence",
			Technique: "T1547",
		}},
		Raw: map[string]interface{}{
			"risk_level":       "notice",
			"operation":        "CreateProcess",
			"fltrname":         "CommonCreateProcess",
			"processuuid":      "{PARENT}",
			"processcp":        `C:\Windows\System32\services.exe`,
			"processcpuuid":    "{CP}",
			"rpcprocess":       `C:\Windows\System32\svchost.exe`,
			"rpcprocessuuid":   "{RPC}",
			"newprocessuuid":   "{CHILD}",
			"process":          `C:\Windows\System32\services.exe`,
			"newprocess":       `C:\Windows\System32\svchost.exe`,
			"command_line":     `C:\Windows\System32\services.exe`,
			"new_command_line": `C:\Windows\System32\svchost.exe -k netsvcs`,
		},
	}

	rows := m.Map(noticeCreate)
	if len(rows) == 0 {
		t.Fatalf("expected rows for notice CreateProcess")
	}

	hostKey := pickHost(noticeCreate)
	if hostKey == "" {
		t.Fatalf("expected host key for notice CreateProcess")
	}
	parentID := processVertexID(hostKey, "{PARENT}")
	cpID := processVertexID(hostKey, "{CP}")

	var hasParentEdge, hasCP, hasRPC bool
	for _, r := range rows {
		if r == nil || r.RecordType != "edge" {
			continue
		}
		if r.Type == "ParentOfEdge" {
			hasParentEdge = true
			if len(r.IoaTags) == 0 {
				t.Fatalf("expected ParentOfEdge to keep ioa tags")
			}
		}
		if r.Type == "ProcessCPEdge" {
			hasCP = true
			if !r.Timestamp.Equal(noticeCreate.Timestamp) {
				t.Fatalf("expected ProcessCPEdge timestamp to match source event, got %s want %s", r.Timestamp, noticeCreate.Timestamp)
			}
			if r.VertexID != cpID || r.AdjacentID != parentID {
				t.Fatalf("expected ProcessCPEdge %s -> %s, got %s -> %s", cpID, parentID, r.VertexID, r.AdjacentID)
			}
			if len(r.IoaTags) != 0 {
				t.Fatalf("expected ProcessCPEdge to drop ioa tags")
			}
		}
		if r.Type == "RPCTriggerEdge" {
			hasRPC = true
			if !r.Timestamp.Equal(noticeCreate.Timestamp) {
				t.Fatalf("expected RPCTriggerEdge timestamp to match source event, got %s want %s", r.Timestamp, noticeCreate.Timestamp)
			}
			if len(r.IoaTags) != 0 {
				t.Fatalf("expected RPCTriggerEdge to drop ioa tags")
			}
		}
	}
	if !hasParentEdge || !hasCP || !hasRPC {
		t.Fatalf("expected ParentOfEdge, ProcessCPEdge, RPCTriggerEdge; got rows=%v", rows)
	}

	noticeNonCreate := &models.Event{
		Timestamp: time.Date(2026, 3, 4, 15, 50, 0, 0, time.UTC),
		AgentID:   "agent-edr",
		RecordID:  "notice-non-create-1",
		Raw: map[string]interface{}{
			"risk_level":  "notice",
			"operation":   "CreateProcess",
			"processuuid": "{PROC}",
			"fltrname":    "OtherCreateProcess",
		},
	}
	if rows := m.Map(noticeNonCreate); len(rows) != 0 {
		t.Fatalf("expected no rows for notice CreateProcess without CommonCreateProcess fltrname, got %d", len(rows))
	}

	noticeWriteNewFile := &models.Event{
		Timestamp: time.Date(2026, 3, 4, 15, 51, 0, 0, time.UTC),
		AgentID:   "agent-edr",
		RecordID:  "notice-write-new-file-1",
		Raw: map[string]interface{}{
			"client_id":      "AA0000119100000427",
			"risk_level":     "notice",
			"operation":      "WriteComplete",
			"fltrname":       "WriteNewFile.ExcuteFile",
			"processuuid":    "{SUBJ}",
			"process":        `C:\Program Files\Tencent\Weixin\Weixin.exe`,
			"command_line":   `C:\Program Files\Tencent\Weixin\Weixin.exe --scene=desktop`,
			"file":           `C:\Users\Administrator\AppData\LocalLow\SogouPY\temp.dll`,
			"processcpuuid":  "{CP}",
			"processcp":      `C:\Windows\explorer.exe`,
			"rpcprocessuuid": "{RPC}",
			"rpcprocess":     `C:\Windows\svchost.exe`,
		},
	}
	rows = m.Map(noticeWriteNewFile)
	if len(rows) == 0 {
		t.Fatalf("expected rows for notice WriteNewFile.ExcuteFile")
	}
	var hasFileWrite bool
	for _, r := range rows {
		if r == nil || r.RecordType != "edge" {
			continue
		}
		switch r.Type {
		case "FileWriteEdge":
			hasFileWrite = true
		case "ProcessCPEdge", "RPCTriggerEdge":
			if !r.Timestamp.Equal(noticeWriteNewFile.Timestamp) {
				t.Fatalf("expected cp/rpc edge timestamp to match source event, got %s want %s", r.Timestamp, noticeWriteNewFile.Timestamp)
			}
		}
	}
	if !hasFileWrite {
		t.Fatalf("expected FileWriteEdge for notice WriteNewFile.ExcuteFile")
	}
}

func TestMapOfflineEDRNonNoticeAddsProcessCPAndRPCTrigger(t *testing.T) {
	m := NewMapper(MapperOptions{WriteVertexRows: false, IncludeEdgeData: false})
	e := &models.Event{
		Timestamp: time.Date(2026, 3, 4, 16, 3, 52, 0, time.UTC),
		AgentID:   "agent-edr",
		RecordID:  "non-notice-1",
		Raw: map[string]interface{}{
			"risk_level":     "high",
			"operation":      "SetValueKey",
			"processuuid":    "{SUBJ}",
			"process":        `C:\Windows\System32\lsass.exe`,
			"rpcprocess":     `C:\Windows\System32\spoolsv.exe`,
			"rpcprocessuuid": "{RPC}",
			"processcp":      `C:\Windows\System32\services.exe`,
			"processcpuuid":  "{CP}",
		},
	}

	rows := m.Map(e)
	if len(rows) == 0 {
		t.Fatalf("expected rows for non-notice event")
	}

	var hasRPCTrigger, hasCPEdge bool
	for _, r := range rows {
		if r == nil || r.RecordType != "edge" {
			continue
		}
		switch r.Type {
		case "RPCTriggerEdge":
			hasRPCTrigger = true
			if !r.Timestamp.Equal(e.Timestamp) {
				t.Fatalf("expected RPCTriggerEdge timestamp to match source event, got %s want %s", r.Timestamp, e.Timestamp)
			}
		case "ProcessCPEdge":
			hasCPEdge = true
			if !r.Timestamp.Equal(e.Timestamp) {
				t.Fatalf("expected ProcessCPEdge timestamp to match source event, got %s want %s", r.Timestamp, e.Timestamp)
			}
		}
	}

	if !hasRPCTrigger {
		t.Fatalf("expected RPCTriggerEdge")
	}
	if !hasCPEdge {
		t.Fatalf("expected ProcessCPEdge")
	}
}

func TestMapOfflineEDRNonNoticeSkipsCPAndRPCWithoutUUID(t *testing.T) {
	m := NewMapper(MapperOptions{WriteVertexRows: false, IncludeEdgeData: false})
	e := &models.Event{
		Timestamp: time.Date(2026, 3, 4, 16, 4, 0, 0, time.UTC),
		AgentID:   "agent-edr",
		RecordID:  "non-notice-no-uuid",
		Raw: map[string]interface{}{
			"risk_level":  "high",
			"operation":   "SetValueKey",
			"processuuid": "{SUBJ}",
			"process":     `C:\Windows\System32\lsass.exe`,
			"rpcprocess":  `C:\Windows\System32\spoolsv.exe`,
			"processcp":   `C:\Windows\System32\services.exe`,
			"keyname":     `\REGISTRY\MACHINE\SOFTWARE\Test`,
		},
	}

	rows := m.Map(e)
	if len(rows) == 0 {
		t.Fatalf("expected rows for non-notice event")
	}

	for _, r := range rows {
		if r == nil || r.RecordType != "edge" {
			continue
		}
		if r.Type == "RPCTriggerEdge" || r.Type == "ProcessCPEdge" || r.Type == "RPCTriggerImageEdge" || r.Type == "ProcessCPImageEdge" {
			t.Fatalf("expected no cp/rpc relation edge without uuid, got %s", r.Type)
		}
	}
}

func TestMapOfflineEDRSkipsRPCWhenSubjectAndRPCUUIDEqual(t *testing.T) {
	m := NewMapper(MapperOptions{WriteVertexRows: false, IncludeEdgeData: false})
	e := &models.Event{
		Timestamp: time.Date(2026, 3, 4, 16, 5, 0, 0, time.UTC),
		AgentID:   "agent-edr",
		RecordID:  "non-notice-same-rpc-uuid",
		Raw: map[string]interface{}{
			"risk_level":     "high",
			"operation":      "SetValueKey",
			"processuuid":    "{ABC-123}",
			"process":        `C:\Windows\System32\lsass.exe`,
			"rpcprocess":     `C:\Windows\System32\spoolsv.exe`,
			"rpcprocessuuid": "abc-123",
			"keyname":        `\REGISTRY\MACHINE\SOFTWARE\Test`,
		},
	}

	rows := m.Map(e)
	if len(rows) == 0 {
		t.Fatalf("expected rows for non-notice event")
	}

	for _, r := range rows {
		if r == nil || r.RecordType != "edge" {
			continue
		}
		if r.Type == "RPCTriggerEdge" {
			t.Fatalf("expected no RPCTriggerEdge when processuuid == rpcprocessuuid")
		}
	}
}

func TestMapOfflineEDRPrefersClientIDAsHostKey(t *testing.T) {
	m := NewMapper(MapperOptions{WriteVertexRows: false, IncludeEdgeData: false})
	e := &models.Event{
		Timestamp: time.Date(2026, 3, 4, 16, 6, 0, 0, time.UTC),
		AgentID:   "agent-should-not-win",
		Hostname:  "hostname-should-not-win",
		RecordID:  "non-notice-client-id-host-key",
		Raw: map[string]interface{}{
			"client_id":   "AA0000119100000427",
			"risk_level":  "high",
			"operation":   "SetValueKey",
			"processuuid": "{SUBJ}",
			"process":     `C:\Windows\System32\lsass.exe`,
			"keyname":     `\REGISTRY\MACHINE\SOFTWARE\Test`,
		},
	}

	rows := m.Map(e)
	if len(rows) == 0 {
		t.Fatalf("expected rows for non-notice event")
	}

	found := false
	for _, r := range rows {
		if r == nil || r.RecordType != "edge" {
			continue
		}
		if strings.HasPrefix(r.VertexID, "proc:aa0000119100000427:") || strings.HasPrefix(r.AdjacentID, "proc:aa0000119100000427:") {
			found = true
		}
		if strings.HasPrefix(r.VertexID, "proc:agent-should-not-win:") || strings.HasPrefix(r.AdjacentID, "proc:agent-should-not-win:") {
			t.Fatalf("expected client_id host key, got agent id in vertex ids")
		}
	}
	if !found {
		t.Fatalf("expected proc vertex ids keyed by client_id")
	}
}

func TestMapOfflineEDRNonNoticeSkipsPortAttack(t *testing.T) {
	m := NewMapper(MapperOptions{WriteVertexRows: false, IncludeEdgeData: false})
	e := &models.Event{
		Timestamp: time.Date(2026, 3, 4, 16, 7, 0, 0, time.UTC),
		RecordID:  "portattack-skip",
		Raw: map[string]interface{}{
			"client_id":   "AA0000119100000427",
			"risk_level":  "high",
			"operation":   "PortAttack",
			"processuuid": "{SUBJ}",
			"process":     `C:\Windows\System32\svchost.exe`,
		},
	}
	if rows := m.Map(e); len(rows) != 0 {
		t.Fatalf("expected PortAttack to be skipped, got %d rows", len(rows))
	}
}

func TestMapOfflineEDRNonNoticeAddsSubjectObjectEdges(t *testing.T) {
	m := NewMapper(MapperOptions{WriteVertexRows: false, IncludeEdgeData: false})
	e := &models.Event{
		Timestamp: time.Date(2026, 3, 4, 16, 8, 0, 0, time.UTC),
		RecordID:  "non-notice-objects",
		Raw: map[string]interface{}{
			"client_id":         "AA0000119100000427",
			"risk_level":        "high",
			"operation":         "SetValueKey",
			"processuuid":       "{SUBJ}",
			"process":           `C:\Windows\System32\lsass.exe`,
			"targetprocessuuid": "{TGT}",
			"targetprocess":     `C:\Windows\System32\winlogon.exe`,
			"file":              `C:\ProgramData\dropper.exe`,
			"newimage":          `C:\ProgramData\evil.dll`,
			"keyname":           `\REGISTRY\MACHINE\SOFTWARE\Test`,
			"valuename":         `Start`,
			"valuetype":         `3`,
			"remoteip":          `8.8.8.8`,
			"remoteport":        `443`,
		},
	}

	rows := m.Map(e)
	if len(rows) == 0 {
		t.Fatalf("expected rows for non-notice object mapping")
	}

	seen := map[string]bool{}
	for _, r := range rows {
		if r == nil || r.RecordType != "edge" {
			continue
		}
		seen[r.Type] = true
		if r.Type == "ImageLoadEdge" && !strings.HasPrefix(r.VertexID, "path:aa0000119100000427:") {
			t.Fatalf("expected module path to point to subject via client_id-scoped path vertex")
		}
	}
	for _, typ := range []string{"TargetProcessEdge", "FileAccessEdge", "ImageLoadEdge", "RegistrySetValueEdge", "ConnectEdge"} {
		if !seen[typ] {
			t.Fatalf("expected edge type %s to be present", typ)
		}
	}
}

func TestMapOfflineEDRProcessModificationShellcodeExecuteAlwaysSelfTargets(t *testing.T) {
	m := NewMapper(MapperOptions{WriteVertexRows: false, IncludeEdgeData: false})
	e := &models.Event{
		Timestamp: time.Date(2026, 3, 4, 16, 10, 0, 0, time.UTC),
		RecordID:  "shellcode-self-target",
		Raw: map[string]interface{}{
			"client_id":         "AA0000119100000427",
			"risk_level":        "high",
			"datasource":        "DS0009.Process.Modification",
			"operation":         "AdvancedDetect",
			"fltrname":          "ShellcodeExecute",
			"processuuid":       "{SELF}",
			"targetprocessuuid": "{OTHER}",
			"process":           `C:\Windows\explorer.exe`,
		},
	}

	rows := m.Map(e)
	if len(rows) == 0 {
		t.Fatalf("expected rows for ShellcodeExecute self-target case")
	}
	for _, r := range rows {
		if r == nil || r.RecordType != "edge" || r.Type != "TargetProcessEdge" {
			continue
		}
		if r.AdjacentID != "proc:aa0000119100000427:{self}" {
			t.Fatalf("expected self target proc id, got %s", r.AdjacentID)
		}
		return
	}
	t.Fatalf("expected TargetProcessEdge for ShellcodeExecute")
}

func TestMapOfflineEDRProcessModificationHollowingAlwaysSelfTargets(t *testing.T) {
	m := NewMapper(MapperOptions{WriteVertexRows: false, IncludeEdgeData: false})
	e := &models.Event{
		Timestamp: time.Date(2026, 3, 4, 16, 11, 0, 0, time.UTC),
		RecordID:  "hollowing-self-target",
		Raw: map[string]interface{}{
			"client_id":         "AA0000119100000427",
			"risk_level":        "high",
			"datasource":        "DS0009.Process.Modification",
			"operation":         "AdvancedDetect",
			"fltrname":          "Hollowing",
			"processuuid":       "{SELF2}",
			"targetprocessuuid": "{OTHER2}",
			"process":           `C:\Windows\explorer.exe`,
		},
	}

	rows := m.Map(e)
	if len(rows) == 0 {
		t.Fatalf("expected rows for Hollowing self-target case")
	}
	for _, r := range rows {
		if r == nil || r.RecordType != "edge" || r.Type != "TargetProcessEdge" {
			continue
		}
		if r.AdjacentID != "proc:aa0000119100000427:{self2}" {
			t.Fatalf("expected self target proc id, got %s", r.AdjacentID)
		}
		return
	}
	t.Fatalf("expected TargetProcessEdge for Hollowing")
}
