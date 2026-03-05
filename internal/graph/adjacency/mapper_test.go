package adjacency

import (
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
