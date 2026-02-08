package adjacency

import (
	"fmt"
	"strings"
	"time"

	"threatgraph/pkg/models"
)

const (
	recordVertex = "vertex"
	recordEdge   = "edge"
)

// Mapper converts events into adjacency rows.
type Mapper struct{}

// NewMapper creates a mapper.
func NewMapper() *Mapper {
	return &Mapper{}
}

// Map converts a single event into adjacency rows.
func (m *Mapper) Map(event *models.Event) []*models.AdjacencyRow {
	if event == nil {
		return nil
	}
	var rows []*models.AdjacencyRow
	switch event.EventID {
	case 1:
		rows = m.mapProcessCreate(event)
	case 3:
		rows = m.mapNetworkConnect(event)
	case 7:
		rows = m.mapImageLoad(event)
	case 8:
		rows = m.mapRemoteThread(event)
	case 10:
		rows = m.mapProcessAccess(event)
	case 11:
		rows = m.mapFileCreate(event)
	case 22:
		rows = m.mapDNSQuery(event)
	default:
		rows = nil
	}

	if len(event.IoaTags) > 0 {
		if event.EventID == 1 {
			for _, row := range rows {
				if row != nil && row.RecordType == recordVertex && row.Type == "ProcessVertex" {
					row.IoaTags = event.IoaTags
					break
				}
			}
		} else {
			if ioaRow := m.processIoaVertex(event); ioaRow != nil {
				rows = append(rows, ioaRow)
			}
		}
	}

	return rows
}

func (m *Mapper) processIoaVertex(event *models.Event) *models.AdjacencyRow {
	procID, ok := processIDFromEvent(event)
	if !ok {
		return nil
	}
	row := vertexRow("ProcessVertex", procID, event, map[string]interface{}{
		"ioa_event_id": event.EventID,
	})
	row.IoaTags = event.IoaTags
	return row
}

func (m *Mapper) mapProcessCreate(event *models.Event) []*models.AdjacencyRow {
	procGuid := event.Field("ProcessGuid")
	if procGuid == "" {
		return nil
	}

	host := pickHost(event)
	procID := processVertexID(host, procGuid)

	rows := []*models.AdjacencyRow{
		vertexRow("ProcessVertex", procID, event, map[string]interface{}{
			"image":           event.Field("Image"),
			"command_line":    event.Field("CommandLine"),
			"parent_guid":     event.Field("ParentProcessGuid"),
			"parent_image":    event.Field("ParentImage"),
			"user":            event.Field("User"),
			"integrity_level": event.Field("IntegrityLevel"),
			"hashes":          event.Field("Hashes"),
			"product":         event.Field("Product"),
		}),
	}

	if parentGuid := event.Field("ParentProcessGuid"); parentGuid != "" {
		parentID := processVertexID(host, parentGuid)
		rows = append(rows, edgeRow("ParentOfEdge", parentID, procID, event, nil))
	}

	if image := event.Field("Image"); image != "" {
		pathID := filePathVertexID(host, image)
		rows = append(rows, edgeRow("ImageOfEdge", pathID, procID, event, nil))
	}

	return rows
}

func (m *Mapper) mapFileCreate(event *models.Event) []*models.AdjacencyRow {
	procID, ok := processIDFromEvent(event)
	if !ok {
		return nil
	}

	target := firstField(event, "TargetFilename", "TargetFileName", "TargetFilename", "Image")
	if target == "" {
		return nil
	}

	host := pickHost(event)
	pathID := filePathVertexID(host, target)
	rows := []*models.AdjacencyRow{
		vertexRow("FilePathVertex", pathID, event, map[string]interface{}{
			"path": target,
		}),
		edgeRow("CreatedFileEdge", procID, pathID, event, nil),
	}

	return rows
}

func (m *Mapper) mapImageLoad(event *models.Event) []*models.AdjacencyRow {
	procID, ok := processIDFromEvent(event)
	if !ok {
		return nil
	}
	imageLoaded := firstField(event, "ImageLoaded", "ImageLoaded", "Image")
	if imageLoaded == "" {
		return nil
	}
	host := pickHost(event)
	pathID := filePathVertexID(host, imageLoaded)

	return []*models.AdjacencyRow{
		edgeRow("ImageLoadEdge", procID, pathID, event, nil),
	}
}

func (m *Mapper) mapNetworkConnect(event *models.Event) []*models.AdjacencyRow {
	procID, ok := processIDFromEvent(event)
	if !ok {
		return nil
	}
	ip := firstField(event, "DestinationIp", "DestinationIP", "DestinationIp")
	port := firstField(event, "DestinationPort")
	if ip == "" {
		return nil
	}
	netID := networkVertexID(ip, port)
	rows := []*models.AdjacencyRow{
		vertexRow("NetworkVertex", netID, event, map[string]interface{}{
			"ip":   ip,
			"port": port,
		}),
		edgeRow("ConnectEdge", procID, netID, event, nil),
	}
	return rows
}

func (m *Mapper) mapDNSQuery(event *models.Event) []*models.AdjacencyRow {
	procID, ok := processIDFromEvent(event)
	if !ok {
		return nil
	}
	name := firstField(event, "QueryName", "QueryName", "Query")
	if name == "" {
		return nil
	}
	domainID := domainVertexID(name)
	rows := []*models.AdjacencyRow{
		vertexRow("DomainVertex", domainID, event, map[string]interface{}{
			"domain": name,
		}),
		edgeRow("DNSQueryEdge", procID, domainID, event, nil),
	}
	return rows
}

func (m *Mapper) mapRemoteThread(event *models.Event) []*models.AdjacencyRow {
	sourceID := processVertexID(pickHost(event), event.Field("SourceProcessGuid"))
	targetID := processVertexID(pickHost(event), event.Field("TargetProcessGuid"))
	if sourceID == "" || targetID == "" {
		return nil
	}
	return []*models.AdjacencyRow{
		edgeRow("RemoteThreadEdge", sourceID, targetID, event, nil),
	}
}

func (m *Mapper) mapProcessAccess(event *models.Event) []*models.AdjacencyRow {
	sourceID := processVertexID(pickHost(event), event.Field("SourceProcessGuid"))
	targetID := processVertexID(pickHost(event), event.Field("TargetProcessGuid"))
	if sourceID == "" || targetID == "" {
		return nil
	}
	return []*models.AdjacencyRow{
		edgeRow("ProcessAccessEdge", sourceID, targetID, event, nil),
	}
}

func vertexRow(rowType, vertexID string, event *models.Event, data map[string]interface{}) *models.AdjacencyRow {
	return baseRow(event, recordVertex, rowType, vertexID, "", data)
}

func edgeRow(rowType, vertexID, adjacentID string, event *models.Event, data map[string]interface{}) *models.AdjacencyRow {
	if data == nil {
		data = map[string]interface{}{
			"fields": event.Fields,
		}
	}
	return baseRow(event, recordEdge, rowType, vertexID, adjacentID, data)
}

func baseRow(event *models.Event, recordType, rowType, vertexID, adjacentID string, data map[string]interface{}) *models.AdjacencyRow {
	ts := event.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	if data == nil {
		data = map[string]interface{}{}
	}
	return &models.AdjacencyRow{
		Timestamp:  ts,
		RecordType: recordType,
		Type:       rowType,
		VertexID:   vertexID,
		AdjacentID: adjacentID,
		EventID:    event.EventID,
		Hostname:   pickHost(event),
		AgentID:    event.AgentID,
		RecordID:   event.RecordID,
		Data:       data,
	}
}

func pickHost(event *models.Event) string {
	if event.Hostname != "" {
		return event.Hostname
	}
	return event.AgentID
}

func processIDFromEvent(event *models.Event) (string, bool) {
	guid := event.Field("ProcessGuid")
	if guid == "" {
		guid = event.Field("SourceProcessGuid")
	}
	if guid == "" {
		return "", false
	}
	return processVertexID(pickHost(event), guid), true
}

func processVertexID(host, guid string) string {
	if host == "" || guid == "" {
		return ""
	}
	return fmt.Sprintf("proc:%s:%s", strings.ToLower(host), strings.ToLower(guid))
}

func filePathVertexID(host, path string) string {
	if host == "" || path == "" {
		return ""
	}
	return fmt.Sprintf("path:%s:%s", strings.ToLower(host), strings.ToLower(path))
}

func fileHashVertexID(hash string) string {
	if hash == "" {
		return ""
	}
	return fmt.Sprintf("file:sha256:%s", strings.ToLower(hash))
}

func domainVertexID(domain string) string {
	if domain == "" {
		return ""
	}
	return fmt.Sprintf("domain:%s", strings.ToLower(domain))
}

func networkVertexID(ip, port string) string {
	if port != "" {
		return fmt.Sprintf("net:%s:%s", strings.ToLower(ip), port)
	}
	return fmt.Sprintf("net:%s", strings.ToLower(ip))
}

func extractHash(hashes, key string) string {
	if hashes == "" {
		return ""
	}
	key = strings.ToUpper(key) + "="
	parts := strings.Split(hashes, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), key) {
			return strings.TrimSpace(part[len(key):])
		}
	}
	return ""
}

func firstField(event *models.Event, names ...string) string {
	for _, name := range names {
		if v := event.Field(name); v != "" {
			return v
		}
	}
	return ""
}
