package adjacency

import (
	"fmt"
	"strings"

	"threatgraph/internal/logger"
	"threatgraph/pkg/models"
)

const (
	recordVertex = "vertex"
	recordEdge   = "edge"
)

// Mapper converts events into adjacency rows.
type Mapper struct {
	writeVertexRows bool
	includeEdgeData bool
}

// MapperOptions controls mapper output size and fidelity.
type MapperOptions struct {
	WriteVertexRows bool
	IncludeEdgeData bool
}

// NewMapper creates a mapper.
func NewMapper(opts MapperOptions) *Mapper {
	return &Mapper{
		writeVertexRows: opts.WriteVertexRows,
		includeEdgeData: opts.IncludeEdgeData,
	}
}

// Map converts a single event into adjacency rows.
func (m *Mapper) Map(event *models.Event) []*models.AdjacencyRow {
	if event == nil {
		return nil
	}
	if event.Timestamp.IsZero() {
		logger.Errorf("Skipping event without valid UtcTime (event_id=%d, record_id=%s, host=%s, agent_id=%s)", event.EventID, event.RecordID, event.Hostname, event.AgentID)
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
		rows = attachIOATags(rows, event.IoaTags)
	}

	return rows
}

func attachIOATags(rows []*models.AdjacencyRow, tags []models.IoaTag) []*models.AdjacencyRow {
	if len(rows) == 0 || len(tags) == 0 {
		return rows
	}

	for _, row := range rows {
		if row == nil || row.RecordType != recordEdge {
			continue
		}
		row.IoaTags = append([]models.IoaTag(nil), tags...)
	}

	return rows
}

func (m *Mapper) mapProcessCreate(event *models.Event) []*models.AdjacencyRow {
	procGuid := event.Field("ProcessGuid")
	if procGuid == "" {
		return nil
	}

	host := pickHost(event)
	procID := processVertexID(host, procGuid)

	rows := make([]*models.AdjacencyRow, 0, 3)

	if m.writeVertexRows {
		rows = append(rows, vertexRow("ProcessVertex", procID, event, map[string]interface{}{
			"image":               event.Field("Image"),
			"process_path":        event.Field("Image"),
			"command_line":        event.Field("CommandLine"),
			"parent_image":        event.Field("ParentImage"),
			"parent_process_path": event.Field("ParentImage"),
			"parent_command_line": event.Field("ParentCommandLine"),
		}))
	}

	if parentGuid := event.Field("ParentProcessGuid"); parentGuid != "" {
		parentID := processVertexID(host, parentGuid)
		if m.writeVertexRows {
			rows = append(rows, vertexRow("ProcessVertex", parentID, event, map[string]interface{}{
				"image":        event.Field("ParentImage"),
				"process_path": event.Field("ParentImage"),
				"command_line": event.Field("ParentCommandLine"),
			}))
		}
		rows = append(rows, edgeRow("ParentOfEdge", parentID, procID, event, nil, m.includeEdgeData))
	}

	if image := event.Field("Image"); image != "" {
		pathID := filePathVertexID(host, image)
		if m.writeVertexRows {
			rows = append(rows, vertexRow("FilePathVertex", pathID, event, nil))
		}
		rows = append(rows, edgeRow("ImageOfEdge", pathID, procID, event, nil, m.includeEdgeData))
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
	rows := make([]*models.AdjacencyRow, 0, 2)
	if m.writeVertexRows {
		rows = append(rows, vertexRow("ProcessVertex", procID, event, processVertexData(event)))
		rows = append(rows, vertexRow("FilePathVertex", pathID, event, nil))
	}
	rows = append(rows, edgeRow("CreatedFileEdge", procID, pathID, event, nil, m.includeEdgeData))

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

	rows := make([]*models.AdjacencyRow, 0, 3)
	if m.writeVertexRows {
		rows = append(rows, vertexRow("ProcessVertex", procID, event, processVertexData(event)))
		rows = append(rows, vertexRow("FilePathVertex", pathID, event, nil))
	}
	rows = append(rows, edgeRow("ImageLoadEdge", pathID, procID, event, nil, m.includeEdgeData))
	return rows
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
	rows := make([]*models.AdjacencyRow, 0, 2)
	if m.writeVertexRows {
		rows = append(rows, vertexRow("ProcessVertex", procID, event, processVertexData(event)))
		rows = append(rows, vertexRow("NetworkVertex", netID, event, nil))
	}
	rows = append(rows, edgeRow("ConnectEdge", procID, netID, event, nil, m.includeEdgeData))
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
	rows := make([]*models.AdjacencyRow, 0, 2)
	if m.writeVertexRows {
		rows = append(rows, vertexRow("ProcessVertex", procID, event, processVertexData(event)))
		rows = append(rows, vertexRow("DomainVertex", domainID, event, nil))
	}
	rows = append(rows, edgeRow("DNSQueryEdge", procID, domainID, event, nil, m.includeEdgeData))
	return rows
}

func (m *Mapper) mapRemoteThread(event *models.Event) []*models.AdjacencyRow {
	sourceGUID := event.Field("SourceProcessGuid")
	targetGUID := event.Field("TargetProcessGuid")
	sourceID := processVertexID(pickHost(event), sourceGUID)
	targetID := processVertexID(pickHost(event), targetGUID)
	if sourceID == "" || targetID == "" {
		return nil
	}
	rows := make([]*models.AdjacencyRow, 0, 3)
	if m.writeVertexRows {
		rows = append(rows, vertexRow("ProcessVertex", sourceID, event, processVertexDataFromFields(event, "SourceImage", "SourceCommandLine", "")))
		rows = append(rows, vertexRow("ProcessVertex", targetID, event, processVertexDataFromFields(event, "TargetImage", "TargetCommandLine", "")))
	}
	rows = append(rows, edgeRow("RemoteThreadEdge", sourceID, targetID, event, nil, m.includeEdgeData))
	return rows
}

func (m *Mapper) mapProcessAccess(event *models.Event) []*models.AdjacencyRow {
	sourceGUID := event.Field("SourceProcessGuid")
	targetGUID := event.Field("TargetProcessGuid")
	sourceID := processVertexID(pickHost(event), sourceGUID)
	targetID := processVertexID(pickHost(event), targetGUID)
	if sourceID == "" || targetID == "" {
		return nil
	}
	rows := make([]*models.AdjacencyRow, 0, 3)
	if m.writeVertexRows {
		rows = append(rows, vertexRow("ProcessVertex", sourceID, event, processVertexDataFromFields(event, "SourceImage", "SourceCommandLine", "")))
		rows = append(rows, vertexRow("ProcessVertex", targetID, event, processVertexDataFromFields(event, "TargetImage", "TargetCommandLine", "")))
	}
	rows = append(rows, edgeRow("ProcessAccessEdge", sourceID, targetID, event, nil, m.includeEdgeData))
	return rows
}

func vertexRow(rowType, vertexID string, event *models.Event, data map[string]interface{}) *models.AdjacencyRow {
	return baseRow(event, recordVertex, rowType, vertexID, "", data)
}

func edgeRow(rowType, vertexID, adjacentID string, event *models.Event, data map[string]interface{}, includeEdgeData bool) *models.AdjacencyRow {
	if includeEdgeData && data == nil {
		data = map[string]interface{}{
			"fields": event.Fields,
		}
	}
	return baseRow(event, recordEdge, rowType, vertexID, adjacentID, data)
}

func baseRow(event *models.Event, recordType, rowType, vertexID, adjacentID string, data map[string]interface{}) *models.AdjacencyRow {
	return &models.AdjacencyRow{
		Timestamp:  event.Timestamp,
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

func processVertexData(event *models.Event) map[string]interface{} {
	return processVertexDataFromFields(event, "Image", "CommandLine", "ParentImage")
}

func processVertexDataFromFields(event *models.Event, imageField, commandLineField, parentImageField string) map[string]interface{} {
	image := strings.TrimSpace(event.Field(imageField))
	commandLine := strings.TrimSpace(event.Field(commandLineField))
	parentImage := strings.TrimSpace(event.Field(parentImageField))

	if image == "" && commandLine == "" && parentImage == "" {
		return nil
	}

	data := map[string]interface{}{}
	if image != "" {
		data["image"] = image
		data["process_path"] = image
	}
	if commandLine != "" {
		data["command_line"] = commandLine
	}
	if parentImage != "" {
		data["parent_image"] = parentImage
		data["parent_process_path"] = parentImage
	}
	return data
}
