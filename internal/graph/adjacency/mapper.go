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
	if rows, handled := m.mapEDROffline(event); handled {
		if len(event.IoaTags) > 0 {
			rows = attachIOATags(rows, event.IoaTags)
		}
		return rows
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

func (m *Mapper) mapEDROffline(event *models.Event) ([]*models.AdjacencyRow, bool) {
	risk := strings.ToLower(strings.TrimSpace(edrField(event, "risk_level")))
	if risk == "" {
		return nil, false
	}
	operation := strings.TrimSpace(edrField(event, "operation"))
	if risk == "notice" {
		if strings.EqualFold(operation, "CreateProcess") && strings.EqualFold(strings.TrimSpace(edrField(event, "fltrname")), "CommonCreateProcess") {
			return m.mapEDRNoticeProcessCreate(event), true
		}
		if strings.EqualFold(operation, "WriteComplete") && strings.EqualFold(strings.TrimSpace(edrField(event, "fltrname")), "WriteNewFile.ExcuteFile") {
			return m.mapEDRNoticeWriteNewFileExecuteFile(event), true
		}
		return nil, true
	}
	if strings.EqualFold(operation, "PortAttack") {
		return nil, true
	}
	return m.mapEDRNonNotice(event), true
}

func (m *Mapper) mapEDRNoticeProcessCreate(event *models.Event) []*models.AdjacencyRow {
	childGUID := firstField(event,
		"ProcessGuid",
		"newprocessuuid",
		"new_process_uuid",
	)
	if childGUID == "" {
		return nil
	}
	host := pickHost(event)
	childID := processVertexID(host, childGUID)
	if childID == "" {
		return nil
	}

	childImage := firstField(event, "Image", "newprocess", "new_process")
	childCommandLine := firstField(event, "CommandLine", "new_command_line", "newcommandline")
	creatorGUID := firstField(event, "ParentProcessGuid", "processuuid", "parent_processuuid")
	parentImage := firstField(event, "ParentImage", "process", "parent_process")
	parentCommandLine := firstField(event, "ParentCommandLine", "command_line")

	rows := make([]*models.AdjacencyRow, 0, 4)
	if m.writeVertexRows {
		rows = append(rows, vertexRow("ProcessVertex", childID, event, map[string]interface{}{
			"image":               childImage,
			"process_path":        childImage,
			"command_line":        childCommandLine,
			"parent_image":        parentImage,
			"parent_process_path": parentImage,
			"parent_command_line": parentCommandLine,
		}))
	}

	creatorID := ""
	if creatorGUID != "" {
		creatorID = processVertexID(host, creatorGUID)
		if creatorID != "" && creatorID != childID {
			if m.writeVertexRows {
				rows = append(rows, vertexRow("ProcessVertex", creatorID, event, map[string]interface{}{
					"image":        parentImage,
					"process_path": parentImage,
					"command_line": parentCommandLine,
				}))
			}
			rows = append(rows, edgeRow("ParentOfEdge", creatorID, childID, event, nil, m.includeEdgeData))
		}
	}

	if creatorID != "" {
		rows = m.appendOfflineProcessCPEdges(rows, event, creatorID)
	}
	if creatorID != "" {
		rows = m.appendOfflineRPCTriggerEdges(rows, event, creatorID)
	}

	return rows
}

func (m *Mapper) mapEDRNoticeWriteNewFileExecuteFile(event *models.Event) []*models.AdjacencyRow {
	host := pickHost(event)
	subjectGUID := firstField(event, "ProcessGuid", "processuuid")
	targetPath := firstField(event, "file", "filepath", "filename", "TargetFilename")
	if host == "" || subjectGUID == "" || targetPath == "" {
		return nil
	}
	subjectID := processVertexID(host, subjectGUID)
	if subjectID == "" {
		return nil
	}
	pathID := filePathVertexID(host, targetPath)
	if pathID == "" {
		return nil
	}

	rows := make([]*models.AdjacencyRow, 0, 4)
	if m.writeVertexRows {
		rows = append(rows, vertexRow("ProcessVertex", subjectID, event, processVertexDataFromRaw(event, "process", "command_line")))
		rows = append(rows, vertexRow("FilePathVertex", pathID, event, nil))
	}
	rows = append(rows, edgeRow("FileWriteEdge", subjectID, pathID, event, nil, m.includeEdgeData))
	rows = m.appendOfflineProcessCPEdges(rows, event, subjectID)
	rows = m.appendOfflineRPCTriggerEdges(rows, event, subjectID)
	return rows
}

func (m *Mapper) mapEDRNonNotice(event *models.Event) []*models.AdjacencyRow {
	host := pickHost(event)
	subjectGUID := firstField(event, "ProcessGuid", "processuuid")
	if subjectGUID == "" {
		return nil
	}
	subjectID := processVertexID(host, subjectGUID)
	if subjectID == "" {
		return nil
	}

	subjectImage := firstField(event, "Image", "process")
	subjectCommandLine := firstField(event, "CommandLine", "command_line")
	rows := make([]*models.AdjacencyRow, 0, 6)

	if m.writeVertexRows {
		rows = append(rows, vertexRow("ProcessVertex", subjectID, event, map[string]interface{}{
			"image":        subjectImage,
			"process_path": subjectImage,
			"command_line": subjectCommandLine,
		}))
	}

	rows = m.appendOfflineProcessCPEdges(rows, event, subjectID)
	rows = m.appendOfflineRPCTriggerEdges(rows, event, subjectID)
	rows = m.appendOfflineTargetProcessEdges(rows, event, subjectID)
	rows = m.appendOfflineFileEdges(rows, event, subjectID)
	rows = m.appendOfflineModuleEdges(rows, event, subjectID)
	rows = m.appendOfflineRegistryEdges(rows, event, subjectID)
	rows = m.appendOfflineNetworkEdges(rows, event, subjectID)

	return rows
}

func (m *Mapper) appendOfflineProcessCPEdges(rows []*models.AdjacencyRow, event *models.Event, targetProcID string) []*models.AdjacencyRow {
	host := pickHost(event)
	if targetProcID == "" || host == "" {
		return rows
	}

	if cpGUID := strings.TrimSpace(edrField(event, "processcpuuid")); cpGUID != "" {
		cpID := processVertexID(host, cpGUID)
		if cpID != "" && cpID != targetProcID {
			if m.writeVertexRows {
				rows = append(rows, vertexRow("ProcessVertex", cpID, event, processVertexDataFromRaw(event, "processcp", "")))
			}
			rows = append(rows, edgeRow("ProcessCPEdge", cpID, targetProcID, event, nil, m.includeEdgeData))
		}
	}

	return rows
}

func (m *Mapper) appendOfflineRPCTriggerEdges(rows []*models.AdjacencyRow, event *models.Event, targetProcID string) []*models.AdjacencyRow {
	host := pickHost(event)
	if targetProcID == "" || host == "" {
		return rows
	}
	targetGUID := normalizeGUIDForCompare(firstField(event, "ProcessGuid", "processuuid", "newprocessuuid"))

	if rpcGUID := strings.TrimSpace(edrField(event, "rpcprocessuuid")); rpcGUID != "" {
		if targetGUID != "" && normalizeGUIDForCompare(rpcGUID) == targetGUID {
			return rows
		}
		rpcID := processVertexID(host, rpcGUID)
		if rpcID != "" && rpcID != targetProcID {
			if m.writeVertexRows {
				rows = append(rows, vertexRow("ProcessVertex", rpcID, event, processVertexDataFromRaw(event, "rpcprocess", "")))
			}
			rows = append(rows, edgeRow("RPCTriggerEdge", rpcID, targetProcID, event, nil, m.includeEdgeData))
		}
	}

	return rows
}

func (m *Mapper) appendOfflineTargetProcessEdges(rows []*models.AdjacencyRow, event *models.Event, subjectID string) []*models.AdjacencyRow {
	host := pickHost(event)
	targetGUID := offlineTargetProcessGUID(event)
	if host == "" || subjectID == "" || targetGUID == "" {
		return rows
	}
	targetID := processVertexID(host, targetGUID)
	if targetID == "" {
		return rows
	}
	if m.writeVertexRows {
		rows = append(rows, vertexRow("ProcessVertex", targetID, event, offlineTargetProcessData(event)))
	}
	rows = append(rows, edgeRow("TargetProcessEdge", subjectID, targetID, event, nil, m.includeEdgeData))
	return rows
}

func (m *Mapper) appendOfflineFileEdges(rows []*models.AdjacencyRow, event *models.Event, subjectID string) []*models.AdjacencyRow {
	host := pickHost(event)
	targetPath := firstField(event, "file", "filepath", "filename")
	if host == "" || subjectID == "" || targetPath == "" {
		return rows
	}
	pathID := filePathVertexID(host, targetPath)
	if pathID == "" {
		return rows
	}
	if m.writeVertexRows {
		rows = append(rows, vertexRow("FilePathVertex", pathID, event, nil))
	}
	rows = append(rows, edgeRow("FileAccessEdge", subjectID, pathID, event, nil, m.includeEdgeData))
	return rows
}

func (m *Mapper) appendOfflineModuleEdges(rows []*models.AdjacencyRow, event *models.Event, subjectID string) []*models.AdjacencyRow {
	host := pickHost(event)
	modulePath := firstField(event, "newimage", "moduleilpath", "modulename")
	if host == "" || subjectID == "" || modulePath == "" {
		return rows
	}
	pathID := filePathVertexID(host, modulePath)
	if pathID == "" {
		return rows
	}
	if m.writeVertexRows {
		rows = append(rows, vertexRow("FilePathVertex", pathID, event, nil))
	}
	rows = append(rows, edgeRow("ImageLoadEdge", pathID, subjectID, event, nil, m.includeEdgeData))
	return rows
}

func (m *Mapper) appendOfflineRegistryEdges(rows []*models.AdjacencyRow, event *models.Event, subjectID string) []*models.AdjacencyRow {
	host := pickHost(event)
	keyName := firstField(event, "keyname", "registry_path", "reg_path")
	if host == "" || subjectID == "" || keyName == "" {
		return rows
	}
	valueName := firstField(event, "valuename", "value_name")
	keyID := registryKeyVertexID(host, keyName)
	if valueName != "" {
		valueID := registryValueVertexID(host, keyName, valueName)
		if m.writeVertexRows {
			rows = append(rows, vertexRow("RegistryValueVertex", valueID, event, registryValueData(event, keyName, valueName)))
		}
		rows = append(rows, edgeRow("RegistrySetValueEdge", subjectID, valueID, event, nil, m.includeEdgeData))
		return rows
	}
	if m.writeVertexRows {
		rows = append(rows, vertexRow("RegistryKeyVertex", keyID, event, registryKeyData(keyName)))
	}
	rows = append(rows, edgeRow("RegistryKeyEdge", subjectID, keyID, event, nil, m.includeEdgeData))
	return rows
}

func (m *Mapper) appendOfflineNetworkEdges(rows []*models.AdjacencyRow, event *models.Event, subjectID string) []*models.AdjacencyRow {
	ip := firstField(event, "DestinationIp", "remoteip", "dstip")
	port := firstField(event, "DestinationPort", "remoteport", "dstport")
	if subjectID == "" || ip == "" {
		return rows
	}
	netID := networkVertexID(ip, port)
	if m.writeVertexRows {
		rows = append(rows, vertexRow("NetworkVertex", netID, event, nil))
	}
	rows = append(rows, edgeRow("ConnectEdge", subjectID, netID, event, nil, m.includeEdgeData))
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
		if skipIOATagEdgeType(row.Type) {
			continue
		}
		row.IoaTags = append([]models.IoaTag(nil), tags...)
	}

	return rows
}

func skipIOATagEdgeType(edgeType string) bool {
	t := strings.TrimSpace(edgeType)
	if strings.HasPrefix(t, "RPC") {
		return true
	}
	if strings.HasPrefix(t, "ProcessCP") {
		return true
	}
	return false
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
	host := pickHost(event)
	sourceGUID := event.Field("SourceProcessGuid")
	targetGUID := event.Field("TargetProcessGuid")
	sourceID := processVertexID(host, sourceGUID)
	targetID := processVertexID(host, targetGUID)
	if sourceID == "" || targetID == "" {
		return nil
	}
	rows := make([]*models.AdjacencyRow, 0, 3)
	if m.writeVertexRows {
		rows = append(rows, vertexRow("ProcessVertex", sourceID, event, processVertexDataFromFields(event, "SourceImage", "SourceCommandLine", "")))
		rows = append(rows, vertexRow("ProcessVertex", targetID, event, processVertexDataFromFields(event, "TargetImage", "TargetCommandLine", "")))
	}
	rows = append(rows, edgeRow("ProcessAccessEdge", sourceID, targetID, event, processAccessImageData(event), m.includeEdgeData))
	return rows
}

func processAccessImageData(event *models.Event) map[string]interface{} {
	sourceImage := strings.TrimSpace(event.Field("SourceImage"))
	targetImage := strings.TrimSpace(event.Field("TargetImage"))
	if sourceImage == "" && targetImage == "" {
		return nil
	}
	data := map[string]interface{}{}
	if sourceImage != "" {
		data["source_image"] = sourceImage
	}
	if targetImage != "" {
		data["target_image"] = targetImage
	}
	return data
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
	if clientID := strings.TrimSpace(edrField(event, "client_id")); clientID != "" {
		return clientID
	}
	if event.AgentID != "" {
		return event.AgentID
	}
	return event.Hostname
}

func processIDFromEvent(event *models.Event) (string, bool) {
	guid := firstField(event, "ProcessGuid", "processuuid", "newprocessuuid")
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

func registryKeyVertexID(host, key string) string {
	if host == "" || key == "" {
		return ""
	}
	return fmt.Sprintf("regkey:%s:%s", strings.ToLower(host), strings.ToLower(key))
}

func registryValueVertexID(host, key, value string) string {
	if host == "" || key == "" || value == "" {
		return ""
	}
	return fmt.Sprintf("regval:%s:%s|%s", strings.ToLower(host), strings.ToLower(key), strings.ToLower(value))
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
		if v := edrField(event, name); v != "" {
			return v
		}
	}
	return ""
}

func edrField(event *models.Event, key string) string {
	if event == nil {
		return ""
	}
	if event.Lookup != nil {
		if v, ok := event.Lookup[key]; ok {
			return v
		}
	}
	if event.Raw != nil {
		if v, ok := event.Raw[key]; ok {
			if s := strings.TrimSpace(fmt.Sprintf("%v", v)); s != "" {
				return s
			}
		}
	}
	return ""
}

func processVertexDataFromRaw(event *models.Event, imageKey, commandKey string) map[string]interface{} {
	image := strings.TrimSpace(edrField(event, imageKey))
	command := strings.TrimSpace(edrField(event, commandKey))
	if image == "" && command == "" {
		return nil
	}
	data := map[string]interface{}{}
	if image != "" {
		data["image"] = image
		data["process_path"] = image
	}
	if command != "" {
		data["command_line"] = command
	}
	return data
}

func registryKeyData(keyName string) map[string]interface{} {
	if strings.TrimSpace(keyName) == "" {
		return nil
	}
	return map[string]interface{}{"keyname": keyName}
}

func registryValueData(event *models.Event, keyName, valueName string) map[string]interface{} {
	data := map[string]interface{}{}
	if strings.TrimSpace(keyName) != "" {
		data["keyname"] = keyName
	}
	if strings.TrimSpace(valueName) != "" {
		data["valuename"] = valueName
	}
	if valueType := strings.TrimSpace(edrField(event, "valuetype")); valueType != "" {
		data["valuetype"] = valueType
	}
	if len(data) == 0 {
		return nil
	}
	return data
}

func offlineTargetProcessGUID(event *models.Event) string {
	fltrName := strings.TrimSpace(edrField(event, "fltrname"))
	if strings.EqualFold(fltrName, "ObOpenProcess") {
		return firstField(event, "objectuuid")
	}
	if strings.EqualFold(fltrName, "ShellcodeExecute") || strings.EqualFold(fltrName, "Hollowing") {
		return firstField(event, "ProcessGuid", "processuuid")
	}
	targetGUID := firstField(event, "TargetProcessGuid", "targetprocessuuid")
	if strings.TrimSpace(targetGUID) != "" {
		return targetGUID
	}
	return ""
}

func offlineTargetProcessData(event *models.Event) map[string]interface{} {
	fltrName := strings.TrimSpace(edrField(event, "fltrname"))
	if strings.EqualFold(fltrName, "ObOpenProcess") {
		return processVertexDataFromRaw(event, "object", "")
	}
	return processVertexDataFromRaw(event, "targetprocess", "")
}

func normalizeGUIDForCompare(v string) string {
	s := strings.ToLower(strings.TrimSpace(v))
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimSuffix(s, "}")
	return strings.TrimSpace(s)
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
