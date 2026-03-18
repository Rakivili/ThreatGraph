package sysmon

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"threatgraph/internal/logger"
	"threatgraph/pkg/models"
)

var missingWinlogEventDataCount uint64

type textValue string

func (v *textValue) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		*v = ""
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*v = textValue(strings.TrimSpace(s))
		return nil
	}
	var i int64
	if err := json.Unmarshal(data, &i); err == nil {
		*v = textValue(fmt.Sprintf("%d", i))
		return nil
	}
	var f float64
	if err := json.Unmarshal(data, &f); err == nil {
		if f == float64(int64(f)) {
			*v = textValue(fmt.Sprintf("%d", int64(f)))
		} else {
			*v = textValue(fmt.Sprintf("%f", f))
		}
		return nil
	}
	var b bool
	if err := json.Unmarshal(data, &b); err == nil {
		if b {
			*v = "true"
		} else {
			*v = "false"
		}
		return nil
	}
	*v = ""
	return nil
}

type eventEnvelope struct {
	Timestamp       textValue       `json:"@timestamp"`
	Time            textValue       `json:"time"`
	DetectTime      textValue       `json:"t_detect_time"`
	ShortTime       textValue       `json:"t"`
	EventID         json.RawMessage `json:"event_id"`
	ClientID        textValue       `json:"client_id"`
	ExtDetectionID  textValue       `json:"ext_detection_id"`
	Hash            textValue       `json:"@hash"`
	RMLogUUID       textValue       `json:"rm_log_uuid"`
	RiskLevel       textValue       `json:"risk_level"`
	Operation       textValue       `json:"operation"`
	Fltrname        textValue       `json:"fltrname"`
	AlertName       textValue       `json:"alert_name"`
	NameKey         textValue       `json:"name_key"`
	ExtRuleID       textValue       `json:"ext_process_rule_id"`
	AttackTactic    textValue       `json:"attack.tactic"`
	AttackTech      textValue       `json:"attack.technique"`
	ProcessGuid     textValue       `json:"ProcessGuid"`
	NewProcessUUID  textValue       `json:"newprocessuuid"`
	NewProcUUIDAlt  textValue       `json:"new_process_uuid"`
	Image           textValue       `json:"Image"`
	NewProcess      textValue       `json:"newprocess"`
	NewProcessAlt   textValue       `json:"new_process"`
	CommandLine     textValue       `json:"CommandLine"`
	NewCommandLine  textValue       `json:"new_command_line"`
	NewCmdAlt       textValue       `json:"newcommandline"`
	ParentProcGuid  textValue       `json:"ParentProcessGuid"`
	ProcessUUID     textValue       `json:"processuuid"`
	ParentProcUUID  textValue       `json:"parent_processuuid"`
	ParentImage     textValue       `json:"ParentImage"`
	Process         textValue       `json:"process"`
	ParentProcess   textValue       `json:"parent_process"`
	ParentCmdLine   textValue       `json:"ParentCommandLine"`
	CommandLineAlt  textValue       `json:"command_line"`
	File            textValue       `json:"file"`
	FilePath        textValue       `json:"filepath"`
	FileName        textValue       `json:"filename"`
	TargetFilename  textValue       `json:"TargetFilename"`
	ProcessCPUUID   textValue       `json:"processcpuuid"`
	RPCProcessUUID  textValue       `json:"rpcprocessuuid"`
	NewImage        textValue       `json:"newimage"`
	ModuleILPath    textValue       `json:"moduleilpath"`
	ModuleName      textValue       `json:"modulename"`
	KeyName         textValue       `json:"keyname"`
	RegistryPath    textValue       `json:"registry_path"`
	RegPath         textValue       `json:"reg_path"`
	ValueName       textValue       `json:"valuename"`
	ValueNameAlt    textValue       `json:"value_name"`
	ValueType       textValue       `json:"valuetype"`
	DestinationIP   textValue       `json:"DestinationIp"`
	RemoteIP        textValue       `json:"remoteip"`
	DstIP           textValue       `json:"dstip"`
	DestinationPort textValue       `json:"DestinationPort"`
	RemotePort      textValue       `json:"remoteport"`
	DstPort         textValue       `json:"dstport"`
	ObjectUUID      textValue       `json:"objectuuid"`
	TargetProcGuid  textValue       `json:"TargetProcessGuid"`
	TargetProcUUID  textValue       `json:"targetprocessuuid"`
	TargetProcess   textValue       `json:"targetprocess"`
	Object          textValue       `json:"object"`
	Winlog          struct {
		EventID   json.RawMessage `json:"event_id"`
		Channel   textValue       `json:"channel"`
		RecordID  textValue       `json:"record_id"`
		EventData json.RawMessage `json:"event_data"`
	} `json:"winlog"`
	Agent struct {
		ID textValue `json:"id"`
	} `json:"agent"`
	Host struct {
		Name     textValue `json:"name"`
		Hostname textValue `json:"hostname"`
	} `json:"host"`
	Event struct {
		Code json.RawMessage `json:"code"`
	} `json:"event"`
}

// Parse converts a winlogbeat Sysmon event into a normalized Event.
func Parse(data []byte) (*models.Event, error) {
	var env eventEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, err
	}

	event := &models.Event{
		Fields: make(map[string]interface{}),
		Lookup: make(map[string]string, 48),
	}

	event.EventID = firstIntRaw(env.Winlog.EventID, env.Event.Code, env.EventID)
	event.AgentID = firstText(env.Agent.ID, env.ClientID)
	event.Hostname = firstText(env.Host.Name, env.Host.Hostname)
	event.Channel = string(env.Winlog.Channel)
	event.RecordID = firstText(env.Winlog.RecordID, env.ExtDetectionID, env.Hash, env.RMLogUUID)

	if len(env.Winlog.EventData) > 0 && string(env.Winlog.EventData) != "null" && string(env.Winlog.EventData) != "{}" {
		_ = json.Unmarshal(env.Winlog.EventData, &event.Fields)
	}
	populateLookup(event.Lookup, env)
	if utcValue := getString(event.Fields, "UtcTime"); utcValue != "" {
		if t, ok := parseUtcTime(utcValue); ok {
			event.Timestamp = t
		}
	}
	if event.Timestamp.IsZero() {
		if ts := firstText(env.Timestamp, env.Time, env.DetectTime, env.ShortTime); ts != "" {
			if t, ok := parseUtcTime(ts); ok {
				event.Timestamp = t
			}
		}
	}
	if len(event.Fields) == 0 {
		atomic.AddUint64(&missingWinlogEventDataCount, 1)
	}
	return event, nil
}

func populateLookup(dst map[string]string, env eventEnvelope) {
	set := func(k string, v textValue) {
		if strings.TrimSpace(string(v)) != "" {
			dst[k] = strings.TrimSpace(string(v))
		}
	}
	set("client_id", env.ClientID)
	set("risk_level", env.RiskLevel)
	set("operation", env.Operation)
	set("fltrname", env.Fltrname)
	set("alert_name", env.AlertName)
	set("name_key", env.NameKey)
	set("ext_process_rule_id", env.ExtRuleID)
	set("attack.tactic", env.AttackTactic)
	set("attack.technique", env.AttackTech)
	set("ProcessGuid", env.ProcessGuid)
	set("newprocessuuid", env.NewProcessUUID)
	set("new_process_uuid", env.NewProcUUIDAlt)
	set("Image", env.Image)
	set("newprocess", env.NewProcess)
	set("new_process", env.NewProcessAlt)
	set("CommandLine", env.CommandLine)
	set("new_command_line", env.NewCommandLine)
	set("newcommandline", env.NewCmdAlt)
	set("ParentProcessGuid", env.ParentProcGuid)
	set("processuuid", env.ProcessUUID)
	set("parent_processuuid", env.ParentProcUUID)
	set("ParentImage", env.ParentImage)
	set("process", env.Process)
	set("parent_process", env.ParentProcess)
	set("ParentCommandLine", env.ParentCmdLine)
	set("command_line", env.CommandLineAlt)
	set("file", env.File)
	set("filepath", env.FilePath)
	set("filename", env.FileName)
	set("TargetFilename", env.TargetFilename)
	set("processcpuuid", env.ProcessCPUUID)
	set("rpcprocessuuid", env.RPCProcessUUID)
	set("newimage", env.NewImage)
	set("moduleilpath", env.ModuleILPath)
	set("modulename", env.ModuleName)
	set("keyname", env.KeyName)
	set("registry_path", env.RegistryPath)
	set("reg_path", env.RegPath)
	set("valuename", env.ValueName)
	set("value_name", env.ValueNameAlt)
	set("valuetype", env.ValueType)
	set("DestinationIp", env.DestinationIP)
	set("remoteip", env.RemoteIP)
	set("dstip", env.DstIP)
	set("DestinationPort", env.DestinationPort)
	set("remoteport", env.RemotePort)
	set("dstport", env.DstPort)
	set("objectuuid", env.ObjectUUID)
	set("TargetProcessGuid", env.TargetProcGuid)
	set("targetprocessuuid", env.TargetProcUUID)
	set("targetprocess", env.TargetProcess)
	set("object", env.Object)
}

func firstText(values ...textValue) string {
	for _, v := range values {
		if strings.TrimSpace(string(v)) != "" {
			return strings.TrimSpace(string(v))
		}
	}
	return ""
}

func firstIntRaw(values ...json.RawMessage) int {
	for _, raw := range values {
		if len(raw) == 0 || string(raw) == "null" {
			continue
		}
		var i int
		if err := json.Unmarshal(raw, &i); err == nil {
			return i
		}
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			var parsed int
			if _, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &parsed); err == nil {
				return parsed
			}
		}
	}
	return 0
}

func ResetStats() {
	atomic.StoreUint64(&missingWinlogEventDataCount, 0)
}

func MissingWinlogEventDataCount() uint64 {
	return atomic.LoadUint64(&missingWinlogEventDataCount)
}

func LogStats() {
	if n := MissingWinlogEventDataCount(); n > 0 {
		logger.Infof("Sysmon parser saw %d event(s) without winlog.event_data", n)
	}
}

func firstRawString(raw map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := raw[k]; ok && v != nil {
			s := strings.TrimSpace(fmt.Sprintf("%v", v))
			if s != "" {
				return s
			}
		}
	}
	return ""
}

func parseUtcTime(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}

	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, value); err == nil {
			return t.UTC(), true
		}
	}

	for _, layout := range []string{
		"2006-01-02 15:04:05.000000000",
		"2006-01-02 15:04:05.0000000",
		"2006-01-02 15:04:05.000000",
		"2006-01-02 15:04:05.000",
		"2006-01-02 15:04:05",
	} {
		if t, err := time.ParseInLocation(layout, value, time.UTC); err == nil {
			return t.UTC(), true
		}
	}

	return time.Time{}, false
}

func getString(root map[string]interface{}, paths ...string) string {
	for _, path := range paths {
		if v, ok := getPath(root, path); ok {
			switch val := v.(type) {
			case string:
				return val
			case fmt.Stringer:
				return val.String()
			case int:
				return fmt.Sprintf("%d", val)
			case int64:
				return fmt.Sprintf("%d", val)
			case float64:
				if val == float64(int64(val)) {
					return fmt.Sprintf("%d", int64(val))
				}
				return fmt.Sprintf("%f", val)
			}
		}
	}
	return ""
}

func getInt(root map[string]interface{}, paths ...string) int {
	for _, path := range paths {
		if v, ok := getPath(root, path); ok {
			switch val := v.(type) {
			case int:
				return val
			case int64:
				return int(val)
			case float64:
				return int(val)
			case string:
				if val == "" {
					continue
				}
				var parsed int
				_, err := fmt.Sscanf(val, "%d", &parsed)
				if err == nil {
					return parsed
				}
			}
		}
	}
	return 0
}

func getPath(root map[string]interface{}, path string) (interface{}, bool) {
	parts := strings.Split(path, ".")
	var current interface{} = root
	for _, part := range parts {
		m, ok := current.(map[string]interface{})
		if !ok {
			return nil, false
		}
		v, ok := m[part]
		if !ok {
			return nil, false
		}
		current = v
	}
	return current, true
}
