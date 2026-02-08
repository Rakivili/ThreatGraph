package models

import (
	"fmt"
	"time"
)

// Event represents a Sysmon event.
type Event struct {
	Timestamp time.Time              `json:"@timestamp"`
	EventID   int                    `json:"event_id"`
	AgentID   string                 `json:"agent_id"`
	Hostname  string                 `json:"hostname"`
	Channel   string                 `json:"channel,omitempty"`
	RecordID  string                 `json:"record_id,omitempty"`
	Fields    map[string]interface{} `json:"fields"`
	IoaTags   []IoaTag               `json:"ioa_tags,omitempty"`

	Raw map[string]interface{} `json:"-"`
}

// Field returns a field value.
func (e *Event) Field(name string) string {
	if e == nil || e.Fields == nil {
		return ""
	}
	if v, ok := e.Fields[name]; ok {
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
		case bool:
			if val {
				return "true"
			}
			return "false"
		default:
			return fmt.Sprintf("%v", val)
		}
	}
	return ""
}

// ProcessGuid returns the ProcessGuid field.
func (e *Event) ProcessGuid() string {
	return e.Field("ProcessGuid")
}

// SourceProcessGuid returns the SourceProcessGuid field.
func (e *Event) SourceProcessGuid() string {
	return e.Field("SourceProcessGuid")
}

// GroupGuid returns the grouping GUID and the field name used.
func (e *Event) GroupGuid() (string, string) {
	if v := e.ProcessGuid(); v != "" {
		return v, "ProcessGuid"
	}
	if v := e.SourceProcessGuid(); v != "" {
		return v, "SourceProcessGuid"
	}
	return "", ""
}
