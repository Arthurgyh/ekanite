package input

import (
	"fmt"
	//	"regexp"
	"strconv"

	"github.com/Arthurgyh/syslog"
)

// RFC5424 represents a parser for RFC5424-compliant log messages
type NginxLogParser struct {
	logType string
}

func (p *Parser) newNginxParser(logger string) {
	var nginxParser = &NginxLogParser{logType: logger}
	//rfc5424.compileMatcher()
	p.syslogParser = nginxParser
}

func (s *NginxLogParser) doParse(raw []byte) (*syslog.Message, error) {
	switch s.logType {
	case fmtsByStandard[1]:
		fmt.Printf("enter 1: %s", s.logType)
		return syslog.ParseMessage(raw, syslog.NginxError)
		break
	default: //case "NginxAccess":
		fmt.Printf("enter 2 NginxAccess: %s", s.logType)
		return syslog.ParseMessage(raw, syslog.NginxAccess)
		break
	}
	return nil, fmt.Errorf("Unkonw format.")
}

func (s *NginxLogParser) parse(raw []byte, result *map[string]interface{}) {
	msg, err := syslog.ParseMessage(raw, syslog.NginxAccess)
	if err != nil || msg == nil {
		stats.Add(s.logType+"Unparsed", 1)
		return
	}
	stats.Add(s.logType+"Parsed", 1)

	pri := int(msg.Priority)
	ver := int(msg.Version)
	var pid int

	if msg.ProcessID != "-" {
		pid, _ = strconv.Atoi(msg.ProcessID)
	}
	*result = map[string]interface{}{
		"priority":   pri,
		"version":    ver,
		"timestamp":  msg.Timestamp,
		"host":       msg.Hostname,
		"app":        msg.Appname,
		"pid":        pid,
		"message_id": msg.MessageID,
		"message":    msg.Message,
	}
}
