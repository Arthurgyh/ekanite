package input

import (
	"fmt"
	"strings"
)

var (
	fmtsByStandard = []string{"rfc5424", "NginxError", "NginxAccess"}
	fmtsByName     = []string{"syslog", "nginxerror", "nginxaccess"}
)

// ValidFormat returns if the given format matches one of the possible formats.
func ValidFormat(format string) bool {
	for _, f := range append(fmtsByStandard, fmtsByName...) {
		if f == format {
			return true
		}
	}
	return false
}

type SyslogParser interface {
	parse(raw []byte, result *map[string]interface{})
}

// A Parser parses the raw input as a map with a timestamp field.
type Parser struct {
	fmt          string
	Raw          []byte
	Result       map[string]interface{}
	syslogParser SyslogParser
}

// NewParser returns a new Parser instance.
func NewParser(f string) (*Parser, error) {
	//	fmt.Printf("-----collect fmt for: %s", f)

	if !ValidFormat(f) {
		return nil, fmt.Errorf("%s is not a valid format", f)
	}

	p := &Parser{}
	var logger = strings.TrimSpace(strings.ToLower(f))

	p.detectFmt(logger)
	fmt.Printf("-----detectFmt: %s - %s - %s ?== %s\n\n", f, logger, p.fmt, fmtsByStandard[1])

	if p.fmt == fmtsByStandard[0] {
		p.newRFC5424Parser()
	} else {
		p.newNginxParser(p.fmt)
	}
	return p, nil
}

// Reads the given format and detects its internal name.
func (p *Parser) detectFmt(f string) {

	//	if f == fmtsByName[0] {
	//		p.fmt = fmtsByStandard[0] //already ok
	//		return
	//	}

	for i, v := range fmtsByName {
		if f == v {
			p.fmt = fmtsByStandard[i]
			return
		}
	}
	for _, v := range fmtsByStandard {
		if f == v {
			p.fmt = v
			return
		}
	}
	fmt.Printf("invalidParserFormat:%s\n", f)
	stats.Add("invalidParserFormat", 1)
	p.fmt = fmtsByStandard[0]
	return
}

// Parse the given byte slice.
func (p *Parser) Parse(b []byte) bool {
	p.Result = map[string]interface{}{}
	p.Raw = b
	p.syslogParser.parse(p.Raw, &p.Result)
	if len(p.Result) == 0 {
		return false
	}
	return true
}
