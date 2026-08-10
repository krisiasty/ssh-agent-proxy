package service

import (
	"encoding/xml"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestRenderSystemdUnitEscapesArguments(t *testing.T) {
	executable := `/opt/SSH Agent "Proxy" 100% & <prod>/$bin`
	cfgPath := `/home/test/Config 'quoted' "double" 50% & <prod>/$config.yaml`

	unit := renderSystemdUnit(executable, cfgPath, 17)
	var execStart string
	for _, line := range strings.Split(unit, "\n") {
		if value, ok := strings.CutPrefix(line, "ExecStart="); ok {
			execStart = value
			break
		}
	}
	if execStart == "" {
		t.Fatal("rendered unit has no ExecStart directive")
	}

	args, err := parseSystemdArguments(execStart)
	if err != nil {
		t.Fatalf("parseSystemdArguments() error = %v", err)
	}
	wantArgs := []string{executable, "-config", cfgPath, "--cache", "17"}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Errorf("ExecStart arguments = %#v, want %#v", args, wantArgs)
	}
	if !strings.Contains(execStart, "100%%") || !strings.Contains(execStart, "50%%") {
		t.Errorf("ExecStart does not escape systemd percent specifiers: %s", execStart)
	}
	if !strings.Contains(execStart, "$$bin") || !strings.Contains(execStart, "$$config") {
		t.Errorf("ExecStart does not escape systemd variable expansion: %s", execStart)
	}

	program, err := parseSystemdExecStartBinary(unit)
	if err != nil {
		t.Fatalf("parseSystemdExecStartBinary() error = %v", err)
	}
	if program != executable {
		t.Errorf("program = %q, want %q", program, executable)
	}
}

func TestParseSystemdExecStartBinarySupportsLegacyUnit(t *testing.T) {
	program, err := parseSystemdExecStartBinary("[Service]\nExecStart=/usr/local/bin/ssh-agent-proxy -config /tmp/config.yaml\n")
	if err != nil {
		t.Fatalf("parseSystemdExecStartBinary() error = %v", err)
	}
	if want := "/usr/local/bin/ssh-agent-proxy"; program != want {
		t.Errorf("program = %q, want %q", program, want)
	}
}

func TestParseSystemdExecStartBinaryRejectsMalformedCommand(t *testing.T) {
	if _, err := parseSystemdExecStartBinary("[Service]\nExecStart=\"unterminated\n"); err == nil {
		t.Fatal("parseSystemdExecStartBinary() error = nil, want malformed command error")
	}
}

func TestRenderLaunchdPlistEscapesValues(t *testing.T) {
	label := `io.github.example.ssh&agent<proxy>`
	executable := `/Applications/SSH Agent "Proxy" 100% & <prod>/proxy`
	cfgPath := `/Users/test/Config 'quoted' "double" 50% & <prod>/config.yaml`
	logPath := `/Users/test/Library/Logs/SSH & Agent <proxy>.log`
	wantArgs := []string{executable, "-config", cfgPath, "--cache", "17"}

	data, err := renderLaunchdPlist(label, wantArgs, logPath)
	if err != nil {
		t.Fatalf("renderLaunchdPlist() error = %v", err)
	}

	var decoded struct {
		XMLName xml.Name `xml:"plist"`
		Version string   `xml:"version,attr"`
		Dict    struct {
			Keys             []string `xml:"key"`
			Strings          []string `xml:"string"`
			ProgramArguments []string `xml:"array>string"`
		} `xml:"dict"`
	}
	if err := xml.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("xml.Unmarshal() error = %v\n%s", err, data)
	}
	if decoded.XMLName.Local != "plist" || decoded.Version != "1.0" {
		t.Errorf("plist root = %q version %q, want plist version 1.0", decoded.XMLName.Local, decoded.Version)
	}
	if !reflect.DeepEqual(decoded.Dict.ProgramArguments, wantArgs) {
		t.Errorf("ProgramArguments = %#v, want %#v", decoded.Dict.ProgramArguments, wantArgs)
	}
	if want := []string{label, logPath, logPath}; !reflect.DeepEqual(decoded.Dict.Strings, want) {
		t.Errorf("top-level string values = %#v, want %#v", decoded.Dict.Strings, want)
	}
	for _, escaped := range []string{"&amp;", "&lt;", "&gt;"} {
		if !strings.Contains(string(data), escaped) {
			t.Errorf("plist does not contain XML escape %q:\n%s", escaped, data)
		}
	}
	for _, element := range []string{"<true/>", "<false/>"} {
		if !strings.Contains(string(data), element) {
			t.Errorf("plist does not contain canonical boolean element %q:\n%s", element, data)
		}
	}
	for _, invalid := range []string{"<true></true>", "<false></false>"} {
		if strings.Contains(string(data), invalid) {
			t.Errorf("plist contains launchd-incompatible boolean element %q:\n%s", invalid, data)
		}
	}
}

func TestParseLaunchdProgramUnescapesProgram(t *testing.T) {
	program := `/Applications/SSH Agent "Proxy" 100% & <prod>/proxy`
	output := `{ "Program" = ` + strconv.Quote(program) + `; }`

	got, err := parseLaunchdProgram(output)
	if err != nil {
		t.Fatalf("parseLaunchdProgram() error = %v", err)
	}
	if got != program {
		t.Errorf("parseLaunchdProgram() = %q, want %q", got, program)
	}
}

func TestParseLaunchdProgramFallsBackToFirstArgument(t *testing.T) {
	program := `/Applications/SSH Agent "Proxy" 100% & <prod>/proxy`
	output := `{ "ProgramArguments" = ( ` + strconv.Quote(program) + `, "-config" ); }`

	got, err := parseLaunchdProgram(output)
	if err != nil {
		t.Fatalf("parseLaunchdProgram() error = %v", err)
	}
	if got != program {
		t.Errorf("parseLaunchdProgram() = %q, want %q", got, program)
	}
}

func TestParseLaunchdProgramRejectsMalformedEscape(t *testing.T) {
	if _, err := parseLaunchdProgram(`{ "Program" = "/Applications/bad\qpath"; }`); err == nil {
		t.Fatal("parseLaunchdProgram() error = nil, want malformed escape error")
	}
}
