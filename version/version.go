package version

import (
	"fmt"
	"strings"
)

// Version information.
var (
	BuildTS   = "None"
	GitHash   = "None"
	GitBranch = "None"
	Version   = "None"
	App       = "None"
)

func GetApp() string {
	if App != "None" {
		return fmt.Sprintf("%s-%s", App, GitBranch)
	}
	return App
}

// GetVersion Printer print build version
func GetVersion() string {
	if GitHash != "None" {
		h := GitHash
		if len(h) > 7 {
			h = h[:7]
		}
		return fmt.Sprintf("%s-%s", GitBranch, h)
	}
	return Version
}

func FullVersionInfo() string {
	buf := strings.Builder{}
	buf.WriteString(fmt.Sprintf("Application:%s \n", App))
	buf.WriteString(fmt.Sprintf("Version:%s \n", GetVersion()))
	buf.WriteString(fmt.Sprintf("Git Branch:%s \n", GitBranch))
	buf.WriteString(fmt.Sprintf("Git Commit:%s \n", GitHash))
	buf.WriteString(fmt.Sprintf("Build Time:%s \n", BuildTS))
	return buf.String()
}
