package cli

import "fmt"

type buildInfo struct {
	Version   string
	Commit    string
	BuildTime string
}

var currentBuildInfo = buildInfo{
	Version:   "dev",
	Commit:    "unknown",
	BuildTime: "unknown",
}

func SetBuildInfo(version, commit, buildTime string) {
	currentBuildInfo = buildInfo{
		Version:   defaultBuildValue(version, "dev"),
		Commit:    defaultBuildValue(commit, "unknown"),
		BuildTime: defaultBuildValue(buildTime, "unknown"),
	}
}

func defaultBuildValue(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func versionString(info buildInfo) string {
	return fmt.Sprintf("secssh %s\ncommit: %s\nbuilt: %s\n", info.Version, info.Commit, info.BuildTime)
}
