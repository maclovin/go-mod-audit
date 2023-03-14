package main

import (
	"regexp"

	"github.com/Masterminds/semver/v3"
)

var clearVersionregex = regexp.MustCompile(`[^0-9.]`)

func toClearVersion(s string) string {
	return clearVersionregex.ReplaceAllString(s, "")
}

func isVulnerableBetweenRanges(currentVersion string, vulnerableRanges []string) (bool, string) {
	// Check if the current version match exactly the vulnerable ranges
	for _, v := range vulnerableRanges {
		if v == currentVersion {
			return true, vulnerableRanges[len(vulnerableRanges)-1]
		}
	}

	// Check if the current version is between the vulnerable ranges
	for i := 0; i < len(vulnerableRanges)-1; i = i + 2 {
		verConstraint, _ := semver.NewConstraint(vulnerableRanges[i] + " - " + vulnerableRanges[+1])
		parsedVersion, _ := semver.NewVersion(currentVersion)

		if verConstraint.Check(parsedVersion) {
			return true, vulnerableRanges[len(vulnerableRanges)-1]
		}
	}

	return false, ""
}
