package main

import "testing"

func TestIsVulnetableBetweenRanges(t *testing.T) {

	expectedArg1 := false
	expectedArg2 := ""

	resultArg1, resultArg2 := isVulnerableBetweenRanges("", []string{""})

	if resultArg1 != expectedArg1 {
		t.Errorf("Output %t is not equal result %t", resultArg1, expectedArg1)
	}

	if resultArg2 != expectedArg2 {
		t.Errorf("Output %s is not equal result %s", resultArg2, expectedArg2)
	}
}
