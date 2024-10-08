package main

import (
	"encoding/csv"
	"strings"
	"unicode"
)

func CheckCSVForInjection(csvData string) string {
	reader := csv.NewReader(strings.NewReader(csvData))
	records, err := reader.ReadAll()
	if err != nil {
		return "Error reading CSV data"
	}

	for _, row := range records {
		for _, field := range row {
			if containsSuspiciousCharacters(field) {
				return "Potential injection attack detected"
			}
		}
	}

	return "No injection attacks detected"
}

func containsSuspiciousCharacters(s string) bool {
	suspiciousChars := []rune{';', '\'', '"', '-', '=', '+', '|', '&', '!', '(', ')', '{', '}', '[', ']'}

	for _, char := range s {
		if unicode.IsControl(char) {
			return true
		}
		for _, suspicious := range suspiciousChars {
			if char == suspicious {
				return true
			}
		}
	}

	return false
}
