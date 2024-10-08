package main

import (
	"testing"
)

func TestCheckCSVForInjection(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Clean CSV", "name,age\nJohn,30\nJane,25", "No injection attacks detected"},
		{"SQL Injection", "name,age\nJohn,30\nJane,25; DROP TABLE users;", "Potential injection attack detected"},
		{"XSS Attack", "name,age\nJohn,30\n<script>alert('XSS')</script>,25", "Potential injection attack detected"},
		{"Command Injection", "name,age\nJohn,30\n|cat /etc/passwd,25", "Potential injection attack detected"},
		{"Empty CSV", "", "No injection attacks detected"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckCSVForInjection(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}
