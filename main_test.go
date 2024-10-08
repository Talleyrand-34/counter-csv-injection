package main

import (
	"os"
	"reflect"
	"testing"
)

func TestDetectInjection(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected InjectionType
	}{
		{"No Injection", "Hello, World!", NoInjection},
		{"Command Injection", "ls | grep secret", CommandInjection},
		{"SQL Injection", "SELECT * FROM users", SQLInjection},
		{"XSS Injection", "<script>alert('XSS')</script>", XSSInjection},
		{"Formula Injection", "=SUM(A1:A10)", FormulaInjection},
		{"Another Formula Injection", "@SUM(A1:A10)", FormulaInjection},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detect_injection(tt.input)
			if result != tt.expected {
				t.Errorf("detect_injection(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestReplaceInjection(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		injectionType InjectionType
		expected      string
	}{
		{"Command Injection", "ls | grep secret", CommandInjection, "ls //| grep secret"},
		{"SQL Injection", "SELECT * FROM users", SQLInjection, "SELECT * FROM users"},
		{"XSS Injection", "<script>alert('XSS')</script>", XSSInjection, "&lt;script&gt;alert(''XSS'')&lt;/script&gt;"},
		{"Formula Injection", "=SUM(A1:A10)", FormulaInjection, "'=SUM(A1:A10)"},
		{"No Injection", "Hello, World!", NoInjection, "Hello, World!"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := replace_injection(tt.input, tt.injectionType)
			if result != tt.expected {
				t.Errorf("replace_injection(%q, %v) = %q, want %q", tt.input, tt.injectionType, result, tt.expected)
			}
		})
	}
}

func TestReadCSV(t *testing.T) {
	// Create a temporary CSV file
	content := []byte("name,age\nAlice,30\nBob,25\n")
	tmpfile, err := os.CreateTemp("", "test*.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Test read_csv function
	records, err := read_csv(tmpfile.Name())
	if err != nil {
		t.Fatalf("read_csv() error = %v", err)
	}

	expected := [][]string{
		{"name", "age"},
		{"Alice", "30"},
		{"Bob", "25"},
	}

	if !reflect.DeepEqual(records, expected) {
		t.Errorf("read_csv() = %v, want %v", records, expected)
	}
}

func TestWriteCSV(t *testing.T) {
	records := [][]string{
		{"name", "age"},
		{"Alice", "30"},
		{"Bob", "25"},
	}

	tmpfile, err := os.CreateTemp("", "test_output*.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if err := write_csv(tmpfile.Name(), records); err != nil {
		t.Fatalf("write_csv() error = %v", err)
	}

	// Read the file back and check its contents
	content, err := os.ReadFile(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}

	expected := "name,age\nAlice,30\nBob,25\n"
	if string(content) != expected {
		t.Errorf("write_csv() wrote %q, want %q", string(content), expected)
	}
}

func TestMainCSV(t *testing.T) {
	// Create a temporary input CSV file with some injections
	inputContent := []byte("name,data\nAlice,Normal data\nBob,=SUM(A1:A10)\nCharlie,<script>alert('XSS')</script>\n")
	inputFile, err := os.CreateTemp("", "test_input*.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(inputFile.Name())

	if _, err := inputFile.Write(inputContent); err != nil {
		t.Fatal(err)
	}
	if err := inputFile.Close(); err != nil {
		t.Fatal(err)
	}

	// Create a temporary output file
	outputFile, err := os.CreateTemp("", "test_output*.csv")
	if err != nil {
		t.Fatal(err)
	}
	// defer os.Remove(outputFile.Name())

	// Run main_csv
	if err := main_csv(inputFile.Name(), outputFile.Name()); err != nil {
		t.Fatalf("main_csv() error = %v", err)
	}

	// Read the output file and check its contents
	outputContent, err := os.ReadFile(outputFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	expected := "name,data\nAlice,Normal data\nBob,'=SUM(A1:A10)\nCharlie,&lt;script&gt;alert(''XSS'')&lt;/script&gt;\n"
	if string(outputContent) != expected {
		t.Errorf("main_csv() produced\n%q\nwant\n%q", string(outputContent), expected)
	}
}

func TestProcessCSV(t *testing.T) {
	input := [][]string{
		{"name", "data"},
		{"Alice", "Normal data"},
		{"Bob", "=SUM(A1:A10)"},
		{"Charlie", "<script>alert('XSS')</script>"},
	}

	expected := [][]string{
		{"name", "data"},
		{"Alice", "Normal data"},
		{"Bob", "'=SUM(A1:A10)"},
		{"Charlie", "&lt;script&gt;alert(''XSS'')&lt;/script&gt;"},
	}

	result, err := process_csv(input)
	if err != nil {
		t.Fatalf("process_csv() error = %v", err)
	}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("process_csv() = %v, want %v", result, expected)
	}
}
