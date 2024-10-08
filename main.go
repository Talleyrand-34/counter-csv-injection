package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"strings"
)

type InjectionType int

const (
	NoInjection InjectionType = iota
	CommandInjection
	SQLInjection
	XSSInjection
	FormulaInjection
)

func (it InjectionType) String() string {
	return [...]string{"NoInjection", "CommandInjection", "SQLInjection", "XSSInjection", "FormulaInjection"}[it]
}

func main_csv(inputFile, outputFile string) error {
	// Read CSV
	records, err := read_csv(inputFile)
	if err != nil {
		return fmt.Errorf("error reading CSV: %v", err)
	}

	// Process CSV
	processedRecords, err := process_csv(records)
	if err != nil {
		return fmt.Errorf("error processing CSV: %v", err)
	}

	// Write CSV
	err = write_csv(outputFile, processedRecords)
	if err != nil {
		return fmt.Errorf("error writing CSV: %v", err)
	}

	return nil
}

func process_csv(records [][]string) ([][]string, error) {
	processedRecords := make([][]string, len(records))
	for i, row := range records {
		processedRow := make([]string, len(row))
		for j, field := range row {
			injectionType := detect_injection(field)
			if injectionType != NoInjection {
				processedRow[j] = replace_injection(field, injectionType)
			} else {
				processedRow[j] = field
			}
		}
		processedRecords[i] = processedRow
	}
	return processedRecords, nil
}

func read_csv(filename string) ([][]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	return reader.ReadAll()
}

func write_csv(filename string, records [][]string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	return writer.WriteAll(records)
}

func detect_injection(s string) InjectionType {
	if strings.ContainsAny(s, "|&;`") {
		return CommandInjection
	}

	sqlPatterns := []string{"SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION", "--"}
	for _, pattern := range sqlPatterns {
		if strings.Contains(strings.ToUpper(s), pattern) {
			return SQLInjection
		}
	}

	xssPatterns := []string{"<script", "javascript:", "onload=", "onerror="}
	for _, pattern := range xssPatterns {
		if strings.Contains(strings.ToLower(s), pattern) {
			return XSSInjection
		}
	}

	if strings.HasPrefix(s, "=") || strings.HasPrefix(s, "+") || strings.HasPrefix(s, "-") || strings.HasPrefix(s, "@") {
		return FormulaInjection
	}

	return NoInjection
}

func replace_injection(s string, injectionType InjectionType) string {
	switch injectionType {
	case CommandInjection:
		s = strings.ReplaceAll(s, "|", "//|")
		s = strings.ReplaceAll(s, "&", "//&")
		s = strings.ReplaceAll(s, ";", "//;")
		s = strings.ReplaceAll(s, "`", "//`")
	case SQLInjection, XSSInjection:
		s = strings.ReplaceAll(s, "<", "&lt;")
		s = strings.ReplaceAll(s, ">", "&gt;")
		s = strings.ReplaceAll(s, "'", "''")
		s = strings.ReplaceAll(s, "\"", "\"\"")
	case FormulaInjection:
		s = "'" + s // Prepend with single quote to treat as text
	}
	// Only add quotes if they're not already present
	// if !strings.HasPrefix(s, "\"") || !strings.HasSuffix(s, "\"") {
	// 	s = "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	// }
	// Escape double quotes and wrap in quotes as a general safety measure
	// s = strings.ReplaceAll(s, "\"", "\"\"")
	// return "\"" + s + "\""
	return s
}
func main() {}
