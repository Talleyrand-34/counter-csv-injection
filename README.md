# Counter csv injection
The aim of this app is to filter a csv to avoid injection attacks

## How it works
This program detects the type of injection that the cell could be and applies a patch to avoid explotation but without deleting any data

## Structure
- CSV Processing
- Injection detection
  - Detects if there is an injection risk and returns its type
- Injection Patching
  - Applies a patch to the field depending on the injection type detected
