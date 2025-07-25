# Third-Party PDF Validation

This document describes the third-party PDF validation system implemented in this project.

## Overview

The PDF validation system provides automated validation of PDF files generated during testing using two complementary tools:

1. **pdfcpu** - A Go-based PDF processor for structural validation
2. **DSS (Digital Signature Service)** - European Commission's official digital signature validation service

## Components

### 1. pdfcpu Validation

[pdfcpu](https://github.com/pdfcpu/pdfcpu) is used for basic PDF structure validation:

- **Purpose**: Validates PDF structure, syntax, and compliance with ISO standards
- **Mode**: Strict validation mode for comprehensive checking
- **Coverage**: PDF/A compliance, cross-reference tables, object structure, etc.

### 2. DSS Validation

The [DSS (Digital Signature Service)](https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/) validates digital signatures:

- **Purpose**: Validates digital signatures according to European standards
- **Standards**: eIDAS regulation compliance, PAdES validation
- **Features**: Signature verification, certificate chain validation, timestamp validation

## Workflow Integration

### GitHub Actions Workflows

The validation system is integrated into GitHub Actions through two workflows:

#### 1. Build & Test Workflow (`.github/workflows/go.yml`)

- Runs the standard Go test suite
- Collects test-generated PDF files from the `TMPDIR`
- Uploads PDF artifacts for validation

#### 2. PDF Validation Workflow (`.github/workflows/pdf-validation.yml`)

- Triggered after the Build & Test workflow completes
- Downloads test PDF artifacts
- Runs both pdfcpu and DSS validation
- Generates detailed validation reports
- Posts results as PR comments (when applicable)

### Validation Process

1. **Artifact Collection**: Test PDFs are collected during the test run
2. **pdfcpu Validation**: 
   - Downloads artifacts
   - Installs pdfcpu
   - Validates each PDF in strict mode
   - Generates validation report
3. **DSS Validation**:
   - Sets up DSS Docker service
   - Validates digital signatures
   - Checks eIDAS compliance
   - Generates JSON validation reports
4. **Results Combination**:
   - Combines both validation results
   - Creates summary report
   - Posts to PR (if applicable)
   - Fails the workflow if validation fails

## Usage

### Manual Validation

You can run pdfcpu validation manually:

```bash
# Install pdfcpu
go install github.com/pdfcpu/pdfcpu/cmd/pdfcpu@latest

# Validate a PDF file
pdfcpu validate -mode strict your-file.pdf
```

### Automated Validation

The validation runs automatically on:

- **Workflow Dispatch**: Manual trigger
- **After Build & Test**: Automatic trigger when tests complete

### Understanding Results

#### pdfcpu Results

- ✅ **Pass**: PDF structure is valid and compliant
- ❌ **Fail**: PDF has structural issues or non-compliance

#### DSS Results

- ✅ **Pass**: Digital signatures are valid and trusted
- ❌ **Fail**: Signature validation failed or certificates are invalid

## Configuration

### Permissions

The workflow requires specific GitHub permissions:

```yaml
permissions:
  contents: read      # Read repository contents
  actions: read       # Download artifacts
  pull-requests: write # Post PR comments
  checks: write       # Update check status
```

### Customization

You can customize the validation by:

1. **Changing validation mode**: Modify `-mode strict` to `-mode relaxed` for less strict validation
2. **Adding validation rules**: Extend the validation scripts
3. **Modifying triggers**: Change when validation runs
4. **Adjusting timeout**: Modify DSS service startup timeout

## Troubleshooting

### Common Issues

1. **No PDF files found**: Tests didn't generate expected PDF files
2. **pdfcpu validation fails**: PDF structure issues in generated files
3. **DSS service timeout**: DSS Docker container failed to start
4. **Empty files**: Test failures resulted in empty PDF files

### Debugging

- Check the workflow logs for detailed validation output
- Review test logs to ensure PDFs are generated correctly
- Verify artifact upload/download is working
- Check DSS service logs if signature validation fails

## Security Considerations

- The workflow runs with minimal required permissions
- DSS validation uses the official European Commission Docker image
- No sensitive data is exposed in validation reports
- Artifacts are automatically cleaned up after 7 days