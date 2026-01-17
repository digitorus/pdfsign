# DSS Validator Test Infrastructure

This directory contains Docker configuration for running the [EU DSS (Digital Signature Services)](https://ec.europa.eu/digital-building-blocks/wikis/display/DIGITAL/Digital+Signature+Service+-++DSS) validator for integration testing.

## Usage

From the repository root:

```bash
./scripts/setup-dss.sh
```

This will:
1. Build a Docker image with DSS Webapp
2. Start the container on port 8080
3. Wait for the service to be ready

Then run the DSS validation tests:

```bash
DSS_API_URL=http://localhost:8080/services/rest/validation/validateSignature go test -v ./sign -run TestValidateDSSValidation
```

## Files

- `Dockerfile.dss` - Dockerfile for DSS Webapp
- `docker-compose.yml` - docker-compose.yml for DSS Webapp

## Note

This is TEST infrastructure only, not for production use.
