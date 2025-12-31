# Nvelox Testing Guide

This document outlines how to run the test suite for the Nvelox proxy server.

## Prerequisites

-   **Go**: Version 1.25 or higher

## Running Tests

### 1. Run All Tests
To run both unit and integration tests:

```bash
cd nvelox
go test -v ./...
```

### 2. Run Specific Tests

**Unit Tests Only:**
```bash
go test -v ./config/...
go test -v ./lb/...
go test -v ./core/...
```

**Integration Tests Only:**
```bash
go test -v ./integration/...
```

## detailed Coverage Report

To see the exact code coverage percentage:

```bash
# Run tests and generate coverage profile (including integration test coverage)
go test -v -coverpkg=./... -coverprofile=coverage.out ./...

# Display function-level coverage statistics
go tool cover -func=coverage.out

# Generate HTML report
go tool cover -html=coverage.out -o coverage.html
```

## CI/CD

Tests are automatically run on every push to the `main` branch and on Pull Requests via GitHub Actions.
See `.github/workflows/test.yml` for the configuration.

## Current Coverage Status

-   **Core Logic**: High coverage (Handler, Engine, Listeners)
-   **Health Checks**: ~90-100% Coverage
-   **Load Balancing**: 100% Coverage for RoundRobin strategy
-   **Proxy Protocol**: ~94% Coverage
-   **Total Statement Coverage**: ~56% (includes boilerplate and untested legacy implementations)
