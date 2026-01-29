# Reusable GitHub Actions

This directory contains composite actions that can be reused across workflows in the cc-audit project.

## Available Actions

### check-results

Standardized result checker for workflow jobs with automatic summary generation.

#### Purpose

The `check-results` action provides a consistent way to:
- Check the results of multiple workflow jobs
- Generate formatted summary tables
- Handle skip conditions (e.g., when no relevant changes detected)
- Provide clear error messages when jobs fail

#### Usage

```yaml
- uses: ./.github/actions/check-results
  with:
    workflow-name: 'CI'
    skip-condition: ${{ needs.changes.outputs.rust != 'true' && 'No Rust changes detected' || '' }}
    jobs: |
      [
        {"name": "fmt", "result": "${{ needs.fmt.result }}"},
        {"name": "clippy", "result": "${{ needs.clippy.result }}"},
        {"name": "test", "result": "${{ needs.test.result }}"}
      ]
```

#### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `workflow-name` | Yes | - | Name of the workflow for summary display (e.g., "CI", "Security") |
| `jobs` | Yes | - | JSON array of job results in format `[{"name":"job-name","result":"success"}]` |
| `skip-condition` | No | `''` | Condition message to skip checks (e.g., "No changes detected"). If provided, the action exits successfully without checking job results. |

#### Job Results Format

The `jobs` input expects a JSON array where each object has:
- `name` (string): The job name as it appears in the workflow
- `result` (string): The job result, typically one of:
  - `success` - Job completed successfully
  - `failure` - Job failed
  - `cancelled` - Job was cancelled
  - `skipped` - Job was skipped

Example:
```json
[
  {"name": "test", "result": "success"},
  {"name": "lint", "result": "failure"},
  {"name": "build", "result": "success"}
]
```

#### Outputs

This action generates two outputs:

1. **Exit Code**:
   - `0` if all jobs passed or skip-condition is provided
   - `1` if any job failed

2. **GitHub Step Summary**:
   - Creates a formatted table showing all job results
   - Table format:
     ```
     ## {workflow-name} Summary

     | Job | Status |
     |-----|--------|
     | fmt | success |
     | clippy | success |
     | test | failure |
     ```

#### Error Handling

- **Skip Condition**: If `skip-condition` is provided, the action prints the message and exits successfully (code 0)
- **Failed Jobs**: If any job result is "failure", the action:
  1. Prints an error message listing all failed jobs
  2. Exits with code 1
- **All Passed**: If all jobs succeeded, prints success message and exits with code 0

#### Examples

##### Basic Usage (CI Workflow)

```yaml
ci-result:
  name: CI Result
  needs: [changes, fmt, clippy, test, coverage, doc]
  if: always()
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v6
    - uses: ./.github/actions/check-results
      with:
        workflow-name: 'CI'
        skip-condition: ${{ needs.changes.outputs.rust != 'true' && 'No Rust changes detected' || '' }}
        jobs: |
          [
            {"name": "fmt", "result": "${{ needs.fmt.result }}"},
            {"name": "clippy", "result": "${{ needs.clippy.result }}"},
            {"name": "test", "result": "${{ needs.test.result }}"},
            {"name": "coverage", "result": "${{ needs.coverage.result }}"},
            {"name": "doc", "result": "${{ needs.doc.result }}"}
          ]
```

##### Security Workflow with Different Skip Condition

```yaml
security-result:
  name: Security Result
  needs: [changes, audit, deny, supply-chain]
  if: always()
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v6
    - uses: ./.github/actions/check-results
      with:
        workflow-name: 'Security'
        skip-condition: ${{ needs.changes.outputs.should_run != 'true' && 'No relevant changes detected' || '' }}
        jobs: |
          [
            {"name": "audit", "result": "${{ needs.audit.result }}"},
            {"name": "deny", "result": "${{ needs.deny.result }}"},
            {"name": "supply-chain", "result": "${{ needs.supply-chain.result }}"}
          ]
```

##### Simple Result Check Without Skip Condition

```yaml
test-result:
  name: Test Result
  needs: [unit-tests, integration-tests]
  if: always()
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v6
    - uses: ./.github/actions/check-results
      with:
        workflow-name: 'Tests'
        jobs: |
          [
            {"name": "unit-tests", "result": "${{ needs.unit-tests.result }}"},
            {"name": "integration-tests", "result": "${{ needs.integration-tests.result }}"}
          ]
```

#### Implementation Details

The action is implemented as a composite action using two steps:

1. **Check results**: Parses the JSON array, identifies failed jobs, and exits with appropriate code
2. **Create summary**: Generates a formatted table in GitHub Step Summary (skipped if skip-condition is provided)

Key implementation features:
- Uses `jq` for JSON parsing
- Formats failed job names as comma-separated list
- Uses GitHub Actions annotations (`::error::`) for visibility
- Conditionally creates summary only when checks are performed

#### Benefits

Using this composite action provides:
- **Consistency**: All result jobs use the same logic
- **Maintainability**: Changes to result checking logic in one place
- **Readability**: Clear JSON format for job results
- **Automation**: Automatic summary table generation
- **DRY Principle**: Eliminates 147+ lines of duplicated code across workflows

#### Migration from Legacy Pattern

**Before** (legacy pattern):
```yaml
result-job:
  needs: [job1, job2, job3]
  if: always()
  runs-on: ubuntu-latest
  steps:
    - name: Check results
      run: |
        if [[ "${{ needs.changes.outputs.rust }}" != "true" ]]; then
          echo "No changes detected"
          exit 0
        fi
        if [[ "${{ needs.job1.result }}" == "failure" || \
              "${{ needs.job2.result }}" == "failure" || \
              "${{ needs.job3.result }}" == "failure" ]]; then
          echo "One or more jobs failed"
          exit 1
        fi
        echo "All checks passed"
```

**After** (using check-results):
```yaml
result-job:
  needs: [job1, job2, job3]
  if: always()
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v6
    - uses: ./.github/actions/check-results
      with:
        workflow-name: 'Workflow Name'
        skip-condition: ${{ needs.changes.outputs.rust != 'true' && 'No changes detected' || '' }}
        jobs: |
          [
            {"name": "job1", "result": "${{ needs.job1.result }}"},
            {"name": "job2", "result": "${{ needs.job2.result }}"},
            {"name": "job3", "result": "${{ needs.job3.result }}"}
          ]
```

#### Troubleshooting

**Issue**: JSON parsing error
**Solution**: Ensure JSON is valid. Use a JSON validator or check for:
- Missing commas between objects
- Unescaped quotes in strings
- Trailing commas (not allowed in JSON)

**Issue**: Action always succeeds even with failed jobs
**Solution**: Verify that `skip-condition` is not inadvertently set. Check the conditional expression logic.

**Issue**: Summary table not appearing
**Solution**:
- Ensure `skip-condition` is not provided (summary is skipped when skip-condition is set)
- Check that the workflow has write permissions to create job summaries

**Issue**: Action fails with "jq: command not found"
**Solution**: This shouldn't occur as GitHub Actions runners include jq by default. If it does, report it as a bug.

---

## Adding New Composite Actions

To add a new composite action to this directory:

1. **Create a directory**: `mkdir -p .github/actions/{action-name}`
2. **Create action.yml**: Define the action with proper metadata:
   ```yaml
   name: 'Action Name'
   description: 'Clear description of what the action does'
   inputs:
     input-name:
       description: 'Description of input'
       required: true
   runs:
     using: 'composite'
     steps:
       - name: Step name
         shell: bash
         run: |
           # Implementation
   ```
3. **Document it here**: Add usage examples and descriptions to this README
4. **Test thoroughly**: Create a test workflow to validate the action
5. **Update references**: Add to [GITHUB_ACTIONS_ARCHITECTURE.md](../../docs/GITHUB_ACTIONS_ARCHITECTURE.md)

---

## Best Practices

### Composite Action Design

1. **Single Responsibility**: Each action should do one thing well
2. **Clear Inputs/Outputs**: Document all parameters with descriptions
3. **Error Handling**: Always handle errors gracefully
4. **Shell Selection**: Use `bash` for compatibility across runners
5. **Logging**: Use GitHub Actions annotations for visibility

### Versioning

Composite actions in this repository are not versioned separately. They follow the project version and are used via relative path (`./.github/actions/{name}`).

If you need stability across branches:
- Pin to specific commits in external repositories
- Test actions thoroughly before merging to main
- Document breaking changes in CHANGELOG.md

### Testing

Test composite actions by:
1. Creating a test workflow in `.github/workflows/`
2. Running the workflow on a feature branch
3. Verifying outputs and behavior
4. Checking GitHub Actions logs for errors

---

## Related Documentation

- [GitHub Actions Architecture](../../docs/GITHUB_ACTIONS_ARCHITECTURE.md) - Overall workflow structure
- [CI Error Handling](../../docs/CI_ERROR_HANDLING.md) - Error handling standards
- [GitHub Actions Documentation](https://docs.github.com/en/actions/creating-actions/creating-a-composite-action) - Official composite action guide

---

## Maintenance

This directory is maintained by the cc-audit team. When modifying composite actions:

1. **Update this README** with changes
2. **Update dependent workflows** if inputs/outputs change
3. **Test thoroughly** on a feature branch
4. **Document breaking changes** in PR description
5. **Update architecture docs** if behavior changes significantly

For questions or issues with composite actions, please open an issue or discussion in the repository.
