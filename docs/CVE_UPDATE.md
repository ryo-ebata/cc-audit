# CVE Database Auto-Update

[日本語](./CVE-UPDATE.ja.md)

This document describes how cc-audit's CVE database is automatically updated using GitHub Actions.

## Overview

cc-audit maintains a database of known CVEs affecting AI coding tools and MCP-related products. This database is automatically updated daily by fetching new vulnerabilities from the [NVD (National Vulnerability Database) API](https://nvd.nist.gov/developers/vulnerabilities).

## How It Works

### Daily Cron Job

The GitHub Actions workflow runs daily at **09:00 UTC (18:00 JST)**:

```yaml
on:
  schedule:
    - cron: '0 9 * * *'
```

### Update Process

1. **Fetch CVEs**: The script queries the NVD API for CVEs related to:
   - MCP (Model Context Protocol)
   - Claude Code
   - Cursor IDE
   - GitHub Copilot
   - Codeium, Tabnine, and other AI coding tools

2. **Filter Relevant CVEs**: Only CVEs affecting known AI coding tool vendors/products are included

3. **Merge with Existing**: New CVEs are merged with the existing database, avoiding duplicates

4. **Create Pull Request**: If new CVEs are found, a PR is automatically created for review

### Manual Trigger

You can also trigger the workflow manually from GitHub Actions:

1. Go to **Actions** → **CVE Database Update**
2. Click **Run workflow**
3. Optionally specify the number of days to look back (default: 90)

## Configuration

### NVD API Key (Recommended)

Setting up an NVD API key increases the rate limit from 5 requests/30 seconds to 50 requests/30 seconds.

1. Request an API key at [NVD API Key Request](https://nvd.nist.gov/developers/request-an-api-key)
2. Add the key as a GitHub Secret:
   - Go to **Settings** → **Secrets and variables** → **Actions**
   - Create a new secret named `NVD_API_KEY`

### Workflow Permissions

The workflow requires:
- `contents: write` - To commit database updates
- `pull-requests: write` - To create PRs

## Database Structure

The CVE database is stored at `data/cve-database.json`:

```json
{
  "version": "1.0.0",
  "updated_at": "2025-01-26T00:00:00Z",
  "entries": [
    {
      "id": "CVE-2025-XXXXX",
      "title": "Vulnerability title",
      "description": "Detailed description...",
      "severity": "critical",
      "cvss_score": 9.8,
      "affected_products": [
        {
          "vendor": "anthropic",
          "product": "claude-code",
          "version_affected": "< 1.5.0",
          "version_fixed": "1.5.0"
        }
      ],
      "cwe_ids": ["CWE-78"],
      "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-XXXXX"],
      "published_at": "2025-01-15T00:00:00Z"
    }
  ]
}
```

## Pull Request Review

When a PR is created, reviewers should verify:

- [ ] New CVE entries are relevant to AI coding tools
- [ ] Severity ratings are accurate
- [ ] Affected version ranges are correct
- [ ] Fixed versions are properly specified

## Adding CVEs Manually

To add a CVE manually:

1. Edit `data/cve-database.json`
2. Add a new entry following the structure above
3. Increment the `version` patch number
4. Update `updated_at` timestamp
5. Submit a PR

## Troubleshooting

### Rate Limiting

If you see rate limit errors:
- Add an NVD API key (see Configuration above)
- Wait and retry later

### No New CVEs Found

This is normal if:
- No new AI coding tool CVEs were published
- The CVEs found don't match known vendor/product names

### Script Errors

Check the GitHub Actions logs for details. Common issues:
- Network connectivity problems
- NVD API temporary outages
- JSON parsing errors (malformed CVE data)

## Related Documentation

- [FEATURES.md](./FEATURES.md) - CVE Database feature overview
- [NVD API Documentation](https://nvd.nist.gov/developers/vulnerabilities)
