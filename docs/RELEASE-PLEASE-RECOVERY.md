# Release Please Failure Recovery

Use this runbook when `.github/workflows/release-please.yml` fails. It is
intentionally read-only until the release state has been established.

## 1. Capture evidence without exposing secrets

Record the workflow run URL, run attempt, head SHA, failed job URL, action
version and resolved action commit. Retrieve the failed job log with GitHub's
web UI or:

```bash
gh run view RUN_ID --job JOB_ID --log-failed
```

Share only the relevant error and GitHub diagnostic ID. Do not print workflow
environments, token values, request headers, or unredacted debug output.

The GraphQL rate limit shown by `gh api rate_limit` belongs to the token used by
that command. It does not prove the remaining quota or permissions of the
workflow's `RELEASE_PLEASE_TOKEN`.

## 2. Establish the release state before rerunning

Set the expected tag locally, then perform read-only checks:

```bash
TAG=vX.Y.Z
gh repo view --json nameWithOwner
git remote get-url origin
git ls-remote --tags origin "$TAG"
gh release view "$TAG" --json tagName,url,isDraft,isPrerelease,publishedAt
```

Before interpreting the results, confirm that `gh repo view` and `origin` refer
to the same repository. If the repository or tag query fails, or the repository
cannot be verified, the release state is unknown. Stop without rerunning or
modifying a release. After repository access is verified, only an explicit
not-found response from the Release query means that the Release is absent;
authentication, permission, network, and 5xx errors are unknown state.

Interpret the results separately:

- A tag or GitHub Release exists: pass 1 may have completed. Inspect the
  release, assets, and downstream workflow runs. Do not blindly rerun Release
  Please or recreate the tag/release.
- The tag query succeeds with no tag and, after repository access is verified,
  the release query returns an explicit 404/not-found: the release state is
  known to be absent, but absence alone does not show whether pass 1 ran or how
  far it progressed. Confirm the failed step and its logs before deciding
  whether a single manually approved rerun is safe.
- `release_created` is missing or unavailable because the job failed: treat it
  as an unavailable output, not as proof that no release was created.

## 3. Classify the failure

Retry only a read-only, known-transient GitHub API failure, and only with a
bounded, manually approved rerun after the release state is clear. Examples are
an HTTP 502/503/504 or a documented temporary GitHub service failure.

Fail without retry for authentication, authorization, repository access,
validation, malformed query, or unknown errors. The workflow's current action
has an exception retry path that covers HTTP 502 only; an HTTP 200 GraphQL
response containing `errors` is not covered by that path.

This behavior was verified in the exact action commit
[`45996ed`](https://github.com/googleapis/release-please-action/blob/45996ed1f6d02564a971a2fa1b5860e934307cf7/src/index.ts), whose
`package.json` pins `release-please` 17.6.0
([immutable package metadata](https://github.com/googleapis/release-please-action/blob/45996ed1f6d02564a971a2fa1b5860e934307cf7/package.json)).

Do not add `continue-on-error` to make the workflow green. Do not use an
unbounded retry or rerun a release merely because `release_created` is absent.

## 4. Recovery decision

If a tag/release exists, continue by checking its assets and downstream
publication workflows. Repair only the specific missing downstream artifact,
following the relevant distribution runbook. Preserve the existing tag and
release.

If no tag/release exists and the error is confirmed transient, a maintainer may
rerun the workflow once. Re-check the tag and release after the rerun before
performing any downstream release action.

If the error is not clearly transient, leave the run failed and record the
diagnostic ID. Escalate with the action version, fixed action commit, exact
timestamp, repository, job URL, and redacted error text.

## 5. Known pass-1/pass-2 failure mode

The action can create a release in pass 1 and then fail while scanning merge
history or creating pull requests in pass 2. In that case the job can be failed
while downstream consumers cannot safely rely on `release_created`. This is
why artifact existence must be checked directly before any rerun.

The upstream action's internal retry behavior is outside this repository's
workflow configuration. Do not fork, vendor, or change the external action as
part of incident recovery without a separate design and review.
