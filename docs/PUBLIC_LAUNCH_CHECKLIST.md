# Public Launch Checklist

Use this checklist when moving from private to public operation.

## In-Repo Baseline

1. Security policy file exists and is current: `SECURITY.md`.
2. CI workflow uses least-privilege `permissions` and explicit versioned action references.
3. Dependency automation exists: `.github/dependabot.yml`.
4. Local/sensitive files are ignored (`.env*`, `local.properties`, build outputs, IDE state).
5. Required quality gates pass:
   - `tools/agent/quality-gate.sh --mode fast --scope changed --block false`
   - `tools/agent/quality-gate.sh --mode strict --scope changed --block true`

## GitHub Repository Settings

1. Rename and set default branch to `main`.
2. Change visibility to public.
3. Re-apply branch protections/rulesets after visibility change.
4. Enable security analysis features:
   - Dependency graph
   - Dependabot alerts
   - Dependabot security updates
   - Secret scanning
   - Secret scanning push protection
   - Code scanning
5. Enable private vulnerability reporting.
6. Confirm GitHub Actions repository settings are least privilege.

## Post-Launch Verification

1. CI runs successfully on `main` pushes and pull requests.
2. Dependabot creates update PRs for Gradle and GitHub Actions.
3. `SECURITY.md` appears in repository security surfaces.
4. No secret findings in baseline scans; if any are found, rotate credentials immediately and evaluate targeted history rewrite.
