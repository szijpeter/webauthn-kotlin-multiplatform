## Summary

-

## Checks

- [ ] `tools/agent/quality-gate.sh --mode fast --scope changed --block false`
- [ ] `tools/agent/quality-gate.sh --mode strict --scope changed --block false`
- [ ] `./gradlew apiCheck --stacktrace` (if BCV-covered public API changed)
- [ ] `./gradlew publishToMavenLocal --stacktrace` (if public API or publishing/build metadata changed)

## Docs

- [ ] Docs updated if public behavior, release workflow, or security posture changed
- [ ] `docs/ai/FIRST_PUBLIC_RELEASE_PLAN.md` updated if the first-release sequence or decisions changed
- [ ] `CHANGELOG.md` updated if the change affects published consumers

## Notes

-
