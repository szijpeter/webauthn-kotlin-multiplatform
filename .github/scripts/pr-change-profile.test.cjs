const test = require('node:test')
const assert = require('node:assert/strict')
const profile = require('./pr-change-profile.cjs')
const config = require('../pr-change-profile.config.json')

const cases = [
  ['core/webauthn-core/src/commonMain/kotlin/dev/webauthn/core/TestFactory.kt', 'published'],
  ['client/webauthn-client-android/src/androidMain/kotlin/dev/webauthn/client/AndroidClient.kt', 'published'],
  ['client/webauthn-client-ios/src/iosMain/kotlin/dev/webauthn/client/IosClient.kt', 'published'],
  ['server/webauthn-server-core-jvm/src/main/kotlin/dev/webauthn/server/Server.kt', 'published'],
  ['core/webauthn-core/src/commonTest/kotlin/dev/webauthn/core/ProductionFactory.kt', 'test'],
  ['client/webauthn-client-android/src/androidUnitTest/kotlin/dev/webauthn/client/ClientTest.kt', 'test'],
  ['server/webauthn-server-core-jvm/src/testFixtures/kotlin/dev/webauthn/server/StoreContractTestBase.kt', 'test'],
  ['documentation/consumer-smoke/client/src/commonMain/kotlin/smoke/client/CommonSmoke.kt', 'test'],
  ['documentation/examples/src/commonTest/kotlin/dev/webauthn/documentation/examples/DocumentationBehaviorTest.kt', 'test'],
  ['documentation/examples/src/commonMain/kotlin/dev/webauthn/documentation/examples/ModelExample.kt', 'docs_examples'],
  ['documentation/examples/build.gradle.kts', 'tooling'],
  ['documentation/tooling/src/main/kotlin/dev/webauthn/documentation/DocumentationExamples.kt', 'tooling'],
  ['documentation/tooling/src/test/kotlin/dev/webauthn/documentation/DocumentationVerifierTest.kt', 'test'],
  ['sample/compose-passkey/src/commonMain/kotlin/dev/webauthn/samples/App.kt', 'sample'],
  ['sample/compose-passkey/src/commonTest/kotlin/dev/webauthn/samples/AppTest.kt', 'test'],
  ['sample/backend-ktor/build.gradle.kts', 'tooling'],
  ['platform/bom/build.gradle.kts', 'publishing'],
  ['gradle/libs.versions.toml', 'publishing'],
  ['core/webauthn-core/api/webauthn-core.api', 'api'],
  ['client/webauthn-client-core/api/webauthn-client-core.klib.api', 'api'],
  ['documentation/example-inventory.md', 'generated_reference'],
  ['spec-cache/webauthn-3.html', 'generated_reference'],
  ['spec-cache/README.md', 'docs'],
  ['docs/IMPLEMENTATION_STATUS.md', 'docs'],
  ['server/webauthn-server-ktor/README.md', 'docs'],
  ['README.md', 'docs'],
  ['build-logic/src/main/kotlin/webauthn.kotlin.multiplatform.gradle.kts', 'tooling'],
  ['tools/agent/quality-gate.sh', 'tooling'],
  ['.github/workflows/ci.yml', 'tooling'],
  ['.gemini/workflows/fast-pr-check.md', 'tooling'],
  ['.kiro/steering/10-quality-gates.md', 'tooling'],
  ['new-area/foo/src/commonMain/kotlin/Foo.kt', 'unclassified'],
  ['assets/logo.png', 'other'],
]

for (const [path, expected] of cases) {
  test(`classifies ${path} as ${expected}`, () => {
    assert.equal(profile.classifyPath(path, config), expected)
  })
}

test('extracts repository modules', () => {
  assert.deepEqual(profile.extractModule('client/webauthn-client-core/src/commonMain/kotlin/Foo.kt'), {
    area: 'client',
    module: 'webauthn-client-core',
    key: 'client/webauthn-client-core',
  })
  assert.deepEqual(profile.extractModule('.github/workflows/ci.yml'), {
    area: '.github',
    module: '.github',
    key: '.github',
  })
})

test('groups published source sets into review-oriented platforms', () => {
  assert.equal(profile.extractPublishedPlatform('core/x/src/commonMain/kotlin/Foo.kt'), 'Common')
  assert.equal(profile.extractPublishedPlatform('server/x/src/main/kotlin/Foo.kt'), 'JVM')
  assert.equal(profile.extractPublishedPlatform('client/x/src/androidMain/kotlin/Foo.kt'), 'Android')
  assert.equal(profile.extractPublishedPlatform('client/x/src/iosMain/kotlin/Foo.kt'), 'iOS / Apple')
  assert.equal(profile.extractPublishedPlatform('client/x/src/wasmJsMain/kotlin/Foo.kt'), 'JS / Web')
})

test('aggregates every file exactly once', () => {
  const files = [
    { filename: 'core/webauthn-core/src/commonMain/kotlin/Foo.kt', additions: 20, deletions: 5 },
    { filename: 'core/webauthn-core/src/commonTest/kotlin/FooTest.kt', additions: 30, deletions: 2 },
    { filename: 'core/webauthn-core/api/webauthn-core.api', additions: 4, deletions: 1 },
    { filename: 'sample/compose-passkey/src/commonMain/kotlin/App.kt', additions: 10, deletions: 0 },
    { filename: 'README.md', additions: 5, deletions: 3 },
  ]

  const stats = profile.aggregateFiles(files, config)
  assert.deepEqual(stats.totals, { files: 5, additions: 69, deletions: 11, churn: 80 })
  assert.equal(stats.categories.published.churn, 25)
  assert.equal(stats.categories.test.churn, 32)
  assert.equal(stats.categories.api.churn, 5)
  assert.equal(stats.categories.sample.churn, 10)
  assert.equal(stats.categories.docs.churn, 8)
  assert.equal(stats.modules.length, 1)
  assert.equal(stats.modules[0].module, 'webauthn-core')
  assert.equal(stats.modules[0].published.churn, 25)
  assert.equal(stats.modules[0].test.churn, 32)
  assert.equal(stats.modules[0].api.churn, 5)
})

test('renders zero-production PRs without invalid ratios', () => {
  const stats = profile.aggregateFiles([
    { filename: 'README.md', additions: 10, deletions: 2 },
  ], config)
  const body = profile.renderComment({
    pr: { base: { ref: 'main' }, head: { sha: '1234567890abcdef' } },
    stats,
  })

  assert.match(body, /Test \/ published additions: \*\*n\/a\*\*/)
  assert.doesNotMatch(body, /NaN|Infinity/)
})

test('surfaces unclassified source paths', () => {
  const stats = profile.aggregateFiles([
    { filename: 'experimental/foo/src/commonMain/kotlin/Foo.kt', additions: 3, deletions: 1 },
  ], config)
  const body = profile.renderComment({
    pr: { base: { ref: 'main' }, head: { sha: '1234567890abcdef' } },
    stats,
  })

  assert.match(body, /Unclassified source files/)
  assert.match(body, /experimental\/foo\/src\/commonMain\/kotlin\/Foo\.kt/)
})

test('updates the existing GitHub Actions marker comment', async () => {
  const calls = []
  const github = {
    rest: {
      issues: {
        listComments: Symbol('listComments'),
        createComment: async args => calls.push(['create', args]),
        updateComment: async args => calls.push(['update', args]),
      },
    },
    paginate: async () => [{
      id: 42,
      user: { login: 'github-actions[bot]' },
      body: `${profile.MARKER}\nold`,
    }],
  }

  const result = await profile.upsertComment({
    github,
    owner: 'szijpeter',
    repo: 'webauthn-kotlin-multiplatform',
    prNumber: 123,
    body: `${profile.MARKER}\nnew`,
  })

  assert.equal(result, 'updated')
  assert.equal(calls.length, 1)
  assert.equal(calls[0][0], 'update')
  assert.equal(calls[0][1].comment_id, 42)
})
