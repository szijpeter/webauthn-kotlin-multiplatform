const MARKER = '<!-- webauthn-pr-change-profile:v1 -->'

const CATEGORY_META = {
  published: { label: '📦 Published library source' },
  test: { label: '🧪 Tests / verification' },
  sample: { label: '🧭 Samples / demos' },
  docs_examples: { label: '📖 Documentation examples' },
  docs: { label: '📚 Documentation / specifications' },
  tooling: { label: '🔧 Build / CI / repo tooling' },
  publishing: { label: '📦 Publishing / dependency metadata' },
  api: { label: '📐 Public API baselines' },
  generated_reference: { label: '⚙️ Generated / reference material' },
  unclassified: { label: '⚠️ Unclassified source' },
  other: { label: '◻️ Other' },
}

const CATEGORY_ORDER = [
  'published',
  'test',
  'sample',
  'docs_examples',
  'docs',
  'tooling',
  'publishing',
  'api',
  'generated_reference',
  'unclassified',
  'other',
]

function startsWithAny(value, prefixes = []) {
  return prefixes.some(prefix => value.startsWith(prefix))
}

function isTestSource(path) {
  return /\/src\/(?:testFixtures|test|[^/]*Test)(?:\/|$)/.test(path)
}

function isApiBaseline(path) {
  return /(?:^|\/)api\/.*(?:\.api|\.klib\.api)$/.test(path)
}

function isBuildOrRepoMetadata(path) {
  if ([
    'build.gradle.kts',
    'settings.gradle.kts',
    'gradle.properties',
    'gradlew',
    'gradlew.bat',
  ].includes(path)) {
    return true
  }

  return /(?:^|\/)(?:build\.gradle\.kts|settings\.gradle\.kts|gradle\.properties)$/.test(path)
    || /(?:^|\/)gradle\.lockfile$/.test(path)
}

function isDocumentationPath(path, config) {
  if ((config.rootDocumentationFiles || []).includes(path)) {
    return true
  }

  if (startsWithAny(path, config.documentationPrefixes)) {
    return true
  }

  const basename = path.split('/').at(-1)
  return basename === 'README.md'
    || basename === 'CONTRIBUTING.md'
    || basename === 'SECURITY.md'
    || basename === 'CHANGELOG.md'
    || basename === 'LICENSE'
    || basename === 'LICENSE.md'
}

function isPublishedSource(path, config) {
  const [area] = path.split('/')
  if (!(config.publishedAreas || []).includes(area)) {
    return false
  }
  return /\/src\/(?:main|[^/]*Main)(?:\/|$)/.test(path)
}

function isSourceLike(path, config) {
  return (config.sourceExtensions || []).some(extension => path.endsWith(extension))
}

function classifyPath(path, config) {
  if (isTestSource(path)) return 'test'
  if (startsWithAny(path, config.testVerificationPrefixes)) return 'test'
  if ((config.generatedFiles || []).includes(path)) return 'generated_reference'
  if (isApiBaseline(path)) return 'api'
  if (startsWithAny(path, config.toolingPrefixes)) return 'tooling'
  if (isDocumentationPath(path, config)) return 'docs'
  if (startsWithAny(path, config.publishingPrefixes) || (config.publishingFiles || []).includes(path)) return 'publishing'
  if (isBuildOrRepoMetadata(path)) return 'tooling'
  if (startsWithAny(path, config.documentationExamplePrefixes)) return 'docs_examples'
  if (startsWithAny(path, config.samplePrefixes)) return 'sample'
  if (isPublishedSource(path, config)) return 'published'
  if (startsWithAny(path, config.referencePrefixes)) return 'generated_reference'
  if (path.startsWith('documentation/')) return 'docs'
  return isSourceLike(path, config) ? 'unclassified' : 'other'
}

function extractModule(path) {
  const parts = path.split('/')
  if (['core', 'client', 'server', 'sample', 'platform', 'documentation'].includes(parts[0]) && parts[1]) {
    return {
      area: parts[0],
      module: parts[1],
      key: `${parts[0]}/${parts[1]}`,
    }
  }

  if (['build-logic', 'tools', 'gradle', 'config', 'spec-cache', 'spec-notes'].includes(parts[0])) {
    return { area: parts[0], module: parts[0], key: parts[0] }
  }

  if (parts[0] === '.github') return { area: '.github', module: '.github', key: '.github' }
  return { area: 'repository', module: 'repository', key: 'repository' }
}

function extractPublishedPlatform(path) {
  const match = path.match(/\/src\/([^/]+)\//)
  if (!match) return null
  const sourceSet = match[1]

  if (sourceSet === 'commonMain') return 'Common'
  if (sourceSet === 'main' || sourceSet === 'jvmMain') return 'JVM'
  if (sourceSet === 'androidMain') return 'Android'
  if (sourceSet === 'iosMain' || sourceSet === 'appleMain' || sourceSet.startsWith('ios')) return 'iOS / Apple'
  if (sourceSet === 'jsMain' || sourceSet === 'wasmJsMain') return 'JS / Web'
  if (sourceSet === 'nativeMain' || /^(?:macos|linux|mingw)/.test(sourceSet)) return 'Native'
  if (sourceSet.endsWith('Main')) return sourceSet
  return null
}

function emptyStats() {
  return { files: 0, additions: 0, deletions: 0, churn: 0 }
}

function addFileStats(target, file) {
  target.files += 1
  target.additions += file.additions || 0
  target.deletions += file.deletions || 0
  target.churn += (file.additions || 0) + (file.deletions || 0)
}

function aggregateFiles(files, config) {
  const categories = Object.fromEntries(CATEGORY_ORDER.map(category => [category, emptyStats()]))
  const modules = new Map()
  const publishedPlatforms = new Map()
  const classifiedFiles = []

  for (const file of files) {
    const category = classifyPath(file.filename, config)
    const module = extractModule(file.filename)
    const classified = { ...file, category, module }
    classifiedFiles.push(classified)
    addFileStats(categories[category], file)

    if (['core', 'client', 'server'].includes(module.area) && ['published', 'test', 'api'].includes(category)) {
      if (!modules.has(module.key)) {
        modules.set(module.key, {
          area: module.area,
          module: module.module,
          published: emptyStats(),
          test: emptyStats(),
          api: emptyStats(),
        })
      }
      addFileStats(modules.get(module.key)[category], file)
    }

    if (category === 'published') {
      const platform = extractPublishedPlatform(file.filename) || 'Other published source'
      if (!publishedPlatforms.has(platform)) publishedPlatforms.set(platform, emptyStats())
      addFileStats(publishedPlatforms.get(platform), file)
    }
  }

  const totals = emptyStats()
  for (const category of CATEGORY_ORDER) {
    totals.files += categories[category].files
    totals.additions += categories[category].additions
    totals.deletions += categories[category].deletions
    totals.churn += categories[category].churn
  }

  return {
    categories,
    totals,
    modules: [...modules.values()],
    publishedPlatforms: [...publishedPlatforms.entries()].map(([platform, stats]) => ({ platform, ...stats })),
    classifiedFiles,
  }
}

function formatNumber(number) {
  return new Intl.NumberFormat('en-US').format(number)
}

function formatRatio(numerator, denominator) {
  if (denominator === 0) return 'n/a'
  return `${(numerator / denominator).toFixed(2)}×`
}

function formatPercent(part, total) {
  if (total === 0) return '0.0%'
  return `${((part / total) * 100).toFixed(1)}%`
}

function renderCategoryTable(stats) {
  const rows = [
    '| Category | Files | Added | Deleted | Churn | Share |',
    '|---|---:|---:|---:|---:|---:|',
  ]

  for (const category of CATEGORY_ORDER) {
    const values = stats.categories[category]
    if (values.files === 0) continue
    rows.push(
      `| ${CATEGORY_META[category].label} | ${formatNumber(values.files)} | +${formatNumber(values.additions)} | -${formatNumber(values.deletions)} | ${formatNumber(values.churn)} | ${formatPercent(values.churn, stats.totals.churn)} |`,
    )
  }

  return rows.join('\n')
}

function renderModuleTable(stats) {
  const modules = stats.modules
    .filter(module => module.published.churn + module.test.churn + module.api.churn > 0)
    .sort((a, b) => {
      const aChurn = a.published.churn + a.test.churn + a.api.churn
      const bChurn = b.published.churn + b.test.churn + b.api.churn
      return bChurn - aChurn || a.module.localeCompare(b.module)
    })

  if (modules.length === 0) return ''

  const rows = [
    '<details>',
    '<summary>Published changes by module</summary>',
    '',
    '| Module | Published churn | Test churn | API churn |',
    '|---|---:|---:|---:|',
  ]

  for (const module of modules) {
    rows.push(`| \`${module.module}\` | ${formatNumber(module.published.churn)} | ${formatNumber(module.test.churn)} | ${formatNumber(module.api.churn)} |`)
  }

  rows.push('', '</details>')
  return rows.join('\n')
}

function renderPlatformTable(stats) {
  const platforms = [...stats.publishedPlatforms]
    .filter(platform => platform.churn > 0)
    .sort((a, b) => b.churn - a.churn || a.platform.localeCompare(b.platform))

  if (platforms.length === 0) return ''

  const rows = [
    '<details>',
    '<summary>Published source by platform/source set</summary>',
    '',
    '| Platform / source set | Files | Churn |',
    '|---|---:|---:|',
  ]

  for (const platform of platforms) {
    rows.push(`| ${platform.platform} | ${formatNumber(platform.files)} | ${formatNumber(platform.churn)} |`)
  }

  rows.push('', '</details>')
  return rows.join('\n')
}

function renderUnclassified(stats) {
  const files = stats.classifiedFiles.filter(file => file.category === 'unclassified')
  if (files.length === 0) return ''

  const shown = files.slice(0, 20)
  const lines = [
    '> [!WARNING]',
    `> ${files.length} source-like file${files.length === 1 ? '' : 's'} did not match a known repository layout. Review the classifier before relying on the category totals.`,
    '',
    '<details>',
    '<summary>Unclassified source files</summary>',
    '',
    ...shown.map(file => `- \`${file.filename}\``),
  ]

  if (files.length > shown.length) lines.push(`- …and ${files.length - shown.length} more`)
  lines.push('', '</details>')
  return lines.join('\n')
}

function renderComment({ pr, stats, incomplete = false, includeMarker = true }) {
  const published = stats.categories.published
  const tests = stats.categories.test
  const relevantChurn = published.churn + tests.churn
  const lines = []

  if (includeMarker) lines.push(MARKER, '')
  lines.push(
    '## 📊 PR change profile',
    '',
    `Compared with \`${pr.base.ref}\` · head \`${pr.head.sha.slice(0, 7)}\``,
    '',
  )

  if (incomplete) {
    lines.push(
      '> [!WARNING]',
      '> GitHub returned fewer changed files than the PR reports. The statistics below are incomplete.',
      '',
    )
  }

  lines.push(
    renderCategoryTable(stats),
    '',
    '**Published source vs verification**',
    '',
    `- Published source churn: **${formatNumber(published.churn)}**`,
    `- Test / verification churn: **${formatNumber(tests.churn)}**`,
    `- Tests: **${formatPercent(tests.churn, relevantChurn)}** of published + test churn`,
    `- Test / published additions: **${formatRatio(tests.additions, published.additions)}**`,
    '',
    '> Change volume is descriptive; it is not a test coverage metric.',
  )

  const moduleTable = renderModuleTable(stats)
  if (moduleTable) lines.push('', moduleTable)

  const platformTable = renderPlatformTable(stats)
  if (platformTable) lines.push('', platformTable)

  const unclassified = renderUnclassified(stats)
  if (unclassified) lines.push('', unclassified)

  lines.push(
    '',
    '<details>',
    '<summary>Classification notes</summary>',
    '',
    '- Published source is shipped code under `core/`, `client/`, and `server/` production source sets.',
    '- Tests include test source sets, test fixtures, and committed external-consumer verification fixtures.',
    '- Samples, documentation examples, API baselines, build/CI/tooling, publishing metadata, and generated/reference material are tracked separately.',
    '- Metrics come from GitHub PR file metadata; PR code is not executed to produce this comment.',
    '',
    '</details>',
  )

  return lines.join('\n')
}

async function upsertComment({ github, owner, repo, prNumber, body }) {
  const comments = await github.paginate(
    github.rest.issues.listComments,
    { owner, repo, issue_number: prNumber, per_page: 100 },
  )

  const existing = comments.find(comment =>
    comment.user?.login === 'github-actions[bot]' && comment.body?.includes(MARKER),
  )

  if (!existing) {
    await github.rest.issues.createComment({ owner, repo, issue_number: prNumber, body })
    return 'created'
  }

  if (existing.body === body) return 'unchanged'

  await github.rest.issues.updateComment({ owner, repo, comment_id: existing.id, body })
  return 'updated'
}

async function run({ github, context, core, prNumber, config }) {
  if (!Number.isInteger(prNumber) || prNumber <= 0) {
    throw new Error(`Invalid pull request number: ${prNumber}`)
  }

  const { owner, repo } = context.repo
  const { data: pr } = await github.rest.pulls.get({ owner, repo, pull_number: prNumber })
  const files = await github.paginate(
    github.rest.pulls.listFiles,
    { owner, repo, pull_number: prNumber, per_page: 100 },
  )

  const incomplete = pr.changed_files > files.length
  const stats = aggregateFiles(files, config)

  if (!incomplete) {
    if (stats.totals.files !== pr.changed_files) {
      throw new Error(`File-count invariant failed: classified=${stats.totals.files}, PR=${pr.changed_files}`)
    }
    if (stats.totals.additions !== pr.additions) {
      throw new Error(`Addition invariant failed: classified=${stats.totals.additions}, PR=${pr.additions}`)
    }
    if (stats.totals.deletions !== pr.deletions) {
      throw new Error(`Deletion invariant failed: classified=${stats.totals.deletions}, PR=${pr.deletions}`)
    }
  }

  const body = renderComment({ pr, stats, incomplete })
  const result = await upsertComment({ github, owner, repo, prNumber, body })

  core.info(`PR change profile ${result}: ${stats.totals.files} files, ${stats.totals.churn} lines of churn`)
  await core.summary.addRaw(renderComment({ pr, stats, incomplete, includeMarker: false })).write()
}

module.exports = {
  MARKER,
  CATEGORY_META,
  CATEGORY_ORDER,
  classifyPath,
  extractModule,
  extractPublishedPlatform,
  aggregateFiles,
  renderComment,
  upsertComment,
  run,
}
