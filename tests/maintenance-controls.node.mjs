import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'

const root = new URL('../', import.meta.url)
const ci = readFileSync(new URL('.github/workflows/ci.yml', root), 'utf8')
const deploy = readFileSync(new URL('.github/workflows/deploy.yml', root), 'utf8')
const packageJson = JSON.parse(readFileSync(new URL('package.json', root), 'utf8'))

function job(workflow, name) {
  const match = workflow.match(new RegExp(`\\n  ${name}:\\n[\\s\\S]*?(?=\\n  [a-z][a-z0-9-]*:\\n|$)`))
  assert.ok(match, `missing ${name} job`)
  return match[0]
}

test('build jobs cannot mint Pages credentials', () => {
  for (const [name, workflow] of [['ci', ci], ['deploy', deploy]]) {
    const header = workflow.slice(0, workflow.indexOf('\njobs:'))
    assert.match(header, /permissions:\n  contents: read\n/, `${name} lacks read-only global permissions`)
    assert.doesNotMatch(header, /pages: write|id-token: write/, `${name} grants deployment credentials globally`)
    assert.doesNotMatch(job(workflow, name === 'ci' ? 'validate' : 'build'), /pages: write|id-token: write/)
  }

  assert.match(
    job(deploy, 'deploy'),
    /permissions:\n      contents: read\n      pages: write\n      id-token: write\n/,
  )
})

test('every action is pinned to an immutable commit', () => {
  for (const workflow of [ci, deploy]) {
    // Both step shapes, because workflows here use both: `- uses: x@sha`, and a
    // step that opens with `- id:` or `- name:` carrying `uses:` on its own line.
    // Anchored on `- uses:` alone this control could not see the deploy step at
    // all -- the one action that publishes the site -- so unpinning
    // actions/deploy-pages back to @v5 left every control green. Measured.
    const actions = [...workflow.matchAll(/^[ \t]*(?:-[ \t]+)?uses:[ \t]+([^@\s]+)@([^\s]+)/gm)]
    // A declared denominator. Every `uses:` line present must be a `uses:` line
    // parsed, so a step in a shape this pattern cannot read fails here instead
    // of passing unseen -- which is how the hole above stayed quiet.
    const present = workflow.match(/^[ \t]*(?:-[ \t]+)?uses:/gm) ?? []
    assert.equal(actions.length, present.length,
      `${present.length - actions.length} uses: line(s) this control cannot read`)

    assert.ok(actions.length > 0, 'workflow has no actions')
    for (const [, action, reference] of actions) {
      assert.match(reference, /^[0-9a-f]{40}$/, `${action} is not commit-pinned`)
    }
  }
})

test('the deploy build has no unnecessary Pages configuration action', () => {
  assert.doesNotMatch(deploy, /actions\/configure-pages/)
  assert.match(deploy, /actions\/upload-pages-artifact@[0-9a-f]{40}/)
})

test('the post-merge deployment dispatch stays direct and fail-closed', () => {
  const autoMerge = job(ci, 'dependabot-auto-merge')
  assert.doesNotMatch(autoMerge, /dependabot\/fetch-metadata/)
  assert.match(autoMerge, /gh workflow run deploy\.yml --repo "\$GITHUB_REPOSITORY" --ref main/)
  assert.doesNotMatch(autoMerge, /\|\|\s*(?:echo|true)|continue-on-error/)
})

test('the production build runs this maintenance gate', () => {
  assert.equal(packageJson.scripts['test:maintenance'], 'node --test tests/maintenance-controls.node.mjs')
  assert.match(packageJson.scripts.build, /npm run test:maintenance/)
})

test('both hosted validation paths run the focused Off-Key mutation gate', () => {
  assert.equal(packageJson.scripts['test:mutations'], 'node scripts/mutations.mjs')
  assert.match(job(ci, 'validate'), /npm run test:mutations/)
  assert.match(job(deploy, 'build'), /npm run test:mutations/)
})
