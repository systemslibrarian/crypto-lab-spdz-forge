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
    const actions = [...workflow.matchAll(/^\s*-\s+uses:\s+([^@\s]+)@([^\s]+)/gm)]
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
