/**
 * Focused mutation gate for the three relations that own the Off-Key lesson.
 *
 * Run only from a committed source tree. Each mutation is applied to the real
 * implementation, its named unit oracle must go red for an assertion reason,
 * and the source is restored byte-for-byte in a finally block.
 */

import { spawnSync } from 'node:child_process'
import { readFileSync, writeFileSync } from 'node:fs'

const SOURCE = 'src/spdz/offkey.ts'
const SPEC = 'src/spdz/offkey.test.ts'

const mutations = [
  {
    name: 'off-key mask loses beta context',
    anchor: 'const maskUnderBeta = shareSecret(blindMask, betaShares, sharingRand)',
    replacement: 'const maskUnderBeta = shareSecret(blindMask, alphaShares, sharingRand)',
    test: 'off-key masked check accepts exactly the matching guess and exposes the paper residual',
  },
  {
    name: 'repaired mask silently moves to beta',
    anchor: 'const maskUnderAlpha = shareSecret(blindMask, alphaShares, sharingRand)',
    replacement: 'const maskUnderAlpha = shareSecret(blindMask, betaShares, sharingRand)',
    test: 'same-context repair keeps preprocessing under alpha and turns the residual into a function of public d',
  },
  {
    name: 'attacker omits Delta times guess MAC shift',
    anchor: 'inputMacShareShift: mul(delta, guess),',
    replacement: 'inputMacShareShift: 0n,',
    test: 'attacker request adds Delta times the guess to its own MAC share',
  },
]

function run(command, args, timeout = 120_000) {
  return spawnSync(command, args, {
    encoding: 'utf8',
    env: { ...process.env, CI: '1' },
    maxBuffer: 16 * 1024 * 1024,
    timeout,
  })
}

function output(result) {
  return `${result.stdout ?? ''}${result.stderr ?? ''}`
}

function assertNormalExit(result, label) {
  if (result.error) throw result.error
  if (result.signal) throw new Error(`${label} ended by signal ${result.signal}\n${output(result)}`)
  if (result.status === null) throw new Error(`${label} did not report an exit code\n${output(result)}`)
}

function namedTest(testName, shouldPass) {
  const result = run('npx', [
    'vitest',
    'run',
    SPEC,
    '--reporter=verbose',
    '-t',
    testName,
  ])
  assertNormalExit(result, testName)
  const combined = output(result)
  if (!combined.includes(testName)) {
    throw new Error(`test output did not name its oracle: ${testName}\n${combined}`)
  }
  if (/No test files found|Failed to load|Cannot find module|Unhandled Error/i.test(combined)) {
    throw new Error(`infrastructure failure is not a mutation kill: ${testName}\n${combined}`)
  }
  if (shouldPass && result.status !== 0) {
    throw new Error(`clean oracle failed: ${testName}\n${combined}`)
  }
  if (!shouldPass && result.status === 0) {
    throw new Error(`mutation survived: ${testName}\n${combined}`)
  }
}

const source = readFileSync(SOURCE, 'utf8')
const initialDiff = run('git', ['diff', '--no-ext-diff', '--', SOURCE], 30_000)
assertNormalExit(initialDiff, 'git diff')
if (initialDiff.status !== 0 || output(initialDiff).trim() !== '') {
  throw new Error(`${SOURCE} must be committed and clean before mutation replay`)
}

const baseline = run('npx', ['vitest', 'run', SPEC, '--reporter=verbose'])
assertNormalExit(baseline, 'unmutated baseline')
if (baseline.status !== 0) throw new Error(`unmutated baseline failed\n${output(baseline)}`)
console.log('baseline: unmutated copy PASSES')

let caught = 0
for (const mutation of mutations) {
  if (source.split(mutation.anchor).length !== 2) {
    throw new Error(`${mutation.name}: source anchor must occur exactly once`)
  }

  try {
    const changed = source.replace(mutation.anchor, mutation.replacement)
    writeFileSync(SOURCE, changed)

    const diff = run('git', ['diff', '--no-ext-diff', '--', SOURCE], 30_000)
    assertNormalExit(diff, `${mutation.name}: git diff`)
    if (diff.status !== 0 || output(diff).trim() === '') {
      throw new Error(`${mutation.name}: mutation produced no source diff`)
    }

    namedTest(mutation.test, false)
    caught += 1
    console.log(`caught: ${mutation.name} -> ${mutation.test}`)
  } finally {
    writeFileSync(SOURCE, source)
  }

  if (readFileSync(SOURCE, 'utf8') !== source) {
    throw new Error(`${mutation.name}: source was not restored byte-for-byte`)
  }
  namedTest(mutation.test, true)
}

const finalDiff = run('git', ['diff', '--no-ext-diff', '--', SOURCE], 30_000)
assertNormalExit(finalDiff, 'final git diff')
if (finalDiff.status !== 0 || output(finalDiff).trim() !== '') {
  throw new Error(`${SOURCE} differs after mutation replay`)
}

console.log(`all ${caught} mutation(s) caught; source restored and controls PASS`)
