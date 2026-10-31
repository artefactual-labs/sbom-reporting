import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { sbomEvidence } from '../src/sbom_reporting/frontend/sbom-evidence.mjs'

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'sbom-plugin-'))
  const previous = process.env.SBOM_FRONTEND_EVIDENCE
  const cwd = process.cwd()
  process.chdir(root)
  process.env.SBOM_FRONTEND_EVIDENCE = join(root, 'evidence.json')
  t.after(() => {
    process.chdir(cwd)
    if (previous === undefined) delete process.env.SBOM_FRONTEND_EVIDENCE
    else process.env.SBOM_FRONTEND_EVIDENCE = previous
    rmSync(root, { recursive: true, force: true })
  })
  const file = (name, value) => {
    const path = join(root, name)
    mkdirSync(dirname(path), { recursive: true })
    writeFileSync(path, typeof value === 'string' ? value : JSON.stringify(value))
    return path
  }
  const context = { environment: { config: { consumer: 'client' } } }
  return { root, file, context, read: () => JSON.parse(readFileSync(process.env.SBOM_FRONTEND_EVIDENCE, 'utf8')) }
}

test('attributes rendered packages separately from build-only inputs without changing output', t => {
  const f = fixture(t)
  for (const name of ['shipped', 'shaken']) f.file(`node_modules/${name}/package.json`, { name, version: '1.2.3' })
  const shipped = f.file('node_modules/shipped/index.js', 'export const answer = 42')
  const shaken = f.file('node_modules/shaken/index.js', 'export const unused = 0')
  const plugin = sbomEvidence()
  assert.equal(plugin.transform('', shipped), null)
  assert.equal(plugin.transform('', shaken), null)
  const bundle = { 'app.js': { type: 'chunk', fileName: 'app.js', code: 'console.log(42)', modules: { [shipped]: { renderedLength: 10 }, [shaken]: { renderedLength: 0 } } } }
  const before = structuredClone(bundle)
  plugin.writeBundle.call(f.context, {}, bundle)
  assert.deepEqual(bundle, before)
  const result = f.read()
  assert.deepEqual(result.packages.find(p => p.name === 'shipped').origins, ['frontend-bundle', 'frontend-build-input'])
  assert.deepEqual(result.packages.find(p => p.name === 'shaken').origins, ['frontend-build-input'])
  assert.equal(result.chunks[0].sha256, createHash('sha256').update(bundle['app.js'].code).digest('hex'))
})

test('Nuxt Icon attribution validates generated data against its installed package', t => {
  const f = fixture(t)
  f.file('node_modules/@iconify-json/demo/package.json', { name: '@iconify-json/demo', version: '1.0.0' })
  f.file('node_modules/@iconify-json/demo/icons.json', { icons: { check: { body: '<path/>' } } })
  const id = join(f.root, '.nuxt/nuxt-icon-client-bundle.mjs')
  const code = `const collections = JSON.parse(${JSON.stringify(JSON.stringify([{ prefix: 'demo', icons: { check: { body: '<path/>' } } }]))})`
  const plugin = sbomEvidence({ nuxtIcons: true })
  plugin.transform(code, id)
  const bundle = { 'app.js': { type: 'chunk', fileName: 'app.js', code, modules: { [id]: { renderedLength: code.length } } } }
  plugin.writeBundle.call(f.context, {}, bundle)
  assert.equal(f.read().packages[0].name, '@iconify-json/demo')
  f.file('node_modules/@iconify-json/demo/icons.json', { icons: { check: { body: 'different' } } })
  assert.throws(() => plugin.writeBundle.call(f.context, {}, bundle), /Unknown bundled icon/)
  plugin.transform('changed upstream format', id)
  assert.throws(() => plugin.writeBundle.call(f.context, {}, bundle), /Unknown Nuxt Icon bundle format/)
})

test('fails when a rendered package cannot be identified', t => {
  const f = fixture(t)
  const id = f.file('node_modules/unknown/index.js', 'x')
  const plugin = sbomEvidence()
  assert.throws(() => plugin.writeBundle.call(f.context, {}, { 'app.js': { type: 'chunk', fileName: 'app.js', code: 'x', modules: { [id]: { renderedLength: 1 } } } }), /Cannot identify bundled package/)
})
