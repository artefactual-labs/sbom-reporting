import { createHash } from 'node:crypto'
import { readFileSync, existsSync, mkdirSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'

// Record package attribution and hashes without changing emitted bundle bytes.
export function sbomEvidence({ nuxtIcons = false } = {}) {
  const transformed = new Set()
  const generatedIcons = new Map()
  return {
    name: 'sbom-reporting-evidence',
    apply: 'build',
    enforce: 'post',
    transform(_code, id) {
      transformed.add(id)
      if (nuxtIcons && decodeURIComponent(id).endsWith('/nuxt-icon-client-bundle.mjs')) generatedIcons.set(id, _code)
      return null
    },
    writeBundle(_options, bundle) {
      const destination = process.env.SBOM_FRONTEND_EVIDENCE
      if (!destination || this.environment?.config.consumer !== 'client') return
      const packages = new Map()
      const observe = (id, origin) => {
        const clean = decodeURIComponent(id.replace(/^\0/, '').split('?')[0])
        // Nuxt Icon inlines collection data into a generated module. Recover
        // its package origin from that module, and verify the actual icon bodies.
        if (nuxtIcons && origin === 'frontend-bundle' && clean.endsWith('/nuxt-icon-client-bundle.mjs')) {
          const code = generatedIcons.get(id)
          if (!code) throw new Error('Missing generated icon module evidence')
          const match = code.match(/const collections = JSON\.parse\(("(?:\\.|[^"\\])*")\)/)
          if (!match) throw new Error('Unknown Nuxt Icon bundle format')
          for (const collection of JSON.parse(JSON.parse(match[1]))) {
            const iconsPath = resolve('node_modules', '@iconify-json', collection.prefix, 'icons.json')
            const installed = JSON.parse(readFileSync(iconsPath, 'utf8'))
            for (const [name, icon] of Object.entries(collection.icons)) {
              if (icon.body !== installed.icons[name]?.body) throw new Error(`Unknown bundled icon: ${collection.prefix}:${name}`)
            }
            observe(iconsPath, 'frontend-bundle')
          }
        }
        if (!clean.includes('/node_modules/')) return
        let directory = dirname(clean)
        while (directory.includes('/node_modules')) {
          const manifest = join(directory, 'package.json')
          if (existsSync(manifest)) {
            const pkg = JSON.parse(readFileSync(manifest, 'utf8'))
            if (pkg.name && pkg.version) {
              const key = `${pkg.name}@${pkg.version}`
              const entry = packages.get(key) || { name: pkg.name, version: pkg.version, origins: [] }
              if (!entry.origins.includes(origin)) entry.origins.push(origin)
              packages.set(key, entry)
              return
            }
          }
          directory = dirname(directory)
        }
        throw new Error(`Cannot identify bundled package: ${id}`)
      }
      const chunks = []
      for (const item of Object.values(bundle)) {
        if (item.type !== 'chunk') continue
        for (const [id, info] of Object.entries(item.modules)) {
          if (info.renderedLength > 0) observe(id, 'frontend-bundle')
        }
        chunks.push({ name: item.fileName, sha256: createHash('sha256').update(item.code).digest('hex'), modules: Object.entries(item.modules).map(([id, info]) => ({ id, renderedLength: info.renderedLength })) })
      }
      // Includes CSS/JSON consumed by transforms; this is build evidence, not a
      // claim that every watched package survives tree shaking.
      for (const id of transformed) observe(id, 'frontend-build-input')
      if (!chunks.length || !packages.size) throw new Error('Empty frontend build evidence')
      mkdirSync(dirname(resolve(destination)), { recursive: true })
      writeFileSync(destination, JSON.stringify({ packages: [...packages.values()], chunks }, null, 2))
    }
  }
}
