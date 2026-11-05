// onosendai-region-vectors.ts: writes region-prefix-vectors.json from
// ONOSENDAI's own /C/ route code (origin/v2 src/lib/coordRoute.ts:
// parseCoordRoute, prefixRegion, coordPlace, placeHex), so the relay's
// relay.onosendai.tech/<hex> and ONOSENDAI's www.onosendai.tech/C/<hex> are
// tested against one file (speakeasy ruling D7, 2026-11-04).
//
// Every number in the file comes from ONOSENDAI's functions; this script only
// chooses the inputs and the points, and checks that every point it lists as
// inside starts with the region's hex and every point outside does not.
//
// To run it, copy src/lib/coordRoute.ts from arkin0x/ONOSENDAI origin/v2 next
// to this file, then, with an ONOSENDAI checkout's node_modules (npm ci) on
// NODE_PATH:
//   esbuild onosendai-region-vectors.ts --bundle --platform=node --format=esm --outfile=run.mjs
//   node run.mjs <onosendai commit> > region-prefix-vectors.json
import { coordToXyz } from 'cyberspace-core'
import { coordPlace, parseCoordRoute, placeHex, prefixRegion } from './coordRoute'

type Plane = 0 | 1
const AXIS_MAX = (1n << 85n) - 1n

// A coordinate with no structure, used to fill a prefix out to 64 characters.
const FILL = '9e3779b97f4a7c15f39cc0605cedc8341082276bf3a27251f86c6a11d0c18e95'
// The owner's example (design 2026-11-04, section 1).
const OWNER = '0fe6b3deeb67e952f852e8c1df15'
const FULL1 = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9f'
const FULL0 = FULL1.slice(0, 63) + 'e'

interface Input { name: string; input: string; note: string }

const inputs: Input[] = [
  { name: 'shortest-0', input: '0', note: 'One character, the shortest prefix: the low corner of the whole space. Fixes x84 y84 z84 x83.' },
  { name: 'shortest-f', input: 'f', note: 'One character: x84 y84 z84 x83 all 1.' },
  { name: 'one-char-8', input: '8', note: 'One character: only x84 is 1.' },
  { name: 'two-chars', input: '0f', note: 'Two characters, 8 bits fixed.' },
  { name: 'odd-length-3', input: 'abc', note: 'An odd length: 12 bits fixed, 4 per axis.' },
  { name: 'odd-length-5', input: '7d2a9', note: 'An odd length: 20 bits fixed.' },
  { name: 'cube-21', input: FULL1.slice(0, 21), note: '21 characters fix 84 bits, 28 per axis: equal heights, a cube.' },
  { name: 'owner-example', input: OWNER, note: 'The owner\'s example, relay.onosendai.tech/' + OWNER + ' and www.onosendai.tech/C/' + OWNER + '.' },
  { name: 'longest-62', input: FULL1.slice(0, 62), note: '62 characters: 248 bits fixed.' },
  { name: 'longest-63', input: FULL1.slice(0, 63), note: '63 characters, the longest prefix: one bit free per axis and the plane bit open.' },
  { name: 'full-plane-1', input: FULL1, note: '64 characters: one gibson, the plane fixed by the last bit (1, ideaspace).' },
  { name: 'full-plane-0', input: FULL0, note: '64 characters: one gibson, plane 0 (dataspace).' },
  { name: 'full-all-zero', input: '0'.repeat(64), note: 'The origin of dataspace.' },
  { name: 'full-all-f', input: 'f'.repeat(64), note: 'The far corner of ideaspace.' },
  { name: 'upper-case', input: 'ABC', note: 'Case does not matter: the same region as abc.' },
  { name: 'mixed-case', input: 'AbC', note: 'Mixed case: the same region as abc.' },
  { name: 'mixed-case-owner', input: '0FE6b3DEeb67E952f852E8c1DF15', note: 'Mixed case: the same region as the owner\'s example.' },
  { name: 'full-upper-case', input: FULL1.toUpperCase(), note: '64 characters in upper case.' },
  { name: '0x-prefix', input: '0xabc', note: 'A leading 0x is dropped.' },
  { name: '0X-prefix', input: '0XABC', note: 'A leading 0X is dropped too.' },
  { name: 'full-0x-prefix', input: '0x' + FULL1, note: '0x and 64 characters: one gibson.' },
  { name: 'trailing-slash', input: 'abc/', note: 'Trailing slashes are dropped.' },
  { name: 'trailing-slashes', input: 'abc///', note: 'Every trailing slash is dropped.' },
  { name: 'percent-encoded', input: '%61%62%63', note: 'The path is percent-decoded once, then read: abc.' },
  { name: 'encoded-slash', input: 'abc%2F', note: 'An encoded trailing slash decodes to a slash, which is then dropped.' },
  { name: 'encoded-spaces', input: '%20abc%20', note: 'Whitespace around the decoded text is trimmed (JavaScript String.prototype.trim).' },
  { name: 'encoded-nbsp', input: '%C2%A0abc', note: 'U+00A0 is whitespace to trim.' },
  { name: 'encoded-bom', input: '%EF%BB%BFabc', note: 'U+FEFF is whitespace to trim (JavaScript trim strips it; Go unicode.IsSpace does not).' },
  { name: 'encoded-lf', input: '%0Aabc', note: 'U+000A (line feed) is whitespace to trim.' },
  { name: 'encoded-cr', input: '%0Dabc', note: 'U+000D (carriage return) is whitespace to trim.' },
  { name: 'encoded-vt', input: '%0Babc', note: 'U+000B (vertical tab) is whitespace to trim.' },
  { name: 'encoded-ff', input: '%0Cabc', note: 'U+000C (form feed) is whitespace to trim.' },
  { name: 'encoded-tab', input: '%09abc', note: 'U+0009 (tab) is whitespace to trim.' },
  { name: 'encoded-ogham-space', input: '%E1%9A%80abc', note: 'U+1680 (ogham space mark) is whitespace to trim.' },
  { name: 'encoded-en-quad', input: '%E2%80%80abc', note: 'U+2000 (en quad, the first of U+2000 to U+200A) is whitespace to trim.' },
  { name: 'encoded-hair-space', input: '%E2%80%8Aabc', note: 'U+200A (hair space, the last of U+2000 to U+200A) is whitespace to trim.' },
  { name: 'encoded-line-separator', input: '%E2%80%A8abc', note: 'U+2028 (line separator) is whitespace to trim.' },
  { name: 'encoded-paragraph-separator', input: '%E2%80%A9abc', note: 'U+2029 (paragraph separator) is whitespace to trim.' },
  { name: 'encoded-narrow-nbsp', input: '%E2%80%AFabc', note: 'U+202F (narrow no-break space) is whitespace to trim.' },
  { name: 'encoded-math-space', input: '%E2%81%9Fabc', note: 'U+205F (medium mathematical space) is whitespace to trim.' },
  { name: 'encoded-ideographic-space', input: '%E3%80%80abc', note: 'U+3000 (ideographic space) is whitespace to trim.' },
  { name: 'encoded-space-then-0x', input: '%200xabc', note: 'Trim runs before 0x is dropped, so a space before 0x still leaves abc.' },
  { name: 'zero-prefix-00', input: '00', note: 'Leading zeros are significant: 00 is not 0.' },
  { name: 'invalid-empty', input: '', note: 'Nothing after the slash.' },
  { name: 'invalid-slash-only', input: '/', note: 'Only slashes: empty once they are dropped.' },
  { name: 'invalid-0x-only', input: '0x', note: '0x and nothing else.' },
  { name: 'invalid-double-0x', input: '0x0xabc', note: 'Only one 0x is dropped.' },
  { name: 'invalid-not-hex', input: 'xyz', note: 'Not hex.' },
  { name: 'invalid-g', input: 'abg', note: 'One character that is not hex.' },
  { name: 'invalid-65-chars', input: FULL1 + '0', note: '65 characters: longer than a coordinate.' },
  { name: 'invalid-66-chars-0x', input: '0x' + FULL1 + '00', note: '0x and 66 characters.' },
  { name: 'invalid-inner-slash', input: 'ab/cd', note: 'A second path segment.' },
  { name: 'invalid-leading-slash', input: '/abc', note: 'A leading slash is not dropped.' },
  { name: 'invalid-dash', input: 'abc-def', note: 'A dash: a speakeasy name may have one, a region never does.' },
  { name: 'invalid-sign', input: '+abc', note: 'A sign.' },
  { name: 'invalid-inner-space', input: 'ab%20cd', note: 'Whitespace inside the text is not trimmed.' },
  { name: 'invalid-space-before-slash', input: 'abc%20/', note: 'Trim runs before the trailing slashes are dropped, so the space stays.' },
  { name: 'invalid-encoded-space-only', input: '%20', note: 'Only whitespace.' },
  { name: 'invalid-double-encoded', input: '%2561bc', note: 'Decoded once only: %2561 becomes %61, which is not hex.' },
  { name: 'invalid-bad-escape', input: '%zzabc', note: 'A malformed escape: the text is read undecoded, and % is not hex.' },
  { name: 'invalid-nel', input: '%C2%85abc', note: 'U+0085 is not whitespace to JavaScript trim (Go unicode.IsSpace says it is).' },
  { name: 'invalid-zwsp', input: '%E2%80%8Babc', note: 'U+200B (zero width space) is not whitespace to JavaScript trim: the range ends at U+200A.' },
  { name: 'invalid-mongolian-vowel-separator', input: '%E1%A0%8Eabc', note: 'U+180E (Mongolian vowel separator) is not whitespace to JavaScript trim (it was before Unicode 6.3).' },
  { name: 'invalid-fullwidth', input: '%EF%BD%81bc', note: 'A fullwidth a (U+FF41) is not hex.' },
]

interface Point { coord: string; x: string; y: string; z: string; plane: Plane }
interface Axis { min: string; max: string; height: number; size: string }

function point(hex: string): Point {
  const c = coordToXyz(BigInt('0x' + hex))
  return { coord: hex, x: c.x.toString(), y: c.y.toString(), z: c.z.toString(), plane: c.plane }
}
function at(x: bigint, y: bigint, z: bigint, plane: Plane): string {
  return placeHex({ x, y, z }, plane)
}
function flip(hex: string, bit: number): string {
  return (BigInt('0x' + hex) ^ (1n << BigInt(bit))).toString(16).padStart(64, '0')
}
function axis(min: bigint, h: number): Axis {
  const size = 1n << BigInt(h)
  return { min: min.toString(), max: (min + size - 1n).toString(), height: h, size: size.toString() }
}
function uniq(hexes: string[]): string[] {
  return [...new Set(hexes)]
}

const vectors: unknown[] = []
for (const v of inputs) {
  const route = parseCoordRoute('/C/' + v.input)
  if (route === null) throw new Error(`${v.name}: not a /C/ route`)
  if (route.kind === 'invalid') {
    vectors.push({ name: v.name, input: v.input, note: v.note, valid: false })
    continue
  }
  const hex = route.hex
  let base: { x: bigint; y: bigint; z: bigint }
  let h: { x: number; y: number; z: number }
  let plane: Plane | null
  let inside: string[]
  if (route.kind === 'prefix') {
    const r = prefixRegion(hex)
    base = r.base
    h = r.heights
    plane = null
    const max = { x: base.x + (1n << BigInt(h.x)) - 1n, y: base.y + (1n << BigInt(h.y)) - 1n, z: base.z + (1n << BigInt(h.z)) - 1n }
    inside = uniq([
      at(base.x, base.y, base.z, 0),
      at(base.x, base.y, base.z, 1),
      at(max.x, max.y, max.z, 0),
      at(max.x, max.y, max.z, 1),
      at(r.center.x, r.center.y, r.center.z, 0),
      hex + FILL.slice(hex.length),
    ])
  } else {
    const p = coordPlace(hex)
    base = p.position
    h = { x: 0, y: 0, z: 0 }
    plane = p.plane
    inside = [hex]
  }
  const ax = { x: axis(base.x, h.x), y: axis(base.y, h.y), z: axis(base.z, h.z) }
  const lo = { x: base.x, y: base.y, z: base.z }
  const hi = { x: BigInt(ax.x.max), y: BigInt(ax.y.max), z: BigInt(ax.z.max) }
  const p0: Plane = plane ?? 0
  const outside: string[] = []
  // One gibson past each face of the box, where the space goes on.
  for (const a of ['x', 'y', 'z'] as const) {
    if (lo[a] > 0n) outside.push(at(a === 'x' ? lo.x - 1n : lo.x, a === 'y' ? lo.y - 1n : lo.y, a === 'z' ? lo.z - 1n : lo.z, p0))
    if (hi[a] < AXIS_MAX) outside.push(at(a === 'x' ? hi.x + 1n : hi.x, a === 'y' ? hi.y + 1n : hi.y, a === 'z' ? hi.z + 1n : hi.z, p0))
  }
  const corner = at(lo.x, lo.y, lo.z, p0)
  // The lowest and the highest bit the hex fixes, flipped.
  outside.push(flip(corner, 256 - 4 * hex.length), flip(corner, 255))
  // A full coordinate fixes its plane: the same place in the other plane is outside.
  if (plane !== null) outside.push(flip(hex, 0))
  const out = uniq(outside)

  for (const c of inside) if (!c.startsWith(hex)) throw new Error(`${v.name}: inside point ${c} does not start with ${hex}`)
  for (const c of out) if (c.startsWith(hex)) throw new Error(`${v.name}: outside point ${c} starts with ${hex}`)
  if (placeHex(base, p0).slice(0, hex.length) !== hex) throw new Error(`${v.name}: the box corner does not encode back to ${hex}`)

  vectors.push({
    name: v.name,
    input: v.input,
    note: v.note,
    valid: true,
    kind: route.kind,
    hex,
    region: { plane, x: ax.x, y: ax.y, z: ax.z },
    inside: inside.map(point),
    outside: out.map(point),
  })
}

const commit = process.argv[2]
if (!commit || !/^[0-9a-f]{40}$/.test(commit)) throw new Error('usage: node run.mjs <onosendai commit, 40 hex>')

const file = {
  description: 'Region strings: what relay.onosendai.tech/<hex> and www.onosendai.tech/C/<hex> name, so a speakeasy URL and an ONOSENDAI link agree on the region (speakeasy ruling D7, 2026-11-04). Written from ONOSENDAI\'s own route code; this file is not normative. CYBERSPACE_V2.md defines the bit layout (section 2.2) and the hint box (section 7.7) but no region string; where a value here disagrees with that text, the text is right and the file is a bug.',
  format: [
    'input: the text after "/C/" in an ONOSENDAI path, or after "/" in a relay path, exactly as it appears in the URL (percent-encoding included).',
    'Reading an input: percent-decode it once (decodeURIComponent; on a malformed escape keep the text undecoded); trim whitespace as JavaScript String.prototype.trim does; drop every trailing "/"; drop one leading "0x" or "0X"; lowercase. The result must be 1 to 64 hex characters, or the input is invalid (valid: false, and nothing else is given).',
    'hex: the result. kind: "prefix" for 1 to 63 characters, "full" for 64.',
    'A prefix of n characters fixes the top 4n bits of the coordinate (CYBERSPACE_V2.md section 2.2: x84 y84 z84 x83 ... z0, then the plane bit), so it names the aligned box of every coordinate whose 64-hex form starts with hex. Each axis keeps its own number of free low bits, its height; the heights are equal (a cube) only when n is a multiple of 3. The plane bit is the coordinate\'s lowest bit, so a prefix never fixes it: plane is null, and the box is the same in both planes.',
    'A full coordinate is one gibson (every height 0) in the plane its lowest bit names.',
    'region: per axis, min and max (inclusive) as decimal integers, height, and size = 2^height = max - min + 1; plane is 0, 1, or null for either plane. A coordinate is inside exactly when its 64-hex form starts with hex: each axis in [min, max], and, when plane is not null, the same plane.',
    'inside and outside: coordinates as 64 lowercase hex characters with their axes as decimal integers and their plane, each one inside or outside the region. outside always holds one gibson past each face of the box where the space continues, and the box corner with the lowest and with the highest fixed bit flipped; for a full coordinate, also the same gibson in the other plane.',
  ],
  provenance: {
    onosendai_commit: commit,
    onosendai_code: 'src/lib/coordRoute.ts: parseCoordRoute, prefixRegion, coordPlace, placeHex; cyberspace-core coordToXyz',
    generator: 'arkin0x/cyberspace-relay server/regiongate/testdata/tools/onosendai-region-vectors.ts',
  },
  vectors,
}
process.stdout.write(JSON.stringify(file, null, 1) + '\n')
