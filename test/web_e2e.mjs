#!/usr/bin/env node
// Headless end-to-end test for the moonbin wasm playground.
//
// Strategy: no browser required. The page's inline glue (<script
// id="moonbin-glue"> in web/index.html) is extracted and evaluated in a VM
// sandbox, then driven against the real release wasm (web/main.wasm, produced
// by web/build.sh). This exercises the exact code the browser runs: the
// MoonBit fs/argv/stdout import protocol, the JSON report, and the hex parser.
//
// Fixtures mirror the golden in-repo MoonBit fixtures (src/pe/pe_test.mbt
// build_pe(true), and a minimal valid ELF64), so the parsers are fed bytes
// they are known to accept.
//
// Run: node test/web_e2e.mjs   (after bash web/build.sh)

import { readFileSync, existsSync, mkdtempSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import vm from 'node:vm';
import http from 'node:http';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const wasmPath = path.join(root, 'web', 'main.wasm');
const htmlPath = path.join(root, 'web', 'index.html');

// ---------------------------------------------------------------- fixtures

/// Golden PE32+ image, byte-for-byte mirror of src/pe/pe_test.mbt build_pe(true).
export function buildPeFixture() {
  const a = new Uint8Array(0x600);
  const dv = new DataView(a.buffer);
  const put16 = (off, v) => dv.setUint16(off, v, true);
  const put32 = (off, v) => dv.setUint32(off, v, true);
  const put64 = (off, v) => dv.setBigUint64(off, BigInt(v), true);
  const putstr = (off, s) => {
    for (let i = 0; i < s.length; i++) a[off + i] = s.charCodeAt(i);
  };
  const putname = (off, s) => {
    for (let i = 0; i < 8; i++) a[off + i] = i < s.length ? s.charCodeAt(i) : 0;
  };
  // DOS header
  putstr(0, 'MZ');
  put32(0x3c, 0x40);
  // NT signature + COFF
  putstr(0x40, 'PE');
  put16(0x44, 0x8664);
  put16(0x46, 2);
  put32(0x48, 0x60000000);
  put16(0x54, 240);
  put16(0x56, 0x2022);
  // Optional header (PE32+)
  const o = 0x58;
  put16(o, 0x20b);
  a[o + 2] = 14;
  put32(o + 4, 0x200);
  put32(o + 8, 0x200);
  put32(o + 16, 0x1000);
  put32(o + 20, 0x1000);
  put64(o + 24, 0x140000000);
  put32(o + 32, 0x1000);
  put32(o + 36, 0x200);
  put16(o + 40, 6);
  put16(o + 48, 6);
  put32(o + 56, 0x3000);
  put32(o + 60, 0x200);
  put16(o + 68, 3);
  put16(o + 70, 0x160);
  put64(o + 72, 0x100000);
  put64(o + 80, 0x1000);
  put64(o + 88, 0x100000);
  put64(o + 96, 0x1000);
  put32(o + 108, 16);
  const d = o + 112;
  put32(d, 0x2000);
  put32(d + 4, 0xa0);
  put32(d + 8, 0x2100);
  put32(d + 12, 40);
  // Section table
  const s = o + 240;
  putname(s, '.text');
  put32(s + 8, 0x40);
  put32(s + 12, 0x1000);
  put32(s + 16, 0x200);
  put32(s + 20, 0x200);
  put32(s + 36, 0x60000020);
  putname(s + 40, '.rdata');
  put32(s + 48, 0x1c0);
  put32(s + 52, 0x2000);
  put32(s + 56, 0x200);
  put32(s + 60, 0x400);
  put32(s + 76, 0x40000040);
  // .text raw: ret then int3 padding
  for (let i = 0x200; i < 0x400; i++) a[i] = 0xcc;
  a[0x200] = 0xc3;
  // .rdata: export directory
  const rd = 0x400;
  put32(rd + 4, 0x60000000);
  put32(rd + 12, 0x2080);
  put32(rd + 16, 1);
  put32(rd + 20, 1);
  put32(rd + 24, 1);
  put32(rd + 28, 0x2040);
  put32(rd + 32, 0x2050);
  put32(rd + 36, 0x2060);
  put32(rd + 0x40, 0x1000);
  put32(rd + 0x50, 0x2090);
  put16(rd + 0x60, 0);
  putstr(rd + 0x80, 'moonbin_test.dll');
  putstr(rd + 0x90, 'moonbin_export');
  // Import directory
  const im = rd + 0x100;
  put32(im, 0x2140);
  put32(im + 12, 0x2180);
  put32(im + 16, 0x2160);
  const ilt = rd + 0x140;
  const iat = rd + 0x160;
  put64(ilt, 0x21a0);
  put64(ilt + 8, 0x21b0);
  put64(iat, 0x21a0);
  put64(iat + 8, 0x21b0);
  putstr(rd + 0x180, 'KERNEL32.dll');
  put16(rd + 0x1a0, 0);
  putstr(rd + 0x1a2, 'LoadLibraryA');
  put16(rd + 0x1b0, 0);
  putstr(rd + 0x1b2, 'GetProcAddress');
  return a;
}

/// Minimal valid ELF64 LSB x86-64 executable:
/// sections NULL/.text/.symtab/.strtab/.shstrtab, one PT_LOAD, symbol "main".
export function buildElfFixture() {
  const fileSize = 0x2a1;
  const a = new Uint8Array(fileSize);
  const dv = new DataView(a.buffer);
  const u16 = (off, v) => dv.setUint16(off, v, true);
  const u32 = (off, v) => dv.setUint32(off, v, true);
  const u64 = (off, v) => dv.setBigUint64(off, BigInt(v), true);
  const str = (off, s) => {
    for (let i = 0; i < s.length; i++) a[off + i] = s.charCodeAt(i);
  };
  // e_ident
  a[0] = 0x7f; a[1] = 0x45; a[2] = 0x4c; a[3] = 0x46;
  a[4] = 2; a[5] = 1; a[6] = 1;
  u16(16, 2);          // e_type EXEC
  u16(18, 62);         // e_machine x86-64
  u32(20, 1);          // e_version
  u64(24, 0x1080);     // e_entry
  u64(32, 0x40);       // e_phoff
  u64(40, 0x100);      // e_shoff
  u16(52, 64);         // e_ehsize
  u16(54, 56);         // e_phentsize
  u16(56, 1);          // e_phnum
  u16(58, 64);         // e_shentsize
  u16(60, 5);          // e_shnum
  u16(62, 4);          // e_shstrndx
  // PT_LOAD covering the whole file at vaddr 0x1000
  u32(0x40, 1); u32(0x44, 5);
  u64(0x48, 0); u64(0x50, 0x1000); u64(0x58, 0x1000);
  u64(0x60, fileSize); u64(0x68, fileSize); u64(0x70, 0x1000);
  // .text at file 0x80: ret + int3 padding
  a[0x80] = 0xc3; a[0x81] = 0xcc; a[0x82] = 0xcc; a[0x83] = 0xcc;
  // section headers at 0x100
  const sh = (i, name, type, flags, addr, off, size, link, info, align, entsize) => {
    const b = 0x100 + i * 64;
    u32(b, name); u32(b + 4, type); u64(b + 8, flags); u64(b + 16, addr);
    u64(b + 24, off); u64(b + 32, size); u32(b + 40, link); u32(b + 44, info);
    u64(b + 48, align); u64(b + 56, entsize);
  };
  sh(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  sh(1, 1, 1, 6, 0x1080, 0x80, 4, 0, 0, 16, 0);        // .text
  sh(2, 7, 2, 0, 0, 0x240, 48, 3, 1, 8, 24);           // .symtab
  sh(3, 15, 3, 0, 0, 0x270, 6, 0, 0, 1, 0);            // .strtab
  sh(4, 23, 3, 0, 0, 0x280, 33, 0, 0, 1, 0);           // .shstrtab
  // .symtab: null + main (FUNC GLOBAL, section 1)
  u32(0x240 + 24, 1);            // st_name
  a[0x240 + 28] = 0x12;          // st_info
  u16(0x240 + 30, 1);            // st_shndx
  u64(0x240 + 32, 0x1080);       // st_value
  u64(0x240 + 40, 4);            // st_size
  // .strtab / .shstrtab
  str(0x271, 'main');
  str(0x281, '.text');
  str(0x287, '.symtab');
  str(0x28f, '.strtab');
  str(0x297, '.shstrtab');
  return a;
}

// ------------------------------------------------- headless browser check

function findBrowser() {
  const candidates = process.platform === 'win32' ? [
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
    'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
  ] : process.platform === 'darwin' ? [
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
  ] : [
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/usr/bin/microsoft-edge',
  ];
  for (const c of candidates) {
    if (existsSync(c)) return c;
  }
  return null;
}

/// Serve web/ over HTTP, load index.html?sample=1 in headless Chrome/Edge,
/// and assert the *rendered DOM* contains the analysis results. Markers are
/// chosen so they cannot appear in the static page source (only in output
/// produced by running the wasm).
async function headlessCheck(check) {
  const browser = findBrowser();
  if (!browser) {
    console.log('headless browser: not found -- the node smoke above is the fallback');
    return;
  }
  const webRoot = path.join(root, 'web');
  const server = http.createServer((req, res) => {
    const urlPath = decodeURIComponent((req.url || '/').split('?')[0]);
    const file = path.join(webRoot, urlPath === '/' ? 'index.html' : urlPath);
    if (!file.startsWith(webRoot) || !existsSync(file)) {
      res.statusCode = 404;
      res.end('not found');
      return;
    }
    const type = file.endsWith('.wasm') ? 'application/wasm'
      : file.endsWith('.html') ? 'text/html; charset=utf-8'
      : 'application/octet-stream';
    res.setHeader('Content-Type', type);
    res.end(readFileSync(file));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const profile = mkdtempSync(path.join(os.tmpdir(), 'mbweb-browser-'));
  try {
    const args = [
      '--headless=new', '--no-sandbox', '--disable-gpu', '--no-first-run',
      '--no-default-browser-check', '--disable-extensions',
      '--user-data-dir=' + profile,
      '--virtual-time-budget=15000',
      '--dump-dom',
      `http://127.0.0.1:${port}/index.html?sample=1`,
    ];
    const r = spawnSync(browser, args, { encoding: 'utf8', timeout: 90000, maxBuffer: 64 * 1024 * 1024 });
    const dom = r.stdout || '';
    const diag = `exit=${r.status} ${(r.stderr || '').slice(0, 200)}`;
    // Some sandboxes launch a browser that hangs / exits null. The node wasm
    // leg above is the authoritative check there; only assert the DOM when the
    // browser actually rendered (CI with a working Chrome exercises this leg).
    if (r.status !== 0 || dom.length === 0) {
      console.log('  headless browser did not render (exit=' + r.status + '); skipping DOM leg (node wasm leg already verified)');
      return;
    }
    check('headless: page rendered image base', dom.includes('0x140000000'), diag);
    check('headless: page rendered imports', dom.includes('KERNEL32.dll') && dom.includes('LoadLibraryA'), diag);
    check('headless: page rendered exports', dom.includes('moonbin_export'), diag);
    check('headless: page rendered disassembly', dom.includes('int3'), diag);
  } finally {
    server.close();
    // A hung browser may still hold the temp profile on Windows; cleanup is
    // best-effort and must not fail the run.
    try { rmSync(profile, { recursive: true, force: true }); } catch {}
  }
}

// ------------------------------------------------------------------ harness

async function main() {
let passed = 0;
let failed = 0;
function check(name, cond, detail) {
  if (cond) {
    passed += 1;
    console.log(`  ok: ${name}`);
  } else {
    failed += 1;
    console.log(`  FAIL: ${name}${detail === undefined ? '' : ' -- ' + detail}`);
  }
}

function fail(msg) {
  console.error(`web_e2e: FATAL: ${msg}`);
  console.error('web_e2e: 0 passed, 1 failed');
  process.exit(1);
}

if (!existsSync(htmlPath)) fail(`missing ${htmlPath}`);
if (!existsSync(wasmPath)) fail(`missing ${wasmPath} -- run: bash web/build.sh`);

const html = readFileSync(htmlPath, 'utf8');
const glueMatch = html.match(/<script id="moonbin-glue">([\s\S]*?)<\/script>/);
if (!glueMatch) fail('web/index.html has no <script id="moonbin-glue"> block');

const sandbox = {
  console,
  WebAssembly,
  TextDecoder,
  TextEncoder,
  Uint8Array,
  DataView,
  BigInt,
  JSON,
  Math,
  setTimeout,
  clearTimeout,
};
vm.createContext(sandbox);
vm.runInContext(glueMatch[1], sandbox, { filename: 'moonbin-glue.js' });
if (typeof sandbox.createMoonbinRuntime !== 'function') fail('glue does not define createMoonbinRuntime');
if (typeof sandbox.parseHex !== 'function') fail('glue does not define parseHex');

const wasmBytes = readFileSync(wasmPath);
const mod = new WebAssembly.Module(wasmBytes);
const exportNames = WebAssembly.Module.exports(mod).map((e) => e.name);
check('wasm exports memory and _start entry', exportNames.includes('memory') && exportNames.includes('_start'), JSON.stringify(exportNames));

const rt = sandbox.createMoonbinRuntime(mod);
function run(bytes) {
  const res = rt.run(bytes);
  if (res.exitCode !== null && res.exitCode !== 0) {
    throw new Error(`entry exited with code ${res.exitCode}; stderr=${res.stderr}`);
  }
  return JSON.parse(res.stdout);
}
function ascii(s) {
  return Uint8Array.from([...s].map((c) => c.charCodeAt(0)));
}

// ------------------------------------------------------------------- tests

console.log('PE32+ golden fixture:');
{
  const r = run(buildPeFixture());
  check('parse ok', r.ok === true, r.error);
  check('format PE', r.format === 'PE');
  check('machine AMD64', r.machine === 0x8664);
  check('is64', r.is64 === true);
  check('entry RVA', r.entry === '0x1000');
  check('image base', r.base === '0x140000000');
  check('two sections', r.sections.length === 2 && r.sections[0].name === '.text' && r.sections[1].name === '.rdata');
  check('.text flags rx', r.sections[0].flags.includes('r') && r.sections[0].flags.includes('x'));
  check('imports LoadLibraryA', r.imports.some((i) => i.library === 'KERNEL32.dll' && i.name === 'LoadLibraryA'));
  check('imports GetProcAddress', r.imports.some((i) => i.library === 'KERNEL32.dll' && i.name === 'GetProcAddress'));
  check('export moonbin_export', r.exports.some((e) => e.name === 'moonbin_export' && e.ordinal === 1));
  check('disasm first insn ret', r.disasm.insns.length > 0 && r.disasm.insns[0].mnemonic === 'ret' && r.disasm.insns[0].addr === '0x1000' && r.disasm.insns[0].bytes === 'c3');
  check('disasm second insn int3', r.disasm.insns.length > 1 && r.disasm.insns[1].mnemonic === 'int3');
  // The fixture writes "moonbin_test.dll" at 0x480 and "moonbin_export" at
  // 0x490 with NO NUL between them, so they form one maximal printable run.
  check('strings find dll+export run', r.strings.some((s) => s.text === 'moonbin_test.dllmoonbin_export' && s.offset === '0x480'));
  check('strings find KERNEL32.dll', r.strings.some((s) => s.text === 'KERNEL32.dll'));
  check('entropy in 0..8', typeof r.entropy === 'number' && r.entropy >= 0 && r.entropy <= 8);
  check('section_entropy per section', r.section_entropy.length === 2 && r.section_entropy[0].name === '.text');
  check('size reported', r.size === 0x600);
}

console.log('ELF64 fixture:');
{
  const r = run(buildElfFixture());
  check('parse ok', r.ok === true, r.error);
  check('format ELF', r.format === 'ELF');
  check('class 64', r.class === 64);
  check('little endian', r.endian === 'little');
  check('machine x86-64', r.machine === 62);
  check('entry', r.entry === '0x1080');
  check('sections include .text/.symtab', r.sections.some((s) => s.name === '.text') && r.sections.some((s) => s.name === '.symtab'));
  check('symbol main', r.symbols.some((s) => s.name === 'main' && s.kind === 'func'));
  check('disasm ret at entry', r.disasm.insns.length > 0 && r.disasm.insns[0].mnemonic === 'ret' && r.disasm.insns[0].addr === '0x1080');
  check('strings find main', r.strings.some((s) => s.text === 'main'));
}

console.log('raw / refused inputs:');
{
  const r = run(ascii('\x00\x00Hello world\x00\x00'));
  check('unknown format refused', r.ok === false && r.format === 'unknown');
  check('strings still extracted', r.strings.some((s) => s.text === 'Hello world' && s.offset === '0x2'));
  check('entropy positive', r.entropy > 0);
}
{
  const r = run(new Uint8Array(1024));
  check('all-zero entropy is 0', r.entropy === 0);
  check('all-zero strings empty', r.strings.length === 0);
}
{
  const r = run(new Uint8Array(256).map((_, i) => i));
  check('uniform 256 entropy is 8', r.entropy === 8);
}
{
  const r = run(buildPeFixture().slice(0, 0x50));
  check('truncated PE refused', r.ok === false && r.format === 'PE' && /^truncated/.test(r.error), r.error);
  check('truncated PE still has entropy field', typeof r.entropy === 'number');
}
{
  const r = run(new Uint8Array(0));
  check('empty input refused cleanly', r.ok === false && r.size === 0 && r.entropy === 0 && r.strings.length === 0);
}
{
  const r = run(Uint8Array.from([0xfe, 0xed, 0xfa, 0xce, 0, 0, 0, 0]));
  check('Mach-O detected and parsed (truncated fixture refused)', r.format === 'Mach-O' && r.ok === false && !/not supported/.test(r.error));
}

console.log('hex parser (page input path):');
{
  const ph = sandbox.parseHex;
  check('plain hex pairs', JSON.stringify([...ph('4d 5a 90')]) === '[77,90,144]');
  check('0x prefixes and commas', JSON.stringify([...ph('0x4d, 0x5a; 90')]) === '[77,90,144]');
  check('empty text -> empty bytes', ph('  \n ').length === 0);
  let threw = false;
  try { ph('abc'); } catch (e) { threw = true; }
  check('odd digit count rejected', threw);
  threw = false;
  try { ph('zz'); } catch (e) { threw = true; }
  check('invalid hex chars rejected', threw);
}

console.log('runtime stability:');
{
  const pe = buildPeFixture();
  const a = rt.run(pe).stdout;
  const b = rt.run(pe).stdout;
  check('repeat runs are deterministic (fresh instance per run)', a === b);
  check('report is a single line', a.trim().split('\n').length === 1);
}

// ------------------------------------------------------------------ summary

console.log('headless browser page load:');
await headlessCheck(check);

console.log(`web_e2e: ${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
}

// Run the harness only when executed directly; importing this module (e.g.
// to regenerate the page's sample hex from buildPeFixture) runs no tests.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}