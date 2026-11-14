import { readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
const html = readFileSync(new URL('../web/index.html', import.meta.url), 'utf8');
const m = html.match(/<script id="moonbin-glue">([\s\S]*?)<\/script>/);
// evaluate glue in a scope without document so DOM wiring is skipped
const fn = new Function(m[1] + '; return { createMoonbinRuntime, parseHex };');
const { createMoonbinRuntime } = fn();
const wasm = readFileSync(new URL('../web/main.wasm', import.meta.url));
const mod = new WebAssembly.Module(wasm);
const rt = createMoonbinRuntime(mod);
const bytes = new Uint8Array(readFileSync(new URL('../examples/notepad.exe', import.meta.url)));
const res = rt.run(bytes);
writeFileSync(new URL('../docs/report.json', import.meta.url), res.stdout);
console.log('report bytes', res.stdout.length);
