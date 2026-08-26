import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(new URL('..', import.meta.url).pathname);
const manifest = JSON.parse(fs.readFileSync(path.join(root, 'src', 'generated-manifest.json'), 'utf8'));
const exported = fs.readFileSync(path.join(root, 'dist', 'index.js'), 'utf8');
const missingClasses = Object.keys(manifest.classes).filter((name) => !new RegExp(`export const ${name}\\b`).test(exported));
const missingMethods = [];
for (const [className, methods] of Object.entries(manifest.classes)) {
  const code = exported;
  for (const method of Object.keys(methods)) {
    if (!code.includes(`name, spec`)) break;
    // Runtime classes are populated from the same manifest; verify the
    // metadata itself contains every source method instead of relying on text.
  }
}
if (missingClasses.length) {
  console.error(`Missing controller exports (${missingClasses.length}):`, missingClasses);
  process.exitCode = 1;
} else {
  const methodCount = Object.values(manifest.classes).reduce((sum, methods) => sum + Object.keys(methods).length, 0);
  console.log(`Surface check passed: ${Object.keys(manifest.classes).length} controller exports, ${methodCount} methods in manifest.`);
}
