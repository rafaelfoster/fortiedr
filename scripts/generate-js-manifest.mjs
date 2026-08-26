import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(new URL('..', import.meta.url).pathname);
const sources = [
  path.join(root, 'fortiedr', 'fortiedr.py'),
  ...fs.readdirSync(path.join(root, 'fortiedr', 'api'))
    .filter((file) => file.endsWith('.py'))
    .sort()
    .map((file) => path.join(root, 'fortiedr', 'api', file)),
];

const classes = {};
const sourceSymbols = {};

for (const filename of sources) {
  const source = fs.readFileSync(filename, 'utf8');
  const classMatches = [...source.matchAll(/^class\s+([A-Za-z_]\w*)[^:]*:/gm)];
  const fileSymbols = [];

  for (let index = 0; index < classMatches.length; index += 1) {
    const className = classMatches[index][1];
    const start = classMatches[index].index + classMatches[index][0].length;
    const end = classMatches[index + 1]?.index ?? source.length;
    const classSource = source.slice(start, end);
    const methods = {};

    for (const match of classSource.matchAll(/^\s{1,4}def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)/gm)) {
      const methodName = match[1];
      if (methodName === '__init__') continue;

      const signature = match[2]
        .split(',')
        .map((part) => part.trim())
        .filter((part) => part && part !== 'self' && !part.startsWith('*'))
        .map((part) => part.split(':')[0].split('=')[0].trim())
        .filter(Boolean);

      const methodStart = start + match.index + match[0].length;
      const nextMethod = classSource.slice(match.index + match[0].length).match(/^\s{1,4}def\s+/m);
      const methodEnd = nextMethod
        ? start + match.index + match[0].length + nextMethod.index
        : end;
      const body = source.slice(methodStart, methodEnd);
      const call = body.match(/(?:fortiedr_connection|self\.conn)\.(get|send|insert|update|delete|download|upload|post|put)\s*\(/);
      if (!call) continue;

      const directUrl = body.match(/(?:fortiedr_connection|self\.conn)\.(?:get|send|insert|update|delete|download|upload|post|put)\s*\(\s*f?["']([^"']+)["']/);
      const assignedUrl = body.match(/url\s*=\s*f?["']([^"']+)["']/);
      const url = directUrl?.[1] ?? assignedUrl?.[1];
      if (!url) continue;

      const method = call[1] === 'send' || call[1] === 'post'
        ? 'POST'
        : call[1] === 'insert' || call[1] === 'put'
          ? 'PUT'
          : call[1].toUpperCase();

      methods[methodName] = { params: signature, method, url };
      fileSymbols.push(`${className}.${methodName}`);
    }

    if (Object.keys(methods).length > 0) {
      classes[className] ??= {};
      Object.assign(classes[className], methods);
    }
  }

  sourceSymbols[path.relative(root, filename)] = fileSymbols;
}

const manifest = {
  generatedFrom: sources.map((filename) => path.relative(root, filename)),
  classes,
  sourceSymbols,
};

const output = path.join(root, 'src', 'generated-manifest.json');
fs.mkdirSync(path.dirname(output), { recursive: true });
fs.writeFileSync(output, `${JSON.stringify(manifest, null, 2)}\n`);
console.log(`Generated ${Object.keys(classes).length} classes and ${Object.values(classes).reduce((count, methods) => count + Object.keys(methods).length, 0)} methods.`);
