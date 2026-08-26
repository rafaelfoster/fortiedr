import test from 'node:test';
import assert from 'node:assert/strict';
import manifest from '../src/generated-manifest.json' with { type: 'json' };
import * as client from '../dist/index.js';

test('exports every controller discovered from the Python implementation', () => {
  for (const className of Object.keys(manifest.classes)) {
    assert.equal(typeof client[className], 'function', `missing export ${className}`);
  }
});

test('controller instances expose every discovered method', () => {
  for (const [className, methods] of Object.entries(manifest.classes)) {
    const instance = new client[className]({
      get: async () => ({ status: true, data: null }),
      send: async () => ({ status: true, data: null }),
      insert: async () => ({ status: true, data: null }),
      update: async () => ({ status: true, data: null }),
      delete: async () => ({ status: true, data: null }),
    });
    for (const method of Object.keys(methods)) assert.equal(typeof instance[method], 'function', `${className}.${method}`);
  }
});
