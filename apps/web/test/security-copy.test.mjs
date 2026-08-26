import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

test('simulated attestation is never presented as verified hardware', () => {
  const page = readFileSync(new URL('../app/page.tsx', import.meta.url), 'utf8');
  assert.match(page, /SIMULATED/);
  assert.match(page, /NOT HARDWARE-BACKED/);
  assert.doesNotMatch(page, /Confidential Computing enabled/);
});
