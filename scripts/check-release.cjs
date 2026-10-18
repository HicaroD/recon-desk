const assert = require('node:assert/strict');
const manifest = require('../extension/manifest.json');
const pkg = require('../package.json');

const tag = process.argv[2] || process.env.RELEASE_TAG;
assert.ok(tag, 'Provide the release tag: npm run check:release -- v0.1.0');
assert.equal(tag, `v${manifest.version}`, 'Release tag must match the manifest version');
assert.equal(pkg.version, manifest.version, 'Package and manifest versions must match');

const id = manifest.browser_specific_settings?.gecko?.id;
assert.ok(id && id !== 'client-watcher@local.invalid',
  'Choose a permanent gecko.id in extension/manifest.json before publishing');
assert.ok(manifest.browser_specific_settings.gecko.strict_min_version,
  'Declare the minimum supported Firefox version');

console.log(`Release ${tag} is ready for submission as ${id}`);
