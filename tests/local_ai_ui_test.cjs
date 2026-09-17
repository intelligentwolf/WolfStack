const assert = require('node:assert/strict');
const fs = require('node:fs');

const app = fs.readFileSync('web/js/app.js', 'utf8');
const page = fs.readFileSync('web/index.html', 'utf8');

assert.match(app, /data-view="local-ai"/);
assert.match(app, /selectServerView\('\$\{node\.id\}', 'local-ai'\)/);
assert.match(app, /if \(view === 'local-ai'\)/);
assert.match(app, /function loadLocalAiPage/);
assert.match(page, /id="page-local-ai"/);
assert.match(app, /api\/ai\/diagnostics/);

console.log('Local AI menu/page contract is present');
