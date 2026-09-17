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
assert.match(app, /api\/metrics/);
assert.match(app, /local-ai-gpu/);
assert.match(app, /History messages/);
assert.doesNotMatch(app, /No chat history on this server\./);
assert.match(app, /active_compute_processes/);
assert.match(app, /memory_used_bytes/);

console.log('Local AI menu/page contract is present');
