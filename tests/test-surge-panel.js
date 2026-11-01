const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const script = fs.readFileSync(
  path.join(__dirname, '../scripts/po0-firewall-whitelist.js'),
  'utf8'
);

function status(count = 3, enabled = true) {
  return {
    enabled,
    currentIp: '203.0.113.0/24',
    limit: 5,
    whitelist: [
      { ip: '203.0.113.0/24', slot: 0 },
      { ip: '198.51.100.0/24', slot: null },
      { ip: '192.0.2.0/24', slot: null },
      { ip: '192.0.3.0/24', slot: null },
    ].slice(0, count),
  };
}

function run({ tokens = 'pgnfw_one', trigger, event, panel = false, responses = {} } = {}) {
  const calls = [];
  const notifications = [];
  const writes = [];
  const storage = {};
  let done;
  const completed = new Promise((resolve) => { done = resolve; });
  const http = (method, options, callback) => {
    calls.push({ method, options });
    const token = decodeURIComponent(options.url.split('/api/firewall/')[1].split('/')[0]);
    const reply = responses[token] || { status: 200, body: status() };
    callback(null, { status: reply.status }, JSON.stringify(reply.body));
  };
  const context = {
    $argument: 'tokens=' + tokens,
    $environment: { 'surge-version': '6' },
    $httpClient: {
      get(options, callback) { http('GET', options, callback); },
      post(options, callback) { http('POST', options, callback); },
    },
    $notification: { post(...args) { notifications.push(args); } },
    $persistentStore: {
      read(key) { return storage[key] || null; },
      write(value, key) { writes.push(key); storage[key] = value; return true; },
    },
    $done(result) { done(result); },
  };
  if (panel) context.$input = { purpose: 'panel', panelName: 'po0-fw' };
  if (trigger) context.$trigger = trigger;
  if (event) context.$event = { name: event };
  vm.runInNewContext(script, context);
  return completed.then((result) => ({ result, calls, notifications, writes }));
}

test('automatic panel refresh queries one token without adding or notifying', async () => {
  const { result, calls, notifications, writes } = await run({
    trigger: 'auto-interval', panel: true,
  });
  assert.deepEqual(calls.map((call) => call.method), ['GET']);
  assert.match(calls[0].options.url, /\/api\/firewall\/pgnfw_one$/);
  assert.equal(result.title, 'po0 防火墙 ✅ 1/1');
  assert.match(result.content, /出口 203\.0\.113\.0\/24\n白名单占用 3\/5/);
  assert.doesNotMatch(result.content, /198\.51\.100|📌|pgnfw_/);
  assert.equal(notifications.length, 0);
  assert.equal(writes.length, 0);
});

test('panel button adds current IP and shows whitelist detail', async () => {
  const { result, calls, notifications } = await run({
    tokens: 'pgnfw_one@0', trigger: 'button', panel: true,
  });
  assert.deepEqual(calls.map((call) => call.method), ['POST']);
  assert.match(calls[0].options.url, /\/api\/firewall\/pgnfw_one\/add\?slot=0$/);
  assert.equal(result.title, 'po0 防火墙 ✅ 1/1');
  assert.match(result.content, /白名单 3\/5\n  203\.0\.113\.0\/24 ← 当前出口/);
  assert.match(result.content, /198\.51\.100\.0\/24/);
  assert.doesNotMatch(result.content, /📌|pgnfw_/);
  assert.equal(notifications.length, 0);
});

test('automatic panel refresh summarizes three tokens', async () => {
  const { result, calls } = await run({
    tokens: 'pgnfw_one,pgnfw_two,pgnfw_three', trigger: 'auto-interval', panel: true,
    responses: {
      pgnfw_one: { status: 200, body: status(3) },
      pgnfw_two: { status: 200, body: status(4) },
      pgnfw_three: { status: 200, body: status(2) },
    },
  });
  assert.deepEqual(calls.map((call) => call.method), ['GET', 'GET', 'GET']);
  assert.equal(result.title, 'po0 防火墙 ✅ 3/3');
  assert.match(result.content, /#1 已加白 · 占用 3\/5/);
  assert.match(result.content, /#2 已加白 · 占用 4\/5/);
  assert.match(result.content, /#3 已加白 · 占用 2\/5/);
  assert.doesNotMatch(result.content, /📌|pgnfw_|198\.51\.100/);
});

for (const [label, options] of [['cron', {}], ['network-changed', { event: 'network-changed' }]]) {
  test(`${label} still adds and notifies on state change`, async () => {
    const { calls, notifications, result } = await run(options);
    assert.deepEqual(calls.map((call) => call.method), ['POST']);
    assert.match(calls[0].options.url, /\/add$/);
    assert.equal(notifications.length, 1);
    assert.match(result.title, /po0 加白 1\/1/);
  });
}

test('panel reports API failures without a success state', async () => {
  const { result, notifications } = await run({
    trigger: 'auto-interval', panel: true,
    responses: { pgnfw_one: { status: 400, body: { message: 'invalid token' } } },
  });
  assert.equal(result.title, 'po0 防火墙 ❌ 0/1');
  assert.match(result.content, /HTTP 400：invalid token/);
  assert.equal(notifications.length, 0);
});

test('disabled firewall is not displayed as whitelisted', async () => {
  const { result } = await run({
    trigger: 'auto-interval', panel: true,
    responses: { pgnfw_one: { status: 200, body: status(3, false) } },
  });
  assert.equal(result.title, 'po0 防火墙 ❌ 0/1');
  assert.match(result.content, /防火墙未启用/);
});
