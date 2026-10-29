import assert from 'node:assert/strict';
import {spawn, spawnSync} from 'node:child_process';
import {createHash, webcrypto} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {createInterface} from 'node:readline';
import test from 'node:test';
import {fileURLToPath} from 'node:url';
import {isAbsolute} from 'node:path';

class Node {
  constructor(tag, text = '') {
    this.tag = tag;
    this._text = text;
    this.children = [];
    this.parent = null;
    this.className = '';
    this.style = {};
    this.disabled = false;
  }
  appendChild(child) {
    child.parent = this;
    this.children.push(child);
    return child;
  }
  replaceChildren(...children) {
    for (const child of this.children) child.parent = null;
    this.children = [];
    for (const child of children) this.appendChild(child);
  }
  set textContent(value) { this.replaceChildren(); this._text = String(value); }
  get textContent() { return this._text + this.children.map((child) => child.textContent).join(''); }
  get isConnected() { return this.tag === 'root' || (this.parent !== null && this.parent.isConnected); }
  getClientRects() { return this.isConnected ? [{}] : []; }
}

async function sidebar(fetch, loadGraphData = async () => {}, options = {}) {
  const installed = process.env.OA_COMFYUI_FRONTEND_UNDER_TEST;
  const expected = process.env.OA_COMFYUI_FRONTEND_SHA256;
  assert.equal(Boolean(installed), Boolean(expected), 'installed frontend needs its authenticated payload pin');
  if (installed) {
    assert.ok(isAbsolute(installed));
    assert.match(expected, /^[0-9a-f]{64}$/);
  }
  const bytes = await readFile(installed || new URL('../../openabstractions-flat/adopter-comfyui/web/oa_downloads.js', import.meta.url));
  if (installed) assert.equal(createHash('sha256').update(bytes).digest('hex'), expected, 'installed frontend bytes changed');
  const source = new TextDecoder('utf-8', {fatal: true}).decode(bytes);
  const timers = new Map();
  let nextTimer = 0;
  const root = new Node('root');
  const head = root.appendChild(new Node('head'));
  const document = {
    hidden: false,
    head,
    createElement: (tag) => new Node(tag),
    createTextNode: (value) => new Node('#text', String(value)),
    getElementById(id) {
      const visit = (node) => node.id === id ? node : node.children.map(visit).find(Boolean);
      return visit(root);
    },
  };
  let extension;
  let sidebarTab;
  let graph = options.graph || {nodes: [{id: 99}]};
  const renderRequests = [];
  const app = {registerExtension(value) { extension = value; }, loadGraphData,
    queuePrompt(...args) { renderRequests.push(args); return Promise.resolve(); },
    graph: {serialize: () => graph},
    extensionManager: {registerSidebarTab(value) { sidebarTab = value; },
      workflow: {activeWorkflow: {isModified: false}}, ...(options.extensionManager || {})}};
  const location = options.location || {search: '', pathname: '/'};
  const history = {replaced: [], replaceState(_state, _title, url) { this.replaced.push(url); location.search = ''; }};
  const make = new Function('app', 'document', 'fetch', 'setTimeout', 'clearTimeout', 'AbortController', 'crypto', 'TextEncoder', 'Date', 'location', 'history',
    `${source.replace(/^import .*;\r?\n/m, '')}\nreturn {mount, drawRow, actionMessage};`);
  const api = make(app, document, fetch,
    (callback, delay) => { const id = ++nextTimer; timers.set(id, {callback, delay}); return id; },
    (id) => timers.delete(id), AbortController, webcrypto, TextEncoder, options.Date || Date, location, history);
  await extension.setup();
  const tick = (delay) => {
    const [id, timer] = [...timers.entries()].find(([, timer]) => delay === undefined || timer.delay === delay) || [];
    assert.ok(timer, 'a poll is scheduled');
    timers.delete(id);
    return timer.callback();
  };
  return {api, root, document, timers, tick, extension, sidebarTab, history, renderRequests,
    serializeGraph: () => JSON.stringify(app.graph.serialize()), setGraph(value) { graph = value; }};
}

function find(node, predicate) {
  if (predicate(node)) return node;
  for (const child of node.children) {
    const found = find(child, predicate);
    if (found) return found;
  }
  return null;
}

const row = (state, percent, extras = {}) => ({
  id: 'f123', kind: 'file', model: 'flux-2-klein.safetensors',
  destination: 'C:\\ComfyUI\\models\\diffusion_models\\flux-2-klein.safetensors',
  state, percent, source: 'fetched', present: false, reason: '', children: [],
  identity: {key: 'fixture-key', history_epoch: 'fixture-epoch', attempt: 0}, ...extras,
});

const digest = 'a'.repeat(64);
const plan = (ready = false) => ({
  id: 'flux2-klein-distilled-v1', title: 'Prepare FLUX.2 Klein distilled',
  manifest_sha256: digest,
  template: {name: 'Official FLUX.2 Klein', revision: 'v1', url: 'https://example.org/template', variant: 'distilled-fp8'},
  assets: ['diffusion_models', 'text_encoders', 'vae'].map((folder, index) => ({
    role: folder, repository: 'black-forest-labs/FLUX.2-klein-4B', revision: 'pinned',
    url: `https://example.org/asset-${index}`, filename: `${folder}.safetensors`, folder,
    size_bytes: 1073741824, sha256: digest, license: {id: 'apache-2.0', url: 'https://example.org/license'},
    state: ready ? 'ready' : 'missing',
  })), ready, detail: '',
});

test('sidebar names the OpenAbstractions picture and download actions', async () => {
  const view = await sidebar(async () => reply(page()));
  assert.equal(view.sidebarTab.id, 'oaDownloads');
  assert.equal(view.sidebarTab.title, 'OpenAbstractions');
  assert.match(view.sidebarTab.tooltip, /picture workflows/);
  assert.match(view.sidebarTab.tooltip, /downloads/);
  assert.equal(view.sidebarTab.type, 'custom');
});

test('the image recipe loads on the click when the Klein asset plan is not ready', async () => {
  const graph = {nodes: [{id: 1, type: 'OAImageGenerate'}]};
  const calls = [];
  const fetch = async (path, options = {}) => {
    calls.push([path, options]);
    if (path === '/abstraction/jobs') return reply(page());
    if (path === '/abstraction/workflows/oa-image-generate') {
      return reply({id: 'oa-image-generate-preview-save-v1', ready: true, detail: ''});
    }
    if (path === '/abstraction/workflows/flux2-klein-distilled') return reply(plan(false));
    if (path === '/abstraction/workflows/oa-image-generate/graph') return graphReply(graph);
    assert.fail(`unexpected fetch ${path}`);
  };
  let loaded;
  const view = await sidebar(fetch, async (value) => { loaded = value; view.setGraph(value); });
  const host = view.root.appendChild(new Node('host'));
  const cleanup = view.api.mount(host);
  await waitUntil(() => {
    const button = find(host, (node) => node.tag === 'button' && node.textContent === 'Load picture recipe');
    return button && !button.disabled;
  }, 'image recipe setup readiness');
  const button = find(host, (node) => node.tag === 'button' && node.textContent === 'Load picture recipe');
  await button.onclick();
  assert.deepEqual(calls.filter(([path]) => path.endsWith('/graph')).map(([path]) => path),
    ['/abstraction/workflows/oa-image-generate/graph']);
  assert.equal(calls.some(([path, options]) => path.includes('/approval') || options.method === 'POST'), false,
    'the click asks no OA question');
  assert.deepEqual(loaded, graph);
  assert.match(host.textContent, /Workflow loaded into the editable canvas/);
  assert.equal(calls.includes('/abstraction/workflows/flux2-klein-distilled/graph'), false);
  cleanup();
});

const page = (rows = []) => ({outcome: 'page', changed: true, cursor: 'a', rows});
const reply = (body, status = 200) => ({ok: status < 400, status, json: async () => body});
const graphReply = (graph, hash = null) => {
  const raw = JSON.stringify(graph);
  return {ok: true, headers: {get: () => hash || createHash('sha256').update(raw).digest('hex')}, text: async () => raw};
};

function backendPlan() {
  const recipe = fileURLToPath(new URL('../../openabstractions-flat/adopter-comfyui/klein_recipe.py', import.meta.url));
  const script = `
import importlib.util, json, sys, tempfile, types
aiohttp = types.ModuleType("aiohttp")
aiohttp.web = types.SimpleNamespace()
sys.modules["aiohttp"] = aiohttp
spec = importlib.util.spec_from_file_location("oa_klein_recipe", sys.argv[1])
recipe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recipe)
with tempfile.TemporaryDirectory() as folder:
    recipe.configure(folder_paths=types.SimpleNamespace(get_folder_paths=lambda kind: [folder]))
    print(json.dumps(recipe.manifest()))
`;
  const args = process.platform === 'win32' ? ['-3.12', '-c', script, recipe] : ['-c', script, recipe];
  const result = spawnSync(process.platform === 'win32' ? 'py' : 'python3', args,
    {encoding: 'utf8', timeout: 15000});
  assert.equal(result.status, 0, result.stderr || String(result.error));
  return JSON.parse(result.stdout);
}

const flush = async () => { await new Promise((resolve) => setImmediate(resolve)); };
async function waitUntil(predicate, description) {
  for (let index = 0; index < 200; index++) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.fail(`timed out waiting for ${description}`);
}
async function stopFixtureProcess(child) {
  if (child.pid === undefined || child.exitCode !== null || child.signalCode !== null) return;
  child.kill();
  await new Promise((resolve) => {
    let finished = false;
    const finish = () => {
      if (finished) return;
      finished = true;
      clearTimeout(timeout);
      resolve();
    };
    const timeout = setTimeout(finish, 1000);
    child.once('close', finish);
    child.once('error', finish);
    if (child.exitCode !== null || child.signalCode !== null) finish();
  });
}

test('first detached render keeps polling and shows fresh progress after attachment', async () => {
  const requests = [];
  const pages = [
    {outcome: 'page', changed: true, cursor: 'a', rows: [row('running', 40)]},
    {outcome: 'page', changed: true, cursor: 'b', rows: [row('running', 42)]},
  ];
  const view = await sidebar(async (url, options) => {
    requests.push([url, options]);
    return reply(url === '/abstraction/jobs' || url.startsWith('/abstraction/jobs?') ? pages.shift() : plan());
  });
  const host = new Node('host');
  const cleanup = view.api.mount(host);
  await flush();
  assert.equal(requests.length, 2);
  view.root.appendChild(host);
  view.tick();
  await flush();
  assert.equal(requests.length, 3);
  assert.equal(requests[2][0], '/abstraction/jobs?since=a');
  const card = find(host, (node) => node.className === 'oa-row');
  assert.match(card.textContent, /In progress · 42%/);
  assert.doesNotMatch(card.textContent, /fetched/i);
  assert.match(card.textContent, /Folder: diffusion_models/);
  assert.equal(find(card, (node) => node.tag === 'details').children[1].textContent, row().destination);
  assert.equal(find(card, (node) => node.textContent === 'Retry').disabled, true);
  assert.equal(find(card, (node) => node.textContent === 'Cancel').disabled, false);
  assert.match(host.textContent, /1 operation/);
  cleanup();
  assert.equal(view.timers.size, 0);
});

test('terminal and uncertain states expose only meaningful actions and claims', async () => {
  const view = await sidebar(async () => { throw new Error('unused'); });
  assert.equal(view.api.actionMessage('cancel', {outcome: 'requested'}),
    'Cancellation requested; the operation may still finish');
  assert.equal(view.api.actionMessage('retry', {outcome: 'started'}), 'Retry started');
  for (const [state, present, retry, cancel] of [
    ['failed', false, false, true],
    ['cancelled', false, true, true],
    ['complete', false, true, true],
    ['complete', true, true, true],
    ['unknown', false, true, true],
    ['running', false, true, false],
  ]) {
    const card = view.api.drawRow(row(state, 100, {present}), () => {});
    assert.equal(find(card, (node) => node.textContent === 'Retry').disabled, retry, state);
    assert.equal(find(card, (node) => node.textContent === 'Cancel').disabled, cancel, state);
    if (state === 'complete' && !present) {
      assert.match(card.textContent, /Preparing model files · Download 100% · final file not yet available/);
      assert.doesNotMatch(card.textContent, /Ready|Downloaded from source/);
      assert.equal(find(card, (node) => node.className === 'oa-bar'), null);
    }
    if (state === 'complete' && present) assert.match(card.textContent, /Ready · Downloaded from source/);
  }
  const repository = view.api.drawRow({
    ...row('complete', 100, {present: true}), kind: 'repository', model: 'model-repo',
    children: [row('complete', 100, {id: 'c1', present: true}), row('complete', 100, {id: 'c2', present: false})],
  }, () => {});
  assert.match(repository.children[1].textContent, /Preparing model files · Download 100%/);
  assert.doesNotMatch(repository.children[1].textContent, /Ready/);
  const reusedMissing = view.api.drawRow(row('complete', 100, {source: 'reused', present: false}), () => {});
  assert.match(reusedMissing.textContent, /Preparing model files · final file not yet available/);
  assert.doesNotMatch(reusedMissing.textContent, /Download 100%|Ready/);
  const cancelling = view.api.drawRow(row('running', 42, {cancellation_requested: true}), () => {});
  assert.equal(find(cancelling, (node) => node.textContent === 'Cancel').disabled, true);
  const activeRetry = view.api.drawRow(row('failed', 42, {retry: {state: 'running'}}), () => {});
  assert.equal(find(activeRetry, (node) => node.textContent === 'Retry').disabled, true);
  const runningRetry = view.api.drawRow(row('running', 42, {retry: {state: 'running'}}), () => {});
  assert.equal(find(runningRetry, (node) => node.textContent === 'Cancel').disabled, false);
});

test('oversized repositories keep only individual Retry and Cancel actions', async () => {
  const view = await sidebar(async () => { throw new Error('unused'); });
  const children = Array.from({length: 257}, (_, i) => row('running', 42, {
    id: 'c' + i, identity: {key: 'key-' + i, history_epoch: 'epoch', attempt: 0},
  }));
  for (const state of ['failed', 'running']) {
    const card = view.api.drawRow(row(state, 42, {kind: 'repository', children}), () => {});
    assert.equal(find(card, (node) => node.textContent === 'Retry').disabled, true);
    assert.equal(find(card, (node) => node.textContent === 'Cancel').disabled, true);
  }
  const child = view.api.drawRow(children[0], () => {});
  assert.equal(find(child, (node) => node.textContent === 'Cancel').disabled, false);
});

test('reopened inventory operation shows progress and cancels without a download or retry claim', async (t) => {
  const requests = [];
  const operation = row('running', 40, {id: 'o123', kind: 'operation', model: '',
    label: 'ComfyUI video', destination: '', source: '', present: false});
  const view = await sidebar(async (url, options) => {
    requests.push([url, options]);
    if (url === '/abstraction/jobs/o123/cancel') return reply({outcome: 'requested'});
    if (url.startsWith('/abstraction/jobs')) return reply({outcome: 'page', changed: true, cursor: 'retained', rows: [operation]});
    return reply(plan());
  });
  const host = view.root.appendChild(new Node('host'));
  const cleanup = view.api.mount(host);
  t.after(cleanup);
  await flush();
  assert.match(host.textContent, /ComfyUI video/);
  assert.match(host.textContent, /In progress · 40%/);
  const retry = find(host, (node) => node.tag === 'button' && node.textContent === 'Retry');
  assert.equal(retry.disabled, true);
  const cancel = find(host, (node) => node.tag === 'button' && node.textContent === 'Cancel');
  assert.equal(cancel.disabled, false);
  await cancel.onclick();
  await flush();
  assert.equal(requests.filter(([url]) => url.endsWith('/cancel')).length, 1);
  assert.deepEqual(JSON.parse(requests.find(([url]) => url.endsWith('/cancel'))[1].body),
    {identities: [operation.identity]});
  assert.equal(requests.some(([url]) => url.endsWith('/retry')), false);
  for (const state of ['complete', 'failed', 'cancelled']) {
    const card = view.api.drawRow({...operation, state}, () => {});
    assert.doesNotMatch(card.textContent, /Preparing model files|Downloaded from source|final file not yet available/);
    assert.equal(find(card, (node) => node.textContent === 'Retry').disabled, true);
  }
});

test('unmount aborts an in-flight listing and a lost action reply is never retried automatically', async () => {
  let listingSignal;
  const waiting = await sidebar(async (_url, options) => {
    listingSignal = options.signal;
    return new Promise(() => {});
  });
  const waitingHost = waiting.root.appendChild(new Node('host'));
  const stop = waiting.api.mount(waitingHost);
  assert.equal(listingSignal.aborted, false);
  stop();
  assert.equal(listingSignal.aborted, true);
  assert.equal(waiting.timers.size, 0);

  let posts = 0;
  const selected = {key: 'retained', history_epoch: 'epoch', attempt: 2};
  const view = await sidebar(async (_url, options) => {
    if (options.method === 'POST') {
      posts++;
      assert.deepEqual(JSON.parse(options.body), {identities: [selected]});
      throw new Error('reply lost after possible delivery');
    }
    return reply(_url.startsWith('/abstraction/jobs') ? page([row('failed', 42, {identity: selected})]) : plan());
  });
  const host = view.root.appendChild(new Node('host'));
  const cleanup = view.api.mount(host);
  await flush();
  const retry = find(host, (node) => node.tag === 'button' && node.textContent === 'Retry');
  await retry.onclick();
  assert.equal(posts, 1);
  assert.match(host.textContent, /request did not return a result\. Check the operation, then reopen this tab/);
  assert.equal(find(host, (node) => node.tag === 'button' && node.textContent === 'Retry').disabled, true);
  cleanup();
});

test('workflow plan is shown before explicit prepare; graph load never queues a render', async () => {
  const requests = [];
  const graphs = [];
  let currentPlan = plan();
  const view = await sidebar(async (url, options = {}) => {
    requests.push([url, options]);
    if (url.startsWith('/abstraction/jobs')) return reply(page([row('running', 42)]));
    if (url.endsWith('/prepare')) return reply({outcome: 'started', detail: 'three assets'});
    if (url.endsWith('/graph')) return graphReply({nodes: [{id: 1}], links: []});
    if (url.includes('/approval')) assert.fail(`the replace click asked OA: ${url}`);
    return reply(currentPlan);
  }, async (graph) => { graphs.push(graph); });
  const host = view.root.appendChild(new Node('host'));
  const cleanup = view.api.mount(host);
  await flush();
  assert.match(host.textContent, /Prepare FLUX\.2 Klein distilled/);
  assert.match(host.textContent, /3 files · 3\.00 GiB total · 0 present .* · 3 missing/);
  assert.match(host.textContent, /License: apache-2\.0/);
  const card = find(host, (node) => node.className === 'oa-recipe' &&
    node.textContent.includes('Prepare FLUX.2 Klein distilled'));
  const assets = card.children.filter((node) => node.className === 'oa-asset');
  assert.deepEqual(assets.map((node) => node.children[0].textContent), [
    'Diffusion model · diffusion_models.safetensors',
    'Text encoder · text_encoders.safetensors',
    'VAE · vae.safetensors',
  ]);
  assert.ok(assets.every((node) => !node.textContent.includes(digest) && !node.textContent.includes('@pinned')));
  const detail = find(card, (node) => node.tag === 'details');
  assert.equal(detail.children[0].textContent, 'Sources and verification');
  assert.match(detail.textContent, /revision v1/);
  assert.match(detail.textContent, /SHA-256/);
  assert.ok(card.children.indexOf(detail) > card.children.findIndex((node) => node.className === 'oa-actions'),
    'exact provenance is collapsed after the main actions');
  assert.match(card.textContent, /ComfyUI’s Run button/);
  assert.equal(requests.filter(([, options]) => options.method === 'POST').length, 0);
  assert.equal(find(host, (node) => node.textContent === 'Replace current canvas with prepared workflow').disabled, true);

  const prepare = find(host, (node) => node.textContent === 'Download missing files and prepare workflow');
  await prepare.onclick();
  const posts = requests.filter(([, options]) => options.method === 'POST');
  assert.equal(posts.length, 1);
  assert.equal(posts[0][0], '/abstraction/workflows/flux2-klein-distilled/prepare');
  assert.deepEqual(JSON.parse(posts[0][1].body), {manifest_sha256: digest, approve: true});
  assert.match(host.textContent, /Preparation started/);
  const held = find(host, (node) => node.textContent === 'Download missing files and prepare workflow');
  assert.equal(held.disabled, true, 'accepted preparation cannot be submitted twice');
  await held.onclick();
  assert.equal(requests.filter(([, options]) => options.method === 'POST').length, 1);
  view.tick();
  await flush();
  assert.equal(requests.filter(([url]) => url === '/abstraction/workflows/flux2-klein-distilled').length, 1,
    'jobs polling does not rehash the plan');

  currentPlan = plan(true);
  await find(host, (node) => node.textContent === 'Check workflow readiness').onclick();
  await flush();
  assert.equal(requests.some(([url]) => url.endsWith('?verify=1')), true);
  assert.equal(find(host, (node) => node.textContent === 'Replace current canvas with prepared workflow').disabled, false);
  const postsBefore = requests.filter(([, options]) => options.method === 'POST').length;
  await find(host, (node) => node.textContent === 'Replace current canvas with prepared workflow').onclick();
  assert.deepEqual(graphs, [{nodes: [{id: 1}], links: []}], 'the click itself replaces the canvas');
  assert.equal(requests.filter(([, options]) => options.method === 'POST').length, postsBefore,
    'replacing the canvas sends nothing to OA');
  assert.equal(requests.some(([url]) => url.includes('/approval')), false);
  assert.match(host.textContent, /Workflow loaded into the editable canvas/);
  assert.equal(requests.filter(([url]) => url === '/prompt' || url.includes('queue')).length, 0);
  cleanup();
});

test('lost preparation reply locks mutation until reopening and invalid plan cannot prepare', async () => {
  let posts = 0;
  const view = await sidebar(async (url, options = {}) => {
    if (url.startsWith('/abstraction/jobs')) return reply(page());
    if (url.endsWith('/prepare')) { posts++; throw new Error('lost reply'); }
    return reply(plan());
  });
  const host = view.root.appendChild(new Node('host'));
  const cleanup = view.api.mount(host);
  await flush();
  await find(host, (node) => node.textContent === 'Download missing files and prepare workflow').onclick();
  assert.equal(posts, 1);
  assert.match(host.textContent, /did not return a result/);
  assert.equal(find(host, (node) => node.textContent === 'Download missing files and prepare workflow').disabled, true);
  view.tick();
  await flush();
  assert.equal(posts, 1);
  cleanup();

  const invalid = await sidebar(async (url) => reply(url.startsWith('/abstraction/jobs') ? page() : {...plan(), manifest_sha256: 'bad'}));
  const invalidHost = invalid.root.appendChild(new Node('host'));
  const stop = invalid.api.mount(invalidHost);
  await flush();
  assert.match(invalidHost.textContent, /invalid asset plan/);
  assert.equal(find(invalidHost, (node) => node.textContent === 'Download missing files and prepare workflow'), null);
  stop();
});

test('fresh Prepare names only the selected cancelled recipe attempt', async () => {
  const current = plan();
  const [asset, other] = current.assets;
  const identity = {key: 'cancelled-key', history_epoch: 'epoch', attempt: 0};
  const requests = [];
  for (const isTrusted of [false, true]) {
    const view = await sidebar(async (url, options = {}) => {
      if (url.startsWith('/abstraction/jobs')) return reply({
        ...page([
          row('cancelled', 12, {model: asset.filename, url: asset.url, identity}),
          row('cancelled', 9, {id: 'other', model: other.filename, url: other.url, identity: {...identity, key: 'other'}}),
        ]), complete: true,
      });
      if (url.endsWith('/prepare')) {
        requests.push(JSON.parse(options.body));
        return reply({outcome: 'started'});
      }
      return reply(current);
    });
    const host = view.root.appendChild(new Node('host'));
    const stop = view.api.mount(host);
    await flush();
    await find(host, (node) => node.textContent === 'Download missing files and prepare workflow').onclick({isTrusted});
    stop();
  }
  const plain = {manifest_sha256: current.manifest_sha256, approve: true};
  assert.deepEqual(requests, [plain, {...plain, cancelled: [{filename: asset.filename, ...identity}]}]);
});

test('invalid asset refuses prepare', async () => {
  let posts = 0;
  let graphReads = 0;
  let loads = 0;
  const invalid = {...plan(), assets: plan().assets.map((asset, index) =>
    index === 0 ? {...asset, state: 'invalid'} : asset)};
  const view = await sidebar(async (url, options = {}) => {
    if (url.startsWith('/abstraction/jobs')) return reply(page());
    if (url.endsWith('/prepare')) { posts++; return reply({outcome: 'started'}); }
    if (url.endsWith('/graph')) { graphReads++; return graphReply({nodes: []}); }
    return reply(invalid);
  });
  const host = view.root.appendChild(new Node('host'));
  const cleanup = view.api.mount(host);
  await flush();
  const prepare = find(host, (node) => node.textContent === 'Download missing files and prepare workflow');
  assert.equal(prepare.disabled, true);
  assert.match(host.textContent, /does not match the pinned asset/);
  await prepare.onclick();
  assert.equal(posts, 0);
  assert.equal(graphReads, 0);
  assert.equal(loads, 0);
  cleanup();
});

test('unsaved canvas changes go through ComfyUI\'s own confirmation', async () => {
  const beforeGraph = {nodes: [{id: 99, type: 'Note', widgets_values: ['unsaved fixture']}],
    links: [], groups: [{title: 'Original group'}], extra: {fixture: 'before'}, version: 0.4};
  const readyGraph = {nodes: [{id: 1, type: 'KSampler', widgets_values: [20]}, {id: 2, type: 'SaveImage'}],
    links: [[1, 1, 0, 2, 0, 'IMAGE']], groups: [], extra: {oa_workflow: {
      id: plan().id, manifest_sha256: digest, variant: plan().template.variant}}, version: 0.4};
  const hash = (raw) => createHash('sha256').update(raw).digest('hex');
  const readyHash = hash(JSON.stringify(readyGraph));
  for (const answer of [false, true]) {
    const questions = [];
    const requests = [];
    let loads = 0;
    const view = await sidebar(async (url, options = {}) => {
      requests.push([url, options.method || 'GET']);
      if (url.startsWith('/abstraction/jobs')) return reply(page());
      if (url.endsWith('/graph')) return graphReply(readyGraph, readyHash);
      if (url.includes('/approval') || options.method === 'POST') assert.fail(`the replace click asked OA: ${url}`);
      return reply(plan(true));
    }, async (graph) => { loads++; view.setGraph(graph); }, {graph: beforeGraph, extensionManager: {
      workflow: {activeWorkflow: {isModified: true}},
      dialog: {confirm: async (value) => { questions.push(value); return answer; }},
    }});
    const host = view.root.appendChild(new Node('host'));
    const cleanup = view.api.mount(host);
    await flush();
    const before = view.serializeGraph();
    const beforeHash = hash(before);
    assert.notEqual(beforeHash, readyHash);
    await find(host, (node) => node.textContent === 'Replace current canvas with prepared workflow').onclick();
    assert.equal(questions.length, 1, 'ComfyUI asks once about the unsaved canvas');
    assert.match(questions[0].message, /unsaved changes/);
    assert.equal(loads, answer ? 1 : 0);
    const after = view.serializeGraph();
    assert.equal(hash(after), answer ? readyHash : beforeHash);
    assert.deepEqual(JSON.parse(after), answer ? readyGraph : JSON.parse(before));
    assert.deepEqual(view.renderRequests, [], 'canvas replacement renders nothing');
    assert.deepEqual(requests.filter(([url, method]) => method === 'POST' || url.includes('/approval') || url === '/prompt' || url === '/queue'), []);
    assert.match(host.textContent, answer ? /Workflow loaded/ : /The canvas was kept/);
    cleanup();
  }
  let loads = 0;
  let asked = 0;
  const savedRequests = [];
  const saved = await sidebar(async (url, options = {}) => {
    savedRequests.push([url, options.method || 'GET']);
    if (url.startsWith('/abstraction/jobs')) return reply(page());
    if (url.endsWith('/graph')) return graphReply({nodes: [{id: 1}]});
    return reply(plan(true));
  }, async () => { loads++; }, {extensionManager: {
    workflow: {activeWorkflow: {isModified: false}},
    dialog: {confirm: async () => { asked++; return false; }},
  }});
  const host = saved.root.appendChild(new Node('host'));
  const cleanup = saved.api.mount(host);
  await flush();
  await find(host, (node) => node.textContent === 'Replace current canvas with prepared workflow').onclick();
  assert.equal(asked, 0, 'a saved canvas is replaced without a confirmation');
  assert.equal(loads, 1);
  assert.deepEqual(saved.renderRequests, [], 'saved-canvas replacement renders nothing');
  assert.deepEqual(savedRequests.filter(([url, method]) => method === 'POST' || url.includes('/approval') || url === '/prompt' || url === '/queue'), []);
  cleanup();
});

test('a navigation to oa_recipe=picture without a spendable Setup token replaces no saved canvas', async () => {
  const graph = {nodes: [{id: 1, type: 'OAImageGenerate'}]};
  const run = async (search, spend = 404) => {
    const calls = [];
    let loaded = null;
    const view = await sidebar(async (path, options = {}) => {
      calls.push([path, options.method || 'GET']);
      if (path.startsWith('/abstraction/workflows/oa-image-generate/arrival/')) return reply({}, spend);
      if (path === '/abstraction/workflows/oa-image-generate/graph') return graphReply(graph);
      return reply(page());
    }, async (value) => { loaded = value; }, {location: {search, pathname: '/'}});
    return {calls, loaded, view};
  };
  const bare = await run('?oa_recipe=picture');
  assert.equal(bare.loaded, null, 'a navigation without the token keeps the saved canvas');
  assert.equal(bare.calls.some(([path]) => path.endsWith('/graph')), false);
  assert.deepEqual(bare.view.history.replaced, ['/'], 'the parameter is still removed');
  const refused = await run('?oa_recipe=picture&oa_token=' + 'a'.repeat(64));
  assert.equal(refused.loaded, null, 'a token the backend does not accept keeps the canvas');
  assert.deepEqual(refused.calls.find(([path]) => path.includes('/arrival/')),
    ['/abstraction/workflows/oa-image-generate/arrival/' + 'a'.repeat(64), 'POST']);
  const spent = await run('?oa_recipe=picture&oa_token=' + 'b'.repeat(64), 204);
  assert.deepEqual(spent.loaded, graph, 'the Panel-issued token loads the recipe once');
});

test('the backend issues an arrival token only without an Origin and spends it once', () => {
  const recipe = fileURLToPath(new URL('../../openabstractions-flat/adopter-comfyui/klein_recipe.py', import.meta.url));
  const script = `
import importlib.util, json, sys, types
aiohttp = types.ModuleType("aiohttp")
aiohttp.web = types.SimpleNamespace()
sys.modules["aiohttp"] = aiohttp
spec = importlib.util.spec_from_file_location("oa_klein_recipe", sys.argv[1])
recipe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recipe)
req = lambda headers: types.SimpleNamespace(headers=headers, host="127.0.0.1:8188")
token = recipe.issue_arrival(now=0)
late = recipe.issue_arrival(now=0)
print(json.dumps([
  len(token) == 64,
  recipe.spend_arrival(token, now=1), recipe.spend_arrival(token, now=2),
  recipe.spend_arrival("b" * 64, now=1), recipe.spend_arrival(late, now=301),
  recipe._may_issue_arrival(req({"X-OA-Arrival": "issue"})),
  recipe._may_issue_arrival(req({})),
  recipe._may_issue_arrival(req({"X-OA-Arrival": "issue", "Origin": "http://evil.example"})),
  recipe._may_issue_arrival(req({"X-OA-Arrival": "issue", "Sec-Fetch-Site": "cross-site"})),
]))
`;
  const args = process.platform === 'win32' ? ['-3.12', '-c', script, recipe] : ['-c', script, recipe];
  const result = spawnSync(process.platform === 'win32' ? 'py' : 'python3', args, {encoding: 'utf8', timeout: 15000});
  assert.equal(result.status, 0, result.stderr || String(result.error));
  assert.deepEqual(JSON.parse(result.stdout), [true, true, false, false, false, true, false, false, false]);
});

test('a Setup Install opening ComfyUI at oa_recipe=picture loads the picture recipe once, with no OA question', async () => {
  const graph = {nodes: [{id: 1, type: 'OAImageGenerate'}]};
  const run = async (search, extensionManager) => {
    const calls = [];
    let loaded = null;
    const view = await sidebar(async (path, options = {}) => {
      calls.push([path, options.method || 'GET']);
      if (path.includes('/arrival/')) return reply({}, 204);
      if (path === '/abstraction/workflows/oa-image-generate/graph') return graphReply(graph);
      return reply(page());
    }, async (value) => { loaded = value; }, {location: {search, pathname: '/'}, extensionManager});
    return {calls, loaded, view};
  };
  const token = '&oa_token=' + 'c'.repeat(64);
  const opened = await run('?oa_recipe=picture' + token);
  assert.deepEqual(opened.loaded, graph, 'the recipe is on the canvas when ComfyUI opens');
  assert.deepEqual(opened.view.history.replaced, ['/'], 'the parameter is removed before the load');
  assert.equal(opened.calls.some(([path, method]) => path.includes('/approval') || (method === 'POST' && !path.includes('/arrival/'))), false, 'no OA question');
  const edited = [];
  const unsaved = await run('?oa_recipe=picture' + token, {workflow: {activeWorkflow: {isModified: true}},
    dialog: {confirm: async (value) => { edited.push(value); return false; }}});
  assert.equal(edited.length, 1, 'unsaved work is confirmed in ComfyUI first');
  assert.equal(unsaved.loaded, null, 'declining keeps the canvas');
  const plain = await run('');
  assert.equal(plain.loaded, null, 'an ordinary ComfyUI start loads nothing');
  assert.equal(plain.calls.some(([path]) => path.endsWith('/graph')), false);
});

test('a frontend without a workflow store counts as unsaved: confirm, or keep the canvas', async () => {
  const run = async (extensionManager) => {
    let loads = 0;
    const requests = [];
    const view = await sidebar(async (url, options = {}) => {
      requests.push([url, options.method || 'GET']);
      assert.notEqual(options.method, 'POST', 'canvas replacement sends no POST');
      assert.ok(!url.includes('/approval') && url !== '/prompt' && url !== '/queue', 'unexpected approval/render request');
      if (url.startsWith('/abstraction/jobs')) return reply(page());
      if (url.endsWith('/graph')) return graphReply({nodes: [{id: 1}]});
      return reply(plan(true));
    }, async () => { loads++; }, {extensionManager});
    const host = view.root.appendChild(new Node('host'));
    const cleanup = view.api.mount(host);
    await flush();
    await find(host, (node) => node.textContent === 'Replace current canvas with prepared workflow').onclick();
    const text = host.textContent;
    cleanup();
    assert.deepEqual(view.renderRequests, [], 'unknown-canvas replacement renders nothing');
    assert.deepEqual(requests.filter(([url, method]) => method === 'POST' || url.includes('/approval') || url === '/prompt' || url === '/queue'), []);
    return {loads, text};
  };
  for (const isModified of [undefined, 'yes', null]) {
    const asked = [];
    const result = await run({workflow: {activeWorkflow: {isModified}},
      dialog: {confirm: async (value) => { asked.push(value); return false; }}});
    assert.equal(asked.length, 1, `isModified ${isModified} asks ComfyUI's dialog`);
    assert.equal(result.loads, 0);
  }
  const dialogOnly = [];
  assert.equal((await run({workflow: undefined,
    dialog: {confirm: async (value) => { dialogOnly.push(value); return true; }}})).loads, 1);
  assert.equal(dialogOnly.length, 1, 'no workflow store: ComfyUI\'s dialog asks first');
  const prior = globalThis.confirm;
  const browser = [];
  globalThis.confirm = (message) => { browser.push(message); return true; };
  try {
    assert.equal((await run({workflow: undefined})).loads, 1);
    assert.equal(browser.length, 1, 'no dialog service: the browser confirm asks');
  } finally {
    if (prior === undefined) delete globalThis.confirm;
    else globalThis.confirm = prior;
  }
  const kept = await run({workflow: undefined});
  assert.equal(kept.loads, 0, 'with no way to ask, the canvas is kept');
  assert.match(kept.text, /The canvas was kept/);
});

test('the Python recipe manifest is accepted by the real sidebar validator', async () => {
  const actualPlan = backendPlan();
  const view = await sidebar(async (url) => reply(url.startsWith('/abstraction/jobs') ? page() : actualPlan));
  const host = view.root.appendChild(new Node('host'));
  const cleanup = view.api.mount(host);
  await flush();
  assert.match(host.textContent, /Prepare FLUX\.2 Klein distilled/);
  assert.match(host.textContent, /3 files · 7\.69 GiB total/);
  assert.doesNotMatch(host.textContent, /invalid asset plan/);
  assert.ok(find(host, (node) => node.textContent === 'Download missing files and prepare workflow'));
  cleanup();
});

test('a second click while the workflow loads reads and loads it once', async () => {
  let graphReads = 0;
  let loads = 0;
  const view = await sidebar(async (url, options = {}) => {
    assert.notEqual(options.method, 'POST', 'loading a canvas does not submit a prompt or an OA approval');
    if (url.startsWith('/abstraction/jobs')) return reply(page());
    if (url.endsWith('/graph')) { graphReads++; return graphReply({nodes: [{id: 1}]}); }
    return reply(plan(true));
  }, async () => { loads++; });
  const host = view.root.appendChild(new Node('host'));
  const cleanup = view.api.mount(host);
  await flush();
  const load = find(host, (node) => node.textContent === 'Replace current canvas with prepared workflow');
  await Promise.all([load.onclick(), load.onclick()]);
  assert.equal(graphReads, 1);
  assert.equal(loads, 1);
  assert.deepEqual(view.renderRequests, []);
  cleanup();
});

test('graph digest mismatch refuses the load without changing the canvas', async () => {
  let loads = 0;
  const view = await sidebar(async (url) => {
    if (url.startsWith('/abstraction/jobs')) return reply(page());
    if (url.endsWith('/graph')) return graphReply({nodes: [{id: 1}]}, '0'.repeat(64));
    return reply(plan(true));
  }, async () => { loads++; });
  const host = view.root.appendChild(new Node('host'));
  const cleanup = view.api.mount(host);
  await flush();
  const before = view.serializeGraph();
  await find(host, (node) => node.textContent === 'Replace current canvas with prepared workflow').onclick();
  assert.equal(loads, 0);
  assert.equal(view.serializeGraph(), before);
  assert.deepEqual(view.renderRequests, []);
  assert.match(host.textContent, /graph verification failed/);
  cleanup();
});

test('unmount aborts an in-flight graph read and loads nothing', async () => {
  let loads = 0;
  let signal;
  const view = await sidebar(async (url, options = {}) => {
    if (url.startsWith('/abstraction/jobs')) return reply(page());
    if (url.endsWith('/graph')) {
      signal = options.signal;
      return new Promise(() => {});
    }
    return reply(plan(true));
  }, async () => { loads++; });
  const host = view.root.appendChild(new Node('host'));
  const cleanup = view.api.mount(host);
  await flush();
  find(host, (node) => node.textContent === 'Replace current canvas with prepared workflow').onclick();
  await flush();
  assert.equal(signal.aborted, false);
  cleanup();
  assert.equal(signal.aborted, true);
  assert.equal(view.timers.size, 0);
  assert.equal(loads, 0);
});

test('actual HTTP graph route loads the sidebar canvas with no OA question', {
  skip: !process.env.OA_COMFYUI_PYTHON,
}, async (t) => {
  const recipePath = fileURLToPath(new URL('../../openabstractions-flat/adopter-comfyui/klein_recipe.py', import.meta.url));
  const fixture = String.raw`
import asyncio, importlib.util, json, sys, tempfile, types
from aiohttp import web
spec = importlib.util.spec_from_file_location('oa_http_fixture_recipe', sys.argv[1])
recipe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recipe)
recipe.configure(folder_paths=types.SimpleNamespace(get_folder_paths=lambda _kind: [tempfile.gettempdir()]))
recipe._state = lambda _asset, verify=False: ('ready', '')
recipe._inspect_assets = lambda: [(asset, ('ready', '')) for asset in recipe.ASSETS]
routes = web.RouteTableDef()
recipe.install(routes)
@routes.get('/abstraction/jobs')
async def jobs(_request):
    return web.json_response({'outcome':'page','changed':True,'cursor':'','rows':[]})
async def main():
    app = web.Application()
    app.add_routes(routes)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    print(json.dumps({'url':f'http://127.0.0.1:{port}'}), flush=True)
    try:
        await asyncio.Event().wait()
    finally:
        await runner.cleanup()
asyncio.run(main())
`;
  const child = spawn(process.env.OA_COMFYUI_PYTHON, ['-c', fixture, recipePath], {stdio: ['ignore', 'pipe', 'pipe']});
  let stderr = '';
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (part) => { stderr += part; });
  const lines = createInterface({input: child.stdout});
  let base;
  try {
    base = await new Promise((resolve, reject) => {
      let finished = false;
      const timeout = setTimeout(() => finish(new Error(`HTTP fixture startup timed out: ${stderr}`)), 15000);
      const finish = (error, value) => {
        if (finished) return;
        finished = true;
        clearTimeout(timeout);
        if (error) reject(error);
        else resolve(value);
      };
      lines.once('line', (line) => {
        try { finish(null, JSON.parse(line).url); } catch (error) { finish(error); }
      });
      child.once('error', (error) => finish(error));
      child.once('exit', (code) => finish(new Error(`HTTP fixture exited ${code}: ${stderr}`)));
    });
  } catch (error) {
    await stopFixtureProcess(child);
    lines.close();
    throw error;
  }
  t.after(async () => {
    await stopFixtureProcess(child);
    lines.close();
  });

  const calls = [];
  const actualFetch = async (path, options = {}) => {
    const method = options.method || 'GET';
    const headers = {...(options.headers || {})};
    if (method === 'POST') {
      headers.Origin = new URL(base).origin;
      headers['Sec-Fetch-Site'] = 'same-origin';
    }
    const response = await globalThis.fetch(new URL(path, base), {...options, headers});
    calls.push({path, method, status: response.status, body: options.body || ''});
    return response;
  };
  let view;
  let loaded;
  view = await sidebar(actualFetch, async (graph) => { loaded = graph; view.setGraph(graph); });
  const host = view.root.appendChild(new Node('host'));
  const cleanup = view.api.mount(host);
  await waitUntil(() => find(host, (node) => node.textContent === 'Replace current canvas with prepared workflow'),
    'the live route plan');
  const button = find(host, (node) => node.textContent === 'Replace current canvas with prepared workflow');
  assert.ok(button, host.textContent);
  assert.equal(button.disabled, false);
  await button.onclick();
  assert.ok(loaded, host.textContent);
  assert.match(host.textContent, /Workflow loaded into the editable canvas/);
  assert.equal(calls.filter((call) => call.path.includes('/approval') || call.method === 'POST').length, 0,
    'the click asks no OA question');
  assert.equal(calls.filter((call) => call.path.endsWith('/graph')).length, 1);
  assert.equal(calls.filter((call) => call.path.endsWith('/prepare')).length, 0);
  assert.equal(calls.filter((call) => call.path === '/prompt' || call.path.includes('queue')).length, 0);
  assert.ok(Array.isArray(loaded.nodes));
  cleanup();
});
