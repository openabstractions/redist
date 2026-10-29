// Fixed native J1 application collector. The disposable lifecycle owns this
// child, authenticates the current SDK and retains its original request/output.
import assert from 'node:assert/strict';
import {readFile, writeFile, realpath} from 'node:fs/promises';
import {createHash, randomBytes} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {isAbsolute} from 'node:path';

const pin = async path => {const bytes = await readFile(path); return {path: await realpath(path), sha256: createHash('sha256').update(bytes).digest('hex'), bytes: bytes.length};};
const opaque = value => typeof value === 'string' ? value : new TextDecoder('utf-8', {fatal: true}).decode(value);
// This projection comes from the connector's source-owned stand-in page.
const fixtureProjection = steps => ({
  nodes: [{id: '7', type: 'KSampler', title: 'KSampler', mode: 'always',
    widgets: [{name: 'steps', type: 'int', value: steps, min: 1, max: 10000}], inputs: [], outputs: []}],
  links: [], groups: [],
});
export const applicationObservationJSON = value => JSON.stringify(value, (_, item) => typeof item === 'bigint' ? item.toString() : item instanceof Uint8Array ? opaque(item) : item);
export async function collectApplication(apps, operation, toJson, onRecord = async () => {}) {
assert.ok(['observe', 'activate', 'graph'].includes(operation));
const operations = [];
const record = async (operation, input, call) => {
  let output;
  try { output = await call(); }
  catch (error) { operations.push({operation, input, error: {name: String(error?.name || 'Error'), code: String(error?.code || ''), message: String(error?.message ?? error).slice(0, 4096)}}); await onRecord(operations); throw error; }
  operations.push({operation, input, output});
  await onRecord(operations);
  return output;
};
const query = {application: 'comfyui', cursor: '', limit: 1, waitMs: 0};
await record('observe', query, () => apps.observe(query));
if (operation === 'activate') {
  const input = {application: 'comfyui', verb: 'open', payload: '{}', context: ''};
  await record('activate', input, () => apps.activate('j1-' + randomBytes(16).toString('hex'), input));
}
if (operation === 'graph') {
  const described = await record('describe', {application: 'comfyui'}, () => apps.describe({application: 'comfyui'}));
  assert.equal(described.outcome, 'applied');
  const listing = described.answer;
  assert.equal(listing.outcome, 'page');
  assert.equal(listing.applications.length, 1);
  const instances = listing.applications[0].instances;
  assert.equal(listing.applications[0].application, 'comfyui');
  assert.equal(instances.length, 1);
  assert.equal(instances[0].interface, 'abstraction.facade/appmodel@1');
  const graphContexts = instances[0].contexts.filter(entry => entry.context.context === 'graph');
  assert.equal(graphContexts.length, 1, 'J1 requires an attached graph context');
  const context = graphContexts[0].context;
  assert.equal(context.instance, instances[0].instance);
  const invoke = async (tool, args, revision = '') => {
    const input = {application: 'comfyui', instance: instances[0].instance, tool,
      arguments: toJson('Invocation', {context, arguments: JSON.stringify(args), mode: 'apply',
        expectedRevision: revision, idempotencyKey: revision ? 'j1-' + randomBytes(16).toString('hex') : '', proposal: ''})};
    return record(tool, input, () => apps.call('j1-' + randomBytes(16).toString('hex'), input));
  };
  const effects = response => {
    assert.equal(response.outcome, 'applied');
    const result = response.answer.result;
    assert.equal(result.outcome, 'applied');
    assert.ok(result.revision);
    const value = JSON.parse(opaque(result.effects));
    assert.equal(value.revision, result.revision);
    return value;
  };
  const read = async steps => {
    const {revision, ...projection} = effects(await invoke('graph.read', {}));
    assert.deepEqual(projection, fixtureProjection(steps), 'J1 requires the source-owned KSampler fixture');
    return revision;
  };
  const edit = async (value, revision) => {
    const result = effects(await invoke('graph.edit', {ops: [{op: 'set_widget', node: '7', widget: 'steps', value}]}, revision));
    assert.deepEqual(result, {applied: 1, revision: result.revision});
    assert.notEqual(result.revision, revision);
    return result.revision;
  };
  const before = await read(20);
  const edited = await edit(21, before);
  const after = await read(21);
  assert.equal(after, edited);
  const restored = await edit(20, after);
  assert.equal(await read(20), restored);
}
return operations;
}

async function main() {
assert.equal(process.argv.length, 4, 'usage: j1_application_probe.mjs REQUEST OUTPUT');
assert.ok(process.argv.slice(2).every(isAbsolute));
assert.equal(process.env.ABSTRACTION_RUNTIME_ENDPOINT, undefined);
assert.equal(process.env.ABSTRACTION_IPC_NODE, undefined);
const requestPin = await pin(process.argv[2]);
const request = JSON.parse(await readFile(process.argv[2], 'utf8'));
assert.deepEqual(Object.keys(request).sort(), ['account', 'operation', 'runtime', 'schema']);
assert.equal(request.schema, 1);
assert.deepEqual(await pin(request.runtime.path), request.runtime);
const [{Machine}, {NativeConnector}, {ApplicationsClient}, {toJson}] = await Promise.all([
  import('@openabstractions/facade'), import('@openabstractions/ipc'),
  import('@openabstractions/facade/applications'), import('@openabstractions/facade/appmodel')]);
const connector = new NativeConnector();
const selected = await connector.selectRuntime({timeout: 5000});
assert.deepEqual(selected, {principalKind: 1, principal: request.account, program: request.runtime.path});
const machine = new Machine(null, {connector, server: selected, timeout: 10000});
const apps = new ApplicationsClient(await machine.resolveService('abstraction.facade/applications@3', {scope: 'local'}));
const origins = {};
for (const name of ['facade', 'ipc']) origins[name] = await pin(fileURLToPath(import.meta.resolve('@openabstractions/' + name)));
for (const name of ['applications', 'appmodel']) origins[name] = await pin(fileURLToPath(import.meta.resolve('@openabstractions/facade/' + name)));
const base = {schema: 1, request: requestPin, process: {pid: process.pid, image: await pin(process.execPath)}, selected, origins};
const save = async (operations, flag) => {
  const bytes = applicationObservationJSON({...base, operations});
  assert.ok(Buffer.byteLength(bytes) <= 1024 * 1024);
  await writeFile(process.argv[3], bytes + '\n', {flag});
};
await save([], 'wx');
const operations = await collectApplication(apps, request.operation, toJson, rows => save(rows, 'w'));
assert.deepEqual(await pin(process.argv[2]), requestPin);
assert.deepEqual(await pin(request.runtime.path), request.runtime);
assert.deepEqual(await connector.selectRuntime({timeout: 5000}), selected);
await save(operations, 'w');
}
if (process.argv[1] && fileURLToPath(import.meta.url) === await realpath(process.argv[1])) await main();
