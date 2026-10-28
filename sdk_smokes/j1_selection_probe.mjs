// Fixed read-only J1 collector. The lifecycle owns request/output paths and
// authenticates the complete current candidate SDK before and after this child.
import assert from 'node:assert/strict';
import {readFile, writeFile, realpath} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {isAbsolute} from 'node:path';
import {Machine} from '@openabstractions/facade';
import {NativeConnector} from '@openabstractions/ipc';
import {SelectionOperatorV2Client} from '@openabstractions/inference';
import {RouterClient} from '@openabstractions/router';

const pin = async path => ({path: await realpath(path), sha256: createHash('sha256').update(await readFile(path)).digest('hex'), bytes: (await readFile(path)).length});
const json = value => JSON.stringify(value, (_, item) => typeof item === 'bigint' ? item.toString() : item);
assert.equal(process.argv.length, 4, 'usage: j1_selection_probe.mjs REQUEST OUTPUT');
assert.ok(process.argv.slice(2).every(isAbsolute));
assert.equal(process.env.ABSTRACTION_RUNTIME_ENDPOINT, undefined);
assert.equal(process.env.ABSTRACTION_IPC_NODE, undefined);
const requestPin = await pin(process.argv[2]);
const request = JSON.parse(await readFile(process.argv[2], 'utf8'));
assert.deepEqual(Object.keys(request).sort(), ['account', 'program', 'runtime', 'schema']);
assert.equal(request.schema, 1);
assert.ok(isAbsolute(request.program.path));
assert.deepEqual(await pin(request.program.path), request.program);
const connector = new NativeConnector();
const selected = await connector.selectRuntime({timeout: 5000});
assert.equal(selected.principalKind, 1);
assert.equal(selected.principal, request.account);
assert.equal(selected.program.toLowerCase(), request.runtime.path.toLowerCase());
const machine = new Machine(null, {connector, server: selected, timeout: 10000});
const operator = new SelectionOperatorV2Client(await machine.resolveService('abstraction.inference/selection-operator@2', {scope: 'local'}));
// This process is a separate subject. An explicit target requires the existing
// selection.manage_for right; an empty target would read this probe's policy.
const before = await operator.read(request.program.path, 'oa-chat-default');
const router = new RouterClient(await machine.resolveService('abstraction.router/router@1', {scope: 'local'}));
const offer = await router.offer({profile: '', placement: 'local', reserve: 4096n, fresh: true});
const after = await operator.read(request.program.path, 'oa-chat-default');
const origins = {};
for (const name of ['facade', 'ipc', 'inference', 'router']) {
  origins[name] = await pin(fileURLToPath(import.meta.resolve('@openabstractions/' + name)));
}
assert.deepEqual(await pin(process.argv[2]), requestPin);
assert.deepEqual(await pin(request.program.path), request.program);
assert.deepEqual(await connector.selectRuntime({timeout: 5000}), selected);
const result = {schema: 1, request: requestPin, process: {pid: process.pid, image: await pin(process.execPath)},
  target: request.program, selected, origins, before, offer, after,
  offer_request: {profile: '', placement: 'local', reserve: '4096', fresh: true}};
const bytes = json(result);
assert.ok(Buffer.byteLength(bytes) <= 1024 * 1024, 'J1 selection observation exceeds bound');
await writeFile(process.argv[3], bytes + '\n', {flag: 'wx'});
