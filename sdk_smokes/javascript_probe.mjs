// Installed Windows JavaScript SDK selection and read-only config call.
import assert from 'node:assert/strict';
import {Machine,ResolutionError} from '@openabstractions/facade';
import {NativeConnector} from '@openabstractions/ipc';
import {ConfigEditorClient} from '@openabstractions/config';
import {within} from '@openabstractions/ipc/path';
import {mkdtemp,mkdir,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

assert.equal(process.argv.length,4,'usage: javascript_probe.mjs EXPECTED_SID EXPECTED_PROGRAM');
assert.equal(process.env.ABSTRACTION_RUNTIME_ENDPOINT,undefined,'endpoint override is forbidden');
assert.equal(process.env.ABSTRACTION_IPC_NODE,undefined,'native addon override is forbidden');
// This package resolver has no development addon/endpoint override. Within
// executes the installed platform addon's identity check on Windows.
const workspace=await mkdtemp(join(tmpdir(),'oa-packed-within-'));
try {
  const project=join(workspace,'project');
  const outside=join(workspace,'outside');
  await mkdir(project);await mkdir(outside);
  assert.equal(await within(join(project,'image.png'),project),true,'packed Within refused its descendant');
  assert.equal(await within(join(outside,'image.png'),project),false,'packed Within admitted an outside sibling');
} finally {
  await rm(workspace,{recursive:true,force:true});
}
const connector=new NativeConnector();
const selected=await connector.selectRuntime({timeout:5000});
assert.equal(selected.principalKind,1);
assert.equal(selected.principal,process.argv[2]);
assert.equal(selected.program.toLowerCase(),process.argv[3].toLowerCase());
let editor;
try {
  editor=(await new Machine(null,{connector,timeout:10000}).resolveService('abstraction.config/editor@1')).client(ConfigEditorClient);
} catch(error) {
  if(error instanceof ResolutionError&&error.status==='runtime_unavailable') {
    throw new Error('typed runtime_unavailable during default config discovery',{cause:error});
  }
  throw error;
}
const snapshot=await editor.readUser();
assert.ok(snapshot.revision,'config ReadUser returned no revision');
console.log('PASS JavaScript installed selection, default discovery and config ReadUser');
