import assert from 'node:assert/strict';
import test from 'node:test';
import * as records from '@openabstractions/facade/appmodel';
import * as applications from '@openabstractions/facade/applications';
import {collectApplication, applicationObservationJSON} from './j1_application_probe.mjs';

function fixture(fault = '') {
  let steps = 20, revision = 1;
  const calls = [];
  const context = {...records.newContextRef(), instance: 'native-instance', context: 'graph', epoch: 'native-epoch'};
  const entry = name => ({...records.newContextEntry(), context: {...context, context: name}, revision: String(revision)});
  const apps = {
    async observe(input) { calls.push(['observe', input]); return {...applications.newPage(), outcome: 'page'}; },
    async activate(key, input) { calls.push(['activate', input]); return {...applications.newActivationResult(), outcome: 'ready', instance: context.instance, started: true}; },
    async describe(input) {
      calls.push(['describe', input]);
      const answer = {...records.newApplicationListing(), outcome: 'page', applications: [
        {...records.newListedApplication(), application: 'comfyui', instances: [
          {...records.newListedInstance(), instance: context.instance, interface: 'abstraction.facade/appmodel@1',
            contexts: ['startup', 'workflows', ...(fault === 'unattached' ? [] : ['graph']),
              ...(fault === 'duplicate-context' ? ['graph'] : [])].map(entry)}]}]};
      // This is the actual generated applications@3 outer/inner reply shape.
      return fault === 'old-direct-listing' ? answer : {...applications.newDescribeResult(), outcome: 'applied', answer};
    },
    async call(key, input) {
      calls.push([input.tool, input]);
      const decoded = records.fromJson('Invocation', input.arguments);
      assert.equal(input.application, 'comfyui');
      assert.equal(input.instance, context.instance);
      assert.deepEqual(decoded.context, context);
      assert.equal(decoded.mode, 'apply');
      assert.equal(decoded.proposal, '');
      const args = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(decoded.arguments));
      const answer = records.newEnvelope();
      let effects;
      if (input.tool === 'graph.read') {
        assert.equal(decoded.expectedRevision, '');
        assert.equal(decoded.idempotencyKey, '');
        assert.deepEqual(args, {});
        const node = {id: fault === 'foreign-id' ? '8' : '7', type: 'KSampler', title: 'KSampler', mode: 'always',
          widgets: [{name: 'steps', type: 'int', value: steps, min: 1, max: 10000}], inputs: [], outputs: []};
        if (fault === 'extra-widget') node.widgets.push({name: 'seed', type: 'seed', value: 1});
        effects = {nodes: [node], links: [], groups: [], revision: String(revision)};
        if (fault === 'ambiguous') effects.nodes.push({...node, id: '8'});
        if (fault === 'stale-read') effects.revision = 'stale';
      } else {
        assert.equal(input.tool, 'graph.edit');
        assert.equal(decoded.expectedRevision, String(revision));
        assert.match(decoded.idempotencyKey, /^j1-[0-9a-f]{32}$/);
        assert.deepEqual(args, {ops: [{op: 'set_widget', node: '7', widget: 'steps', value: steps === 20 ? 21 : 20}]});
        if (fault === 'conflict') return {...applications.newCallResult(), outcome: 'conflict'};
        steps = args.ops[0].value;
        revision++;
        effects = {applied: 1, revision: String(revision)};
      }
      answer.result = {...records.newCommandResult(), outcome: 'applied', revision: String(revision),
        effects: new TextEncoder().encode(JSON.stringify(effects))};
      return {...applications.newCallResult(), outcome: 'applied', answer};
    },
  };
  return {apps, calls, steps: () => steps};
}

test('fixed native collector uses the generated reply/opaque contracts and restores its conditional edit', async () => {
  const f = fixture();
  const rows = JSON.parse(applicationObservationJSON(await collectApplication(f.apps, 'graph', records.toJson)));
  assert.deepEqual(rows.map(row => row.operation), ['observe', 'describe', 'graph.read', 'graph.edit', 'graph.read', 'graph.edit', 'graph.read']);
  assert.equal(f.steps(), 20);
  assert.deepEqual([2, 4, 6].map(i => JSON.parse(rows[i].output.answer.result.effects).nodes[0].widgets[0].value), [20, 21, 20]);
  const {idempotency_key, ...invocation} = JSON.parse(rows[3].input.arguments);
  assert.match(idempotency_key, /^j1-[0-9a-f]{32}$/);
  assert.deepEqual(invocation, {context: {instance: 'native-instance', context: 'graph', epoch: 'native-epoch'},
    arguments: {ops: [{op: 'set_widget', node: '7', widget: 'steps', value: 21}]}, mode: 'apply', expected_revision: '1'});
});

test('native collector refuses foreign/ambiguous graphs before editing and propagates native conflict', async () => {
  for (const fault of ['old-direct-listing', 'unattached', 'duplicate-context', 'foreign-id', 'extra-widget',
    'ambiguous', 'stale-read', 'conflict']) {
    const f = fixture(fault);
    await assert.rejects(collectApplication(f.apps, 'graph', records.toJson));
    assert.equal(f.steps(), 20);
    assert.equal(f.calls.filter(([name]) => name === 'graph.edit').length, fault === 'conflict' ? 1 : 0);
  }
});

test('native observe/activation retain their separate raw outcomes and reject a foreign operation', async () => {
  for (const operation of ['observe', 'activate']) {
    const f = fixture();
    const rows = await collectApplication(f.apps, operation, records.toJson);
    assert.deepEqual(rows.map(row => row.operation), operation === 'observe' ? ['observe'] : ['observe', 'activate']);
    if (operation === 'activate') assert.deepEqual(rows[1].input, {application: 'comfyui', verb: 'open', payload: '{}', context: ''});
  }
  const f = fixture();
  await assert.rejects(collectApplication(f.apps, 'foreign', records.toJson));
  assert.deepEqual(f.calls, []);
});
