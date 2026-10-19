'use strict';
/* Status -> Firewall flow view: the ruleset model (vantage-theme.nftmodel). */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const RES = path.join(__dirname, '..', 'luci-theme-vantage', 'htdocs', 'luci-static', 'resources');

/* same evaluation as tests/host.test.js */
function loadThemeModule(rel) {
	const src = fs.readFileSync(path.join(RES, rel), 'utf8');
	const params = [], values = [];
	for (const m of src.matchAll(/^'require ([\w.-]+)(?: as (\w+))?';$/gm)) {
		if (m[1] !== 'baseclass') throw new Error('unexpected dependency ' + m[1]);
		params.push(m[2] || m[1]);
		values.push({ extend: proto => proto });
	}
	return new Function(...params, src)(...values);
}

const nft = loadThemeModule('vantage-theme/nftmodel.js');

const chain = (family, table, name, hook, prio, policy, type) =>
	({ chain: Object.assign({ family, table, name }, hook ? { type: type || 'filter', hook, prio, policy } : {}) });
const rule = (family, table, chainName, expr, comment) =>
	({ rule: Object.assign({ family, table, chain: chainName, expr }, comment ? { comment } : {}) });
const iif = (dev) => ({ match: { op: '==', left: { meta: { key: 'iifname' } }, right: dev } });

/* an fw4 ruleset trimmed to the shapes that matter, plus a bridge table
   like the one some access point firmware adds */
const RULESET = { nftables: [
	{ metainfo: { version: '1.1.6' } },
	{ table: { family: 'inet', name: 'fw4' } },
	chain('inet', 'fw4', 'input', 'input', 0, 'drop'),
	chain('inet', 'fw4', 'forward', 'forward', 0, 'drop'),
	chain('inet', 'fw4', 'output', 'output', 0, 'accept'),
	chain('inet', 'fw4', 'mangle_input', 'input', -150, 'accept'),
	chain('inet', 'fw4', 'dstnat', 'prerouting', -100, 'accept', 'nat'),
	chain('inet', 'fw4', 'srcnat', 'postrouting', 100, 'accept', 'nat'),
	chain('inet', 'fw4', 'syn_flood'),
	chain('inet', 'fw4', 'input_lan'),
	chain('inet', 'fw4', 'handle_reject'),
	chain('inet', 'fw4', 'helper_lan'),
	rule('inet', 'fw4', 'input', [ { match: { op: '==', left: { meta: { key: 'iif' } }, right: 'lo' } }, { accept: null } ], '!fw4: Accept traffic from loopback'),
	rule('inet', 'fw4', 'input', [ { vmap: { key: { ct: { key: 'state' } }, data: { set: [ [ 'established', { accept: null } ], [ 'related', { accept: null } ] ] } } } ], '!fw4: Handle inbound flows'),
	rule('inet', 'fw4', 'input', [ { match: { op: '==', left: { '&': [ { payload: { protocol: 'tcp', field: 'flags' } }, { '|': [ 'fin', 'syn' ] } ] }, right: 'syn' } }, { jump: { target: 'syn_flood' } } ]),
	rule('inet', 'fw4', 'input', [ iif('br-lan'), { jump: { target: 'input_lan' } } ], '!fw4: Handle lan IPv4/IPv6 input traffic'),
	rule('inet', 'fw4', 'input', [ { jump: { target: 'handle_reject' } } ]),
	rule('inet', 'fw4', 'syn_flood', [ { limit: { rate: 25, burst: 50, per: 'second' } }, { return: null } ], '!fw4: Accept SYN packets below rate-limit'),
	rule('inet', 'fw4', 'syn_flood', [ { drop: null } ], '!fw4: Drop excess packets'),
	rule('inet', 'fw4', 'input_lan', [ { match: { op: '==', left: { payload: { protocol: 'ip', field: 'saddr' } }, right: '192.0.2.10' } }, { counter: { packets: 12, bytes: 3400 } }, { log: { prefix: 'ssh ' } }, { accept: null } ], '!fw4: Allow-SSH'),
	rule('inet', 'fw4', 'input_lan', [ { goto: { target: 'handle_reject' } } ]),
	rule('inet', 'fw4', 'handle_reject', [ { reject: { type: 'tcp reset' } } ]),
	rule('inet', 'fw4', 'srcnat', [ { match: { op: '==', left: { meta: { key: 'oifname' } }, right: 'wan' } }, { masquerade: null } ]),
	rule('inet', 'fw4', 'forward', [ { counter: { packets: 1, bytes: 60 } } ]),
	{ table: { family: 'bridge', name: 'mgmt' } },
	chain('bridge', 'mgmt', 'input', 'input', -200, 'accept'),
	rule('bridge', 'mgmt', 'input', [ { match: { op: '!=', left: { meta: { key: 'iifname' } }, right: 'eth0' } }, { drop: null } ], 'Management only over the wire'),
	{ table: { family: 'netdev', name: 'qos' } }
] };

test('nftmodel: verdicts, comments and LuCI\'s split of conditions and actions', () => {
	const m = nft.build(RULESET);
	const input = m.chains['inet fw4 input'];
	assert.equal(input.base, true);
	assert.equal(input.policy, 'drop');
	assert.deepEqual(input.rules.map((r) => r.verdict.kind), [ 'accept', 'vmap', 'jump', 'jump', 'jump' ]);
	assert.equal(input.rules[0].comment, 'Accept traffic from loopback');
	assert.equal(input.rules[2].comment, '');
	assert.deepEqual(input.rules[1].verdict.map, [ { key: 'established', kind: 'accept', target: undefined }, { key: 'related', kind: 'accept', target: undefined } ]);
	assert.equal(input.rules[3].verdict.target, 'input_lan');

	/* a limit is a condition in LuCI's view, the return the action */
	assert.deepEqual(m.chains['inet fw4 syn_flood'].rules[0].parts, { conds: 1, acts: 1, last: 0 });
	/* counter left out; log is an action beside the deciding accept */
	const ssh = m.chains['inet fw4 input_lan'].rules[0];
	assert.deepEqual(ssh.parts, { conds: 1, acts: 2, last: 1 });
	assert.deepEqual(ssh.counter, { packets: 12, bytes: 3400 });
	assert.equal(ssh.comment, 'Allow-SSH');
	assert.deepEqual(m.chains['inet fw4 input_lan'].rules[1].verdict, { kind: 'goto', target: 'handle_reject' });
	assert.deepEqual(m.chains['inet fw4 srcnat'].rules[0].verdict, { kind: 'nat', nat: 'masquerade' });
	/* a rule that only counts decides nothing */
	assert.deepEqual(m.chains['inet fw4 forward'].rules[0].verdict, { kind: 'none' });
	assert.deepEqual(m.chains['inet fw4 forward'].rules[0].parts, { conds: 0, acts: 0, last: -1 });
});

test('nftmodel: callers, chains nobody jumps to, base chains in path order', () => {
	const m = nft.build(RULESET);
	assert.deepEqual(m.chains['inet fw4 handle_reject'].callers, [ 'inet fw4 input', 'inet fw4 input_lan' ]);
	assert.deepEqual(m.unused, [ 'inet fw4 helper_lan' ]);
	assert.deepEqual(m.bases, [ 'inet fw4 dstnat', 'inet fw4 mangle_input', 'inet fw4 input', 'inet fw4 forward', 'inet fw4 output', 'inet fw4 srcnat' ]);
	assert.deepEqual(m.others, [ { family: 'bridge', name: 'mgmt', chains: [ 'bridge mgmt input' ] } ]);
	/* tables in ruleset order, a chainless one too (LuCI renders it) */
	assert.deepEqual(m.tables.map((t) => t.family + ' ' + t.name), [ 'inet fw4', 'bridge mgmt', 'netdev qos' ]);
});

test('nftmodel: stages put bridge chains where a packet meets them and say what gets dropped', () => {
	const m = nft.build(RULESET), st = m.stages;
	assert.deepEqual(Object.keys(st).filter((k) => st[k]), [ 'prerouting', 'input', 'forward', 'output', 'postrouting', 'bridgeIn', 'bridged' ]);
	assert.deepEqual(st.bridgeIn.chains, [ 'bridge mgmt input' ]);
	assert.equal(st.bridgeIn.drops, 'some');
	assert.equal(st.input.drops, 'all');
	assert.equal(st.prerouting.drops, 'none');
	assert.deepEqual(st.input.chains, [ 'inet fw4 mangle_input', 'inet fw4 input' ]);
	/* the IP hooks are always there, another family's only with chains */
	assert.deepEqual(st.output.chains, [ 'inet fw4 output' ]);
	/* the bridged path is always there: frames between bridge ports skip
	   the IP hooks, and here no bridge chain sees them */
	assert.deepEqual(st.bridged.chains, []);
	assert.equal(st.bridged.drops, 'none');
	assert.equal(st.egress, null);

	const bridged = nft.build({ nftables: RULESET.nftables.concat([ chain('bridge', 'mgmt', 'fwd', 'forward', 0, 'accept') ]) });
	assert.deepEqual(bridged.stages.bridged.chains, [ 'bridge mgmt fwd' ]);
});

test('nftmodel: no ruleset, junk and unknown statements build an empty or partial model', () => {
	for (const j of [ null, {}, { nftables: 'x' }, { nftables: [ null, 1, { chain: {} }, { rule: { chain: 'x' } } ] } ]) {
		const m = nft.build(j);
		assert.deepEqual(m.bases, []);
		assert.deepEqual(m.others, []);
	}
	assert.deepEqual(nft.ruleVerdict([ { queue: { num: 1 } } ]), { kind: 'queue' });
	assert.deepEqual(nft.ruleVerdict([ { jump: {} } ]), { kind: 'none' });
	assert.deepEqual(nft.ruleVerdict('accept'), { kind: 'none' });
	assert.equal(nft.comment('!fw4: Allow-Ping '), 'Allow-Ping');
});

/* LuCI's loader resolves a promise with the module instance: a method
   named then would make the instance a thenable and the load never ends */
test('nftflow: no theme module is a thenable', () => {
	for (const f of fs.readdirSync(path.join(RES, 'vantage-theme')))
		assert.doesNotMatch(fs.readFileSync(path.join(RES, 'vantage-theme', f), 'utf8'), /^\t(then|catch|finally)\s*(\(|:)/m, f);
});
