'use strict';
/* Firewall at a glance (vantage/fwglance.js): what a firewall config lets
   in from the internet, the zone map, what is off, and the two risky
   cases. Configs use documentation addresses only. */
const test = require('node:test');
const assert = require('node:assert/strict');
const { load } = require('./luci-stub');

const fw = load('vantage.fwglance');

/* [ [ type, { options } ], ... ] -> uci get values */
function cfg(list) {
	const out = {};
	list.forEach(([ type, opts ], i) => { out['cfg' + i] = Object.assign({ '.type': type, '.name': 'cfg' + i, '.index': i }, opts); });
	return out;
}

/* OpenWrt's stock firewall: lan, wan, and its default wan rules */
const STOCK = [
	[ 'defaults', { input: 'REJECT', output: 'ACCEPT', forward: 'REJECT', syn_flood: '1' } ],
	[ 'zone', { name: 'lan', network: [ 'lan' ], input: 'ACCEPT', output: 'ACCEPT', forward: 'ACCEPT' } ],
	[ 'zone', { name: 'wan', network: [ 'wan', 'wan6' ], input: 'REJECT', output: 'ACCEPT', forward: 'REJECT', masq: '1', mtu_fix: '1' } ],
	[ 'forwarding', { src: 'lan', dest: 'wan' } ],
	[ 'rule', { name: 'Allow-DHCP-Renew', src: 'wan', proto: 'udp', dest_port: '68', target: 'ACCEPT', family: 'ipv4' } ],
	[ 'rule', { name: 'Allow-Ping', src: 'wan', proto: 'icmp', icmp_type: 'echo-request', family: 'ipv4', target: 'ACCEPT' } ],
	[ 'rule', { name: 'Allow-IGMP', src: 'wan', proto: 'igmp', family: 'ipv4', target: 'ACCEPT' } ],
	[ 'rule', { name: 'Allow-DHCPv6', src: 'wan', proto: 'udp', dest_port: '546', family: 'ipv6', target: 'ACCEPT' } ],
	[ 'rule', { name: 'Allow-MLD', src: 'wan', proto: 'icmp', src_ip: 'fe80::/10', icmp_type: [ '130/0', '131/0', '132/0', '143/0' ], family: 'ipv6', target: 'ACCEPT' } ],
	[ 'rule', { name: 'Allow-ICMPv6-Input', src: 'wan', proto: 'icmp', icmp_type: [ 'echo-request', 'echo-reply' ], limit: '1000/sec', family: 'ipv6', target: 'ACCEPT' } ],
	[ 'rule', { name: 'Allow-ICMPv6-Forward', src: 'wan', dest: '*', proto: 'icmp', icmp_type: [ 'echo-request' ], family: 'ipv6', target: 'ACCEPT' } ],
	[ 'rule', { name: 'Allow-IPSec-ESP', src: 'wan', dest: 'lan', proto: 'esp', target: 'ACCEPT' } ],
	[ 'rule', { name: 'Allow-ISAKMP', src: 'wan', dest: 'lan', dest_port: '500', proto: 'udp', target: 'ACCEPT' } ]
];

test('fwglance: a stock router opens nothing; its default rules are standard housekeeping', () => {
	const r = fw.analyse(cfg(STOCK));
	assert.equal(r.routed, true);
	assert.deepEqual(r.internet, [ 'wan' ]);
	assert.deepEqual(r.open, []);
	assert.deepEqual(r.forwards, []);
	assert.equal(r.standard.length, 9, 'every default wan rule');
	assert.deepEqual(r.warnings, []);
	assert.equal(r.level, 'ok');
	const lan = r.zones.find(z => z.name === 'lan'), wan = r.zones.find(z => z.name === 'wan');
	assert.deepEqual(lan.to, [ 'wan' ]);
	assert.equal(wan.internet, true);
	assert.equal(lan.internet, false);
	assert.deepEqual(wan.networks, [ 'wan', 'wan6' ]);
});

test('fwglance: open ports, forwards into the network and port forwards are listed', () => {
	const r = fw.analyse(cfg(STOCK.concat([
		[ 'rule', { name: 'SSH from office', src: 'wan', src_ip: '203.0.113.10', proto: 'tcp', dest_port: '22', target: 'ACCEPT' } ],
		[ 'rule', { name: 'Game', src: 'wan', proto: 'tcp udp', dest_port: '27015-27030', target: 'ACCEPT' } ],
		[ 'rule', { name: 'NAS from wan', src: 'wan', dest: 'lan', dest_port: '5001', proto: 'tcp', target: 'ACCEPT' } ],
		[ 'rule', { name: 'Blocked', src: 'wan', dest_port: '8080', target: 'REJECT' } ],
		[ 'rule', { name: 'No target means drop', src: 'wan', dest_port: '9000' } ],
		[ 'redirect', { name: 'Web server', src: 'wan', src_dport: '443', dest: 'lan', dest_ip: '192.0.2.20', dest_port: '443', proto: 'tcp' } ],
		[ 'redirect', { name: 'Hairpin SNAT', src: 'lan', dest: 'wan', target: 'SNAT' } ]
	])));
	assert.deepEqual(r.open.map(i => i.name), [ 'SSH from office', 'Game' ]);
	assert.deepEqual(r.open[0].from, [ '203.0.113.10' ]);
	assert.equal(r.open[1].portText, '27015-27030');
	assert.deepEqual(r.forwards.map(i => i.name), [ 'NAS from wan', 'Web server' ]);
	const web = r.forwards[1];
	assert.equal(web.kind, 'redirect');
	assert.equal(web.host, '192.0.2.20');
	assert.equal(web.portText, '443');
	assert.equal(r.level, 'info', 'open but nothing risky: SSH is limited to one address');
	assert.deepEqual(r.warnings, []);
});

test('fwglance: the risky cases warn', () => {
	const risky = STOCK.map(([ t, o ]) => [ t, o.name === 'wan' && t === 'zone' ? Object.assign({}, o, { input: 'ACCEPT' }) : o ]).concat([
		[ 'forwarding', { src: 'wan', dest: 'lan' } ],
		[ 'rule', { name: 'Web admin', src: 'wan', proto: 'tcp', dest_port: '80 443', target: 'ACCEPT' } ],
		[ 'rule', { name: 'Anything from anywhere', src: '*', proto: 'all', target: 'ACCEPT' } ]
	]);
	const r = fw.analyse(cfg(risky));
	assert.deepEqual(r.warnings.map(w => w.code + ':' + (w.dest || w.name || w.zone)).sort(),
		[ 'admin-open:Anything from anywhere', 'admin-open:Web admin', 'forward-into:lan', 'input-accept:wan' ]);
	assert.equal(r.warnings.find(w => w.code === 'forward-into').level, 'err');
	assert.equal(r.warnings.find(w => w.code === 'admin-open').level, 'warn');
	assert.equal(r.level, 'err');
});

test('fwglance: what is switched off is listed and lets nothing in', () => {
	const r = fw.analyse(cfg(STOCK.concat([
		[ 'rule', { name: 'SSH (off)', src: 'wan', proto: 'tcp', dest_port: '22', target: 'ACCEPT', enabled: '0' } ],
		[ 'redirect', { name: 'Camera (off)', src: 'wan', src_dport: '8554', dest: 'lan', dest_ip: '198.51.100.40', enabled: '0' } ],
		[ 'forwarding', { src: 'wan', dest: 'lan', enabled: '0' } ]
	])));
	assert.deepEqual(r.off.map(i => i.kind + ':' + (i.name || i.src + '>' + i.dest)), [ 'forwarding:wan>lan', 'rule:SSH (off)', 'redirect:Camera (off)' ]);
	assert.deepEqual(r.open, []);
	assert.deepEqual(r.forwards, []);
	assert.deepEqual(r.warnings, []);
	assert.deepEqual(r.zones.find(z => z.name === 'wan').to, [], 'an off forwarding forwards nothing');
});

test('fwglance: an access point without a masquerading zone is not routed', () => {
	const r = fw.analyse(cfg([
		[ 'defaults', { input: 'REJECT', output: 'ACCEPT', forward: 'REJECT' } ],
		[ 'zone', { name: 'lan', network: 'lan', input: 'REJECT', output: 'ACCEPT' } ],
		[ 'rule', { name: 'Admin SSH', src: 'lan', proto: 'tcp', dest_port: '22', target: 'ACCEPT' } ]
	]));
	assert.equal(r.routed, false);
	assert.deepEqual(r.open, [], 'from lan is not from the internet');
	assert.equal(r.level, 'ok');
	assert.equal(r.zones[0].forward, 'REJECT', 'unset policies fall back to the defaults section');
	assert.deepEqual(r.zones[0].networks, [ 'lan' ]);
});

test('fwglance: junk in the config is ignored, never thrown on', () => {
	const r = fw.analyse({ a: null, b: 'x', c: { '.type': 'zone' }, d: { '.type': 'rule', src: 'wan', dest_port: 'abc', target: 'ACCEPT' } });
	assert.deepEqual(r.zones, []);
	assert.equal(r.routed, false);
	assert.doesNotThrow(() => fw.analyse(null));
	assert.deepEqual(fw.analyse(undefined).zones, []);
});

test('fwglance: custom rule files are reported, since their rules are not in this config', () => {
	const r = fw.analyse(cfg(STOCK.concat([
		[ 'include', { path: '/etc/firewall.user', type: 'script' } ],
		[ 'include', { path: '/usr/share/miniupnpd/firewall.include', type: 'script' } ],
		[ 'include', { path: '/etc/old.nft', enabled: '0' } ]
	])));
	assert.deepEqual(r.includes.map(i => i.path), [ '/etc/firewall.user', '/usr/share/miniupnpd/firewall.include' ], 'switched-off files load nothing');
	assert.equal(r.level, 'ok', 'a file is a note, not a warning: what it opens is unknown');
	assert.deepEqual(fw.analyse(cfg(STOCK)).includes, []);
});

test('fwglance: wan faces the internet without NAT too (public addresses, routed)', () => {
	const noNat = [
		[ 'defaults', { input: 'REJECT', output: 'ACCEPT', forward: 'REJECT' } ],
		[ 'zone', { name: 'lan', network: 'lan', input: 'ACCEPT', forward: 'ACCEPT' } ],
		[ 'zone', { name: 'wan', network: [ 'wan', 'wan6' ], input: 'ACCEPT' } ],
		[ 'zone', { name: 'upstream', network: [ 'wan6' ], input: 'REJECT' } ],
		[ 'zone', { name: 'dmz', network: 'dmz', input: 'REJECT' } ]
	];
	const r = fw.analyse(cfg(noNat));
	assert.equal(r.routed, true);
	assert.deepEqual(r.internet, [ 'wan', 'upstream' ], 'by name, and by holding the wan6 network');
	assert.deepEqual(r.warnings.map(w => w.code + ':' + w.zone), [ 'input-accept:wan' ]);
	assert.equal(r.zones.find(z => z.name === 'dmz').internet, false);
});

/* addresses built from numbers: the tree carries no private address
   text, and the uplink needs one outside every special-purpose block,
   which documentation addresses are not */
const ip = (...o) => o.join('.');
const PUBLIC = ip(5, 6, 7, 8);

test('fwglance: an uplink is an interface with the default route and a public address', () => {
	const dump = [
		{ interface: 'isp', up: true, route: [ { target: '0.0.0.0', mask: 0 } ], 'ipv4-address': [ { address: PUBLIC, mask: 24 } ] },
		{ interface: 'lan', up: true, route: [], 'ipv4-address': [ { address: ip(192, 168, 1, 1), mask: 24 } ] },
		{ interface: 'down', up: false, route: [ { target: '0.0.0.0', mask: 0 } ], 'ipv4-address': [ { address: PUBLIC, mask: 24 } ] },
		{ interface: 'cgnat', up: true, route: [ { target: '0.0.0.0', mask: 0 } ], 'ipv4-address': [ { address: ip(100, 72, 0, 9), mask: 10 } ] }
	];
	assert.deepEqual(fw.uplinks(dump), [ 'isp' ], 'up, default route, public address');
	/* an access point: its default route runs to the main router over a private address */
	const ap = [ { interface: 'lan', up: true, route: [ { target: '0.0.0.0', mask: 0, nexthop: ip(192, 168, 1, 1) } ], 'ipv4-address': [ { address: ip(192, 168, 1, 2), mask: 24 } ] } ];
	assert.deepEqual(fw.uplinks(ap), []);
	/* the demo replay's documentation addresses are not the internet either */
	for (const a of [ ip(10, 1, 2, 3), ip(172, 20, 0, 1), ip(169, 254, 1, 1), ip(127, 0, 0, 1), '192.0.2.10', '198.51.100.7',
		'203.0.113.10', ip(198, 19, 0, 1), ip(239, 1, 1, 1), ip(255, 255, 255, 255), '300.1.1.1', 'x' ])
		assert.deepEqual(fw.uplinks([ { interface: 'x', up: true, route: [ { target: '0.0.0.0', mask: 0 } ], 'ipv4-address': [ { address: a } ] } ]), [], a);
	assert.deepEqual(fw.uplinks(null), []);
});

test('fwglance: a zone holding the uplink faces the internet, whatever its name and without NAT', () => {
	const conf = cfg([
		[ 'defaults', { input: 'REJECT', output: 'ACCEPT', forward: 'REJECT' } ],
		[ 'zone', { name: 'lan', network: 'lan', input: 'ACCEPT' } ],
		[ 'zone', { name: 'outside', network: 'isp', input: 'ACCEPT' } ]
	]);
	assert.equal(fw.analyse(conf).routed, false, 'no masquerading, no wan name: unknown');
	const r = fw.analyse(conf, [ 'isp' ]);
	assert.deepEqual(r.internet, [ 'outside' ]);
	assert.deepEqual(r.warnings.map(w => w.code + ':' + w.zone), [ 'input-accept:outside' ]);
	assert.equal(fw.analyse(conf, [ 'lan-not-a-network' ]).routed, false);
});
