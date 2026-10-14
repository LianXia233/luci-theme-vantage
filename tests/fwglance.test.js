'use strict';
/* Firewall at a glance (vantage/fwglance.js): what a firewall config lets
   in from the internet, read the way fw4 reads it, and how the overview
   (view/vantage/firewall.js) words it. Each regression names the review
   finding it reproduces. Configs use documentation addresses only; the
   addresses that must be public or private are built from numbers. */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { load, RES } = require('./luci-stub');

const fw = load('vantage.fwglance');

/* [ [ type, { options } ], ... ] -> uci get values */
function cfg(list) {
	const out = {};
	list.forEach(([ type, opts ], i) => { out['cfg' + i] = Object.assign({ '.type': type, '.name': 'cfg' + i, '.index': i }, opts); });
	return out;
}

const ip = (...o) => o.join('.');
const PUBLIC = ip(5, 6, 7, 8);

/* a network.interface dump entry: up, with the IPv4 default route when
   `uplink`, and the given address */
function iface(name, address, extra) {
	return Object.assign({ interface: name, up: true, device: 'eth-' + name, l3_device: 'eth-' + name,
		route: extra && extra.uplink ? [ { target: '0.0.0.0', mask: 0 } ] : [],
		'ipv4-address': [ { address, mask: 24 } ] }, extra || {});
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

/* Codex's base: wan and lan with explicit policies, nothing open */
const BASE = [
	[ 'defaults', { input: 'REJECT', output: 'ACCEPT', forward: 'REJECT' } ],
	[ 'zone', { name: 'wan', network: 'wan', input: 'REJECT', output: 'ACCEPT', forward: 'REJECT' } ],
	[ 'zone', { name: 'lan', network: 'lan', input: 'ACCEPT', output: 'ACCEPT', forward: 'ACCEPT' } ]
];
const withDefaults = (list, opts) => list.map(([ t, o ]) => [ t, t === 'defaults' ? Object.assign({}, o, opts) : o ]);
const codes = r => r.warnings.map(w => w.code + ':' + (w.name || w.iface || (w.zone ? w.zone + '>' + (w.dest || '') : '') || w.dest || w.option || ''));

test('fwglance: a stock router opens nothing; its default rules are standard housekeeping', () => {
	const r = fw.analyse(cfg(STOCK));
	assert.equal(r.routed, true);
	assert.deepEqual(r.internet, [ 'wan' ]);
	assert.deepEqual(r.open, []);
	assert.deepEqual(r.forwards, []);
	assert.equal(r.standard.length, 9, 'every default wan rule, IPsec passed on to lan included');
	assert.deepEqual(r.warnings, []);
	assert.equal(r.level, 'ok');
	const lan = r.zones.find(z => z.name === 'lan'), wan = r.zones.find(z => z.name === 'wan');
	assert.deepEqual(lan.to, [ 'wan' ]);
	assert.equal(wan.internet, true);
	assert.equal(lan.internet, false);
	assert.deepEqual(wan.networks, [ 'wan', 'wan6' ]);
	assert.deepEqual(r.outside, []);
	assert.deepEqual(r.defaults, { input: 'REJECT', output: 'ACCEPT', forward: 'REJECT' });
});

test('fwglance: open ports, forwards into the network and port forwards are listed', () => {
	const r = fw.analyse(cfg(STOCK.concat([
		[ 'rule', { name: 'SSH from office', src: 'wan', src_ip: '203.0.113.10', proto: 'tcp', dest_port: '22', target: 'ACCEPT' } ],
		[ 'rule', { name: 'Game', src: 'wan', proto: 'tcp udp', dest_port: '27015-27030', target: 'ACCEPT' } ],
		[ 'rule', { name: 'NAS from wan', src: 'wan', dest: 'lan', dest_port: '5001', proto: 'tcp', target: 'ACCEPT' } ],
		[ 'rule', { name: 'Blocked', src: 'wan', dest_port: '8080', target: 'REJECT' } ],
		[ 'rule', { name: 'No target does nothing', src: 'wan', dest_port: '9000' } ],
		[ 'redirect', { name: 'Web server', src: 'wan', src_dport: '443', dest: 'lan', dest_ip: '192.0.2.20', dest_port: '443', proto: 'tcp' } ],
		[ 'redirect', { name: 'Hairpin SNAT', src: 'lan', dest: 'wan', target: 'SNAT' } ]
	])));
	assert.deepEqual(r.open.map(i => i.name), [ 'SSH from office', 'Game' ]);
	assert.deepEqual(r.open[0].from, { anywhere: false, only: [ '203.0.113.10' ], except: [] });
	assert.equal(r.open[0].family, 4, 'an IPv4 source makes the rule IPv4 only');
	assert.equal(r.open[1].portText, '27015-27030');
	assert.equal(r.open[1].family, null, 'both families');
	assert.deepEqual(r.forwards.map(i => i.name), [ 'NAS from wan', 'Web server' ]);
	const web = r.forwards[1];
	assert.equal(web.kind, 'redirect');
	assert.equal(web.host, '192.0.2.20');
	assert.equal(web.portText, '443');
	assert.equal(web.hostPort, '443');
	assert.equal(web.local, false);
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
	assert.deepEqual(codes(r).sort(),
		[ 'admin-open:Anything from anywhere', 'admin-open:Web admin', 'forward-into:wan>lan', 'input-accept:wan>' ]);
	assert.equal(r.warnings.find(w => w.code === 'forward-into').level, 'err');
	assert.equal(r.warnings.find(w => w.code === 'admin-open').level, 'warn');
	assert.deepEqual(r.warnings.map(w => w.level), [ 'err', 'err', 'warn', 'warn' ], 'errors first');
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

test('fwglance: an access point without an internet-facing zone is unknown, not green', () => {
	const r = fw.analyse(cfg([
		[ 'defaults', { input: 'REJECT', output: 'ACCEPT', forward: 'REJECT' } ],
		[ 'zone', { name: 'lan', network: 'lan', input: 'REJECT', output: 'ACCEPT' } ],
		[ 'rule', { name: 'Admin SSH', src: 'lan', proto: 'tcp', dest_port: '22', target: 'ACCEPT' } ],
		[ 'rule', { name: 'From any zone', src: '*', proto: 'tcp', dest_port: '22', target: 'ACCEPT' } ]
	]), [ iface('lan', ip(192, 168, 1, 2), { uplink: true }) ]);
	assert.equal(r.routed, false);
	assert.deepEqual(r.open, [], 'from lan is not from the internet');
	assert.deepEqual(r.warnings, [], 'without an internet side, src * says nothing either');
	assert.equal(r.level, 'unknown');
	assert.equal(r.zones[0].forward, 'REJECT', 'unset policies fall back to the defaults section');
	assert.deepEqual(r.zones[0].networks, [ 'lan' ]);
});

test('fwglance: junk in the config is ignored, never thrown on', () => {
	const r = fw.analyse({ a: null, b: 'x', c: { '.type': 'zone' }, d: { '.type': 'rule', src: 'wan', dest_port: 'abc', target: 'ACCEPT' } });
	assert.deepEqual(r.zones, []);
	assert.equal(r.routed, false);
	assert.doesNotThrow(() => fw.analyse(null));
	assert.deepEqual(fw.analyse(undefined).zones, []);
	assert.doesNotThrow(() => fw.analyse(cfg(STOCK), [ null, 'x', { interface: 'wan' }, { interface: 'lan', route: 'x', 'ipv4-address': [ null ] } ]));
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
	assert.deepEqual(codes(r), [ 'input-accept:wan>' ]);
	assert.equal(r.zones.find(z => z.name === 'dmz').internet, false);
});

test('fwglance: an uplink is an interface with the default route and a public address', () => {
	const dump = [
		iface('isp', PUBLIC, { uplink: true }),
		iface('lan', ip(192, 168, 1, 1)),
		iface('down', PUBLIC, { uplink: true, up: false }),
		iface('cgnat', ip(100, 72, 0, 9), { uplink: true })
	];
	assert.deepEqual(fw.uplinks(dump), [ 'isp' ], 'up, default route, public address');
	/* an access point: its default route runs to the main router over a private address */
	assert.deepEqual(fw.uplinks([ iface('lan', ip(192, 168, 1, 2), { uplink: true }) ]), []);
	assert.deepEqual(fw.uplinks(null), []);
});

/* B19: the IANA IPv4 special-purpose registry, table-driven. Each entry
   whose "Globally Reachable" is False (and multicast) is not public,
   checked at its first and last address; the reachable entries, the
   neighbours of each block and ordinary unicast space are. The most
   specific entry decides. */
const REGISTRY = [
	/* [ first address octets, prefix, globally reachable ] */
	[ [ 0, 0, 0, 0 ], 8, false ],
	[ [ 0, 0, 0, 0 ], 32, false ],
	[ [ 10, 0, 0, 0 ], 8, false ],
	[ [ 100, 64, 0, 0 ], 10, false ],
	[ [ 127, 0, 0, 0 ], 8, false ],
	[ [ 169, 254, 0, 0 ], 16, false ],
	[ [ 172, 16, 0, 0 ], 12, false ],
	[ [ 192, 0, 0, 0 ], 24, false ],
	[ [ 192, 0, 0, 0 ], 29, false ],
	[ [ 192, 0, 0, 8 ], 32, false ],
	[ [ 192, 0, 0, 9 ], 32, true ],
	[ [ 192, 0, 0, 10 ], 32, true ],
	[ [ 192, 0, 0, 170 ], 32, false ],
	[ [ 192, 0, 0, 171 ], 32, false ],
	[ [ 192, 0, 2, 0 ], 24, false ],
	[ [ 192, 31, 196, 0 ], 24, true ],
	[ [ 192, 52, 193, 0 ], 24, true ],
	[ [ 192, 88, 99, 2 ], 32, false ],
	[ [ 192, 168, 0, 0 ], 16, false ],
	[ [ 192, 175, 48, 0 ], 24, true ],
	[ [ 198, 18, 0, 0 ], 15, false ],
	[ [ 198, 51, 100, 0 ], 24, false ],
	[ [ 203, 0, 113, 0 ], 24, false ],
	[ [ 224, 0, 0, 0 ], 4, false ],
	[ [ 240, 0, 0, 0 ], 4, false ],
	[ [ 255, 255, 255, 255 ], 32, false ]
];
const toNum = o => ((o[0] << 24) >>> 0) + (o[1] << 16) + (o[2] << 8) + o[3];
const toIp = n => ip(n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);

test('fwglance: public addresses follow the IANA special-purpose registry (B19)', () => {
	/* the most specific entry for an address, null for ordinary space */
	const entry = n => REGISTRY.filter(([ o, len ]) => {
		const mask = len ? (0xffffffff << (32 - len)) >>> 0 : 0;
		return ((n & mask) >>> 0) === ((toNum(o) & mask) >>> 0);
	}).sort((a, b) => b[1] - a[1])[0] || null;
	for (const [ o, len, global ] of REGISTRY) {
		const first = toNum(o), last = (first + 2 ** (32 - len) - 1) >>> 0;
		for (const n of [ first, last ]) {
			const e = entry(n);
			assert.equal(fw.public4(toIp(n)), e[2], `${toIp(n)} (${o.join('.')}/${len})`);
		}
		for (const n of [ first - 1, last + 1 ]) {
			if (n < 0 || n > 0xffffffff) continue;
			const e = entry(n >>> 0);
			assert.equal(fw.public4(toIp(n >>> 0)), e ? e[2] : true, `neighbour ${toIp(n >>> 0)} of ${o.join('.')}/${len}`);
		}
	}
	assert.equal(fw.public4(ip(192, 88, 99, 2)), false, 'the 6a44 relay is not globally reachable');
	assert.equal(fw.public4(ip(192, 88, 99, 1)), true, 'the deprecated 6to4 /24 around it has no reachability entry');
	for (const a of [ PUBLIC, ip(1, 1, 1, 1), ip(223, 255, 255, 254) ]) assert.equal(fw.public4(a), true, a);
	for (const a of [ '300.1.1.1', '1..2.3', '1.2.3', 'x', '', null, ip(1, 2, 3, 4) + '.5' ]) assert.equal(fw.public4(a), false, String(a));
	/* and uplinks() uses it */
	assert.deepEqual(fw.uplinks([ iface('relay', ip(192, 88, 99, 2), { uplink: true }) ]), []);
});

test('fwglance: a zone holding the uplink faces the internet, whatever its name and without NAT', () => {
	const conf = cfg([
		[ 'defaults', { input: 'REJECT', output: 'ACCEPT', forward: 'REJECT' } ],
		[ 'zone', { name: 'lan', network: 'lan', input: 'ACCEPT' } ],
		[ 'zone', { name: 'outside', network: 'isp', input: 'ACCEPT' } ]
	]);
	assert.equal(fw.analyse(conf).routed, false, 'no masquerading, no wan name, no dump: unknown');
	const r = fw.analyse(conf, [ iface('isp', PUBLIC, { uplink: true }) ]);
	assert.deepEqual(r.internet, [ 'outside' ]);
	assert.deepEqual(codes(r), [ 'input-accept:outside>' ]);
	assert.equal(fw.analyse(conf, [ iface('lan', PUBLIC) ]).routed, false, 'lan has no default route');
	/* fw4 also matches a zone by device, and takes the zone an interface names itself */
	const byDev = cfg([ [ 'zone', { name: 'up', device: 'eth-isp', input: 'REJECT' } ] ]);
	assert.deepEqual(fw.analyse(byDev, [ iface('isp', PUBLIC, { uplink: true }) ]).internet, [ 'up' ]);
	const byWild = cfg([ [ 'zone', { name: 'up', device: 'eth-+', input: 'REJECT' } ] ]);
	assert.deepEqual(fw.analyse(byWild, [ iface('isp', PUBLIC, { uplink: true }) ]).internet, [ 'up' ]);
	const byData = cfg([ [ 'zone', { name: 'up', input: 'REJECT' } ] ]);
	assert.deepEqual(fw.analyse(byData, [ iface('isp', PUBLIC, { uplink: true, data: { zone: 'up' } }) ]).internet, [ 'up' ]);
});

/* ------------------------------------------------ A1: forwarding paths */

test('A1: a forwarding from * reaches lan from the internet: an error, not "nothing open" (CS M1, CX M1)', () => {
	const r = fw.analyse(cfg(BASE.concat([ [ 'forwarding', { src: '*', dest: 'lan' } ] ])));
	assert.deepEqual(codes(r), [ 'forward-into:*>lan' ]);
	assert.equal(r.level, 'err');
	assert.deepEqual(r.zones.find(z => z.name === 'wan').to, [ 'lan' ], 'wan forwards to lan through it');
	assert.deepEqual(r.anyTo, [ 'lan' ]);
	/* the path is the same for a routed IPv6 lan: an IPv6-only internet zone */
	const v6 = fw.analyse(cfg([
		[ 'defaults', { input: 'REJECT', forward: 'REJECT' } ],
		[ 'zone', { name: 'wan6', network: 'wan6', family: 'ipv6', input: 'REJECT', forward: 'REJECT' } ],
		[ 'zone', { name: 'lan', network: 'lan', input: 'ACCEPT', forward: 'ACCEPT' } ],
		[ 'forwarding', { src: '*', dest: 'lan' } ]
	]));
	assert.ok(codes(v6).includes('forward-into:*>lan'));
	/* into another internet-facing zone is not into your network */
	assert.deepEqual(codes(fw.analyse(cfg(STOCK.concat([ [ 'forwarding', { src: '*', dest: 'wan' } ] ])))), []);
	/* from * to * accepts everything */
	assert.deepEqual(codes(fw.analyse(cfg(BASE.concat([ [ 'forwarding', { src: '*', dest: '*' } ] ])))), [ 'forward-into:*>*' ]);
});

test('A1: defaults.forward ACCEPT lets the internet into every other zone (CS M1, CX M1)', () => {
	const r = fw.analyse(cfg(withDefaults(BASE, { forward: 'ACCEPT' })));
	assert.deepEqual(codes(r), [ 'default-forward:' ]);
	assert.equal(r.level, 'err');
	assert.equal(r.defaults.forward, 'ACCEPT');
	/* the zone's own forward policy only covers wan to wan: still REJECT */
	assert.equal(r.zones.find(z => z.name === 'wan').forward, 'REJECT');
	/* a stock router with only that changed */
	assert.deepEqual(codes(fw.analyse(cfg(withDefaults(STOCK, { forward: 'accept' })))), [ 'default-forward:' ]);
});

test('A1: an uplink in no zone meets the default policies (CS M1)', () => {
	const conf = withDefaults(STOCK, { input: 'ACCEPT', forward: 'ACCEPT' });
	const dump = [ iface('wan', PUBLIC, { uplink: true }), iface('wwan', ip(5, 6, 7, 9), { uplink: true }) ];
	const r = fw.analyse(cfg(conf), dump);
	assert.deepEqual(r.outside, [ { name: 'wwan', family: null, zone: false } ]);
	assert.deepEqual(codes(r).sort(), [ 'default-forward:', 'outside-input:wwan' ]);
	/* closed defaults: listed, nothing open */
	const closed = fw.analyse(cfg(STOCK), dump);
	assert.deepEqual(closed.outside.map(o => o.name), [ 'wwan' ]);
	assert.deepEqual(closed.warnings, []);
	assert.equal(closed.level, 'ok');
	/* an uplink alone makes a router, even without a zone for it */
	const bare = fw.analyse(cfg([ [ 'defaults', { input: 'ACCEPT' } ], [ 'zone', { name: 'lan', network: 'lan' } ] ]), [ iface('isp', PUBLIC, { uplink: true }) ]);
	assert.equal(bare.routed, true);
	assert.deepEqual(codes(bare), [ 'outside-input:isp' ]);
});

test('A1: without the interface dump, an accepting default input is a caution', () => {
	const conf = cfg(withDefaults(STOCK, { input: 'ACCEPT' }));
	const r = fw.analyse(conf, null);
	assert.deepEqual(codes(r), [ 'uplinks-unknown:' ]);
	assert.equal(r.level, 'warn');
	assert.deepEqual(codes(fw.analyse(conf, [ iface('wan', PUBLIC, { uplink: true }) ])), [], 'all uplinks zoned');
	assert.deepEqual(codes(fw.analyse(cfg(STOCK), null)), [], 'closed defaults need no dump');
});

test('A1: a zone restricted to one family leaves the other to the default policies', () => {
	const conf = withDefaults(STOCK, { input: 'ACCEPT' }).map(([ t, o ]) => [ t, t === 'zone' && o.name === 'wan' ? Object.assign({}, o, { family: 'ipv4' }) : o ]);
	const r = fw.analyse(cfg(conf), [ iface('wan', PUBLIC, { uplink: true }) ]);
	assert.deepEqual(r.outside, [ { name: 'wan', family: 6, zone: true } ]);
	assert.deepEqual(codes(r), [ 'outside-input:wan' ]);
	assert.equal(r.warnings[0].family, 6);
	/* another zone taking IPv6 on the same networks closes it */
	const both = fw.analyse(cfg(conf.concat([ [ 'zone', { name: 'wan6z', network: [ 'wan', 'wan6' ], family: 'ipv6', input: 'REJECT' } ] ])), [ iface('wan', PUBLIC, { uplink: true }) ]);
	assert.deepEqual(both.outside, []);
});

test('B18: policies fall back to the defaults section, then to DROP; fw4 reads them by prefix', () => {
	const r = fw.analyse(cfg([ [ 'zone', { name: 'wan', network: 'wan' } ] ]));
	assert.deepEqual([ r.zones[0].input, r.zones[0].output, r.zones[0].forward ], [ 'DROP', 'DROP', 'DROP' ]);
	assert.deepEqual(r.defaults, { input: 'DROP', output: 'DROP', forward: 'DROP' });
	const p = fw.analyse(cfg([ [ 'defaults', { input: 'rej' } ], [ 'zone', { name: 'wan', network: 'wan', input: 'acc', forward: 'Dr' } ] ]));
	assert.deepEqual([ p.zones[0].input, p.zones[0].forward, p.defaults.input ], [ 'ACCEPT', 'DROP', 'REJECT' ]);
	assert.deepEqual(codes(p), [ 'input-accept:wan>' ]);
	/* an empty value matches the first choice: accept */
	assert.equal(fw.analyse(cfg([ [ 'zone', { name: 'wan', network: 'wan', input: '' } ] ])).zones[0].input, 'ACCEPT');
	/* a value fw4 refuses in the defaults stops it before it loads any rules */
	const bad = fw.analyse(cfg(withDefaults(STOCK, { input: 'deny' })));
	assert.deepEqual(codes(bad), [ 'defaults-invalid:input' ]);
	assert.equal(bad.level, 'warn');
});

/* --------------------------------------- A5: protocols, ports, sources */

const wanRule = opts => fw.analyse(cfg(BASE.concat([ [ 'rule', Object.assign({ name: 'R', src: 'wan', target: 'ACCEPT' }, opts) ] ])));

test('A5: protocol spellings fw4 accepts include TCP, and the admin check sees them (CX M2, CS S3)', () => {
	for (const proto of [ '6', 'tcpudp', 'TCP', '!tcp', [ 'udp', 'tcp' ], 'tcp icmp' ]) {
		const r = wanRule({ proto, dest_port: '22' });
		assert.deepEqual(codes(r), [ 'admin-open:R' ], JSON.stringify(proto));
	}
	assert.deepEqual(wanRule({ dest_port: '22' }).open[0].proto, [ 'tcp', 'udp' ], 'unset is tcp and udp');
	assert.deepEqual(wanRule({ proto: 'tcpudp', dest_port: '22' }).open[0].proto, [ 'tcp', 'udp' ]);
	assert.deepEqual(wanRule({ proto: '17', dest_port: '22' }).warnings, [], 'UDP 22 is no SSH');
	assert.deepEqual(wanRule({ proto: '1' }).standard.map(i => i.proto), [ [ 'icmp' ] ], 'protocol 1 is ICMP: housekeeping');
	assert.deepEqual(wanRule({ proto: '58' }).standard.map(i => i.proto), [ [ 'ipv6-icmp' ] ]);
	assert.equal(wanRule({ proto: '58' }).standard[0].family, 6);
});

test('A5: with protocol all fw4 ignores the ports: every port is open (CX M2)', () => {
	const r = wanRule({ proto: 'all', dest_port: '8080' });
	assert.deepEqual(codes(r), [ 'admin-open:R' ]);
	assert.equal(r.open[0].portText, '', 'no port is shown as a restriction');
	assert.deepEqual(r.open[0].proto, [ 'all' ]);
	/* ports only apply to the tcp and udp parts of a list */
	const mixed = wanRule({ proto: 'gre tcp', dest_port: '8080' });
	assert.deepEqual(mixed.warnings, []);
	assert.equal(mixed.open[0].portText, '8080');
});

test('A5: all-address and negated sources are not restrictions; genuine allowlists are (CX M2, CS N3)', () => {
	for (const src_ip of [ '0.0.0.0/0', '::/0', '0.0.0.0/0.0.0.0', '!203.0.113.8', [ '0.0.0.0/0', '2001:db8::/32' ], [ '203.0.113.0/24', '!2001:db8::1' ] ]) {
		const r = wanRule({ proto: 'tcp', dest_port: '22', src_ip });
		assert.deepEqual(codes(r), [ 'admin-open:R' ], JSON.stringify(src_ip));
		assert.equal(r.open[0].from.anywhere, true, JSON.stringify(src_ip));
	}
	assert.deepEqual(wanRule({ proto: 'tcp', dest_port: '22', src_ip: '!203.0.113.8' }).open[0].from, { anywhere: true, only: [], except: [ '203.0.113.8' ] });
	for (const src_ip of [ '203.0.113.10', '2001:db8::/48', [ '203.0.113.0/24', '2001:db8::/48' ], [ '203.0.113.0/24', '!203.0.113.9' ], '198.51.100.1-198.51.100.9' ]) {
		const r = wanRule({ proto: 'tcp', dest_port: '22', src_ip });
		assert.deepEqual(r.warnings, [], JSON.stringify(src_ip));
		assert.equal(r.open[0].from.anywhere, false, JSON.stringify(src_ip));
	}
	/* a MAC on internet traffic is the upstream router's: no restriction */
	assert.deepEqual(codes(wanRule({ proto: 'tcp', dest_port: '22', src_mac: '00:00:5E:00:53:01' })), [ 'admin-open:R' ]);
	/* a network name stands for its addresses (from the dump) */
	const named = BASE.concat([ [ 'rule', { name: 'R', src: 'wan', target: 'ACCEPT', proto: 'tcp', dest_port: '22', src_ip: 'office' } ] ]);
	assert.deepEqual(fw.analyse(cfg(named), [ iface('office', '203.0.113.1') ]).warnings, []);
	assert.equal(fw.analyse(cfg(named), [ iface('lan', '192.0.2.1') ]).ignored[0].bad, 'src_ip', 'an unknown network: fw4 skips the rule');
});

test('A5: port lists with exclusions and ranges are read as fw4 matches them', () => {
	assert.deepEqual(codes(wanRule({ proto: 'tcp', dest_port: '!22' })), [ 'admin-open:R' ], 'everything but 22 still has 80 and 443');
	assert.deepEqual(wanRule({ proto: 'tcp', dest_port: '!22 !23 !80 !443' }).warnings, []);
	assert.deepEqual(codes(wanRule({ proto: 'tcp', dest_port: '1:1024' })), [ 'admin-open:R' ]);
	assert.deepEqual(wanRule({ proto: 'tcp', dest_port: '1-1024 !1-1024' }).warnings, []);
	const r = wanRule({ proto: 'tcp', dest_port: '1000-2000 !1500' });
	assert.equal(r.open[0].portText, '1000-2000');
	assert.equal(r.open[0].portsExcept, '1500');
	/* a port fw4 refuses skips the rule */
	assert.equal(wanRule({ proto: 'tcp', dest_port: '443-22' }).ignored[0].bad, 'dest_port');
	assert.equal(wanRule({ proto: 'tcp', dest_port: '70000' }).ignored[0].bad, 'dest_port');
});

test('B20: the address family is part of the description', () => {
	assert.equal(wanRule({ proto: 'tcp', dest_port: '22', family: 'ipv4' }).open[0].family, 4);
	assert.equal(wanRule({ proto: 'tcp', dest_port: '22', family: 'ipv6' }).open[0].family, 6);
	assert.equal(wanRule({ proto: 'tcp', dest_port: '22' }).open[0].family, null);
	assert.equal(wanRule({ proto: 'tcp', dest_port: '22', src_ip: '2001:db8::/48' }).open[0].family, 6, 'from the source');
	/* inherited from the zone */
	const z = fw.analyse(cfg([
		[ 'zone', { name: 'wan', network: 'wan', family: 'ipv6', input: 'REJECT' } ],
		[ 'rule', { name: 'R', src: 'wan', proto: 'tcp', dest_port: '8443', target: 'ACCEPT' } ],
		[ 'rule', { name: 'Clash', src: 'wan', proto: 'tcp', dest_port: '8444', family: 'ipv4', target: 'ACCEPT' } ]
	]));
	assert.equal(z.open[0].family, 6);
	assert.deepEqual(z.ignored.map(i => i.name + ':' + i.bad), [ 'Clash:family' ], 'fw4 skips a family the zone does not have');
});

/* ------------------------------------------------------- A6: redirects */

const wanRedirect = (opts, dump) => fw.analyse(cfg(BASE.concat([ [ 'redirect', Object.assign({ name: 'P', src: 'wan', proto: 'tcp' }, opts) ] ])), dump);

test('A6: any redirect target but SNAT is a DNAT (CX M3, CS N2)', () => {
	for (const target of [ 'ACCEPT', 'dnat', 'DNAT', 'drop', 'masquerade', 'acc' ]) {
		const r = wanRedirect({ src_dport: '443', dest_ip: '192.0.2.10', dest_port: '443', target });
		assert.deepEqual(r.forwards.map(i => i.name), [ 'P' ], target);
		assert.equal(r.level, 'info', target);
	}
	assert.deepEqual(wanRedirect({ src_dport: '443', dest_ip: '192.0.2.10', target: 'snat' }).forwards, []);
	assert.equal(wanRedirect({ src_dport: '443', dest_ip: '192.0.2.10', target: 'bogus' }).ignored[0].bad, 'target');
});

test('A6: a redirect without dest_ip goes to the router itself; its admin port warns (CX M3, CS S2)', () => {
	const r = wanRedirect({ name: 'Router SSH', src_dport: '2222', dest_port: '22' });
	assert.deepEqual(r.forwards, []);
	assert.deepEqual(r.open.map(i => [ i.name, i.local, i.portText, i.hostPort ]), [ [ 'Router SSH', true, '2222', '22' ] ]);
	assert.deepEqual(codes(r), [ 'admin-open:Router SSH' ]);
	assert.equal(r.warnings[0].kind, 'redirect');
	/* the translated port decides */
	assert.deepEqual(wanRedirect({ src_dport: '22', dest_port: '2222' }).warnings, []);
	assert.deepEqual(codes(wanRedirect({ src_dport: '443' })), [ 'admin-open:P' ], 'no dest_port: the same port');
	assert.deepEqual(codes(wanRedirect({ dest_port: '22' })), [ 'admin-open:P' ], 'every port sent to 22');
	assert.deepEqual(wanRedirect({ dest_port: '8080' }).warnings, [], 'every port sent to 8080 only');
	assert.deepEqual(codes(wanRedirect({ proto: 'all', dest_port: '8080' })), [ 'admin-open:P' ], 'all protocols ignore the ports');
	assert.deepEqual(wanRedirect({ src_dport: '2222', dest_port: '22', src_ip: '203.0.113.7' }).warnings, [], 'limited to one address');
	/* a DNAT to one of the router's own addresses is local too */
	const own = wanRedirect({ src_dport: '2222', dest_ip: '192.0.2.1', dest_port: '22' }, [ iface('lan', '192.0.2.1') ]);
	assert.equal(own.open[0].local, true);
	assert.deepEqual(codes(own), [ 'admin-open:P' ]);
});

test('A6: fw4 skips a DNAT from * or without a source zone', () => {
	const any = wanRedirect({ src: '*', src_dport: '80', dest_ip: '192.0.2.10' });
	assert.deepEqual(any.forwards, []);
	assert.deepEqual(any.ignored.map(i => i.bad), [ 'src-any' ]);
	assert.equal(any.level, 'ok');
	const none = fw.analyse(cfg(BASE.concat([ [ 'redirect', { name: 'P', src_dport: '80', dest_ip: '192.0.2.10' } ] ])));
	assert.deepEqual(none.ignored.map(i => i.bad), [ 'src' ]);
	assert.equal(wanRedirect({ src_dport: '80', dest_ip: '!192.0.2.10' }).ignored[0].bad, 'dest_ip');
	assert.equal(wanRedirect({ src_dport: '80 443', dest_ip: '192.0.2.10' }).ignored[0].bad, 'src_dport', 'a redirect takes one port or range');
});

test('A6/B20: a redirect without family or address is IPv4, as fw4 keeps it', () => {
	assert.equal(wanRedirect({ src_dport: '443', dest_ip: '192.0.2.10' }).forwards[0].family, 4);
	assert.equal(wanRedirect({ src_dport: '443' }).open[0].family, 4);
	assert.equal(wanRedirect({ src_dport: '443', family: 'any' }).open[0].family, null);
	assert.equal(wanRedirect({ src_dport: '443', dest_ip: '2001:db8::10' }).forwards[0].family, 6);
});

/* -------------------------------------------------- A7: booleans, zones */

test('A7: one boolean parser, as fw4\'s: 0/off/false/no and 1/on/true/yes (CX M4, CS S5)', () => {
	for (const v of [ '0', 'off', 'false', 'no' ]) {
		const r = wanRule({ proto: 'tcp', dest_port: '22', enabled: v });
		assert.deepEqual([ r.open.length, r.off.length, r.warnings.length ], [ 0, 1, 0 ], v);
	}
	for (const v of [ '1', 'on', 'true', 'yes' ]) {
		assert.deepEqual(codes(wanRule({ proto: 'tcp', dest_port: '22', enabled: v })), [ 'admin-open:R' ], v);
		const z = fw.analyse(cfg([ [ 'zone', { name: 'outside', network: 'isp', input: 'ACCEPT', masq: v } ] ]));
		assert.deepEqual(z.internet, [ 'outside' ], 'masq ' + v);
		assert.deepEqual(codes(z), [ 'input-accept:outside>' ]);
	}
	assert.deepEqual(fw.analyse(cfg([ [ 'zone', { name: 'outside', network: 'isp', masq6: '1' } ] ])).internet, [ 'outside' ], 'masq6 alone');
	assert.deepEqual(fw.analyse(cfg([ [ 'zone', { name: 'outside', network: 'isp', masq: '0' } ] ])).internet, []);
	/* fw4 refuses anything else and skips the section */
	const yes = wanRule({ proto: 'tcp', dest_port: '22', enabled: 'Yes' });
	assert.deepEqual(yes.ignored.map(i => i.bad), [ 'enabled' ]);
	assert.deepEqual(yes.open, []);
});

test('A7: a switched-off wan zone leaves the default policies in charge (CX M4)', () => {
	const r = fw.analyse(cfg([
		[ 'defaults', { input: 'ACCEPT', output: 'ACCEPT', forward: 'REJECT' } ],
		[ 'zone', { name: 'wan', network: 'wan', input: 'REJECT', enabled: '0' } ],
		[ 'rule', { name: 'SSH', src: 'wan', proto: 'tcp', dest_port: '22', target: 'ACCEPT' } ]
	]));
	assert.deepEqual(r.zones, []);
	assert.deepEqual(r.off.map(i => i.kind + ':' + i.name), [ 'zone:wan' ]);
	assert.deepEqual(r.outside.map(o => o.name), [ 'wan' ]);
	assert.deepEqual(codes(r), [ 'outside-input:wan' ]);
	assert.equal(r.level, 'err');
	assert.deepEqual(r.ignored.map(i => i.name + ':' + i.bad), [ 'SSH:src' ], 'a rule naming a zone that is off is skipped');
	/* a zone fw4 skips for a bad value behaves the same */
	const bad = fw.analyse(cfg([
		[ 'defaults', { input: 'ACCEPT' } ],
		[ 'zone', { name: 'wan', network: 'wan', input: 'REJECT', masq: 'Yes' } ]
	]));
	assert.deepEqual(bad.ignored.map(i => i.kind + ':' + i.bad), [ 'zone:masq' ]);
	assert.deepEqual(codes(bad), [ 'outside-input:wan' ]);
	/* with the dump, only a network that is up counts */
	assert.deepEqual(fw.analyse(cfg([ [ 'defaults', { input: 'ACCEPT' } ], [ 'zone', { name: 'wan', network: 'wan', enabled: '0' } ], [ 'zone', { name: 'lan', network: 'lan', masq: '1' } ] ]),
		[ iface('lan', '192.0.2.1') ]).outside, []);
});

/* ------------------------------------------------------------- B1, B4 */

test('B1: IKE and ESP to the router are an opening; passed on to a host they are housekeeping (CS S1)', () => {
	for (const opts of [ { proto: 'udp', dest_port: '500 4500' }, { proto: 'esp' }, { proto: 'ah' }, { proto: 'udp', dest_port: '4500' } ]) {
		const r = wanRule(opts);
		assert.deepEqual(r.open.map(i => i.name), [ 'R' ], JSON.stringify(opts));
		assert.deepEqual(r.standard, []);
		assert.equal(r.level, 'info');
	}
	for (const opts of [ { proto: 'udp', dest_port: '500 4500', dest: 'lan' }, { proto: 'esp', dest: 'lan' }, { proto: 'esp', dest: '*' } ])
		assert.deepEqual(wanRule(opts).standard.map(i => i.name), [ 'R' ], JSON.stringify(opts));
	assert.deepEqual(wanRule({ proto: 'udp', dest_port: '68' }).standard.map(i => i.name), [ 'R' ], 'DHCP renewals stay housekeeping');
	assert.deepEqual(wanRule({ proto: 'udp', dest_port: '68 69' }).standard, [], 'one other port is an opening');
});

test('B4: an unrestricted accept rule from the internet into a zone warns like a forwarding (CS S4)', () => {
	for (const opts of [ { proto: 'all' }, {}, { proto: 'tcp' }, { proto: 'tcp', dest_port: '!22' }, { proto: 'all', src_ip: '0.0.0.0/0' } ]) {
		const r = wanRule(Object.assign({ dest: 'lan' }, opts));
		assert.deepEqual(codes(r), [ 'rule-into:R' ], JSON.stringify(opts));
		assert.equal(r.warnings[0].level, 'err');
		assert.equal(r.warnings[0].dest, 'lan');
	}
	assert.deepEqual(codes(wanRule({ dest: '*', proto: 'all' })), [ 'rule-into:R' ]);
	for (const opts of [ { proto: 'tcp', dest_port: '5001' }, { proto: 'all', src_ip: '203.0.113.10' }, { proto: 'all', dest_ip: '192.0.2.10' }, { proto: 'gre' } ])
		assert.deepEqual(wanRule(Object.assign({ dest: 'lan' }, opts)).warnings, [], JSON.stringify(opts));
});

/* ------------------------------------------------------------ B21 */

test('B21: includes are configured, and fw4 ignores a script without fw4_compatible (CX N4)', () => {
	const r = fw.analyse(cfg(STOCK.concat([
		[ 'include', { path: '/etc/firewall.user', type: 'script' } ],
		[ 'include', { path: '/etc/firewall.user', type: 'script', fw4_compatible: '1' } ],
		[ 'include', { path: '/usr/share/miniupnpd/firewall.include', type: 'script' } ],
		[ 'include', { path: '/etc/extra.nft', type: 'nftables', position: 'chain-append', chain: 'input_wan' } ],
		[ 'include', { path: '/etc/old.nft', enabled: '0' } ],
		[ 'include', { path: '/etc/odd.sh', type: 'script', fw4_compatible: '0' } ],
		[ 'include', { path: '/etc/bad.sh', position: 'table-append' } ]
	])));
	assert.deepEqual(r.includes.map(i => i.path), [ '/etc/firewall.user', '/usr/share/miniupnpd/firewall.include', '/etc/extra.nft' ]);
	assert.deepEqual(r.ignored.map(i => i.path + ':' + i.bad), [ '/etc/firewall.user:fw4_compatible', '/etc/odd.sh:fw4_compatible', '/etc/bad.sh:position' ]);
	assert.equal(r.level, 'ok', 'a file is a note, not a warning: what it opens is unknown');
	assert.deepEqual(fw.analyse(cfg(STOCK)).includes, []);
});

/* ------------------------------------------------------- the overview */

/* view/vantage/firewall.js with stub LuCI modules; E() builds plain
   objects and text() reads them back */
function loadView(replies) {
	const src = fs.readFileSync(path.join(RES, 'view/vantage/firewall.js'), 'utf8');
	global.E = (tag, attrs, children) => ({ tag, attrs: attrs || {}, children: children == null ? [] : [].concat(children) });
	global.document = { createElementNS: () => ({ setAttribute() {}, appendChild() {} }) };
	global.fetch = () => Promise.reject(new Error('no fetch'));
	global.L = {
		url: (...p) => '/' + p.join('/'),
		resource: p => '/' + p,
		resolveDefault: (p, d) => Promise.resolve(p).catch(() => d)
	};
	const stubs = {
		view: { extend: p => p },
		rpc: { declare: o => () => replies[o.object + ' ' + o.method]() },
		ui: { menu: { load: () => Promise.resolve({ children: {} }) } },
		'vantage.fwglance': fw
	};
	const params = [], values = [];
	for (const m of src.matchAll(/^'require ([\w.-]+)(?: as (\w+))?';$/gm)) {
		params.push(m[2] || m[1]);
		values.push(stubs[m[1]]);
	}
	return new Function(...params, src)(...values);
}

function text(n) {
	if (n == null || n === '') return '';
	if (typeof n === 'string') return n;
	const t = (n.children || []).map(text).join(n.tag && /^(div|p|header|section|h[1-4]|a)$/.test(n.tag) ? '\n' : '');
	return /vt-fg-row-name|vt-chip-title/.test(n.attrs && n.attrs.class) ? t + '\n' : t;
}

async function page(values, dump) {
	const v = loadView({ 'uci get': () => Promise.resolve(values), 'network.interface dump': () => Promise.resolve(dump === undefined ? null : dump) });
	return text(v.render(await v.load()));
}

test('overview: Codex\'s reproductions no longer read "Nothing is open"', async () => {
	const cases = {
		wildcardForwarding: BASE.concat([ [ 'forwarding', { src: '*', dest: 'lan' } ] ]),
		globalAcceptForward: withDefaults(BASE, { forward: 'ACCEPT' }),
		allWithIgnoredPort: BASE.concat([ [ 'rule', { name: 'All', src: 'wan', proto: 'all', dest_port: '8080', target: 'ACCEPT' } ] ]),
		routerRedirect: BASE.concat([ [ 'redirect', { name: 'Router SSH', src: 'wan', proto: 'tcp', src_dport: '2222', dest_port: '22' } ] ]),
		fallbackRedirectTarget: BASE.concat([ [ 'redirect', { name: 'Coerced', src: 'wan', proto: 'tcp', src_dport: '443', dest_ip: '192.0.2.10', dest_port: '443', target: 'ACCEPT' } ] ]),
		disabledWanWithDefaultAccept: [ [ 'defaults', { input: 'ACCEPT', output: 'ACCEPT', forward: 'REJECT' } ], [ 'zone', { name: 'wan', network: 'wan', input: 'REJECT', enabled: '0' } ] ],
		ipsecToRouter: BASE.concat([ [ 'rule', { name: 'IKE', src: 'wan', proto: 'udp', dest_port: '500 4500', target: 'ACCEPT' } ] ])
	};
	for (const [ name, list ] of Object.entries(cases)) {
		const t = await page(cfg(list));
		assert.doesNotMatch(t, /Nothing is open/, name);
	}
	const fwdText = await page(cfg(cases.wildcardForwarding));
	assert.match(fwdText, /Any zone is forwarded into lan/);
	const defText = await page(cfg(cases.globalAcceptForward));
	assert.match(defText, /Forwarding is accepted by default/);
	assert.match(defText, /any zone \(default policy\)/);
	assert.doesNotMatch(defText, /forwards nowhere/);
	const all = await page(cfg(cases.allWithIgnoredPort));
	assert.match(all, /all protocols · from anywhere/);
	assert.doesNotMatch(all, /8080/);
	const ssh = await page(cfg(cases.routerRedirect));
	assert.match(ssh, /On this router\nRouter SSH\nIPv4 TCP 2222 · from anywhere\nrouter port 22/);
	assert.match(ssh, /Router admin open: Router SSH/);
	assert.match(await page(cfg(cases.fallbackRedirectTarget)), /192\.0\.2\.10:443/);
	assert.match(await page(cfg(cases.disabledWanWithDefaultAccept)), /wan is in no zone and accepts every connection/);
});

test('overview: descriptions carry the family, exceptions and configured includes (B20, B21)', async () => {
	const t = await page(cfg(BASE.concat([
		[ 'rule', { name: 'V4', src: 'wan', proto: 'tcp', dest_port: '8443', family: 'ipv4', target: 'ACCEPT' } ],
		[ 'rule', { name: 'V6', src: 'wan', proto: 'tcp', dest_port: '8443', family: 'ipv6', target: 'ACCEPT' } ],
		[ 'rule', { name: 'Except', src: 'wan', proto: 'tcp', dest_port: '22', src_ip: '!203.0.113.8', target: 'ACCEPT' } ],
		[ 'include', { path: '/etc/firewall.user', type: 'script' } ],
		[ 'include', { path: '/etc/extra.nft', type: 'nftables' } ]
	])));
	assert.match(t, /V4\nIPv4 TCP 8443/);
	assert.match(t, /V6\nIPv6 TCP 8443/);
	assert.match(t, /from anywhere except 203\.0\.113\.8/);
	assert.match(t, /Custom rule files are configured \(\/etc\/extra\.nft\)/);
	assert.match(t, /\/etc\/firewall\.user\ncustom rule file · ignored: not marked as compatible with firewall4/);
	assert.match(t, /Not in effect/);
});

test('B6: a failed read of the firewall config is an error, not the access point text (CS S6)', async () => {
	const v = loadView({ 'uci get': () => Promise.reject(new Error('Access denied')), 'network.interface dump': () => Promise.resolve([]) });
	const fwr = await v.load();
	assert.deepEqual(fwr, { error: true });
	const node = v.render(fwr);
	const t = text(node);
	assert.match(t, /Could not read the firewall configuration/);
	assert.doesNotMatch(t, /access point|Nothing is open/);
	assert.match(JSON.stringify(node), /vt-orb-err/);
	/* a failed interface dump is not an error: the page still reads the config */
	const v2 = loadView({ 'uci get': () => Promise.resolve(cfg(STOCK)), 'network.interface dump': () => Promise.reject(new Error('x')) });
	const r2 = await v2.load();
	assert.equal(r2.level, 'ok');
	assert.equal(r2.interfaces, false);
	/* an access point reads as unknown, with a neutral orb */
	const ap = loadView({ 'uci get': () => Promise.resolve(cfg([ [ 'zone', { name: 'lan', network: 'lan' } ] ])), 'network.interface dump': () => Promise.resolve([]) });
	const apNode = ap.render(await ap.load());
	assert.match(text(apNode), /No internet-facing zone found/);
	assert.match(JSON.stringify(apNode), /vt-orb-unknown/);
});

/* ------------------------------------------- against fw4 itself (optional)

   The same regressions through the fw4 that ships (fw4.uc and its
   templates from the rootfs dump: $VANTAGE_ROOTFS or ../vantage-rootfs),
   under a host ucode binary ($UCODE, else `ucode` on PATH), with uci and
   ubus replaced by small doubles; skipped without either. Each case
   checks the ruleset fw4 writes for the opening (or its absence) the
   model reports. nft is never run: the copy calls /bin/false instead. */
const { spawnSync } = require('child_process');
const mkTmp = require('./tmpdir');

function findUcode() {
	for (const c of [ process.env.UCODE ].concat((process.env.PATH || '').split(path.delimiter).map(d => d && path.join(d, 'ucode')))) {
		if (!c) continue;
		try { fs.accessSync(c, fs.constants.X_OK); return c; } catch (e) {}
	}
	return null;
}
const UCODE = findUcode();
const ROOTFS = path.resolve(process.env.VANTAGE_ROOTFS || path.join(__dirname, '../../vantage-rootfs'));
const FW4 = path.join(ROOTFS, 'usr/share/ucode/fw4.uc');
const NO_FW4 = !UCODE ? 'no ucode binary (set UCODE=/path/to/ucode)' : !fs.existsSync(FW4) ? 'no fw4.uc in the rootfs dump (set VANTAGE_ROOTFS)' : false;

const UCI_DOUBLE = `let fs = require('fs');
let conf = json(fs.readfile(getenv('FW_CONF')));
return { cursor: () => ({
	load: () => true,
	foreach: function(c, t, cb) { for (let s in (conf[c] || [])) if (s['.type'] == t && cb(s) === false) break; return true; },
	get_all: function(c, sid) { for (let s in (conf[c] || [])) if (s['.name'] == sid) return s; return null; },
	get: function(c, sid, o) { for (let s in (conf[c] || [])) if (s['.name'] == sid) return o ? s[o] : s['.type']; return null; }
}) };
`;
const UBUS_DOUBLE = `let fs = require('fs');
let conf = json(fs.readfile(getenv('FW_CONF')));
return { connect: () => ({
	call: (o, m) => (o == 'network.interface' && m == 'dump') ? { interface: conf.dump || [] } : (o == 'service' ? {} : null),
	disconnect: () => null
}), error: () => 'double' };
`;

/* the ruleset fw4 writes for a config, or its error output */
function fw4Ruleset(values, dump) {
	const dir = mkTmp('vantage-fwglance-');
	const lib = path.join(dir, 'lib');
	fs.mkdirSync(lib);
	fs.writeFileSync(path.join(lib, 'fw4.uc'), fs.readFileSync(FW4, 'utf8')
		.replace(/"\/usr\/sbin\/nft"/g, '"/bin/false"').replace(/\/usr\/sbin\/nft -c/g, '/bin/false')
		.replace(/"\/var\/run\/fw4\.state"/, JSON.stringify(path.join(dir, 'fw4.state'))));
	fs.writeFileSync(path.join(lib, 'uci.uc'), UCI_DOUBLE);
	fs.writeFileSync(path.join(lib, 'ubus.uc'), UBUS_DOUBLE);
	const tpl = path.join(ROOTFS, 'usr/share/firewall4/templates/ruleset.uc');
	fs.writeFileSync(path.join(dir, 'render.uc'), `{% let fw4 = require("fw4"); fw4.load(false); include(${JSON.stringify(tpl)}, { fw4, type, exists, length, include }); %}`);
	const conf = { firewall: Object.keys(values).map(k => values[k]), dump: dump || [] };
	fs.writeFileSync(path.join(dir, 'conf.json'), JSON.stringify(conf));
	const args = [ '-T', '-L', lib ];
	const sys = path.join(path.dirname(UCODE), '../lib/ucode');
	if (fs.existsSync(sys)) args.push('-L', sys);
	const r = spawnSync(UCODE, args.concat(path.join(dir, 'render.uc')), { encoding: 'utf8', cwd: dir, env: Object.assign({}, process.env, { FW_CONF: path.join(dir, 'conf.json') }) });
	return r.stdout + r.stderr;
}

/* one chain's body from a ruleset */
function chain(rs, name) {
	const m = new RegExp('\\n\\tchain ' + name.replace(/[.*]/g, '\\$&') + ' \\{\\n([\\s\\S]*?)\\n\\t\\}').exec(rs);
	return m ? m[1] : '';
}

const DUMP = [ iface('lan', '192.0.2.1'), iface('wan', PUBLIC, { uplink: true }) ];

test('fw4 itself: the regressions\' openings are in the ruleset it writes', { skip: NO_FW4 }, () => {
	const cases = [
		[ 'A1 * forwarding', BASE.concat([ [ 'forwarding', { src: '*', dest: 'lan' } ] ]), 'forward-into',
			rs => /jump accept_to_lan comment "!fw4: Accept any to lan forwarding"/.test(chain(rs, 'forward')) ],
		[ 'A1 defaults.forward', withDefaults(BASE, { forward: 'ACCEPT' }), 'default-forward',
			rs => /policy accept;/.test(chain(rs, 'forward')) && /jump reject_to_wan/.test(chain(rs, 'forward_wan')) && /oifname "eth-wan"/.test(chain(rs, 'reject_to_wan')) ],
		[ 'A1 family-restricted zone', withDefaults(BASE, { input: 'ACCEPT' }).map(([ t, o ]) => [ t, o.name === 'wan' ? Object.assign({}, o, { family: 'ipv4' }) : o ]), 'outside-input',
			rs => /policy accept;/.test(chain(rs, 'input')) && /meta nfproto ipv4 iifname "eth-wan" jump input_wan/.test(chain(rs, 'input')) ],
		[ 'A5 proto 6', BASE.concat([ [ 'rule', { name: 'R', src: 'wan', proto: '6', dest_port: '22', target: 'ACCEPT' } ] ]), 'admin-open',
			rs => /tcp dport 22 counter accept comment "!fw4: R"/.test(chain(rs, 'input_wan')) ],
		[ 'A5 !tcp', BASE.concat([ [ 'rule', { name: 'R', src: 'wan', proto: '!tcp', dest_port: '22', target: 'ACCEPT' } ] ]), 'admin-open',
			rs => /tcp dport 22 counter accept comment "!fw4: R"/.test(chain(rs, 'input_wan')) ],
		[ 'A5 all ignores ports', BASE.concat([ [ 'rule', { name: 'R', src: 'wan', proto: 'all', dest_port: '8080', target: 'ACCEPT' } ] ]), 'admin-open',
			rs => /^\s*counter accept comment "!fw4: R"/m.test(chain(rs, 'input_wan')) ],
		[ 'A5 negated source', BASE.concat([ [ 'rule', { name: 'R', src: 'wan', proto: 'tcp', dest_port: '22', src_ip: '!203.0.113.8', target: 'ACCEPT' } ] ]), 'admin-open',
			rs => /ip saddr != 203\.0\.113\.8 tcp dport 22 counter accept/.test(chain(rs, 'input_wan')) ],
		[ 'A6 ACCEPT redirect', BASE.concat([ [ 'redirect', { name: 'P', src: 'wan', proto: 'tcp', src_dport: '443', dest_ip: '192.0.2.10', dest_port: '443', target: 'ACCEPT' } ] ]), null,
			rs => /dnat 192\.0\.2\.10:443 comment "!fw4: P"/.test(chain(rs, 'dstnat_wan')) && /ct status dnat accept/.test(chain(rs, 'forward_wan')) ],
		[ 'A6 local redirect', BASE.concat([ [ 'redirect', { name: 'P', src: 'wan', proto: 'tcp', src_dport: '2222', dest_port: '22' } ] ]), 'admin-open',
			rs => /tcp dport 2222 counter redirect to 22 comment "!fw4: P"/.test(chain(rs, 'dstnat_wan')) && /ct status dnat accept/.test(chain(rs, 'input_wan')) ],
		[ 'A6 wildcard DNAT', BASE.concat([ [ 'redirect', { name: 'P', src: '*', proto: 'tcp', src_dport: '80', dest_ip: '192.0.2.10' } ] ]), null,
			rs => !/!fw4: P"/.test(rs) && /must not have source '\*'/.test(rs) ],
		[ 'A7 disabled wan', [ [ 'defaults', { input: 'ACCEPT', forward: 'REJECT' } ], [ 'zone', { name: 'wan', network: 'wan', input: 'REJECT', enabled: '0' } ],
			[ 'rule', { name: 'R', src: 'wan', proto: 'tcp', dest_port: '22', target: 'ACCEPT' } ] ], 'outside-input',
			rs => /policy accept;/.test(chain(rs, 'input')) && !/input_wan/.test(rs) && !/!fw4: R"/.test(rs) ],
		[ 'A7 masq on', [ [ 'zone', { name: 'outside', network: 'wan', input: 'ACCEPT', masq: 'on' } ] ], 'input-accept',
			rs => /masquerade/.test(chain(rs, 'srcnat_outside')) ],
		[ 'A7 enabled off', BASE.concat([ [ 'rule', { name: 'R', src: 'wan', proto: 'tcp', dest_port: '22', target: 'ACCEPT', enabled: 'off' } ] ]), null,
			rs => !/!fw4: R"/.test(rs) && /is disabled/.test(rs) ],
		[ 'A7 Yes refused', BASE.concat([ [ 'rule', { name: 'R', src: 'wan', proto: 'tcp', dest_port: '22', target: 'ACCEPT', enabled: 'Yes' } ] ]), null,
			rs => !/!fw4: R"/.test(rs) && /invalid value 'Yes'/.test(rs) ],
		[ 'B1 IKE to the router', BASE.concat([ [ 'rule', { name: 'R', src: 'wan', proto: 'udp', dest_port: '500 4500', target: 'ACCEPT' } ] ]), null,
			rs => /udp dport \{ 500, 4500 \} counter accept comment "!fw4: R"/.test(chain(rs, 'input_wan')) ],
		[ 'B4 rule into lan', BASE.concat([ [ 'rule', { name: 'R', src: 'wan', dest: 'lan', proto: 'all', target: 'ACCEPT' } ] ]), 'rule-into',
			rs => /counter jump accept_to_lan comment "!fw4: R"/.test(chain(rs, 'forward_wan')) ],
		[ 'B18 unset policies', [ [ 'zone', { name: 'wan', network: 'wan' } ] ], null,
			rs => /policy drop;/.test(chain(rs, 'input')) && /jump drop_from_wan/.test(chain(rs, 'input_wan')) ]
	];
	for (const [ name, list, code, check ] of cases) {
		const values = cfg(list);
		const rs = fw4Ruleset(values, DUMP);
		assert.ok(check(rs), name + ':\n' + rs.slice(0, 4000));
		const r = fw.analyse(values, DUMP);
		if (code) assert.ok(r.warnings.some(w => w.code === code), name + ': model ' + codes(r));
		else assert.ok(!r.warnings.some(w => w.level === 'err'), name + ': model ' + codes(r));
	}
});
