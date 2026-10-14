'use strict';
'require baseclass';

/* Firewall at a glance: what a firewall configuration (uci `firewall`, as
   `uci get` returns it) lets in, in plain terms. Pure functions over the
   config; the view renders the result. A zone faces the internet when it
   masquerades, holds an uplink (an interface with the default route and
   a public IPv4 address: a router with public addresses routes without
   NAT), or by OpenWrt's naming is called wan or wan6 or holds the wan or
   wan6 network. OpenWrt's defaults apply where an option is unset:
   a rule without a target drops, a redirect without one is a DNAT, an
   item with enabled '0' is off, and a zone policy falls back to the
   `defaults` section, then to REJECT. */

/* ports whose exposure from the internet deserves a warning: the router's
   own SSH, telnet and web admin */
var ADMIN_PORTS = [ 22, 23, 80, 443 ];
/* protocols that open nothing a scanner could talk to: control messages,
   multicast membership and IPsec's ESP/AH */
var QUIET_PROTO = /^(icmp|icmpv6|ipv6-icmp|igmp|esp|ah)$/;
/* UDP ports a router answers as a client or VPN peer: DHCP renew (68),
   DHCPv6 (546), IKE (500, 4500) */
var CLIENT_UDP = [ 68, 546, 500, 4500 ];

function list(v) {
	if (v == null || v === '') return [];
	return (Array.isArray(v) ? v : String(v).split(/\s+/)).map(String).filter(Boolean);
}

function on(s) { return s.enabled !== '0'; }

var WAN = /^wan6?$/;

/* IPv4 blocks that are not reachable from the internet (IANA special-
   purpose registry: private, CGNAT, loopback, link-local, "this network",
   protocol assignments, documentation, benchmarking, multicast and
   reserved), as [ octets..., prefix length ]: numbers, not dotted text */
var LOCAL4 = [
	[ 0, 0, 0, 0, 8 ], [ 10, 0, 0, 0, 8 ], [ 100, 64, 0, 0, 10 ], [ 127, 0, 0, 0, 8 ],
	[ 169, 254, 0, 0, 16 ], [ 172, 16, 0, 0, 12 ], [ 192, 0, 0, 0, 24 ], [ 192, 0, 2, 0, 24 ],
	[ 192, 168, 0, 0, 16 ], [ 198, 18, 0, 0, 15 ], [ 198, 51, 100, 0, 24 ], [ 203, 0, 113, 0, 24 ],
	[ 224, 0, 0, 0, 4 ], [ 240, 0, 0, 0, 4 ]
];

function num4(o) { return ((o[0] << 24) >>> 0) + (o[1] << 16) + (o[2] << 8) + o[3]; }

function public4(addr) {
	var o = String(addr || '').split('.').map(Number);
	if (o.length !== 4 || o.some(function(x) { return !(x >= 0 && x <= 255) || x % 1; })) return false;
	var n = num4(o);
	return !LOCAL4.some(function(b) {
		var mask = b[4] ? (0xffffffff << (32 - b[4])) >>> 0 : 0;
		return ((n & mask) >>> 0) === ((num4(b) & mask) >>> 0);
	});
}

function policy(v, fallback) {
	var p = String(v || fallback || 'REJECT').toUpperCase();
	return /^(ACCEPT|REJECT|DROP)$/.test(p) ? p : 'REJECT';
}

/* "22 443", "27015-27030", [ "80", "8080" ] -> [ [ 22, 22 ], [ 443, 443 ], ... ];
   null when unset (every port) */
function ports(v) {
	var out = [];
	list(v).forEach(function(p) {
		var m = /^(\d{1,5})(?:[-:](\d{1,5}))?$/.exec(p);
		if (m) out.push([ +m[1], +(m[2] || m[1]) ]);
	});
	return out.length ? out : null;
}

function covers(ranges, port) {
	return !ranges || ranges.some(function(r) { return port >= r[0] && port <= r[1]; });
}

/* protocols of a rule or redirect, lower case; unset means tcp and udp */
function protos(v) {
	var p = list(v).map(function(x) { return x.toLowerCase(); });
	return p.length ? p : [ 'tcp', 'udp' ];
}

function anyProto(p) { return p.some(function(x) { return x === 'all' || x === 'any' || x === '*'; }); }

/* standard housekeeping that every router lets in: ping and other
   control messages, multicast membership, IPsec, DHCP renewals */
function quiet(item) {
	if (anyProto(item.proto)) return false;
	return item.proto.every(function(p) {
		if (QUIET_PROTO.test(p)) return true;
		if (p !== 'udp' || !item.ports) return false;
		return item.ports.every(function(r) {
			for (var x = r[0]; x <= r[1]; x++) if (CLIENT_UDP.indexOf(x) < 0) return false;
			return true;
		});
	});
}

return baseclass.extend({
	ADMIN_PORTS: ADMIN_PORTS,

	/* uplinks of a network.interface dump: interfaces that are up, hold the
	   IPv4 default route and a public IPv4 address. An access point's
	   default route runs to the main router over a private address and
	   does not count. -> [ interface name ] */
	uplinks: function(ifaces) {
		return (Array.isArray(ifaces) ? ifaces : []).filter(function(i) {
			return !!(i && i.up && i.interface &&
				(i.route || []).some(function(r) { return r && r.target === '0.0.0.0' && +r.mask === 0; }) &&
				(i['ipv4-address'] || []).some(function(a) { return a && public4(a.address); }));
		}).map(function(i) { return String(i.interface); });
	},

	/* values: { section: { '.type', '.name', '.index', option: value } } ->
	   { routed, internet: [ zone ], zones: [...], open: [...], forwards: [...],
	     standard: [...], off: [...], warnings: [...], includes: [...], level }.
	   Only what this config says: ports UPnP opens at run time and rules
	   in included files are not in it (includes lists those files). */
	analyse: function(values, uplinks) {
		uplinks = Array.isArray(uplinks) ? uplinks : [];
		var secs = Object.keys(values || {}).map(function(k) { return values[k]; })
			.filter(function(s) { return s && typeof s === 'object'; })
			.sort(function(a, b) { return (a['.index'] || 0) - (b['.index'] || 0); });
		var of = function(type) { return secs.filter(function(s) { return s['.type'] === type; }); };
		var defs = of('defaults')[0] || {};

		var zones = of('zone').filter(function(z) { return z.name; }).map(function(z) {
			var nets = list(z.network);
			return {
				name: String(z.name),
				input: policy(z.input, defs.input),
				output: policy(z.output, defs.output),
				forward: policy(z.forward, defs.forward),
				internet: z.masq === '1' || WAN.test(String(z.name)) ||
					nets.some(function(n) { return WAN.test(n) || uplinks.indexOf(n) >= 0; }),
				networks: nets,
				to: []
			};
		});
		var byName = Object.create(null);
		zones.forEach(function(z) { byName[z.name] = z; });
		var internet = zones.filter(function(z) { return z.internet; });
		var fromInternet = function(src) { return src === '*' || !!(byName[src] && byName[src].internet); };

		var warnings = [], off = [];
		of('forwarding').forEach(function(f) {
			if (!on(f)) { off.push({ kind: 'forwarding', name: null, src: f.src || null, dest: f.dest || null }); return; }
			var z = byName[f.src];
			if (z && f.dest && z.to.indexOf(f.dest) < 0) z.to.push(String(f.dest));
		});
		internet.forEach(function(z) {
			if (z.input === 'ACCEPT') warnings.push({ level: 'err', code: 'input-accept', zone: z.name });
			z.to.forEach(function(d) { warnings.push({ level: 'err', code: 'forward-into', zone: z.name, dest: d }); });
		});

		var open = [], fwd = [], standard = [];
		of('rule').forEach(function(r) {
			var item = {
				kind: 'rule', name: r.name ? String(r.name) : null,
				src: r.src ? String(r.src) : null, dest: r.dest ? String(r.dest) : null,
				proto: protos(r.proto), ports: ports(r.dest_port), portText: list(r.dest_port).join(', '),
				icmp: list(r.icmp_type), from: list(r.src_ip).concat(list(r.src_mac)), family: r.family || null
			};
			if (!on(r)) { off.push(item); return; }
			if (String(r.target || 'DROP').toUpperCase() !== 'ACCEPT' || !fromInternet(item.src)) return;
			if (quiet(item)) { standard.push(item); return; }
			if (item.dest) { fwd.push(item); return; }
			open.push(item);
			if (!item.from.length && ADMIN_PORTS.some(function(p) { return (anyProto(item.proto) || item.proto.indexOf('tcp') >= 0) && covers(item.ports, p); }))
				warnings.push({ level: 'warn', code: 'admin-open', name: item.name, ports: item.portText });
		});
		of('redirect').forEach(function(r) {
			var item = {
				kind: 'redirect', name: r.name ? String(r.name) : null,
				src: r.src ? String(r.src) : null, dest: r.dest ? String(r.dest) : null,
				proto: protos(r.proto), portText: list(r.src_dport).join(', '),
				host: r.dest_ip ? String(r.dest_ip) : null, hostPort: list(r.dest_port).join(', '),
				from: list(r.src_ip).concat(list(r.src_mac))
			};
			if (!on(r)) { off.push(item); return; }
			if (String(r.target || 'DNAT').toUpperCase() !== 'DNAT' || !fromInternet(item.src)) return;
			fwd.push(item);
		});

		/* custom rules: files the firewall loads, whose rules this
		   config does not show (the Custom Rules tab, UPnP's include) */
		var includes = of('include').filter(on).map(function(i) {
			return { path: i.path ? String(i.path) : null };
		});

		var level = warnings.some(function(w) { return w.level === 'err'; }) ? 'err' : warnings.length ? 'warn' : (open.length || fwd.length) ? 'info' : 'ok';
		return { routed: internet.length > 0, internet: internet.map(function(z) { return z.name; }), zones: zones,
			open: open, forwards: fwd, standard: standard, off: off, warnings: warnings, includes: includes,
			level: internet.length ? level : 'ok' };
	}
});
