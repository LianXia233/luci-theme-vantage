'use strict';
'require baseclass';

/* Firewall at a glance: what a firewall configuration (uci `firewall`, as
   `uci get` returns it) lets in from the internet, read the way fw4
   (firewall4 as OpenWrt 25.12 ships it, /usr/share/ucode/fw4.uc) reads
   it. Pure functions over the config and the interface dump; the view
   renders the result. What fw4 does that this follows:
   - options parse like fw4's parse_options: booleans are 1/on/true/yes
     and 0/off/false/no, policies and targets match by prefix in any case
     ('acc' is accept, an empty value the first choice), and a value fw4
     cannot parse makes it skip the whole section;
   - a switched-off or skipped zone does not exist: rules naming it are
     skipped, and its networks, like an uplink no zone holds or the
     family a zone leaves out, meet the `defaults` policies;
   - zone policies fall back to `defaults`, whose own fallback is DROP; a
     zone's forward policy only covers traffic back out of the same zone,
     so traffic into another zone without a forwarding or rule meets
     defaults.forward;
   - a forwarding or rule from '*' applies to every zone, the internet's
     included;
   - protocols: unset is tcp and udp; 'tcpudp', 6, 17, 1 and 58 are
     spelled out; 'all' matches everything; fw4 drops a leading '!'; ports
     only apply to tcp and udp;
   - a rule without a target does nothing; a redirect whose target is not
     snat is a DNAT, to the router itself without dest_ip, and is skipped
     from '*' or without a source zone;
   - a script include needs fw4_compatible (default on, except for
     /etc/firewall.user).
   A zone faces the internet when it masquerades (masq or masq6), holds an
   uplink (an interface with the default route and a public IPv4 address:
   a router with public addresses routes without NAT), or by OpenWrt's
   naming is called wan or wan6 or holds the wan or wan6 network. A zone
   matching by `subnet` only is not followed. */

/* ports whose exposure from the internet deserves a warning: the router's
   own SSH, telnet and web admin */
var ADMIN_PORTS = [ 22, 23, 80, 443 ];
/* control messages and multicast membership: open nothing a scanner
   could talk to */
var QUIET_PROTO = /^(icmp|ipv6-icmp|igmp)$/;
/* UDP ports a router answers as a client: DHCP (68), DHCPv6 (546) */
var CLIENT_UDP = [ 68, 546 ];
/* IPsec passed on to a host behind the router: OpenWrt's stock
   Allow-IPSec-ESP and Allow-ISAKMP are forward rules into lan. To the
   router itself they reach its own IKE responder: an opening */
var IPSEC_PROTO = /^(esp|ah)$/;
var IPSEC_UDP = [ 500, 4500 ];

var WAN = /^wan6?$/;

/* IPv4 blocks of the IANA special-purpose registry that are not globally
   reachable, plus multicast, as [ octets..., prefix length, reachable ]:
   numbers, not dotted text. The most specific block decides, so the two
   reachable anycast addresses inside 192.0.0.0/24 count as public. */
var SPECIAL4 = [
	[ 0, 0, 0, 0, 8, false ],          /* "this network" */
	[ 10, 0, 0, 0, 8, false ],         /* private */
	[ 100, 64, 0, 0, 10, false ],      /* shared (CGNAT) */
	[ 127, 0, 0, 0, 8, false ],        /* loopback */
	[ 169, 254, 0, 0, 16, false ],     /* link local */
	[ 172, 16, 0, 0, 12, false ],      /* private */
	[ 192, 0, 0, 0, 24, false ],       /* IETF protocol assignments */
	[ 192, 0, 0, 9, 32, true ],        /* PCP anycast */
	[ 192, 0, 0, 10, 32, true ],       /* TURN anycast */
	[ 192, 0, 2, 0, 24, false ],       /* documentation */
	[ 192, 88, 99, 2, 32, false ],     /* 6a44 relay anycast */
	[ 192, 168, 0, 0, 16, false ],     /* private */
	[ 198, 18, 0, 0, 15, false ],      /* benchmarking */
	[ 198, 51, 100, 0, 24, false ],    /* documentation */
	[ 203, 0, 113, 0, 24, false ],     /* documentation */
	[ 224, 0, 0, 0, 4, false ],        /* multicast */
	[ 240, 0, 0, 0, 4, false ]         /* reserved, limited broadcast */
];

function num4(o) { return ((o[0] << 24) >>> 0) + (o[1] << 16) + (o[2] << 8) + o[3]; }

function public4(addr) {
	var o = String(addr || '').split('.');
	if (o.length !== 4 || o.some(function(x) { return !/^\d{1,3}$/.test(x) || +x > 255; })) return false;
	var n = num4(o.map(Number)), best = null;
	SPECIAL4.forEach(function(b) {
		var mask = b[4] ? (0xffffffff << (32 - b[4])) >>> 0 : 0;
		if (((n & mask) >>> 0) === ((num4(b) & mask) >>> 0) && (!best || b[4] > best[4])) best = b;
	});
	return !best || best[5];
}

/* ---- fw4's option parsers; null is a value fw4 refuses */

function lc(v) { return String(v).toLowerCase(); }

/* to_array: a uci list as it is, an option split at blanks */
function toArray(v) {
	if (Array.isArray(v)) return v.map(String);
	if (v == null) return [];
	v = String(v).trim();
	return v === '' ? [] : v.split(/[ \t]+/);
}

function invert(v) {
	var neg = false;
	v = String(v).replace(/^[ \t]*!/, function() { neg = true; return ''; }).trim();
	return v.length ? { invert: neg, val: v } : null;
}

function bool(v) {
	if (v === '1' || v === 'on' || v === 'true' || v === 'yes') return true;
	if (v === '0' || v === 'off' || v === 'false' || v === 'no') return false;
	return null;
}

function oneOf(choices) {
	return function(v) {
		v = lc(v);
		for (var i = 0; i < choices.length; i++)
			if (choices[i].substr(0, v.length) === v) return choices[i];
		return null;
	};
}

var policy = oneOf([ 'accept', 'reject', 'drop' ]);
var target = oneOf([ 'accept', 'reject', 'drop', 'notrack', 'helper', 'mark', 'dscp', 'dnat', 'snat', 'masquerade' ]);
var includeType = oneOf([ 'script', 'nftables' ]);

function family(v) {
	if (v === 'any' || v === 'all' || v === '*') return 0;
	if (v === 'inet' || v.indexOf('4') > -1) return 4;
	return v.indexOf('6') > -1 ? 6 : null;
}

function str(v) { return v; }
function identifier(v) { return /^[a-zA-Z_.][a-zA-Z0-9\/_.-]*$/.test(v) ? v : null; }
function device(v) { return invert(v); }

/* -> [ name ]: 'tcpudp' is two */
function protocol(v) {
	var p = invert(v);
	if (!p) return null;
	switch (lc(p.val)) {
	case 'all': case 'any': case '*': return [ 'all' ];
	case '1': case 'icmp': return [ 'icmp' ];
	case '58': case 'icmpv6': case 'ipv6-icmp': return [ 'ipv6-icmp' ];
	case 'tcpudp': return [ 'tcp', 'udp' ];
	case '6': return [ 'tcp' ];
	case '17': return [ 'udp' ];
	}
	return [ lc(p.val) ];
}

function port(v) {
	var p = invert(v), m = p && /^([0-9]{1,5})([-:]([0-9]{1,5}))?$/.exec(p.val);
	if (!m) return null;
	var lo = +m[1], hi = m[3] ? +m[3] : lo;
	return (lo > hi || hi > 65535) ? null : { invert: p.invert, min: lo, max: hi };
}

function mac(v) {
	var m = invert(v);
	return m && /^[0-9a-f]{1,2}([:-][0-9a-f]{1,2}){5}$/i.test(m.val) ? m : null;
}

function setmatch(v) {
	var m = invert(v);
	return m && /^[a-zA-Z_.][a-zA-Z0-9\/_.-]*/.test(m.val) ? m : null;
}

function ipFamily(a) {
	if (/^\d{1,3}(\.\d{1,3}){3}$/.test(a)) return a.split('.').every(function(x) { return +x <= 255; }) ? 4 : 0;
	return /^[0-9a-f.]*:[0-9a-f:.]*$/i.test(a) ? 6 : 0;
}

var ZERO = /^[0.:]+$/;

/* an address, address/bits, address/mask or range -> { family, all }
   (all: the whole address space, as 0.0.0.0/0 or ::/0); null when it
   is malformed, undefined when it is no address (a network name) */
function subnet(s) {
	var p = s.split('/'), r = s.split('-'), f;
	if (p.length === 2) {
		f = ipFamily(p[0]);
		if (!f) return null;
		if (/^\d+$/.test(p[1])) return { family: f, all: +p[1] === 0 };
		return ipFamily(p[1]) === f ? { family: f, all: ZERO.test(p[1]) } : null;
	}
	if (p.length > 2) return null;
	if (r.length === 2 && ipFamily(r[0])) {
		f = ipFamily(r[0]);
		return ipFamily(r[1]) === f ? { family: f, all: ZERO.test(r[0]) && (r[1] === '255.255.255.255' || /^(ffff:){7}ffff$/i.test(r[1])) } : null;
	}
	f = ipFamily(s);
	return f ? { family: f, all: false } : undefined;
}

/* ---- the interface dump */

function isUplink(i) {
	return !!(i.up &&
		(i.route || []).some(function(r) { return r && r.target === '0.0.0.0' && +r.mask === 0; }) &&
		(i['ipv4-address'] || []).some(function(a) { return a && public4(a.address); }));
}

/* network.interface dump -> { name: { up, uplink, device, zone, addrs, ips } },
   null when there is none */
function interfaces(dump) {
	if (!Array.isArray(dump)) return null;
	var out = Object.create(null);
	dump.forEach(function(i) {
		if (!i || !i.interface) return;
		var a4 = (i['ipv4-address'] || []).filter(function(a) { return a && a.address; }),
			a6 = (i['ipv6-address'] || []).filter(function(a) { return a && a.address; });
		out[String(i.interface)] = {
			up: !!i.up, uplink: isUplink(i),
			device: i.l3_device || i.device || null,
			zone: (i.data && i.data.zone) ? String(i.data.zone) : null,
			addrs: a4.map(function(a) { return { family: 4, all: +a.mask === 0 }; })
				.concat(a6.map(function(a) { return { family: 6, all: +a.mask === 0 }; })),
			ips: a4.concat(a6).map(function(a) { return String(a.address); })
		};
	});
	return out;
}

/* ---- ports and protocols */

function inRange(p) { return function(r) { return p >= r[0] && p <= r[1]; }; }

/* ports: null (every port) or { pos: [ [ min, max ] ], neg: [...] } */
function hasPort(ports, p) {
	return !ports || ((!ports.pos.length || ports.pos.some(inRange(p))) && !ports.neg.some(inRange(p)));
}

function portRanges(list) {
	if (!list || !list.length) return null;
	var pr = function(neg) { return list.filter(function(x) { return x.invert === neg; }).map(function(x) { return [ x.min, x.max ]; }); };
	return { pos: pr(false), neg: pr(true) };
}

function rangeText(rs) {
	return rs.map(function(r) { return r[0] === r[1] ? String(r[0]) : r[0] + '-' + r[1]; }).join(', ');
}

/* every port in the ranges is one of the list */
function within(rs, list) {
	return rs.length > 0 && rs.every(function(r) {
		if (r[1] - r[0] >= list.length) return false;
		for (var x = r[0]; x <= r[1]; x++) if (list.indexOf(x) < 0) return false;
		return true;
	});
}

function lenient(fn, v) {
	return toArray(v).map(fn).filter(Boolean).reduce(function(a, x) { return a.concat(x); }, []);
}

/* fw4's infer_family over the families a section refers to -> [ 4 ], [ 6 ],
   [ 4, 6 ], or false when two of them conflict (fw4 skips it) */
function families(fam, refs, has4, has6, redirect) {
	var res = fam;
	for (var i = 0; i < refs.length; i++) {
		if (!refs[i] || refs[i] === res) continue;
		if (!res) { res = refs[i]; continue; }
		return false;
	}
	/* a redirect with neither family nor address is IPv4 (fw4 keeps fw3's
	   behaviour) */
	if (redirect && !res && !has4 && !has6) return res === 0 ? [ 4, 6 ] : [ 4 ];
	if (res == null) res = (has4 && !has6) ? 4 : (has6 && !has4) ? 6 : 0;
	return res ? [ res ] : [ 4, 6 ];
}

function famOf(addrs) {
	var f = 0;
	(addrs || []).forEach(function(a) { f |= a.family === 4 ? 1 : 2; });
	return f === 1 ? 4 : f === 2 ? 6 : f ? 0 : null;
}

return baseclass.extend({
	ADMIN_PORTS: ADMIN_PORTS,

	public4: public4,

	/* uplinks of a network.interface dump: interfaces that are up, hold the
	   IPv4 default route and a public IPv4 address. An access point's
	   default route runs to the main router over a private address and
	   does not count. -> [ interface name ] */
	uplinks: function(ifaces) {
		var ifs = interfaces(ifaces) || {};
		return Object.keys(ifs).filter(function(n) { return ifs[n].uplink; });
	},

	/* values: { section: { '.type', '.name', '.index', option: value } },
	   dump: network.interface dump, or null when it could not be read ->
	   { routed, internet: [ zone ], outside: [...], anyTo, defaults, zones, open,
	     forwards, standard, off, ignored, warnings, includes, level }.
	   level is err, warn, info (open, nothing risky), ok, or unknown (no
	   internet-facing zone or uplink: this cannot tell what the internet
	   reaches). Only what this config says: ports UPnP opens at run time
	   and rules in included files are not in it (includes lists those). */
	analyse: function(values, dump) {
		var secs = Object.keys(values || {}).map(function(k) { return values[k]; })
			.filter(function(s) { return s && typeof s === 'object'; })
			.sort(function(a, b) { return (a['.index'] || 0) - (b['.index'] || 0); });
		var of = function(type) { return secs.filter(function(s) { return s['.type'] === type; }); };
		var ifs = interfaces(dump);
		var ups = ifs ? Object.keys(ifs).filter(function(n) { return ifs[n].uplink; }) : [];
		var warnings = [], off = [], ignored = [];

		/* fw4's parse_options: { option: [ parser, default, list ] } ->
		   values, or { bad: option } for a value fw4 refuses */
		var parse = function(s, spec) {
			var out = {};
			for (var k in spec) {
				var fn = spec[k][0], v = s[k] != null ? s[k] : spec[k][1], r;
				if (v == null) { out[k] = null; continue; }
				if (spec[k][2]) {
					r = [];
					var items = toArray(v);
					for (var i = 0; i < items.length; i++) {
						var x = fn(items[i]);
						if (x === null) return { bad: k };
						r = r.concat(x);
					}
					out[k] = r.length ? r : null;
				}
				else {
					if (Array.isArray(v)) return { bad: k };
					r = fn(String(v));
					if (r === null) return { bad: k };
					out[k] = r;
				}
			}
			return out;
		};

		/* an invalid defaults section stops fw4 before it writes any
		   ruleset: what is loaded is then unknown */
		var dsec = of('defaults')[0] || {};
		var DEFS = { input: [ policy, 'drop' ], output: [ policy, 'drop' ], forward: [ policy, 'drop' ] };
		[ 'drop_invalid', 'syn_flood', 'synflood_protect', 'tcp_syncookies', 'tcp_window_scaling', 'accept_redirects',
			'accept_source_route', 'auto_helper', 'custom_chains', 'disable_ipv6', 'flow_offloading', 'flow_offloading_hw',
			'auto_includes' ].forEach(function(k) { DEFS[k] = [ bool ]; });
		var defs = parse(dsec, DEFS);
		if (defs.bad) {
			warnings.push({ level: 'warn', code: 'defaults-invalid', option: defs.bad });
			defs = { input: 'drop', output: 'drop', forward: 'drop' };
		}

		/* zones; a network or device entry is { net | dev, neg } */
		var zones = [], lostNets = [];
		var internetish = function(s, nets) {
			return bool(s.masq) || bool(s.masq6) || WAN.test(String(s.name)) || nets.some(function(n) { return WAN.test(n) || ups.indexOf(n) >= 0; });
		};
		of('zone').forEach(function(s) {
			var nets = toArray(s.network).map(invert).filter(function(e) { return e && !e.invert; }).map(function(e) { return e.val; });
			var item = { kind: 'zone', name: s.name != null ? String(s.name) : null };
			var z = bool(s.enabled) === false ? null : parse(s, {
				enabled: [ bool, '1' ], name: [ identifier ], family: [ family ],
				network: [ device, null, true ], device: [ device, null, true ],
				input: [ policy, defs.input ], output: [ policy, defs.output ], forward: [ policy, defs.forward ],
				masq: [ bool ], masq6: [ bool ]
			});
			if (!z || z.bad || !z.name) {
				if (!z) off.push(item);
				else { item.bad = z.bad || 'name'; ignored.push(item); }
				/* its networks fall to the default policies */
				if (internetish(s, nets)) lostNets = lostNets.concat(nets);
				return;
			}
			var ents = (z.network || []).map(function(e) { return { net: e.val, neg: e.invert }; })
				.concat((z.device || []).map(function(e) { return { dev: e.val, neg: e.invert }; }));
			zones.push({
				name: z.name, family: z.family || null,
				input: z.input.toUpperCase(), output: z.output.toUpperCase(), forward: z.forward.toUpperCase(),
				masq: !!(z.masq || z.masq6),
				networks: nets,
				pos: ents.filter(function(e) { return !e.neg && e.dev !== '+'; }),
				neg: ents.filter(function(e) { return e.neg; }),
				anyDev: ents.some(function(e) { return !e.neg && e.dev === '+'; }),
				to: [], internet: false
			});
		});
		var byName = Object.create(null);
		zones.forEach(function(z) { if (!byName[z.name]) byName[z.name] = z; });

		/* does zone z take traffic from interface n (fw4's zone match on the
		   devices its networks and devices name)? */
		var covers = function(z, n) {
			var i = ifs && ifs[n];
			if (i && i.zone === z.name) return true;
			var hit = function(e) {
				if (e.net != null) return e.net === n;
				if (!i || !i.device) return false;
				return /\+$/.test(e.dev) ? i.device.indexOf(e.dev.slice(0, -1)) === 0 : i.device === e.dev;
			};
			if (z.neg.some(hit)) return false;
			return z.pos.length ? z.pos.some(hit) : (z.neg.length > 0 || z.anyDev);
		};
		var zoned = function(n) { return zones.some(function(z) { return covers(z, n); }); };

		zones.forEach(function(z) {
			z.internet = z.masq || WAN.test(z.name) ||
				z.pos.some(function(e) { return e.net != null && WAN.test(e.net); }) ||
				ups.some(function(u) { return covers(z, u); });
		});
		var internet = zones.filter(function(z) { return z.internet; });

		/* internet traffic no zone takes: it meets the default policies */
		var outside = [];
		var addOut = function(name, fam, zone) {
			if (!outside.some(function(o) { return o.name === name && o.family === fam; }))
				outside.push({ name: name, family: fam, zone: !!zone });
		};
		ups.forEach(function(u) { if (!zoned(u)) addOut(u, null); });
		lostNets.forEach(function(n) {
			if (ifs && !(ifs[n] && ifs[n].up)) return;
			if (!zoned(n)) addOut(n, null);
		});
		internet.forEach(function(z) {
			if (!z.family) return;
			var other = z.family === 4 ? 6 : 4;
			var taken = zones.some(function(y) {
				return y !== z && y.family !== z.family && z.pos.some(function(e) { return e.net != null && covers(y, e.net); });
			});
			if (!taken) addOut(z.name, other, true);
		});

		var routed = internet.length > 0 || outside.length > 0;
		var fromInternet = function(src) { return routed && (src === '*' || !!(byName[src] && byName[src].internet)); };
		var intoInternet = function(dest) { return dest !== '*' && !!(byName[dest] && byName[dest].internet); };
		var zoneRef = function(v) { return (v === '*' || byName[v]) ? v : null; };
		var zoneFam = function(ref) { return (ref && ref !== '*') ? byName[ref].family : null; };

		/* network: an address, or a network name with the dump's addresses
		   -> { invert, text, addrs } (addrs null: unknown, no dump) */
		var network = function(v) {
			var n = invert(v);
			if (!n) return null;
			var s = subnet(n.val);
			if (s === null) return null;
			if (s) return { invert: n.invert, text: n.val, addrs: [ s ] };
			if (!ifs) return { invert: n.invert, text: n.val, addrs: null };
			return ifs[n.val] ? { invert: n.invert, text: n.val, addrs: ifs[n.val].addrs } : null;
		};
		var routerAddr = function(text) {
			return !!ifs && Object.keys(ifs).some(function(n) { return ifs[n].ips.indexOf(text) >= 0; });
		};

		/* what a rule or redirect matches, read leniently so that a section
		   fw4 skips can still be described */
		var describe = function(kind, s) {
			var redirect = kind === 'redirect';
			var proto = lenient(protocol, s.proto != null ? s.proto : 'tcpudp');
			var any = proto.indexOf('all') >= 0;
			proto = any ? [ 'all' ] : proto.filter(function(p, i) { return proto.indexOf(p) === i; });
			var l4 = !any && proto.some(function(p) { return p === 'tcp' || p === 'udp'; });
			var ports = l4 ? portRanges(lenient(port, redirect ? s.src_dport : s.dest_port)) : null;
			var ips = lenient(network, s.src_ip), sets = lenient(setmatch, s.ipset);
			var pos = ips.filter(function(a) { return !a.invert; }), neg = ips.filter(function(a) { return a.invert; });
			var addrs = ips.reduce(function(a, x) { return a.concat(x.addrs || []); }, []);
			var dips = lenient(network, s.dest_ip).reduce(function(a, x) { return a.concat(x.addrs || []); }, []);
			var sdips = redirect ? lenient(network, s.src_dip).reduce(function(a, x) { return a.concat(x.addrs || []); }, []) : [];
			var fam = s.family != null ? family(String(s.family)) : null;
			var src = s.src != null ? String(s.src) : null, dest = s.dest != null ? String(s.dest) : null;
			var refs = [ famOf(addrs), famOf(dips), famOf(sdips), byName[src] ? byName[src].family : null, byName[dest] ? byName[dest].family : null ];
			var has = function(f) { return addrs.concat(dips, sdips).some(function(a) { return a.family === f; }); };
			var fams = [];
			var add = function(f) {
				(families(f, refs, has(4), has(6), redirect) || []).forEach(function(x) { if (fams.indexOf(x) < 0) fams.push(x); });
			};
			/* ipv6-icmp is IPv6 whatever the family says */
			if (proto.some(function(p) { return p !== 'ipv6-icmp'; })) add(fam);
			if (proto.indexOf('ipv6-icmp') >= 0) add(6);
			/* restricted when every family the section applies to has a
			   positive source list that is not the whole address space; a
			   negated address admits everyone else, and a MAC address on
			   internet traffic is the upstream router's */
			var restricted = fams.length > 0 && (sets.some(function(x) { return !x.invert; }) || fams.every(function(f) {
				var mine = pos.filter(function(a) { return !a.addrs || a.addrs.some(function(x) { return x.family === f; }); });
				return mine.length > 0 && !mine.some(function(a) { return a.addrs && a.addrs.some(function(x) { return x.family === f && x.all; }); });
			}));
			var only = pos.filter(function(a) { return !(a.addrs && a.addrs.length && a.addrs.every(function(x) { return x.all; })); }).map(function(a) { return a.text; })
				.concat(sets.filter(function(x) { return !x.invert; }).map(function(x) { return '@' + x.val; }));
			return {
				kind: kind, name: s.name != null ? String(s.name) : null, src: src, dest: dest,
				proto: proto, ports: ports, portText: ports ? rangeText(ports.pos) : '',
				portsExcept: ports ? rangeText(ports.neg) : '',
				icmp: proto.some(function(p) { return /icmp/.test(p); }) ? toArray(s.icmp_type) : [],
				from: { anywhere: !restricted, only: restricted ? only : [], except: restricted ? [] : neg.map(function(a) { return a.text; }) },
				family: fams.length === 1 ? fams[0] : null,
				families: fams
			};
		};
		var admin = function(item, ports) {
			return item.from.anywhere && (item.proto[0] === 'all' || item.proto.indexOf('tcp') >= 0) &&
				ADMIN_PORTS.some(function(p) { return hasPort(ports, p); });
		};
		/* standard housekeeping: ping and other control messages, multicast
		   membership, DHCP client replies, IPsec passed on to a host */
		var quiet = function(item) {
			if (item.proto[0] === 'all') return false;
			return item.proto.every(function(p) {
				if (QUIET_PROTO.test(p)) return true;
				if (IPSEC_PROTO.test(p)) return !!item.dest;
				if (p !== 'udp' || !item.ports) return false;
				return within(item.ports.pos, item.dest ? CLIENT_UDP.concat(IPSEC_UDP) : CLIENT_UDP);
			});
		};

		/* zones every zone forwards to (forwardings from '*') */
		var anyTo = [];
		of('forwarding').forEach(function(s) {
			var item = { kind: 'forwarding', name: null, src: s.src != null ? String(s.src) : null, dest: s.dest != null ? String(s.dest) : null };
			if (bool(s.enabled) === false) { off.push(item); return; }
			var f = parse(s, { enabled: [ bool, '1' ], family: [ family ], src: [ zoneRef ], dest: [ zoneRef ] });
			if (!f.bad && (!f.src || !f.dest)) f.bad = !f.src ? 'src' : 'dest';
			if (f.bad) { item.bad = f.bad; ignored.push(item); return; }
			if (!families(f.family, [ zoneFam(f.src), zoneFam(f.dest) ])) { item.bad = 'family'; ignored.push(item); return; }
			if (f.src === '*' && anyTo.indexOf(f.dest) < 0) anyTo.push(f.dest);
			(f.src === '*' ? zones : [ byName[f.src] ]).forEach(function(z) {
				if (z.name !== f.dest && z.to.indexOf(f.dest) < 0) z.to.push(f.dest);
			});
			if (fromInternet(f.src) && !intoInternet(f.dest))
				warnings.push({ level: 'err', code: 'forward-into', zone: f.src, dest: f.dest });
		});

		if (routed && defs.forward === 'accept') warnings.push({ level: 'err', code: 'default-forward' });
		internet.forEach(function(z) {
			if (z.input === 'ACCEPT') warnings.push({ level: 'err', code: 'input-accept', zone: z.name });
		});
		outside.forEach(function(o) {
			if (defs.input === 'accept') warnings.push({ level: 'err', code: 'outside-input', iface: o.name, family: o.family });
		});
		/* without the dump an uplink outside every zone cannot be seen */
		if (!ifs && routed && defs.input === 'accept' && !outside.length) warnings.push({ level: 'warn', code: 'uplinks-unknown' });

		var open = [], fwd = [], standard = [];
		of('rule').forEach(function(s) {
			var item = describe('rule', s);
			if (bool(s.enabled) === false) { off.push(item); return; }
			var r = parse(s, {
				enabled: [ bool, '1' ], family: [ family ], src: [ zoneRef ], dest: [ zoneRef ],
				proto: [ protocol, 'tcpudp', true ], src_ip: [ network, null, true ], src_mac: [ mac, null, true ],
				src_port: [ port, null, true ], dest_ip: [ network, null, true ], dest_port: [ port, null, true ],
				ipset: [ setmatch ], target: [ target ]
			});
			if (r.bad || !item.families.length) { item.bad = r.bad || 'family'; ignored.push(item); return; }
			if (r.target !== 'accept' || !fromInternet(r.src)) return;
			if (quiet(item)) { standard.push(item); return; }
			if (r.dest) {
				fwd.push(item);
				/* every port from any address into another zone: the same
				   as a forwarding */
				if (!intoInternet(r.dest) && item.from.anywhere && !r.dest_ip &&
					(item.proto[0] === 'all' || (item.proto.some(function(p) { return p === 'tcp' || p === 'udp'; }) && !(item.ports && item.ports.pos.length))))
					warnings.push({ level: 'err', code: 'rule-into', name: item.name, dest: r.dest });
				return;
			}
			open.push(item);
			if (admin(item, item.ports))
				warnings.push({ level: 'warn', code: 'admin-open', kind: 'rule', name: item.name, ports: item.portText });
		});

		of('redirect').forEach(function(s) {
			var item = describe('redirect', s);
			item.host = s.dest_ip != null ? String(s.dest_ip) : null;
			if (bool(s.enabled) === false) { off.push(item); return; }
			var r = parse(s, {
				enabled: [ bool, '1' ], family: [ family ], src: [ zoneRef ], dest: [ zoneRef ],
				proto: [ protocol, 'tcpudp', true ], src_ip: [ network ], src_mac: [ mac, null, true ], src_port: [ port ],
				src_dip: [ network ], src_dport: [ port ], dest_ip: [ network ], dest_port: [ port ],
				ipset: [ setmatch ], target: [ target, 'dnat' ]
			});
			/* fw4 makes every target but snat a DNAT; SNAT opens nothing */
			if (!r.bad && r.target === 'snat') return;
			if (!r.bad && !r.src) r.bad = 'src';
			if (!r.bad && r.src === '*') r.bad = 'src-any';
			if (!r.bad && r.dest_ip && r.dest_ip.invert) r.bad = 'dest_ip';
			if (r.bad || !item.families.length) { item.bad = r.bad || 'family'; ignored.push(item); return; }
			if (!fromInternet(r.src)) return;
			/* the port on the target: dest_port, or the same as outside (fw4
			   copies src_dport); null when every port is sent on */
			var l4 = item.proto.some(function(p) { return p === 'tcp' || p === 'udp'; });
			var inner = !l4 ? null : r.dest_port ? portRanges([ r.dest_port ]) : item.ports;
			item.hostPort = inner ? rangeText(inner.pos) : '';
			item.local = !r.dest_ip || routerAddr(r.dest_ip.text);
			if (!item.local) { fwd.push(item); return; }
			open.push(item);
			if (admin(item, inner))
				warnings.push({ level: 'warn', code: 'admin-open', kind: 'redirect', name: item.name, ports: item.portText });
		});

		/* custom rules: files the firewall config names, whose rules this
		   config does not show (the Custom Rules tab, UPnP's include) */
		var includes = [];
		of('include').forEach(function(s) {
			var path = s.path != null ? String(s.path) : null;
			var item = { kind: 'include', name: null, path: path };
			if (bool(s.enabled) === false) return;
			var inc = parse(s, {
				enabled: [ bool, '1' ], path: [ str ], type: [ includeType, 'script' ],
				fw4_compatible: [ bool, path !== '/etc/firewall.user' ? '1' : '0' ]
			});
			if (!inc.bad && !path) inc.bad = 'path';
			if (!inc.bad && inc.type === 'script' && !inc.fw4_compatible) inc.bad = 'fw4_compatible';
			if (!inc.bad && inc.type !== 'nftables' && (s.position != null || s.chain != null)) inc.bad = s.position != null ? 'position' : 'chain';
			if (inc.bad) { item.bad = inc.bad; ignored.push(item); return; }
			includes.push(item);
		});

		/* errors first */
		warnings = warnings.filter(function(w) { return w.level === 'err'; }).concat(warnings.filter(function(w) { return w.level !== 'err'; }));
		var level = !routed ? 'unknown'
			: warnings.some(function(w) { return w.level === 'err'; }) ? 'err'
			: warnings.length ? 'warn' : (open.length || fwd.length) ? 'info' : 'ok';
		return {
			routed: routed, internet: internet.map(function(z) { return z.name; }), outside: outside, anyTo: anyTo,
			defaults: { input: defs.input.toUpperCase(), output: defs.output.toUpperCase(), forward: defs.forward.toUpperCase() },
			zones: zones, open: open, forwards: fwd, standard: standard, off: off, ignored: ignored,
			warnings: routed ? warnings : [], includes: includes, level: level, interfaces: !!ifs
		};
	}
});
