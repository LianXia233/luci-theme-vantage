'use strict';
/* Wired-router mode (--wired): the recorded access point, served as if it
   were a router without Wi-Fi (an x86 box, a wired board), to develop the
   dashboard's wired-only layout.

   Replies are rewritten after the store answers:
     luci.vantage wireless, network.wireless status   no radios ({})
     network.interface dump   the recorded uplink becomes 'wan' (dhcp);
                              SYNTHETIC 'lan', 'vpn' (WireGuard) and
                              'guest' (down) are added
     network.device status    SYNTHETIC counters for the added devices,
                              growing with the clock
   Added addresses are documentation ranges only. */

const NETS = [
	{ iface: 'lan', dev: 'br-lan0', proto: 'static', addr: '198.51.100.1', mask: 24, up: true, rate: 24e6 },
	{ iface: 'vpn', dev: 'wg0', proto: 'wireguard', addr: '203.0.113.1', mask: 24, up: true, rate: 3e6 },
	{ iface: 'guest', dev: 'br-guest', proto: 'static', addr: '198.51.100.129', mask: 25, up: false, rate: 0 }
];

/* deterministic noise in [0, 1), smooth over `period` seconds */
function hash01(a, b) {
	let h = (Math.imul(a | 0, 0x9e3779b1) ^ Math.imul((b | 0) + 0x7f4a7c15, 0x85ebca6b)) >>> 0;
	h = Math.imul(h ^ (h >>> 15), 0x2c1b3c6d) >>> 0;
	return ((h ^ (h >>> 13)) >>> 0) / 4294967296;
}
function smooth(seed, t, period) {
	const x = t / period, i = Math.floor(x), f = x - i, u = f * f * (3 - 2 * f);
	return hash01(seed, i) * (1 - u) + hash01(seed, i + 1) * u;
}

/* bytes so far at a mean of `bps` bit/s: a slope plus a bounded wobble
   whose derivative stays below the slope, so the counter never drops */
function bytes(bps, seed, t) {
	const B = bps / 8, P = 20;
	return Math.round(B * t + 0.4 * B * P * smooth(seed, t, P));
}

function iface(n) {
	return {
		interface: n.iface, up: n.up, pending: false, available: true, autostart: true, dynamic: false,
		uptime: n.up ? 86400 : undefined, l3_device: n.up ? n.dev : undefined, device: n.dev, proto: n.proto,
		'ipv4-address': n.up ? [ { address: n.addr, mask: n.mask } ] : [], 'ipv6-address': [], route: [], 'dns-server': [], data: {}
	};
}

function device(n, i, t) {
	const tx = n.up ? bytes(n.rate, 2 * i + 1, t) : 0, rx = n.up ? bytes(n.rate / 6, 2 * i + 2, t) : 0;
	return {
		up: n.up, carrier: n.up, devtype: n.proto === 'wireguard' ? 'wireguard' : 'bridge', type: n.proto === 'wireguard' ? 'wireguard' : 'bridge',
		statistics: { rx_bytes: rx, tx_bytes: tx, rx_packets: Math.round(rx / 900), tx_packets: Math.round(tx / 900), rx_errors: 0, tx_errors: 0 }
	};
}

/* reply: { result: [ status, data ] } from the store; returns the reply to send */
function transform(object, method, args, reply) {
	const res = reply && reply.result;
	if (!Array.isArray(res) || res[0] !== 0) return reply;
	if ((object === 'luci.vantage' && method === 'wireless') || (object === 'network.wireless' && method === 'status'))
		return { result: [ 0, {} ] };
	if (object === 'network.interface' && method === 'dump' && res[1] && Array.isArray(res[1].interface)) {
		/* the recorded interface with the default route becomes the
		   uplink; of the rest only loopback stays */
		const isUp = i => (i.route || []).some(r => +r.mask === 0);
		const recorded = res[1].interface.filter(i => i && typeof i === 'object');
		const up = recorded.filter(isUp)[0];
		const out = recorded.filter(i => i.interface === 'loopback')
			.concat(up ? [ Object.assign({}, up, { interface: 'wan', proto: 'dhcp' }) ] : []);
		return { result: [ 0, Object.assign({}, res[1], { interface: out.concat(NETS.map(iface)) }) ] };
	}
	if (object === 'network.device' && method === 'status' && !(args && args.name) && res[1] && typeof res[1] === 'object') {
		const t = Date.now() / 1000, extra = {};
		NETS.forEach((n, i) => { extra[n.dev] = device(n, i, t); });
		return { result: [ 0, Object.assign({}, res[1], extra) ] };
	}
	return reply;
}

module.exports = { transform, NETS };
