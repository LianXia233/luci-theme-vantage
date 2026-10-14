'use strict';
'require view';
'require rpc';
'require ui';
'require vantage.fwglance as fwglance';

/* Network -> Firewall -> Overview (luci-app-vantage): what the firewall
   lets in from the internet, which zone reaches which, what is switched
   off, and the risky cases, read from uci `firewall`. Read-only: every
   item links to the LuCI page that changes it. The menu entry is gated by
   luci-app-firewall's own ACL group, which already lets its holder read
   and change this config; the app grants nothing for it. It shows what
   the config says: ports UPnP opens at run time and rules in custom rule
   files are not in it, and the page says so. All DOM is built with E()
   and text nodes. */

var callUciGet = rpc.declare({ object: 'uci', method: 'get', params: [ 'config' ], expect: { values: {} } });
/* which interface holds the default route, to find an uplink zone that
   does not masquerade: LuCI's luci-base-network-status group grants it
   (also the app's read group); without it the page falls back to
   masquerading and naming */
var callIfDump = rpc.declare({ object: 'network.interface', method: 'dump', expect: { 'interface': [] } });

/* the dashboard's sheet, revalidated on every load (see overview.js) */
var cssPromise = null;
function loadCss() {
	if (cssPromise) return cssPromise;
	cssPromise = fetch(L.resource('vantage/app.css'), { cache: 'no-cache' }).then(function(r) { return r.ok ? r.text() : ''; }).then(function(text) {
		if (!text || !('adoptedStyleSheets' in document) || typeof CSSStyleSheet !== 'function') return;
		var sheet = new CSSStyleSheet();
		sheet.replaceSync(text);
		document.adoptedStyleSheets = document.adoptedStyleSheets.concat([ sheet ]);
	}).catch(function() {});
	return cssPromise;
}

var SVGNS = 'http://www.w3.org/2000/svg';
var ICONS = {
	globe: [ 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18Z', 'M3.4 9.2h17.2M3.4 14.8h17.2', 'M12 3c2.4 2.5 3.6 5.5 3.6 9s-1.2 6.5-3.6 9c-2.4-2.5-3.6-5.5-3.6-9s1.2-6.5 3.6-9Z' ],
	zones: [ 'M4 5.5h6.5v6.5H4zM13.5 5.5H20v6.5h-6.5zM8.75 15.5h6.5V22h-6.5z', 'M7.25 12v1.75h9.5V12M12 13.75v1.75' ],
	off: [ 'M12 3.5a8.5 8.5 0 1 0 0 17a8.5 8.5 0 1 0 0-17Z', 'M6 6l12 12' ],
	check: [ 'M5 12.5l4.5 4.5L19 7.5' ],
	warn: [ 'M10.3 4.6 3 17.5A2 2 0 0 0 4.7 20.5h14.6A2 2 0 0 0 21 17.5L13.7 4.6a2 2 0 0 0-3.4 0Z', 'M12 9.5v4.5', 'M12 17h.01' ],
	err: [ 'M12 3.5a8.5 8.5 0 1 0 0 17a8.5 8.5 0 1 0 0-17Z', 'M9 9l6 6M15 9l-6 6' ],
	chevron: [ 'M9.5 6l6 6-6 6' ],
	info: [ 'M12 3.5a8.5 8.5 0 1 0 0 17a8.5 8.5 0 1 0 0-17Z', 'M12 11v5.5', 'M12 7.8h.01' ],
	arrow: [ 'M5 12h13.5', 'M13 6.5l5.5 5.5-5.5 5.5' ]
};

function icon(name) {
	var s = document.createElementNS(SVGNS, 'svg');
	s.setAttribute('class', 'vt-ico');
	s.setAttribute('viewBox', '0 0 24 24');
	s.setAttribute('aria-hidden', 'true');
	s.setAttribute('focusable', 'false');
	ICONS[name].forEach(function(d) {
		var p = document.createElementNS(SVGNS, 'path');
		p.setAttribute('d', d);
		s.appendChild(p);
	});
	return s;
}

function page(tab) { return L.url('admin', 'network', 'firewall', tab); }

/* is admin/services/upnp in the menu tree (luci-app-upnp installed)? */
function hasUpnp(tree) {
	var n = tree;
	[ 'admin', 'services', 'upnp' ].forEach(function(k) { n = n && n.children ? n.children[k] : null; });
	return !!n;
}

/* "TCP, UDP 27015-27030", "ICMP echo-request", "all protocols" */
function what(item) {
	var any = item.proto.some(function(p) { return p === 'all' || p === 'any' || p === '*'; });
	var proto = any ? _('all protocols') : item.proto.map(function(p) { return p.toUpperCase(); }).join(', ');
	var extra = item.portText || (item.icmp && item.icmp.length ? item.icmp.join(', ') : '');
	return extra ? proto + ' ' + extra : proto;
}

function from(item) {
	return item.from.length ? _('from %s').format(item.from.join(', ')) : _('from anywhere');
}

function named(item) {
	if (item.name) return item.name;
	return item.kind === 'redirect' ? _('Unnamed port forward') : _('Unnamed rule');
}

function polBadge(p, risky) {
	var cls = risky ? 'is-risk' : p === 'ACCEPT' ? 'is-accept' : 'is-stop';
	return E('span', { 'class': 'vt-fg-pol ' + cls }, [ p === 'ACCEPT' ? _('accept') : p === 'DROP' ? _('drop') : _('reject') ]);
}

return view.extend({
	handleSave: null,
	handleSaveApply: null,
	handleReset: null,

	load: function() {
		return Promise.all([ loadCss(), L.resolveDefault(callUciGet('firewall'), {}), L.resolveDefault(ui.menu.load(), null),
			L.resolveDefault(callIfDump(), []) ]).then(function(r) {
			var fw = fwglance.analyse(r[1], fwglance.uplinks(r[3]));
			fw.upnp = hasUpnp(r[2]);
			return fw;
		});
	},

	render: function(fw) {
		return E('div', { 'class': 'vt-app vt-fg' }, [
			E('div', { 'class': 'vt-body' }, [
				this.renderHead(fw),
				fw.warnings.length ? E('div', { 'class': 'vt-fg-warns', 'role': 'list', 'aria-label': _('Warnings') }, fw.warnings.map(this.renderWarning)) : '',
				E('div', { 'class': 'vt-fg-grid' }, [
					fw.routed ? this.renderOpen(fw) : '',
					this.renderZones(fw),
					fw.off.length ? this.renderOff(fw) : ''
				])
			])
		]);
	},

	renderHead: function(fw) {
		var head, sub, n = fw.open.length + fw.forwards.length;
		if (!fw.routed) {
			head = _('No internet-facing zone found');
			sub = _('No zone masquerades, holds the uplink or is called wan, so this page cannot tell which side faces the internet. On an access point that is expected; on a router, check the zones below.');
		}
		else if (fw.warnings.length) {
			head = fw.warnings.length === 1 ? _('1 thing needs attention') : _('%d things need attention').format(fw.warnings.length);
			sub = _('Internet-facing: %s').format(fw.internet.join(', '));
		}
		else if (n) {
			head = _('Open from the internet: %d').format(n);
			sub = _('%d on this router, %d into your network').format(fw.open.length, fw.forwards.length);
		}
		else {
			head = _('Nothing is open in your firewall rules');
			sub = fw.standard.length ? _('Only standard housekeeping (ping, DHCP renewals and the like): %d rules').format(fw.standard.length) : _('Internet-facing: %s').format(fw.internet.join(', '));
		}
		return E('header', { 'class': 'vt-head' }, [
			E('span', { 'class': 'vt-orb vt-orb-' + (fw.level === 'info' ? 'ok' : fw.level) }, [ E('span', { 'class': 'vt-orb-core' }) ]),
			E('div', { 'class': 'vt-head-text' }, [
				E('h2', { 'class': 'vt-headline' }, [ head ]),
				E('p', { 'class': 'vt-subline' }, [ sub ])
			])
		]);
	},

	renderWarning: function(w) {
		var title, reason, tab;
		if (w.code === 'input-accept') {
			title = _('%s accepts every connection').format(w.zone);
			reason = _('Anything on the internet can reach the router itself. Set this zone\'s Input to reject.');
			tab = 'zones';
		}
		else if (w.code === 'forward-into') {
			title = _('%s is forwarded into %s').format(w.zone, w.dest);
			reason = _('Anything on the internet can reach that network. Remove the forwarding unless you mean it.');
			tab = 'zones';
		}
		else {
			title = _('Router admin open: %s').format(w.name || w.ports);
			reason = _('SSH or the web interface answers any address on the internet. Limit the rule to the addresses you use.');
			tab = 'rules';
		}
		return E('a', { 'class': 'vt-chip vt-chip-' + w.level, 'role': 'listitem', 'href': page(tab) }, [
			E('span', { 'class': 'vt-chip-ico' }, [ icon(w.level === 'err' ? 'err' : 'warn') ]),
			E('span', { 'class': 'vt-chip-main' }, [
				E('span', { 'class': 'vt-chip-title' }, [ title ]),
				E('span', { 'class': 'vt-chip-reason' }, [ reason ])
			])
		]);
	},

	tile: function(ic, title, link, linkText, body) {
		return E('section', { 'class': 'vt-tile vt-fg-tile', 'aria-label': title }, [
			E('header', { 'class': 'vt-tile-head' }, [
				E('h3', { 'class': 'vt-tile-title' }, [ icon(ic), E('span', {}, [ title ]) ]),
				E('a', { 'class': 'vt-link', 'href': link }, [ linkText, icon('chevron') ])
			])
		].concat(body));
	},

	row: function(href, main, sub, side) {
		return E('a', { 'class': 'vt-fg-row', 'href': href }, [
			E('span', { 'class': 'vt-fg-row-main' }, [
				E('span', { 'class': 'vt-fg-row-name' }, [ main ]),
				E('span', { 'class': 'vt-fg-row-sub' }, sub)
			]),
			side || ''
		]);
	},

	renderOpen: function(fw) {
		var self = this, body = [];
		var group = function(title, items) {
			body.push(E('h4', { 'class': 'vt-fg-group' }, [ title ]));
			body.push(E('div', { 'class': 'vt-fg-rows' }, items));
		};
		if (fw.open.length)
			group(_('On this router'), fw.open.map(function(i) {
				return self.row(page('rules'), named(i), [ what(i), ' · ', E('span', { 'class': i.from.length ? '' : 'vt-fg-anywhere' }, [ from(i) ]) ]);
			}));
		if (fw.forwards.length)
			group(_('Into your network'), fw.forwards.map(function(i) {
				var to = i.kind === 'redirect'
					? (i.host ? i.host + (i.hostPort ? ':' + i.hostPort : '') : (i.dest || ''))
					: (i.dest === '*' ? _('any zone') : i.dest);
				return self.row(page(i.kind === 'redirect' ? 'forwards' : 'rules'), named(i),
					[ what(i), ' · ', from(i) ],
					E('span', { 'class': 'vt-fg-to' }, [ icon('arrow'), E('span', { 'class': 'vt-mono' }, [ to ]) ]));
			}));
		if (!fw.open.length && !fw.forwards.length)
			body.push(E('p', { 'class': 'vt-empty-inline' }, [ _('Nothing is open in your firewall rules.') ]));
		if (fw.standard.length)
			body.push(E('details', { 'class': 'vt-fg-std' }, [
				E('summary', {}, [ _('Standard housekeeping: %d rules').format(fw.standard.length) ]),
				E('p', { 'class': 'vt-hint' }, [ _('Ping and other control messages, multicast, IPsec and DHCP renewals: what every router lets in.') ]),
				E('div', { 'class': 'vt-fg-rows' }, fw.standard.map(function(i) {
					return self.row(page('rules'), named(i), [ what(i) ]);
				}))
			]));
		/* what the config cannot show */
		if (fw.upnp)
			body.push(E('a', { 'class': 'vt-fg-note', 'href': L.url('admin', 'services', 'upnp') }, [ icon('info'),
				E('span', {}, [ _('UPnP is installed: devices on your network can open ports on their own while it runs, and those are not listed here.') ]) ]));
		if (fw.includes.length)
			body.push(E('p', { 'class': 'vt-fg-note' }, [ icon('info'),
				E('span', {}, [ _('Custom rule files are loaded (%s); rules in them are not listed here.').format(fw.includes.map(function(i) { return i.path || '?'; }).join(', ')) ]) ]));
		/* otherwise still say what this page cannot see: UPnP without its
		   LuCI app, and nftables files the firewall picks up on its own */
		if (!fw.upnp && !fw.includes.length)
			body.push(E('p', { 'class': 'vt-hint vt-fg-foot' }, [ _('From the firewall configuration. Ports opened by UPnP or by custom rule files are not shown.') ]));
		return this.tile('globe', _('Open from the internet'), page('rules'), _('Traffic Rules'), body);
	},

	renderZones: function(fw) {
		var rows = fw.zones.map(function(z) {
			return E('div', { 'class': 'vt-fg-zone' + (z.internet ? ' is-internet' : '') }, [
				E('div', { 'class': 'vt-fg-zone-head' }, [
					E('span', { 'class': 'vt-fg-zone-name' }, [ z.name ]),
					z.internet ? E('span', { 'class': 'vt-fg-tag' }, [ _('internet') ]) : '',
					E('span', { 'class': 'vt-fg-zone-in' }, [ _('Input'), ' ', polBadge(z.input, z.internet && z.input === 'ACCEPT') ])
				]),
				E('div', { 'class': 'vt-fg-zone-to' }, [
					icon('arrow'),
					z.to.length
						? E('span', { 'class': 'vt-fg-dests' }, z.to.map(function(d) {
							return E('span', { 'class': 'vt-fg-dest' + (z.internet ? ' is-risk' : '') }, [ d ]);
						}))
						: E('span', { 'class': 'vt-hint' }, [ _('forwards nowhere') ])
				]),
				z.networks.length ? E('div', { 'class': 'vt-hint vt-fg-nets' }, [ _('Networks: %s').format(z.networks.join(', ')) ]) : ''
			]);
		});
		if (!rows.length) rows = [ E('p', { 'class': 'vt-empty-inline' }, [ _('No zones are configured.') ]) ];
		return this.tile('zones', _('Zones'), page('zones'), _('General Settings'), [ E('div', { 'class': 'vt-fg-zones' }, rows) ]);
	},

	renderOff: function(fw) {
		var self = this;
		return this.tile('off', _('Switched off'), page('rules'), _('Traffic Rules'), [
			E('div', { 'class': 'vt-fg-rows' }, fw.off.map(function(i) {
				if (i.kind === 'forwarding')
					return self.row(page('zones'), _('Forwarding %s to %s').format(i.src || '?', i.dest || '?'), [ _('zone forwarding') ]);
				return self.row(page(i.kind === 'redirect' ? 'forwards' : 'rules'), named(i),
					[ i.kind === 'redirect' ? _('port forward') : _('traffic rule'), ' · ', what(i) ]);
			}))
		]);
	}
});
