'use strict';
'require baseclass';
'require fs';
'require vantage-theme.nftmodel as nftmodel';

/*
 * Vantage theme - Status -> Firewall as a flow chart.
 *
 * LuCI's view lists every chain as a table of rules. On top of it this
 * draws (a Flow / Rules table switch picks one):
 *  - one chart of the way a packet goes: in through prerouting, then
 *    either input, this device and output, or forward, and out through
 *    postrouting; each stage names its chains that hold rules and says
 *    whether it drops unmatched packets; bridge and netdev hooks sit where
 *    a packet meets them;
 *  - every base chain with rules as a list of steps: the rule's name (fw4's
 *    comment), its conditions and what it does; a jump opens the chain it
 *    jumps to in place, so a packet's whole way reads top to bottom.
 * The ruleset comes from the command LuCI's page runs (same ACL). The
 * conditions are clones of LuCI's own rendering of each rule (its rows
 * follow the ruleset's order), so they read exactly as in the table.
 * Rules as in menu-vantage.js: E() with array content only, LuCI's nodes
 * stay where they are (hidden by a class in Flow mode).
 * ------------------------------------------------------------------------ */

const MODE_KEY = 'vantage.nft.mode';
const MAX_DEPTH = 8;

function storageGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
function storageSet(k, v) { try { localStorage.setItem(k, v); } catch (e) {} }

function hookName(h) {
	switch (h) {
	case 'prerouting': return _('Prerouting');
	case 'input': return _('Input');
	case 'forward': return _('Forward');
	case 'output': return _('Output');
	case 'postrouting': return _('Postrouting');
	case 'ingress': return _('Ingress');
	case 'egress': return _('Egress');
	default: return h;
	}
}

function stageName(s) {
	switch (s.hook) {
	case 'ingress': return _('Device ingress');
	case 'egress': return _('Device egress');
	case 'bridgeIn': case 'bridgeOut': return _('Bridge');
	case 'bridged': return _('Bridged between ports');
	default: return hookName(s.hook);
	}
}

/* LuCI's rows per chain key, in the ruleset's order: tables, chains and
   rules are rendered in JSON order, one row per rule */
function luciRows(root, m) {
	const out = Object.create(null);
	const tables = root.querySelectorAll(':scope > .nft-table');
	m.tables.forEach((t, i) => {
		const box = tables[i];
		if (!box) return;
		const cards = box.querySelectorAll('.nft-chain');
		t.chains.forEach((k, j) => {
			const card = cards[j], h = card && card.querySelector(':scope > h4');
			if (!h || h.id !== t.name + '.' + m.chains[k].name) return;
			out[k] = Array.prototype.filter.call(card.querySelectorAll('.nft-rules .tr'), (tr) => !tr.classList.contains('table-titles'));
		});
	});
	return out;
}

/* a rule's conditions as LuCI shows them, without its comment and counter;
   vmap: the verdict chips say it all where LuCI can only show a placeholder
   (LuCI 24.10: "{ vmap }", its fallback for an expression it can't read) */
function conditions(tr, vmap) {
	const td = tr && tr.firstElementChild;
	if (!td) return null;
	const c = td.cloneNode(true);
	c.querySelectorAll('.nft-comment, .nft-counter').forEach((n) => n.remove());
	if (vmap) c.querySelectorAll('.ifacebadge[data-tooltip]').forEach((n) => { if (/^\{\s*vmap\s*\}$/.test(n.textContent.trim())) n.remove(); });
	c.removeAttribute('style');
	c.className = 'v-nft-cond';
	return c.textContent.trim() ? c : null;
}

/* the actions LuCI shows besides the deciding one (log, a helper, a mark) */
function sideActions(tr, parts) {
	const td = tr && tr.children[1];
	if (!td || td.children.length !== parts.acts) return null;
	const keep = Array.prototype.filter.call(td.children, (n, i) => i !== parts.last).map((n) => n.cloneNode(true));
	return keep.length ? E('div', { 'class': 'v-nft-cond v-nft-also' }, keep) : null;
}

function chip(kind, label, title) {
	const el = E('span', { 'class': 'v-nft-verdict', 'data-kind': kind }, [ label ]);
	if (title) el.setAttribute('title', title);
	return el;
}

function verdictLabel(v) {
	switch (v.kind) {
	case 'accept': return _('Accept');
	case 'drop': return _('Drop');
	case 'reject': return _('Reject');
	case 'return': return _('Back');
	case 'queue': return _('Queue');
	case 'nat':
		return v.nat === 'masquerade' ? _('Masquerade') : v.nat === 'snat' ? _('Rewrite source')
			: v.nat === 'dnat' ? _('Rewrite destination') : _('Redirect');
	default: return _('Next rule');
	}
}

return baseclass.extend({
	attach(view) {
		const ready = () => {
			const t = view.querySelector('.nft-table');
			return t && t.parentNode;
		};
		const go = (root) => {
			L.resolveDefault(fs.exec_direct('/usr/sbin/nft', [ '--terse', '--json', 'list', 'ruleset' ], 'json'), null).then((json) => {
				if (!json || root.querySelector(':scope > .v-nft')) return;
				const m = nftmodel.build(json);
				if (!m.bases.length && !m.others.length) return;
				this.draw(root, m);
			}).catch((e) => { if (window.console) console.warn('vantage: firewall flow', e); });
		};
		const root = ready();
		if (root) return go(root);
		const mo = new MutationObserver(() => {
			const r = ready();
			if (r) { mo.disconnect(); go(r); }
		});
		mo.observe(view, { childList: true, subtree: true });
	},

	draw(root, m) {
		this.m = m;
		this.rows = luciRows(root, m);
		this.ids = Object.create(null);
		Object.keys(m.chains).forEach((k, i) => { this.ids[k] = 'v-nft-c' + i; });
		this.cards = Object.create(null);

		const tabs = E('ul', { 'class': 'cbi-tabmenu v-nft-tabs' });
		const panel = E('div', { 'class': 'v-nft-panel' }, [
			E('h3', {}, [ _('Packet path') ]),
			this.chart(),
			E('h3', {}, [ _('Chains') ]),
			E('div', { 'class': 'v-nft-chains' }, this.cardsOf(m.bases))
		]);
		m.others.forEach((t) => {
			panel.appendChild(E('h3', {}, [ _('Table %s (%s)').format(t.name, t.family) ]));
			panel.appendChild(E('div', { 'class': 'v-nft-chains' }, this.cardsOf(t.chains)));
		});
		if (m.unused.length) {
			panel.appendChild(E('h3', {}, [ _('Chains no rule jumps to') ]));
			panel.appendChild(E('div', { 'class': 'v-nft-chains' }, this.cardsOf(m.unused)));
		}

		const box = E('div', { 'class': 'v-nft' }, [ tabs, panel ]);
		const set = (mode) => {
			root.classList.toggle('v-nft-flowmode', mode === 'flow');
			Array.prototype.forEach.call(tabs.children, (li) => {
				const on = li.getAttribute('data-mode') === mode;
				li.className = on ? 'cbi-tab' : 'cbi-tab-disabled';
				li.firstElementChild.setAttribute('aria-selected', String(on));
			});
		};
		[ [ 'flow', _('Flow') ], [ 'table', _('Rules table') ] ].forEach((t) => {
			tabs.appendChild(E('li', { 'data-mode': t[0] }, [
				E('a', { 'href': '#', 'role': 'tab', 'click': (ev) => { ev.preventDefault(); storageSet(MODE_KEY, t[0]); set(t[0]); } }, [ t[1] ])
			]));
		});
		tabs.setAttribute('role', 'tablist');
		root.insertBefore(box, root.firstChild);
		set(storageGet(MODE_KEY) === 'table' ? 'table' : 'flow');
	},

	/* the way through the hooks: in, a fork (to this device and back out,
	   or forwarded), out; the bridged path below when a bridge filters it */
	chart() {
		const st = this.m.stages;
		const arrow = () => E('span', { 'class': 'v-nft-arrow', 'aria-hidden': 'true' });
		const pass = () => E('span', { 'class': 'v-nft-pass', 'aria-hidden': 'true' });
		const end = (where) => E('span', { 'class': 'v-nft-endpoint', 'data-where': where }, [ where === 'device' ? _('This device') : _('Network') ]);
		const row = [ end('net') ];
		[ st.ingress, st.bridgeIn, st.prerouting ].filter(Boolean).forEach((s) => { row.push(arrow(), this.stage(s)); });
		row.push(arrow(), E('div', { 'class': 'v-nft-fork' }, [
			E('div', { 'class': 'v-nft-branch' }, [ this.stage(st.input), arrow(), end('device'), arrow(), this.stage(st.output), pass() ]),
			E('div', { 'class': 'v-nft-branch' }, [ this.stage(st.forward), pass() ])
		]), arrow(), this.stage(st.postrouting));
		[ st.bridgeOut, st.egress ].filter(Boolean).forEach((s) => { row.push(arrow(), this.stage(s)); });
		row.push(arrow(), end('net'));
		return E('div', { 'class': 'v-nft-chart' }, [
			E('div', { 'class': 'v-nft-chart-row' }, row),
			E('div', { 'class': 'v-nft-chart-row' }, [ end('net'), arrow(), this.stage(st.bridged), pass(), arrow(), end('net') ])
		]);
	},

	/* a stage: its name, whether it drops, its chains that hold rules */
	stage(s) {
		const m = this.m, live = s.chains.filter((k) => m.chains[k].rules.length);
		const open = s.hook === 'bridged' && !live.length;
		const name = [ stageName(s) ];
		if (s.drops !== 'none') name.push(E('small', {}, [ s.drops === 'all' ? _('drops unmatched') : _('drops some') ]));
		if (open) name.push(E('small', {}, [ _('not filtered') ]));
		const el = E('div', { 'class': 'v-nft-stage', 'data-drops': open ? 'open' : s.drops, 'data-edge': String(nftmodel.HOOKS.indexOf(s.hook) < 0) }, [
			E('div', { 'class': 'v-nft-stage-name' }, name),
			E('div', { 'class': 'v-nft-stage-chains' }, live.length ? live.map((k) => {
				const c = m.chains[k];
				const b = E('button', { 'type': 'button', 'class': 'v-nft-link', 'click': () => this.show(k),
					'title': _('%s, table %s (%s), priority %d').format(c.name, c.table, c.family, c.prio) }, [ c.name ]);
				if (c.type === 'nat') b.appendChild(E('small', {}, [ 'NAT' ]));
				return b;
			}) : open ? [] : [ E('span', { 'class': 'v-nft-none' }, [ _('no rules') ]) ])
		]);
		if (open) el.setAttribute('title', _('Traffic between ports of one bridge, such as Wi-Fi and LAN in br-lan, never reaches the input, forward or output chains. No bridge-table chain filters it here.'));
		return el;
	},

	/* open a chain's card and bring it into view */
	show(k) {
		const card = this.cards[k];
		if (!card) return;
		card.open = true;
		card.scrollIntoView({ block: 'start', behavior: 'smooth' });
		const s = card.querySelector('summary');
		if (s) s.focus({ preventScroll: true });
	},

	/* a card per chain with rules; the empty ones named on one line */
	cardsOf(keys) {
		const empty = keys.filter((k) => !this.m.chains[k].rules.length);
		const out = keys.filter((k) => this.m.chains[k].rules.length).map((k) => this.card(k));
		if (empty.length)
			out.push(E('p', { 'class': 'v-nft-empty' }, [ _('No rules: %s').format(empty.map((k) => this.m.chains[k].name).join(', ')) ]));
		return out;
	},

	card(k) {
		const c = this.m.chains[k];
		const meta = [];
		if (c.base) {
			meta.push(hookName(c.hook), _('priority %d').format(c.prio));
			if (c.type === 'nat') meta.push('NAT');
		}
		meta.push(N_(c.rules.length, '%d rule', '%d rules').format(c.rules.length));
		const card = E('details', { 'class': 'v-nft-card', 'id': this.ids[k], 'data-chain': c.name, 'data-family': c.family }, [
			E('summary', {}, [ E('strong', {}, [ c.name ]), E('span', { 'class': 'v-nft-meta' }, [ meta.join(' · ') ]) ].concat(c.base ? [ this.policyChip(c) ] : []))
		]);
		/* the chains that drop what no rule accepts start open */
		card.open = c.base && c.policy === 'drop';
		let built = false;
		const fill = () => { if (!built && card.open) { built = true; card.appendChild(this.flow(k, [ k ])); } };
		card.addEventListener('toggle', fill);
		fill();
		this.cards[k] = card;
		return card;
	},

	policyChip(c) {
		if (c.policy === 'drop') return chip('drop', _('Drops unmatched'));
		if (c.type === 'filter') return chip('accept', _('Passes unmatched'));
		return chip('none', _('Leaves unmatched unchanged'));
	},

	/* a chain's rules as steps; path: the chains above it, for the way back
	   and to stop at a loop */
	flow(k, path) {
		const c = this.m.chains[k], rows = this.rows[k] || [];
		const list = E('ol', { 'class': 'v-nft-flow' });
		c.rules.forEach((r) => {
			const cond = r.parts.conds ? conditions(rows[r.index], r.verdict.kind === 'vmap') : null;
			const also = r.verdict.kind !== 'vmap' && r.parts.acts > (r.parts.last >= 0 ? 1 : 0) ? sideActions(rows[r.index], r.parts) : null;
			const what = [ E('div', { 'class': 'v-nft-what-name' }, [ r.comment || (cond ? '' : _('Any packet', 'nft match any traffic')) ]) ];
			if (!r.comment && cond) what[0] = cond;
			else if (cond) what.push(cond);
			if (also) what.push(also);
			const then = this.outcome(r.verdict, c, path);
			if (r.counter)
				then.push(E('span', { 'class': 'v-nft-count', 'title': _('Traffic matched by rule: %.1000mPackets, %.1024mBytes', 'nft counter').format(r.counter.packets, r.counter.bytes) },
					[ _('%s matched').format('%1024.1mB'.format(r.counter.bytes)) ]));
			const step = E('li', { 'class': 'v-nft-step' }, [
				E('span', { 'class': 'v-nft-n' }, [ String(r.index + 1) ]),
				E('div', { 'class': 'v-nft-what' }, what),
				E('div', { 'class': 'v-nft-then' }, then)
			]);
			list.appendChild(step);
		});
		list.appendChild(this.end(c, path));
		return list;
	},

	/* what a rule does: a verdict, or the chain it jumps to (opens below) */
	outcome(v, c, path) {
		const jump = (kind, target, key) => {
			const tk = nftmodel.keyOf(c.family, c.table, target);
			const label = (key != null ? key + ' → ' : '→ ') + target;
			if (!this.m.chains[tk]) return chip(kind, label);
			if (path.indexOf(tk) >= 0 || path.length >= MAX_DEPTH) return chip(kind, label, _('Already on the way here'));
			const b = E('button', { 'type': 'button', 'class': 'v-nft-verdict v-nft-jump', 'data-kind': kind, 'aria-expanded': 'false',
				'title': kind === 'goto' ? _('Continues in %s and does not come back here').format(target) : _('Continues in %s, then comes back here').format(target) }, [ label ]);
			let sub = null;
			b.addEventListener('click', () => {
				const step = b.closest('.v-nft-step');
				if (!sub) {
					sub = E('div', { 'class': 'v-nft-sub' }, [ this.flow(tk, path.concat([ tk ])) ]);
					step.appendChild(sub);
				}
				const open = b.getAttribute('aria-expanded') !== 'true';
				sub.hidden = !open;
				b.setAttribute('aria-expanded', String(open));
			});
			return b;
		};
		const up = path.length > 1 ? this.m.chains[path[path.length - 2]] : null;
		if (v.kind === 'return') return [ chip('return', up ? _('Back to %s').format(up.name) : _('Back to the calling chain')) ];
		if (v.kind === 'jump' || v.kind === 'goto') return [ jump(v.kind, v.target) ];
		if (v.kind === 'vmap') {
			/* keys with the same verdict share a chip: "established, related → Accept" */
			const out = [], same = Object.create(null);
			v.map.forEach((e) => {
				if (e.kind === 'jump' || e.kind === 'goto') return out.push(jump(e.kind, e.target, e.key));
				if (same[e.kind]) return same[e.kind].push(e.key);
				same[e.kind] = [ e.key ];
				out.push(e.kind);
			});
			return out.map((x) => typeof x === 'string' ? chip(x, same[x].join(', ') + ' → ' + verdictLabel({ kind: x })) : x);
		}
		return [ chip(v.kind, verdictLabel(v)) ];
	},

	/* where a packet goes when no rule of the chain decided */
	end(c, path) {
		let what;
		if (c.base) what = c.policy === 'drop' ? chip('drop', _('Drop')) : c.type === 'filter' ? chip('accept', _('Pass')) : chip('none', _('Unchanged'));
		else {
			const up = path.length > 1 ? this.m.chains[path[path.length - 2]] : null;
			what = chip('return', up ? _('Back to %s').format(up.name) : _('Back to the calling chain'));
		}
		return E('li', { 'class': 'v-nft-step v-nft-step-end' }, [
			E('span', { 'class': 'v-nft-n', 'aria-hidden': 'true' }),
			E('div', { 'class': 'v-nft-what' }, [ _('No rule matched') ]),
			E('div', { 'class': 'v-nft-then' }, [ what ])
		]);
	}
});
