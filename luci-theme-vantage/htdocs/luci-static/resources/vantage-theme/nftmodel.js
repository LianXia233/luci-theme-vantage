'use strict';
'require baseclass';

/*
 * Vantage theme - the live nftables ruleset as a model for the flow view
 * on Status -> Firewall (vantage-theme.nftflow draws it).
 *
 * Input: the JSON of `nft --terse --json list ruleset`, the command LuCI's
 * own page runs. Output: tables, chains with their rules and what each
 * rule finally does, and the stages a packet passes (the IP hooks, and
 * the bridge and netdev hooks around them) with their base chains in
 * priority order. Pure functions, no DOM, unit tested in
 * tests/nftflow.test.js.
 */

/* the IP families share the hooks; other families get their own list */
const IP = { ip: true, ip6: true, inet: true };
const HOOKS = [ 'prerouting', 'input', 'forward', 'output', 'postrouting' ];
/* where a packet meets the other families: netdev ingress first and egress
   last on its device; bridge hooks on a bridge port, prerouting and input
   before the IP stack, output and postrouting after it, forward for frames
   bridged from port to port (they never reach the IP hooks) */
const EDGES = {
	ingress: [ 'netdev', [ 'ingress' ] ],
	bridgeIn: [ 'bridge', [ 'prerouting', 'input' ] ],
	bridgeOut: [ 'bridge', [ 'output', 'postrouting' ] ],
	egress: [ 'netdev', [ 'egress' ] ],
	bridged: [ 'bridge', [ 'prerouting', 'forward', 'postrouting' ] ]
};

/* statements that end the rule (the last one wins); everything else
   (counter, limit, log, mangle, ct helper, notrack, flow) lets the packet
   go on to the next rule */
const NAT = { masquerade: true, snat: true, dnat: true, redirect: true };

/* what LuCI's view counts as an action (its isActionExpression); it shows
   every other statement but a counter among the rule's conditions */
const ACTIONS = [ 'accept', 'notrack', 'reject', 'drop', 'jump', 'goto', 'continue', 'snat', 'dnat',
	'redirect', 'mangle', 'masquerade', 'return', 'flow', 'ct helper', 'log' ];
function isAction(st) {
	if (typeof st === 'string') return /^flow add @\S+$/.test(st);
	return st != null && typeof st === 'object' && ACTIONS.some((k) => own(st, k));
}

function own(o, k) { return o != null && Object.prototype.hasOwnProperty.call(o, k); }
function str(v) { return typeof v === 'string' ? v : ''; }
function num(v) { return typeof v === 'number' && isFinite(v) ? v : null; }

function keyOf(family, table, name) { return family + ' ' + table + ' ' + name; }

/* a verdict object ({ accept: null }, { jump: { target } }, ...) */
function verdict(v) {
	if (v == null || typeof v !== 'object') return null;
	if (own(v, 'accept')) return { kind: 'accept' };
	if (own(v, 'drop')) return { kind: 'drop' };
	if (own(v, 'reject')) return { kind: 'reject' };
	if (own(v, 'return')) return { kind: 'return' };
	if (own(v, 'continue')) return { kind: 'continue' };
	if (own(v, 'queue')) return { kind: 'queue' };
	for (const k of [ 'jump', 'goto' ])
		if (own(v, k) && v[k] && str(v[k].target)) return { kind: k, target: v[k].target };
	return null;
}

/* a map key as text: strings and numbers; prefixes and ranges roughly */
function keyText(k) {
	if (typeof k === 'string' || typeof k === 'number') return String(k);
	if (k && typeof k === 'object') {
		if (own(k, 'prefix') && k.prefix) return str(k.prefix.addr) + '/' + String(num(k.prefix.len) != null ? k.prefix.len : '');
		if (Array.isArray(k.range)) return k.range.map(keyText).join('-');
		if (Array.isArray(k.concat)) return k.concat.map(keyText).join(' . ');
	}
	return '…';
}

return baseclass.extend({
	HOOKS: HOOKS,

	keyOf: keyOf,

	/* fw4 marks its own comments with "!fw4: " */
	comment(c) { return str(c).replace(/^!fw4:\s*/, '').trim(); },

	/* what a rule's statements finally do:
	   { kind: accept|drop|reject|return|continue|queue|jump|goto|nat|vmap|none,
	     target (jump, goto), map (vmap: [{ key, kind, target }]) } */
	ruleVerdict(expr) {
		let out = { kind: 'none' };
		(Array.isArray(expr) ? expr : []).forEach((st) => {
			if (st == null || typeof st !== 'object') return;
			const v = verdict(st);
			if (v) { out = v; return; }
			for (const k in NAT) if (own(st, k)) { out = { kind: 'nat', nat: k }; return; }
			if (own(st, 'vmap') && st.vmap && st.vmap.data && Array.isArray(st.vmap.data.set)) {
				const map = [];
				st.vmap.data.set.forEach((e) => {
					const d = Array.isArray(e) ? verdict(e[1]) : null;
					if (d) map.push({ key: keyText(e[0]), kind: d.kind, target: d.target });
				});
				out = { kind: 'vmap', map: map };
			}
		});
		return out;
	},

	/* matched packets and bytes, when the rule counts */
	counter(expr) {
		const c = (Array.isArray(expr) ? expr : []).find((st) => st && typeof st === 'object' && own(st, 'counter') && st.counter);
		return c && num(c.counter.packets) != null ? { packets: c.counter.packets, bytes: num(c.counter.bytes) || 0 } : null;
	},

	/* how LuCI's view splits the statements: { conds, acts, last }; conds:
	   statements it shows as conditions (all but counters and actions, the
	   vmap's lookup included), acts: the actions in order, last: the index
	   among them of the one that decides (-1: none does) */
	parts(expr) {
		const out = { conds: 0, acts: 0, last: -1 };
		(Array.isArray(expr) ? expr : []).forEach((st) => {
			if (st && typeof st === 'object' && own(st, 'counter')) return;
			if (st && typeof st === 'object' && own(st, 'vmap')) { out.conds++; return; }
			if (!isAction(st)) { out.conds++; return; }
			if (verdict(st) || Object.keys(NAT).some((k) => own(st, k))) out.last = out.acts;
			out.acts++;
		});
		return out;
	},

	build(json) {
		const items = json && Array.isArray(json.nftables) ? json.nftables : [];
		const tables = [], chains = Object.create(null), byTable = Object.create(null);

		items.forEach((it) => {
			const t = it && it.table;
			if (!t || !str(t.family) || !str(t.name)) return;
			const tk = t.family + ' ' + t.name;
			if (byTable[tk]) return;
			byTable[tk] = { family: t.family, name: t.name, chains: [] };
			tables.push(byTable[tk]);
		});
		items.forEach((it) => {
			const c = it && it.chain;
			if (!c || !str(c.family) || !str(c.table) || !str(c.name)) return;
			const k = keyOf(c.family, c.table, c.name);
			if (chains[k]) return;
			const base = str(c.hook) !== '';
			chains[k] = {
				key: k, family: c.family, table: c.table, name: c.name,
				type: str(c.type), hook: str(c.hook), prio: num(c.prio) || 0,
				policy: base ? (str(c.policy) || 'accept') : '', base: base,
				rules: [], callers: []
			};
			const tk = c.family + ' ' + c.table;
			if (!byTable[tk]) { byTable[tk] = { family: c.family, name: c.table, chains: [] }; tables.push(byTable[tk]); }
			byTable[tk].chains.push(k);
		});
		items.forEach((it) => {
			const r = it && it.rule;
			if (!r || !str(r.family) || !str(r.table) || !str(r.chain)) return;
			const c = chains[keyOf(r.family, r.table, r.chain)];
			if (!c) return;
			c.rules.push({
				index: c.rules.length,
				comment: this.comment(r.comment),
				verdict: this.ruleVerdict(r.expr),
				counter: this.counter(r.expr),
				parts: this.parts(r.expr)
			});
		});

		/* who jumps where: targets live in the caller's table */
		Object.keys(chains).forEach((k) => {
			const c = chains[k];
			c.rules.forEach((r) => {
				const v = r.verdict, targets = v.target ? [ v.target ] : (v.map || []).map((e) => e.target);
				targets.forEach((t) => {
					const to = t && chains[keyOf(c.family, c.table, t)];
					if (to && to.callers.indexOf(k) < 0) to.callers.push(k);
				});
			});
		});

		const byPrio = (a, b) => chains[a].prio - chains[b].prio || (chains[a].name < chains[b].name ? -1 : chains[a].name > chains[b].name ? 1 : 0);
		const at = (hook) => Object.keys(chains).filter((k) => IP[chains[k].family] && chains[k].hook === hook).sort(byPrio);
		const of = (family, hooks) => Object.keys(chains).filter((k) => chains[k].family === family && hooks.indexOf(chains[k].hook) >= 0)
			.sort((a, b) => hooks.indexOf(chains[a].hook) - hooks.indexOf(chains[b].hook) || byPrio(a, b));
		const stage = (hook, list) => ({
			hook: hook, chains: list,
			/* unmatched packets: a filter chain that drops them stops them
			   here; otherwise a rule may still drop some */
			drops: list.some((k) => chains[k].type === 'filter' && chains[k].policy === 'drop') ? 'all'
				: list.some((k) => chains[k].rules.some((r) => r.verdict.kind === 'drop' || r.verdict.kind === 'reject')) ? 'some' : 'none'
		});

		/* the IP hooks always; another family's only where it has chains,
		   but for the bridged path: frames between ports of a bridge (Wi-Fi
		   and LAN on an access point) never meet the IP hooks, and without a
		   bridge chain nothing filters them, which the chart should say */
		const stages = {};
		HOOKS.forEach((h) => { stages[h] = stage(h, at(h)); });
		Object.keys(EDGES).forEach((id) => {
			const list = of(EDGES[id][0], EDGES[id][1]);
			stages[id] = list.length || id === 'bridged' ? stage(id, list) : null;
		});

		/* the IP base chains in the order a packet meets them */
		const bases = [];
		HOOKS.forEach((h) => { at(h).forEach((k) => { bases.push(k); }); });

		/* other families (bridge, netdev, arp): their tables' base chains */
		const others = tables.filter((t) => !IP[t.family])
			.map((t) => ({ family: t.family, name: t.name, chains: t.chains.filter((k) => chains[k].base).sort(byPrio) }))
			.filter((t) => t.chains.length);

		/* regular chains no rule jumps to */
		const unused = Object.keys(chains).filter((k) => !chains[k].base && !chains[k].callers.length);

		return { tables: tables, chains: chains, stages: stages, bases: bases, others: others, unused: unused };
	}
});
