'use strict';
/* vantage.css rules that broke once and are easy to break again: a class
   the theme styles that the dashboard also uses (rule 7: the theme does
   not style app internals), centring that hides the start of a scrolling
   list, a breakpoint pair with a gap between them, pulse rings that cover
   their dot, hit targets under the control height, and phone table cards
   that only half apply. */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const read = p => fs.readFileSync(path.join(root, p), 'utf8');
const stripComments = css => css.replace(/\/\*[\s\S]*?\*\//g, '');
const themeCss = stripComments(read('luci-theme-vantage/htdocs/luci-static/vantage/vantage.css'));
const menuJs = read('luci-theme-vantage/htdocs/luci-static/resources/menu-vantage.js');

/* innermost rules (inside @media blocks too): { sel: [..], body, media } */
function rules(css) {
	const out = [];
	const re = /([^{}]+)\{([^{}]*)\}/g;
	let m;
	while ((m = re.exec(css))) {
		const before = css.slice(0, m.index);
		const opens = [ ...before.matchAll(/@media([^{]*)\{/g) ];
		/* the @media this rule sits in: the last one still open */
		let media = '';
		for (const o of opens) {
			const tail = css.slice(o.index + o[0].length, m.index);
			const depth = (tail.match(/\{/g) || []).length - (tail.match(/\}/g) || []).length;
			if (depth >= 0) media = o[1].trim();
		}
		out.push({ sel: m[1].trim().split(/,(?![^(]*\))/).map(s => s.trim()), body: m[2], media });
	}
	return out;
}
const themeRules = rules(themeCss);

/* every vt-* class name the app can put on an element or style: string
   tokens in its JavaScript and class selectors in app.css. A token that
   ends in "-" ('vt-band-' + band) is a prefix. Custom properties
   (--vt-*) are not classes. */
function appClasses() {
	const dir = 'luci-app-vantage/htdocs/luci-static/resources';
	const files = [];
	const walk = d => {
		for (const e of fs.readdirSync(path.join(root, d), { withFileTypes: true })) {
			const p = path.join(d, e.name);
			if (e.isDirectory()) walk(p);
			else if (/\.(js|css)$/.test(e.name)) files.push(p);
		}
	};
	walk(dir);
	const names = new Set();
	for (const f of files)
		for (const m of stripComments(read(f)).matchAll(/(?<![\w-])vt-[a-z0-9-]*/g)) names.add(m[0]);
	return names;
}

/* every vt-* class the theme's CSS styles */
function themeClasses() {
	const names = new Set();
	for (const r of themeRules)
		for (const s of r.sel)
			/* a class inside :not() is excluded, not styled */
			for (const m of s.replace(/:not\((?:[^()]|\([^()]*\))*\)/g, '').matchAll(/\.(vt-[a-z0-9-]+)/g)) names.add(m[1]);
	return names;
}

/* shared on purpose: the theme marks LuCI's technical cells .vt-num and
   the app resets it inside .vt-app (app.css, "theme numerals") */
const SHARED = new Set([ 'vt-num' ]);

test('the theme styles no class the dashboard uses (but the allowlisted one)', () => {
	const app = appClasses(), theme = themeClasses();
	assert.ok(app.size > 100 && theme.size > 40, 'found both sets');
	/* the scan sees the class that collided in 1.0.5 (the memory bar) */
	assert.ok(app.has('vt-seg'), 'the app uses vt-seg');
	const prefixes = [ ...app ].filter(n => n.endsWith('-'));
	const clash = [ ...theme ].filter(n => !SHARED.has(n) &&
		(app.has(n) || prefixes.some(p => n.startsWith(p))));
	assert.deepEqual(clash, []);
});

test('no scrolling container centres unsafely (its start would be unreachable)', () => {
	const decls = new Map();
	for (const r of themeRules)
		for (const s of r.sel) {
			const d = decls.get(s + '|' + r.media) || [];
			d.push(r.body);
			decls.set(s + '|' + r.media, d);
		}
	let scrollers = 0;
	for (const [ key, bodies ] of decls) {
		const body = bodies.join(';');
		if (!/overflow(-x)?\s*:\s*(auto|scroll)/.test(body)) continue;
		scrollers++;
		const jc = [ ...body.matchAll(/justify-content\s*:\s*([^;]+)/g) ].map(m => m[1].trim());
		for (const v of jc)
			assert.ok(!/^(center|end|flex-end|right)\b/.test(v), key + ': justify-content: ' + v + ' (use auto margins or "safe")');
	}
	assert.ok(scrollers > 5, 'found the scrollers');
	/* the bottom bar is one of them, centred with auto margins */
	const bar = themeRules.find(r => r.sel.includes('.vt-rail-list') && /max-width: 720px/.test(r.media));
	assert.match(bar.body, /overflow-x:\s*auto/);
	assert.match(themeCss, /\.vt-rail-item:first-child \{ margin-inline-start: auto; \}/);
	assert.match(themeCss, /\.vt-rail-item:last-child \{ margin-inline-end: auto; \}/);
});

test('720px: phone rules and desktop rules split without a gap, and the menu script agrees', () => {
	const queries = [ ...themeCss.matchAll(/@media([^{]+)\{/g) ].map(m => m[1].trim());
	/* (min-width: 721px) and (max-width: 720px) both miss 720.5px */
	for (const q of queries) {
		assert.doesNotMatch(q, /min-width:\s*721px/, q);
		if (/72[01]px/.test(q))
			assert.match(q, /\(max-width: 720px\)|\(width > 720px\)|\(720px < width/, q);
	}
	assert.ok(queries.some(q => /\(width > 720px\)/.test(q)), 'the desktop side uses range syntax');
	assert.match(menuJs, /this\.mqMobile = window\.matchMedia\('\(max-width: 720px\)'\);/);
});

test('pulse rings sit behind their dot and stay invisible unless animated', () => {
	const rings = themeRules.filter(r => r.sel.some(s => /::after$/.test(s)) && /animation:[^;]*infinite/.test(r.body));
	assert.ok(rings.length >= 2, 'found the poll and login rings');
	for (const r of rings) {
		/* reduced motion runs the animation once, near-instantly, and the
		   ring falls back to these base values */
		assert.match(r.body, /(^|[;\s])opacity:\s*0\s*;/, r.sel.join(','));
		assert.match(r.body, /z-index:\s*-1/, r.sel.join(','));
	}
	/* the stacking context that keeps z-index -1 above the pill and card */
	assert.match(themeCss, /\[data-indicator="poll-status"\]\[data-style="active"\] \{ position: relative; isolation: isolate; \}/);
	assert.match(themeCss, /\.vt-login-sub \{ isolation: isolate; \}/);
});

test('hit targets: tabs, the crumb switch, its links and touch top-bar buttons are a control high', () => {
	const own = sel => themeRules.filter(r => r.sel.includes(sel) && !r.media);
	const has = (sel, re) => assert.ok(own(sel).some(r => re.test(r.body)), sel + ' ' + re);
	for (const sel of [ '.cbi-tabmenu > li > a', '.vt-pagetabs > .vt-tab' ]) {
		has(sel, /min-height:\s*var\(--ctl-h\)/);
		for (const r of own(sel)) assert.doesNotMatch(r.body, /height:\s*calc\(var\(--ctl-h\)\s*-/, sel);
	}
	has('.cbi-tabmenu', /min-height:\s*var\(--ctl-h\)/);
	has('.vt-crumb-switch', /min-height:\s*var\(--ctl-h\)/);
	has('.vt-fly-link', /min-height:\s*var\(--ctl-h\)/);
	const coarse = themeRules.filter(r => /pointer: coarse/.test(r.media));
	assert.ok(coarse.some(r => r.sel.includes('.vt-icon-btn') && r.sel.includes('.vt-search') &&
		/min-width:\s*var\(--ctl-h\)/.test(r.body) && /height:\s*var\(--ctl-h\)/.test(r.body)));
	/* the page tabs have their own class, under #vt-tabs */
	assert.match(menuJs, /E\('div', \{ 'class': 'vt-pagetabs' \}\)/);
});

test('phone table cards: in pages and modals, header rows only, no fixed row height', () => {
	const phone = themeRules.filter(r => /max-width: 720px/.test(r.media));
	const cardRules = phone.filter(r => r.sel.some(s => /\.table/.test(s) && /\.(tr|td)\b|tr\b/.test(s)));
	assert.ok(cardRules.length > 8, 'found the card rules');
	for (const r of cardRules)
		for (const s of r.sel)
			if (/^\.vt-main|^\.modal|^:is\(\.vt-main/.test(s))
				assert.match(s, /^:is\(\.vt-main, \.modal\)/, 'scoped to pages and modals: ' + s);
	/* LuCI also puts .cbi-section-table-titles on each row's name cell */
	const hide = phone.find(r => /display:\s*none !important/.test(r.body) && r.sel.some(s => /cbi-section-table-titles/.test(s)));
	assert.ok(hide, 'found the header rule');
	for (const s of hide.sel) assert.match(s, /:is\(tr, \.tr\)/, 'rows only: ' + s);
	const cell = phone.find(r => r.sel.includes(':is(.vt-main, .modal) .table .tr > .td'));
	assert.match(cell.body, /height:\s*auto/);
});

test('firewall: verdicts and policies are coloured by their raw value, off rules dim, match styling stays on firewall pages', () => {
	const body = (pred) => themeRules.filter((r) => r.sel.some(pred)).map((r) => r.body).join(';');
	/* LuCI puts the untranslated target in data-tooltip; colour must not depend on the label */
	assert.match(body((s) => /var\[data-tooltip="ACCEPT"\]/.test(s)), /--ok/);
	assert.match(body((s) => /\[data-tooltip="REJECT"\]/.test(s) && /\[data-tooltip="DROP"\]/.test(s) && !/ACCEPT/.test(s)), /--err/);
	assert.match(body((s) => /\[data-tooltip="DNAT"\]/.test(s) && !/ACCEPT/.test(s)), /--info/);
	/* policies: by the selected option's value, live */
	assert.match(body((s) => /select\[id\^="widget\.cbid\.firewall\."\]:has\(> option:checked:is\(\[value="REJECT"\], \[value="DROP"\]\)\)/.test(s)), /--err/);
	assert.match(body((s) => /select\[id\^="widget\.cbid\.firewall\."\]:has\(> option:checked\[value="ACCEPT"\]\)/.test(s)), /--ok/);
	/* a rule unticked looks off, but its switch and buttons stay as they are */
	const off = themeRules.find((r) => r.sel.some((s) => /enabled"\]:not\(:checked\)\) > \.td:not\(\.cbi-section-actions\):not\(:has/.test(s)));
	assert.ok(off && /color:\s*var\(--text-3\)/.test(off.body));
	assert.ok(off.sel.every((s) => /:not\(\.cbi-section-actions\)/.test(s) && /:not\(:has\(input\[data-widget-id\$="\.enabled"\]\)\)/.test(s)));
	/* accept is the risk on the masquerading (internet-facing) zone: input accept and its forwardings warn */
	const risk = themeRules.filter((r) => r.sel.some((s) => /input\[data-widget-id\$="\.masq"\]:checked/.test(s)));
	assert.ok(risk.some((r) => r.sel.some((s) => /data-name="input"\] select:has\(> option:checked\[value="ACCEPT"\]\)/.test(s)) && /--warn/.test(r.body)));
	assert.ok(risk.some((r) => r.sel.some((s) => /\.zone-dest > \.zonebadge:not\(\.zonebadge-empty\)/.test(s)) && /--warn/.test(r.body)));
	/* the muted first line of a match only on firewall pages: other tables use <small><br> too */
	for (const r of themeRules)
		for (const s of r.sel)
			if (/small:has\(> br\)/.test(s)) assert.match(s, /\[id\^="cbi-firewall-"\]/, s);
});

test('tooltips are not clipped by the box that holds them (issue #26: Status -> Port status)', () => {
	/* a box with overflow: hidden cut LuCI's port tooltip ("Part of networks:") off */
	const free = themeRules.find((r) => r.sel.some((s) => s === '.ifacebox:has(.cbi-tooltip-container)'));
	assert.ok(free && /overflow:\s*visible/.test(free.body));
	/* sized to the text, not to the 100 px port box */
	const tip = themeRules.find((r) => r.sel.includes('.cbi-tooltip-container > .cbi-tooltip'));
	assert.match(tip.body, /width:\s*max-content/);
	/* the script's nudge back on screen is applied where the tooltip shows */
	const shown = themeRules.find((r) => r.sel.includes('.cbi-tooltip-container:hover > .cbi-tooltip'));
	assert.match(shown.body, /translate:\s*var\(--vt-tip-dx/);
	assert.match(menuJs, /setupTooltips\(\)\s*\{/);
});

test('row menus: a busy ⋯ swaps its dots for the spinner and stays clickable; a menu too tall for the room scrolls', () => {
	const own = (sel) => themeRules.filter((r) => r.sel.includes(sel) && !r.media).map((r) => r.body).join(';');
	/* .cbi-button.spinning has pointer-events: none: ⋯ must outweigh it */
	assert.match(own('.td.cbi-section-actions .vt-acts-more.spinning'), /pointer-events:\s*auto/);
	assert.match(own('.vt-acts-more.spinning svg'), /display:\s*none/);
	assert.match(own('.vt-actmenu'), /overflow-y:\s*auto/);
	assert.match(menuJs, /menu\.style\.maxHeight = /);
});

/* light and dark token blocks, var() references resolved */
function tokens(block) {
	const m = new RegExp(block.replace(/[[\]"]/g, '\\$&') + ' \\{([^}]*)\\}').exec(themeCss);
	const t = {};
	for (const d of m[1].matchAll(/(--[\w-]+):\s*([^;]+);/g)) t[d[1]] = d[2].trim();
	return t;
}
const light = tokens(':root'), dark = Object.assign({}, light, tokens('html[data-darkmode="true"]'));
function rgba(t, v) {
	for (let i = 0; i < 5; i++) { const m = /^var\((--[\w-]+)\)$/.exec(v); if (!m) break; v = t[m[1]]; }
	let m = /^#([0-9a-f]{6})$/i.exec(v);
	if (m) return [ 0, 2, 4 ].map((i) => parseInt(m[1].slice(i, i + 2), 16)).concat(1);
	m = /^rgba\((\d+),\s*(\d+),\s*(\d+),\s*([\d.]+)\)$/.exec(v);
	assert.ok(m, 'colour ' + v);
	return [ +m[1], +m[2], +m[3], +m[4] ];
}
const over = (f, b) => [ 0, 1, 2 ].map((i) => f[i] * f[3] + b[i] * (1 - f[3])).concat(1);
const lum = (c) => c.slice(0, 3).map((v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); })
	.reduce((a, v, i) => a + v * [ 0.2126, 0.7152, 0.0722 ][i], 0);
const ratio = (a, b) => { const x = lum(a), y = lum(b); return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05); };

test('firewall colours keep 4.5:1 on a hovered row, light and dark (badges, the amber input policy)', () => {
	const body = (pred) => themeRules.filter((r) => r.sel.some(pred)).map((r) => r.body).join(';');
	assert.match(body((s) => /\[data-tooltip="REJECT"\]/.test(s) && /\[data-tooltip="DROP"\]/.test(s) && !/ACCEPT/.test(s)), /color:\s*var\(--err-text\)/);
	assert.match(body((s) => /\[data-tooltip="DNAT"\]/.test(s) && !/ACCEPT/.test(s)), /color:\s*var\(--info-text\)/);
	assert.match(body((s) => /\.td\[data-name="input"\] select:has/.test(s)), /color:\s*var\(--warn-text\)/);
	/* the row hover: --s3 at 55% over the card (--s1), as in the .tr:hover rule */
	assert.match(themeCss, /:hover > \.td \{ background: color-mix\(in srgb, var\(--s3\) 55%, transparent\); \}/);
	for (const [ scheme, t ] of [ [ 'light', light ], [ 'dark', dark ] ]) {
		const card = rgba(t, 'var(--s1)');
		const hover = over(rgba(t, 'var(--s3)').slice(0, 3).concat(0.55), card);
		for (const [ fg, bg ] of [ [ '--err-text', '--err-soft' ], [ '--info-text', '--info-soft' ], [ '--warn-text', '--warn-soft' ], [ '--ok-text', '--ok-soft' ] ])
			for (const [ where, under ] of [ [ 'at rest', card ], [ 'hovered', hover ] ]) {
				const r = ratio(over(rgba(t, 'var(' + fg + ')'), over(rgba(t, 'var(' + bg + ')'), under)), over(rgba(t, 'var(' + bg + ')'), under));
				assert.ok(r >= 4.5, scheme + ' ' + fg + ' on ' + bg + ' ' + where + ': ' + r.toFixed(2));
			}
	}
});

test('switched-off rules are greyed, not faded: the name and match keep 4.5:1', () => {
	assert.doesNotMatch(themeRules.filter((r) => r.sel.some((s) => /enabled"\]:not\(:checked\)/.test(s))).map((r) => r.body).join(';'), /opacity/);
	const badges = themeRules.find((r) => r.sel.some((s) => /enabled"\]:not\(:checked\)/.test(s) && /var\[data-tooltip\], \.zonebadge/.test(s)));
	assert.match(badges.body, /filter:\s*grayscale\(1\)/);
	for (const t of [ light, dark ]) assert.ok(ratio(rgba(t, 'var(--text-3)'), rgba(t, 'var(--s1)')) >= 4.5);
});
