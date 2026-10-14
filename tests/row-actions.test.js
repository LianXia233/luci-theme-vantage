'use strict';
/* Row action menus (menu-vantage.js decorateRowActions): a row with three
   or more actions keeps its main one and a ⋯ button; LuCI's other buttons
   stay in place, hidden, and a menu item clicks the original, so LuCI's
   handler, label and disabled state are the ones that count. Run against
   a fake DOM just big enough for these calls. */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
require('./luci-stub');      /* String.prototype.format */

const SRC = fs.readFileSync(path.join(__dirname, '..', 'luci-theme-vantage/htdocs/luci-static/resources/menu-vantage.js'), 'utf8');

/* "button, .a, input[type="button"]" with optional :not-free simple parts */
function matches(el, list) {
	return list.split(',').some(sel => {
		const m = /^([a-z]+)?((?:\.[\w-]+)*)(?:\[(\w+)="([^"]*)"\])?$/i.exec(sel.trim());
		if (!m) throw new Error('fake DOM: unsupported selector ' + sel);
		if (m[1] && el.tagName !== m[1].toUpperCase()) return false;
		for (const c of (m[2].match(/\.[\w-]+/g) || [])) if (!el.cls.has(c.slice(1))) return false;
		if (m[3] && el.attrs[m[3]] !== m[4]) return false;
		return true;
	});
}

class El {
	constructor(tag, attrs, kids) {
		this.tagName = tag.toUpperCase();
		this.attrs = {}; this.cls = new Set(); this.children = []; this.parentNode = null;
		this.listeners = {}; this.hidden = false; this.disabled = false; this.style = {}; this.clicks = 0;
		this.classList = {
			add: (...c) => c.forEach(x => this.cls.add(x)),
			remove: (...c) => c.forEach(x => this.cls.delete(x)),
			contains: c => this.cls.has(c),
			toggle: (c, on) => { (on === undefined ? !this.cls.has(c) : on) ? this.cls.add(c) : this.cls.delete(c); return this.cls.has(c); }
		};
		for (const [ k, v ] of Object.entries(attrs || {})) {
			if (typeof v === 'function') this.addEventListener(k, v);
			else if (v != null) this.setAttribute(k, v);
		}
		for (const c of [].concat(kids == null ? [] : kids)) this.appendChild(typeof c === 'object' ? c : { nodeType: 3, text: String(c) });
	}
	setAttribute(k, v) {
		if (k === 'class') String(v).split(/\s+/).filter(Boolean).forEach(c => this.cls.add(c));
		else if (k === 'hidden') this.hidden = true;
		else if (k === 'disabled') this.disabled = true;
		else this.attrs[k] = String(v);
	}
	getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
	appendChild(c) { if (c.parentNode) c.parentNode.children.splice(c.parentNode.children.indexOf(c), 1); c.parentNode = this; this.children.push(c); return c; }
	remove() { if (this.parentNode) this.parentNode.children.splice(this.parentNode.children.indexOf(this), 1); this.parentNode = null; }
	set textContent(v) { this.children = []; if (v) this.appendChild({ nodeType: 3, text: v }); }
	get textContent() { return this.children.map(c => c.nodeType === 3 ? c.text : c.textContent).join(''); }
	matches(sel) { return matches(this, sel); }
	closest(sel) { for (let n = this; n && n.tagName; n = n.parentNode) if (matches(n, sel)) return n; return null; }
	contains(n) { for (; n; n = n.parentNode) if (n === this) return true; return false; }
	walk(out) { for (const c of this.children) if (c.tagName) { out.push(c); c.walk(out); } return out; }
	querySelectorAll(sel) {
		const scope = /^:scope > (.+)$/.exec(sel);
		if (scope) return this.children.filter(c => c.tagName && matches(c, scope[1]));
		return this.walk([]).filter(n => matches(n, sel));
	}
	querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
	addEventListener(t, fn) { (this.listeners[t] = this.listeners[t] || []).push(fn); }
	dispatch(t, ev) { ev = Object.assign({ type: t, target: this, preventDefault() {}, stopPropagation() {} }, ev); (this.listeners[t] || []).forEach(fn => fn(ev)); }
	click() { this.clicks++; this.dispatch('click', { detail: 1 }); }
	focus() { doc.activeElement = this; }
	get isConnected() { for (let n = this; n; n = n.parentNode) if (n === doc.body) return true; return false; }
	getBoundingClientRect() { return { left: 1100, right: 1140, top: 300, bottom: 336 }; }
	get offsetWidth() { return 168; }
	get offsetHeight() { return 96; }
}

const doc = { activeElement: null, listeners: {}, createElementNS: (ns, tag) => new El(tag), addEventListener(t, fn) { (this.listeners[t] = this.listeners[t] || []).push(fn); } };

function setup(rows) {
	doc.body = new El('body');
	doc.querySelectorAll = sel => {
		if (sel === '.cbi-section-actions > div') return doc.body.walk([]).filter(n => n.parentNode && n.parentNode.cls.has('cbi-section-actions') && n.tagName === 'DIV');
		return doc.body.querySelectorAll(sel);
	};
	doc.querySelector = sel => doc.querySelectorAll(sel)[0] || null;
	const window = { innerWidth: 1280, innerHeight: 900, addEventListener() {}, matchMedia: () => ({ matches: false, addEventListener() {} }) };
	const E = (tag, attrs, kids) => new El(tag, attrs, kids);
	const proto = new Function('baseclass', 'ui', 'rpc', 'host', 'E', 'L', '_', 'document', 'window', SRC)(
		{ extend: p => p }, {}, { declare: () => () => Promise.resolve({}) }, {}, E, {}, s => s, doc, window);
	const shell = Object.assign(Object.create(proto), { mqMobile: window.matchMedia() });
	const boxes = rows.map(btns => {
		const box = new El('div', {}, btns);
		doc.body.appendChild(new El('div', { 'class': 'tr' }, [ new El('div', { 'class': 'td cbi-section-actions' }, [ box ]) ]));
		return box;
	});
	shell.decorateRowActions();
	return { shell, boxes };
}
const btn = (cls, label) => new El('button', { 'class': 'cbi-button ' + cls }, [ label ]);
const shown = box => box.children.filter(c => !c.cls.has('vt-acts-hidden')).map(c => c.cls.has('vt-acts-more') ? '⋯' : c.textContent);

test('row actions: three or more keep the main one and a ⋯; fewer stay as they are', () => {
	const { boxes } = setup([
		[ btn('cbi-button-neutral', 'Restart'), btn('cbi-button-action important', 'Scan'), btn('cbi-button-add', 'Add') ],
		[ btn('drag-handle', '☰'), btn('cbi-button-edit', 'Edit'), btn('cbi-button-neutral', 'Clone'), btn('cbi-button-remove', 'Delete') ],
		[ btn('cbi-button-edit', 'Edit'), btn('cbi-button-remove', 'Delete') ]
	]);
	assert.deepEqual(shown(boxes[0]), [ 'Scan', '⋯' ], 'the "important" action stays');
	assert.deepEqual(shown(boxes[1]), [ '☰', 'Edit', '⋯' ], 'Edit stays, and so does the drag handle');
	assert.deepEqual(shown(boxes[2]), [ 'Edit', 'Delete' ], 'two actions need no menu');
	assert.equal(boxes[0].children.length, 4, "LuCI's buttons are kept, in their place, plus the ⋯");
	assert.equal(boxes[0].children[0].textContent, 'Restart');
});

test('row actions: a second pass changes nothing; a button LuCI hides is not counted', () => {
	const hiddenByLuci = btn('cbi-button-neutral', 'Stop');
	hiddenByLuci.style.display = 'none';
	const { shell, boxes } = setup([
		[ btn('cbi-button-neutral', 'Restart'), btn('cbi-button-edit', 'Edit'), btn('cbi-button-remove', 'Delete') ],
		[ btn('cbi-button-neutral', 'Restart'), hiddenByLuci, btn('cbi-button-edit', 'Edit') ]
	]);
	shell.decorateRowActions();
	assert.equal(boxes[0].children.filter(c => c.cls.has('vt-acts-more')).length, 1, 'one ⋯ only');
	assert.deepEqual(shown(boxes[1]), [ 'Restart', 'Stop', 'Edit' ], 'two visible actions: untouched');
});

test('row actions: the menu lists the hidden ones; an item clicks the original, with its label and state', () => {
	const disable = btn('cbi-button-neutral enable-disable', 'Disable');
	const remove = btn('cbi-button-negative remove', 'Remove');
	remove.setAttribute('disabled', '');
	const { boxes } = setup([ [ disable, btn('cbi-button-action important', 'Edit'), remove ] ]);
	const more = boxes[0].children.find(c => c.cls.has('vt-acts-more'));
	assert.equal(more.getAttribute('aria-haspopup'), 'menu');
	assert.equal(more.getAttribute('aria-label'), 'More actions');

	disable.textContent = 'Enable';     /* LuCI relabels its button; the menu reads it when it opens */
	more.click();
	const menu = doc.body.children.find(c => c.attrs.id === 'vt-actmenu');
	assert.ok(menu && !menu.hidden);
	assert.equal(more.getAttribute('aria-expanded'), 'true');
	const items = menu.children;
	assert.deepEqual(items.map(i => i.textContent), [ 'Enable', 'Remove' ]);
	assert.equal(items[0].getAttribute('role'), 'menuitem');
	assert.ok(items[1].cls.has('is-danger'), 'Remove reads as dangerous');
	assert.ok(items[1].disabled, "LuCI's disabled state carries over");

	items[0].click();
	assert.equal(disable.clicks, 1, 'the original button got the click');
	assert.ok(menu.hidden);
	assert.equal(more.getAttribute('aria-expanded'), 'false');
	assert.equal(doc.activeElement, more, 'focus goes back to ⋯');
});

test('row actions: keys open the menu at either end, walk it, and Escape returns to ⋯', () => {
	const { boxes } = setup([ [ btn('a', 'Restart'), btn('cbi-button-edit', 'Edit'), btn('b', 'Stop'), btn('cbi-button-remove', 'Delete') ] ]);
	const more = boxes[0].children.find(c => c.cls.has('vt-acts-more'));
	const menu = () => doc.body.children.find(c => c.attrs.id === 'vt-actmenu');
	more.dispatch('keydown', { key: 'ArrowUp' });
	assert.equal(doc.activeElement.textContent, 'Delete', 'ArrowUp starts at the last item');
	menu().dispatch('keydown', { key: 'ArrowDown' });
	assert.equal(doc.activeElement.textContent, 'Restart', 'and wraps around');
	menu().dispatch('keydown', { key: 'End' });
	assert.equal(doc.activeElement.textContent, 'Delete');
	menu().dispatch('keydown', { key: 'Escape' });
	assert.ok(menu().hidden);
	assert.equal(doc.activeElement, more);
});
