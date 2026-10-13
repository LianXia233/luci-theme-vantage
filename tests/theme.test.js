'use strict';
/* menu-vantage.js pieces that decide what reaches the DOM: the SVG helper's
   closed tag/attribute sets, Channel Analysis ownership (by BSSID, never by
   SSID text, which a neighbour controls), and the form chrome (which
   headings count as repeats, where the help button goes). */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const FILE = path.join(__dirname, '..', 'luci-theme-vantage/htdocs/luci-static/resources/menu-vantage.js');
const src = fs.readFileSync(FILE, 'utf8');

/* svgNode/svgAttr/svgEl and the ICONS table, evaluated with a recording document */
function svgKit() {
	const start = src.indexOf('function svgNode(');
	const end = src.indexOf('function svg(name, size)');
	assert.ok(start > 0 && end > start, 'found the SVG helpers');
	const icons = /\nconst ICONS = (\{[\s\S]*?\n\});\n/.exec(src);
	assert.ok(icons, 'found the ICONS table');
	const made = [];
	const document = {
		createElementNS: (ns, tag) => {
			const el = { tag, attrs: {}, setAttribute(k, v) { this.attrs[k] = v; } };
			made.push(el);
			return el;
		}
	};
	const kit = new Function('document', 'SVGNS', src.slice(start, end) + '\nreturn { svgEl, ICONS: ' + icons[1] + ' };')(document, 'http://www.w3.org/2000/svg');
	return Object.assign(kit, { made });
}

test('svgEl: builds every icon; any other tag or attribute throws', () => {
	const { svgEl, ICONS, made } = svgKit();
	for (const parts of Object.values(ICONS)) for (const [ tag, attrs ] of parts) svgEl(tag, attrs);
	svgEl('svg', { 'viewBox': '0 0 24 24', 'width': 20, 'height': 20, 'aria-hidden': 'true', 'focusable': 'false' });
	svgEl('linearGradient', { 'id': 'v-grad-1', 'class': 'v-grad', 'x1': '0', 'y1': '0', 'x2': '0', 'y2': '1' });
	svgEl('stop', { 'offset': '0', 'class': 'v-stop-top' });
	assert.ok(made.length > 30);
	assert.equal(made.find(e => e.tag === 'svg').attrs.width, '20', 'values are strings');
	for (const tag of [ 'script', 'a', 'foreignObject', 'animate', 'set', 'image', 'use', 'style', 'SVG', 'iframe' ])
		assert.throws(() => svgEl(tag, {}), /tag not allowed/, tag);
	for (const k of [ 'href', 'xlink:href', 'onclick', 'onload', 'style', 'attributeName', 'to', 'values', 'begin', '__proto__' ])
		assert.throws(() => svgEl('path', { [k]: 'x' }), /attribute not allowed/, k);
});

test('repeated headings: case, spacing and a trailing colon do not count', () => {
	const start = src.indexOf('function headingKey(');
	assert.ok(start > 0, 'found headingKey');
	const end = src.indexOf('\n}\n', start) + 3;
	const headingKey = new Function(src.slice(start, end) + '\nreturn headingKey;')();
	assert.equal(headingKey('Router Password'), headingKey('router password'));
	assert.equal(headingKey('  General\n Settings: '), 'general settings');
	assert.equal(headingKey('Interfaces'), headingKey('Interfaces'));
	assert.notEqual(headingKey('System'), headingKey('System Properties'));
	assert.notEqual(headingKey('Firewall - Zone Settings'), headingKey('General Settings'));
	assert.equal(headingKey(null), '');
});

test('repeated headings: a card heading never counts as a repeat of the category', () => {
	const start = src.indexOf('function repeatsTrail(');
	assert.ok(start > 0, 'found repeatsTrail');
	const end = src.indexOf('\n}\n', start) + 3;
	const repeatsTrail = new Function(src.slice(start, end) + '\nreturn repeatsTrail;')();
	/* Services > Dynamic DNS: the page title repeats the page crumb, the
	   "Services" table heading only matches the category and is content */
	const ddns = { all: new Set([ 'services', 'dynamic dns' ]), page: new Set([ 'dynamic dns' ]) };
	assert.equal(repeatsTrail('dynamic dns', 'H2', ddns), true);
	assert.equal(repeatsTrail('services', 'H3', ddns), false);
	/* a page title may repeat the category (Status > Overview prints "Status") */
	assert.equal(repeatsTrail('services', 'H2', ddns), true);
	assert.equal(repeatsTrail('', 'H2', ddns), false);
	/* the trail: the category goes only to `all`, unless it is the page */
	assert.match(src, /this\.trail\.all\.add\(headingKey\(p\.title\)\);\n\t\t\t\/\*[^*]*\*\/\n\t\t\tif \(i \|\| parts\.length === 1\) this\.trail\.page\.add\(headingKey\(p\.title\)\);/);
	assert.match(src, /let repeat = repeatsTrail\(key, h\.tagName, this\.trail\);/);
});

test('form chrome: never stands between LuCI nodes, never changes their text', () => {
	const part = (from, to) => {
		const start = src.indexOf(from), end = src.indexOf(to, start);
		assert.ok(start > 0 && end > start, 'found ' + from.trim());
		return src.slice(start, end);
	};
	const field = part('\taddFieldHelp(desc) {', '\taddIntroHelp(desc) {');
	const intro = part('\taddIntroHelp(desc) {', '\thelpToggle(desc, holder, label, title) {');
	const toggle = part('\thelpToggle(desc, holder, label, title) {', '\tfitHelp(desc) {');
	const placing = /insertBefore|insertAdjacent|appendChild|\.before\(|\.after\(|\.prepend\(|\.append\(/g;
	/* field help goes after the field: LuCI's label click finds its widget
	   through nextElementSibling */
	assert.deepEqual(field.match(placing), [ 'appendChild' ]);
	assert.match(field, /row\.appendChild\(this\.helpToggle\(/);
	/* intro help goes inside the description, never beside it: ui.tabs finds
	   a tab menu as its pane group's previous sibling */
	assert.deepEqual(intro.match(placing), [ 'insertBefore' ]);
	assert.match(intro, /desc\.insertBefore\(this\.helpToggle\(.*\), desc\.firstChild\);/);
	assert.equal(toggle.match(placing), null);
	/* descriptions keep their text; folding is an attribute plus CSS */
	for (const body of [ field, intro, toggle ])
		assert.doesNotMatch(body, /textContent\s*=|innerHTML|\.remove\(\)|replaceChildren/);
	/* a heading that holds a control (Overview's Hide/Show label) is never hidden */
	const repeats = src.slice(src.indexOf('\tmarkRepeats() {'));
	assert.match(repeats, /h\.querySelector\('a, button, input, select, \[data-clickable\], \[tabindex\]'\)\) return;/);
});

test('channel analysis: a row or hump is ours by BSSID only', () => {
	assert.doesNotMatch(src, /Local Interface'/, 'no SSID-text match (a neighbour can broadcast that SSID)');
	assert.match(src, /const mine = own\.has\(bssid\);/);
	assert.match(src, /const mine = mineByColour\.has\(colour\);/);
	/* own BSSIDs come from this device's interfaces */
	assert.match(src, /\[ i\.iwinfo && i\.iwinfo\.bssid, i\.config && i\.config\.macaddr \]/);
	/* the view's own row has no colour dot: its colour is rebuilt with the
	   view's derive_color from the BSSID as printed, not upper-cased */
	assert.match(src, /L\.require\('tools\.prng'\)/);
	assert.match(src, /if \(mine && colourOf\) \{\s*const derived = hexRgb\(colourOf\(printed\)\);/);
});

test('channel analysis: a derived colour reads back like element.style', () => {
	const start = src.indexOf('function hexRgb(');
	assert.ok(start > 0, 'found hexRgb');
	const end = src.indexOf('\n}\n', start) + 3;
	const hexRgb = new Function(src.slice(start, end) + '\nreturn hexRgb;')();
	assert.equal(hexRgb('#89cdb4'), 'rgb(137, 205, 180)');
	assert.equal(hexRgb('#FFFFFF'), 'rgb(255, 255, 255)');
	for (const bad of [ '#fff', 'red', '', null, undefined, '#89cdb4 ', 'rgb(1, 2, 3)' ])
		assert.equal(hexRgb(bad), null, String(bad));
});
