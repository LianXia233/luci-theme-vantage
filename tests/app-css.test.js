'use strict';
/* Motion rules of the dashboard stylesheet (app.css): idle animations
   run on the compositor, nothing animates layout on every poll, and the
   Live beat neither covers its dot nor shows without motion. */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const css = fs.readFileSync(path.join(__dirname, '..', 'luci-app-vantage/htdocs/luci-static/resources/vantage/app.css'), 'utf8')
	.replace(/\/\*[\s\S]*?\*\//g, '');
const rules = [ ...css.matchAll(/([^{}]+)\{([^{}]*)\}/g) ].map(m => ({ sel: m[1].trim(), body: m[2] }));
const keyframes = [ ...css.matchAll(/@keyframes\s+([\w-]+)\s*\{((?:[^{}]*\{[^{}]*\})*)\s*\}/g) ].map(m => ({ name: m[1], body: m[2] }));

test('keyframes animate transform and opacity only (compositor), never stroke-dashoffset or a box', () => {
	assert.ok(keyframes.length >= 3, 'found the keyframes');
	for (const k of keyframes)
		for (const p of [ ...k.body.matchAll(/([\w-]+)\s*:/g) ].map(m => m[1]))
			assert.ok([ 'transform', 'opacity' ].includes(p), `@keyframes ${k.name} animates ${p}`);
});

test('no width or height transition runs on every poll', () => {
	for (const r of rules) {
		const t = /(?:^|;)\s*transition\s*:([^;]*)/.exec(r.body);
		if (!t || !/\b(width|height|all)\b/.test(t[1])) continue;
		/* the memory bar animates only a visible change (.vt-seg-move, set by the view) */
		assert.match(r.sel, /\.vt-seg-move\b/, `${r.sel} transitions ${t[1].trim()}`);
	}
});

test('the Live beat: behind its dot, invisible unless it animates', () => {
	const ring = rules.find(r => r.sel === '.vt-app .vt-live-beat::after');
	assert.ok(ring);
	assert.match(ring.body, /z-index:\s*-1/);
	assert.match(ring.body, /(?:^|;|\s)opacity:\s*0\s*;/, 'transparent at rest (reduced motion stops the animation)');
	assert.match(rules.find(r => r.sel === '.vt-app .vt-livepill').body, /isolation:\s*isolate/, 'the ring stays inside the pill');
	assert.match(css, /@media \(prefers-reduced-motion: reduce\)\s*\{[^}]*animation: none !important/);
});

test('reduced motion: no moving flow dots, the static dotted wire instead', () => {
	const rm = /@media \(prefers-reduced-motion: reduce\)\s*\{([\s\S]*?)\n\}/.exec(css);
	assert.ok(rm);
	assert.match(rm[1], /\.vt-flows\s*\{\s*display:\s*none/);
	assert.match(rm[1], /\.vt-flow-on\s*\{\s*opacity:/);
});
