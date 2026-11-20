// Unit tests for applyFacts: Google (SB / Web Risk) and public threat lists merge into the verdict.
const R = require('../public/registry.js'); const createEngine = require('../public/engine.js');
const T = (a, b) => b;           // English strings
const E = createEngine(T, () => 1, R);
let bad = 0;
const ok = (c, m) => { if (!c) { bad++; console.log('FAIL', m); } };
const base = E.analyzeUrl('https://example-shop-x.com/deal');
const mk = f => E.applyFacts(base, [f]);
let r = mk({ d: 'x.com', age: 2000, sb: 'clean', wr: 'clean', fd: [] });
ok(r.score === base.score, 'clean keeps score');
ok(r.evidence.some(e => e.id === 'lists' && e.st === 'ok'), 'lists ok row');
r = mk({ d: 'x.com', age: 2000, sb: null, wr: 'threat', fd: [] });
ok(r.score >= 92 && r.flags[0].rule === 'sb', 'web risk threat -> >=92');
r = mk({ d: 'x.com', age: 2000, sb: 'clean', wr: null, fd: ['OpenPhish'] });
ok(r.score >= 90 && r.evidence.some(e => e.id === 'lists' && e.st === 'bad'), 'feed hit -> >=90');
r = mk({ d: 'x.com', age: 2000, sb: 'threat', wr: 'threat', fd: ['URLhaus'] });
ok(r.score >= 92 && r.flags.filter(f => f.rule === 'sb').length === 1, 'single flag when several sources agree');
r = mk({ d: 'x.com', age: 2000, sb: null, wr: null, fd: null });
ok(!r.evidence.some(e => e.id === 'lists'), 'no lists row when lists not loaded');
// applyAi: the model alone cannot call a message a scam without evidence we can verify
const aiHi = { score: 75, verdict: 'Likely scam', explanation: 'x' };
const sms = "Dear Khaldon, kindly complete your details using the link below to continue with the service: https://s.auctions.ae/khNvSIzLd9CtUi5Y5uWZMjASt The link will stay active for 15 minutes. Call 600500372.";
let m = E.analyzeMsg(sms); ok(m.score < 25 && m.verified, 'Emirates Auction SMS verified official');
m = E.applyAi(m, aiHi); ok(m.score < 25, 'AI 75 does not override verified official link: ' + m.score);
let u = E.analyzeMsg('Your parcel is on hold. Pay AED 5 at https://post-fee.top/x now'); u = E.applyAi(u, { score: 90, verdict: 'Likely scam' });
ok(u.score >= 62, 'real scam with hard evidence stays scam: ' + u.score);
let g = E.analyzeMsg('Hi, your order is ready for pickup tomorrow at the branch. Please bring your ID.'); const g0 = g.score; g = E.applyAi(g, aiHi);
ok(g.score <= 55 && g.score >= 40 && !E.hardEvidence(E.analyzeMsg('Hi, your order is ready for pickup tomorrow at the branch. Please bring your ID.')), 'AI alone with no evidence is capped at suspicious: ' + g.score);
// community lists are weaker than OpenPhish/URLhaus
{
  const base = E.analyzeMsg('Your parcel is waiting. Track it: https://parcel-x7.top/t');
  let w = E.applyFacts(base, [{ d: 'parcel-x7.top', age: 20, sb: 'clean', wr: 'clean', fd: ['PhishDestroy'] }]);
  ok(w.score >= 62, 'community-list hit on a new domain is scam-level: ' + w.score);
  const old = E.analyzeMsg('See our offers: https://oldshop-example.com/o');
  w = E.applyFacts(old, [{ d: 'oldshop-example.com', age: 4000, sb: 'clean', wr: 'clean', fd: ['Scam-Blocklist'] }]);
  ok(w.score < 55, 'old Google-clean domain is not condemned by a community list alone: ' + w.score);
  w = E.applyFacts(old, [{ d: 'oldshop-example.com', age: 4000, sb: 'clean', wr: 'clean', fd: ['OpenPhish'] }]);
  ok(w.score >= 90, 'OpenPhish hit stays decisive: ' + w.score);
}
// applyOpen: what really happens when the link is opened
{
  const msg = 'Your parcel is waiting. Track it: https://bit.ly/3xYz12';
  let r = E.analyzeMsg(msg); const before = r.score;
  let o = E.applyOpen(r, { ok: true, hops: [{ host: 'bit.ly', status: 301 }, { host: 'www.emiratesauction.com', status: 200 }], host: 'www.emiratesauction.com', url: 'https://www.emiratesauction.com/', status: 200, title: 'Emirates Auction', pw: false, sens: false });
  ok(o.score <= 18 && o.verified, 'shortener that opens on an official domain becomes safe: ' + before + ' -> ' + o.score);
  r = E.analyzeMsg(msg);
  o = E.applyOpen(r, { ok: true, hops: [{ host: 'bit.ly', status: 301 }, { host: 'secure-pay-x.top', status: 200 }], host: 'secure-pay-x.top', url: 'https://secure-pay-x.top/p', status: 200, title: 'Emirates NBD Login', pw: true, sens: true });
  ok(o.score >= 70, 'opened page that asks a password and impersonates a bank is scam: ' + o.score);
  r = E.analyzeMsg(msg); o = E.applyOpen(r, { ok: true, hops: [{ host: 'bit.ly', status: 200 }], host: 'bit.ly', url: 'https://bit.ly/3xYz12', status: 200, title: 'Welcome', pw: false, sens: false });
  ok(o.score === r.score, 'plain page without login form does not change the score');
  o = E.applyOpen(r, null); ok(o.score === r.score && o.evidence.some(e => e.id === 'open'), 'unreachable link leaves verdict unchanged');
  const sc = E.analyzeMsg('Pay AED 5 fee now: https://bit.ly/3xYz12 and send OTP'); const o2 = E.applyOpen(sc, { ok: true, hops: [], host: 'www.emiratesauction.com', url: 'https://www.emiratesauction.com/', status: 200, title: '', pw: false, sens: false });
  ok(o2.score > 25, 'official redirect does not whitewash a message that asks OTP/payment: ' + o2.score);
}
console.log(bad ? 'FACTS FAIL' : 'FACTS PASS');
process.exit(bad ? 1 : 0);
