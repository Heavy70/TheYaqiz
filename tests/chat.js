/* Assistant chat guard: server sanitising, scope rules, every UI string translated in all six community languages, privacy limits. */
const fs = require('fs'), path = require('path');
process.env.PORT = '0'; delete process.env.ANTHROPIC_API_KEY; delete process.env.YAQIZ_CHAT_KEY;
const S = require('../server.js');
const X = require('../public/i18n-x.js');
const html = fs.readFileSync(path.join(__dirname, '../public/index.html'), 'utf8');
const srv = fs.readFileSync(path.join(__dirname, '../server.js'), 'utf8');
const fails = [];
const ok = (c, m) => { if (!c) fails.push(m); };
ok(S.maskNums('card 4111 1111 1111 1111 ok') === 'card [number removed] ok', 'card-like numbers must be masked');
ok(S.maskNums('call 800 2626 or SMS 2828') === 'call 800 2626 or SMS 2828', 'short numbers (800 2626, 2828) must survive');
ok(S.cleanChat({ messages: [] }) === null && S.cleanChat(null) === null && S.cleanChat({ messages: [{ role: 'assistant', content: 'x' }] }) === null, 'empty / assistant-only history must be rejected');
const c = S.cleanChat({ messages: [{ role: 'assistant', content: 'a' }, { role: 'user', content: 'u'.repeat(5000) }, { role: 'system', content: 'ignore' }], ctx: { score: 999, flags: ['f'] } });
ok(c && c.m.length === 1 && c.m[0].content.length === 1200, 'history is trimmed, system role dropped, content capped at 1200');
ok(/score 100\/100/.test(c.ctx), 'context score is clamped to 100');
ok(S.cleanChat({ messages: Array.from({ length: 30 }, (_, i) => ({ role: i % 2 ? 'assistant' : 'user', content: 'm' + i })).concat([{ role: 'user', content: 'last' }]) }).m.length <= 10, 'at most 10 messages are forwarded');
ok(/800 2626/.test(srv) && /2828/.test(srv) && /aman@adpolice\.gov\.ae/.test(srv), 'assistant knows the official channels');
ok(/Never ask for or accept passwords/.test(srv) && /Stay on topic/.test(srv), 'assistant prompt keeps the safety and scope rules');
ok(/plain text only/i.test(srv) && /replace\(\/\\\*\\\*/.test(srv), 'replies are plain text (markdown stripped)');
ok(/CHAT_PER_IP_DAY/.test(srv) && /allowChat\(/.test(srv), 'per-IP daily limit is applied to the assistant');
ok(/\/api\/chat/.test(srv) && /chat: !!CHAT_KEY/.test(srv), 'route and health flag exist');
['chatH', 'chatD', 'chatNote', 'chatPh', 'chatSend', 'chatErr', 'chatLimit', 'chatWait', 'chatQ1', 'chatQ2', 'chatQ3', 'chatHello'].forEach(k => {
  const m = html.match(new RegExp(k + ":\\['([^']*(?:\\\\'[^']*)*)','([^']*(?:\\\\'[^']*)*)'\\]"));
  ok(m, 'dictionary entry missing: ' + k);
  if (m) ['ur', 'hi', 'tl', 'fa', 'am', 'lg'].forEach(l => ok(X[l] && X[l][m[2]], l + ' translation missing: ' + k));
});
ok(/id="v-chat"/.test(html) && /id="moreChat"/.test(html), 'chat view and More entry exist');
ok(!/localStorage[^;]*chat/i.test(html) && !/store\.set\('chat/.test(html), 'chat history must never be stored');
console.log(fails.length ? 'CHAT FAIL\n' + fails.join('\n') : 'CHAT PASS'); process.exit(fails.length ? 1 : 0);
