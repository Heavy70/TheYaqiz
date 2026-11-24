/* Early warning (Certificate Transparency) and evidence facts, with the network stubbed: look-alikes are kept, official and old domains are dropped. */
process.env.PORT = '0'; delete process.env.ANTHROPIC_API_KEY;
const day = 864e5, iso = t => new Date(t).toISOString().slice(0, 19);
const CRT = [
  { issuer_name: 'C=US, O=Let\'s Encrypt, CN=R11', name_value: 'adcb-secure-login.top\nwww.adcb-secure-login.top', not_before: iso(Date.now() - 2 * day) },
  { issuer_name: 'C=US, O=DigiCert Inc, CN=x', name_value: 'www.adcb.com', not_before: iso(Date.now() - 3 * day) },
  { issuer_name: 'C=US, O=Google Trust Services, CN=WE1', name_value: 'uaepass-verify.com', not_before: iso(Date.now() - 1 * day) },
  { issuer_name: 'C=US, O=Let\'s Encrypt, CN=R11', name_value: 'old-adcb-fan.com', not_before: iso(Date.now() - 4 * day) },
  { issuer_name: 'C=US, O=Let\'s Encrypt, CN=R11', name_value: 'adcb-loan-offer.xyz', not_before: iso(Date.now() - 120 * day) },
  { issuer_name: 'C=US, O=DigiCert Inc, CN=x', name_value: 'www.emiratesnbd.com.eg\nmashreq.com.cn\nadpolice.gov.ae.admin-mcas-df.ms\nadpolice.gov.ae.mcas.ms', not_before: iso(Date.now() - 2 * day) }
];
global.fetch = async (url) => {
  const u = String(url), ok = (j) => ({ ok: true, status: 200, json: async () => j, text: async () => JSON.stringify(j), body: null });
  if (u.includes('crt.sh')) return ok(CRT);
  if (u.includes('rdap.org/domain/old-adcb-fan.com')) return ok({ events: [{ eventAction: 'registration', eventDate: '2015-03-01T00:00:00Z' }] });
  if (u.includes('rdap.org/domain/')) return ok({ events: [{ eventAction: 'registration', eventDate: new Date(Date.now() - 5 * day).toISOString() }], entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['fn', {}, 'text', 'Example Registrar LLC']]] }], nameservers: [{ ldhName: 'NS1.EXAMPLE.NET' }] });
  return { ok: false, status: 404, json: async () => ({}), text: async () => '', body: null };
};
const S = require('../server.js');
(async () => {
  let bad = 0; const chk = (c, m) => { if (!c) { bad++; console.log(' ✗', m); } };
  const w = await S.refreshWatch();
  const doms = w.items.map(i => i.reg);
  chk(doms.includes('adcb-secure-login.top'), 'new ADCB look-alike kept');
  chk(doms.includes('uaepass-verify.com'), 'new UAE PASS look-alike kept');
  chk(!doms.includes('adcb.com'), 'official domain dropped');
  chk(!doms.includes('old-adcb-fan.com'), 'domain registered years ago dropped');
  chk(!doms.includes('adcb-loan-offer.xyz'), 'certificate older than the window dropped');
  chk(!doms.includes('emiratesnbd.com.eg') && !doms.includes('mashreq.com.cn'), 'the brand\'s own country sites dropped');
  chk(!doms.some(d => /mcas/.test(d)), 'Microsoft Defender proxy names dropped');
  const it = w.items.find(i => i.reg === 'adcb-secure-login.top') || {};
  chk(it.age !== null && it.age <= 6 && it.seen && it.issuer === 'Let\'s Encrypt', 'age, first-seen date and issuer recorded');
  const f = await S.hostFacts('adcb-secure-login.top');
  chk(f.registrar === 'Example Registrar LLC' && f.ns[0] === 'ns1.example.net' && f.created && f.checked, 'registrar, name servers, creation date and timestamp in facts');
  chk(/ADCB 600502030/.test(S.TEL_LINE), 'official numbers given to the AI');
  /* every new evidence-pack / early-warning / helpline string is translated in all six community languages */
  const X = require('../public/i18n-x.js'), html = require('fs').readFileSync(require('path').join(__dirname, '../public/index.html'), 'utf8');
  const en = [...html.matchAll(/\b(?:ev|ew)[A-Z][A-Za-z]*:\['(?:[^'\\]|\\.)*','((?:[^'\\]|\\.)*)'\]/g)].map(m => m[1]);
  chk(en.length >= 35, 'evidence and early-warning strings found (' + en.length + ')');
  const eng = ['Hides the real destination behind a redirect through', 'Uses look-alike letters to imitate', 'Asks you to send your Emirates ID or passport', 'Asks you to call a number that is not an official number of the organisation it names', 'Official numbers of this organisation', 'official number of', 'not one of the official numbers of', 'Phone number'];
  en.concat(eng).forEach(k => ['ur', 'hi', 'tl', 'fa', 'am', 'lg'].forEach(l => chk(X[l][k], l + ' translation missing: ' + k)));
  console.log(bad ? 'WATCH FAIL' : 'WATCH PASS'); process.exit(bad ? 1 : 0);
})();
