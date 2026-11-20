/* Accuracy gate: node tests/run.js   (exit code 1 if below the threshold) */
const path = require('path');
const R = require('../public/registry.js');
const createEngine = require('../public/engine.js');
const E = createEngine((a, e) => e, () => 1, R);
const cases = require('./cases-all.js');
const cls = s => s >= 60 ? 'x' : s >= 25 ? 'w' : 's';
let ok = 0, missed = [], falseAlarm = [], other = [];
cases.forEach(([t, e, a = '', o], i) => {
  const isUrl = /^https?:\/\/\S+$/.test(t);
  const r = isUrl ? E.analyzeUrl(t) : E.analyzeMsg(t, { sender: o });
  const c = cls(r.score);
  if (c === e || a.includes(c)) ok++;
  else {
    const row = `#${i + 1} want ${e}${a ? '/' + a : ''} got ${c} (${r.score}) :: ${t.replace(/\s+/g, ' ').slice(0, 90)} :: ${r.flags.filter(f => f.w > 0).map(f => f.rule || f.l.slice(0, 30)).join(',')}`;
    if (e === 'x' && c === 's') missed.push(row); else if (e === 's' && c === 'x') falseAlarm.push(row); else other.push(row);
  }
});
const n = cases.length, acc = (ok / n * 100).toFixed(1);
console.log(`Cases: ${n} | correct: ${ok} | accuracy: ${acc}%`);
console.log(`Missed scams (scam judged safe): ${missed.length} | False alarms (safe judged scam): ${falseAlarm.length} | Other: ${other.length}`);
[...missed, ...falseAlarm, ...other].forEach(r => console.log(' ✗', r));
const pass = missed.length === 0 && falseAlarm.length === 0 && +acc >= 95;
console.log(pass ? 'PASS' : 'FAIL');
process.exit(pass ? 0 : 1);
