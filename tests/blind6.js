/* Blind set 6 (30 new cases, written 25 Nov 2026 before any engine change; mixed Arabic, Gulf dialect and English).
   [text, expected ('x' scam | 'w' suspicious | 's' safe), allowed alternatives]. Not part of cases-all.js:
   run it alone with  node tests/blind6.js  and report the result honestly, including misses. */
const cases = [
// --- scams (x) ---
['السلام عليكم، معك قسم الأمن في بنكك. تم رصد عملية مشبوهة على حسابك. لإلغائها أرسل لنا الرمز الذي وصلك الآن.','x'],
['هلا والله، هذا رقمي الجديد، فلوسي عالقة بالبنك. ممكن تحول لي 1500 درهم وأرجعها لك بكرة؟','x'],
['مبروك! فزت بسحب تسوق مول الإمارات. لاستلام قسيمة 5000 درهم أرسل صورة الهوية وبيانات البطاقة على هذا الرابط https://mall-uae-prize.top/claim','x'],
['Your Salik balance is low and your account will be blocked today. Top up now: https://salik-topup-uae.xyz/pay','x'],
['Abu Dhabi Police: unpaid fine AED 400. Pay within 24 hours to avoid a travel ban: http://adpolice-fines-pay.top/ticket','x'],
['شحنتك من بريد الإمارات محتجزة. ادفع رسوم الجمارك 7.5 درهم عبر https://empost-customs-fee.click/track','x'],
['Dear customer, your Emirates ID is expired. Update it today to keep your bank account active: https://icp-id-renew.online/update','x'],
['وظيفة من البيت براتب 600 درهم يوميًا بدون خبرة. أرسل نسخة من جواز سفرك وبطاقتك البنكية للتسجيل على واتساب.','x'],
['Investment alert: our AI trading bot made 40% this week. Deposit 2000 USDT today and withdraw anytime. Join the VIP group now.','x'],
['Your DEWA bill is overdue. Electricity will be cut tonight at 6 PM unless you pay at https://dewa-billing-uae.xyz/now','x'],
['أنا من شرطة دبي، ابنك عليه قضية حادث. حوّل مبلغ الكفالة الآن ولا تخبر أحدًا حتى لا يُسجن.','x'],
['Hello, this is Emirates NBD security. We detected a login from another country. Please share the OTP you received to block it.','x'],
['Congratulations, you are selected for a Government Housing grant. Pay a 300 AED processing fee to https://housing-grant-uae.top to receive it.','x'],
['Hi Mum, I dropped my phone in water, this is my new number. Please send 2500 AED to this account, I will explain later.','x'],
['تم تعليق حساب أمان الخاص بك. أدخل كلمة المرور على الرابط لإعادة تفعيله http://uaepass-verify-login.top','x'],
// --- borderline (w), either w or x accepted ---
['Your parcel could not be delivered. Please confirm your address here: https://track-parcel-ae.com/id/88231','w','x'],
['عرض حصري: خصم 70% على الأجهزة اليوم فقط! تسوق الآن قبل نفاد الكمية.','w','xs'],
['Your bank card ends with 4417 was used for AED 52 at a pharmacy. If this was not you, call the number on the back of your card.','w','s'],
['Reminder: your appointment is tomorrow at 10:00. Reply YES to confirm or call the clinic.','w','s'],
['You have a new voicemail. Listen at https://vmail-service.link/u/92','w','x'],
// --- genuine (s), must NOT be flagged as scam ---
['Your Salik account has been topped up with AED 100. Thank you. Details at https://www.salik.ae','s'],
['ADCB: Never share your OTP, PIN or card number with anyone, including bank staff. Report suspicious calls via our official app.','s'],
['تذكير من دو: فاتورتك لهذا الشهر جاهزة. يمكنك الاطلاع عليها ودفعها عبر تطبيق du الرسمي.','s'],
['Emirates NBD: Your OTP for the online purchase is 482913. Do not share it with anyone. Valid for 5 minutes.','s'],
['Your DEWA bill for October is AED 312. Pay via the DEWA app or at https://www.dewa.gov.ae','s','w'],
['هلا، اجتماع الأولياء يوم الخميس الساعة 10 صباحًا في المدرسة. نرجو الحضور.','s'],
['Hi, I am running late, will be there in 15 minutes. Please order for me.','s'],
['Your TAMM service request has been received. Track it at https://www.tamm.abudhabi','s','w'],
['Abu Dhabi Police reminds you: report scams on Aman 800 2626 or SMS 2828. Do not share your bank details with anyone.','s'],
['Your Careem ride receipt: AED 28. Thank you for riding with us.','s'],
];
module.exports = cases;
if (require.main === module) {
  const R = require('../public/registry.js'), createEngine = require('../public/engine.js');
  const E = createEngine((a, e) => e, () => 1, R);
  const cls = s => s >= 60 ? 'x' : s >= 25 ? 'w' : 's';
  let ok = 0, missed = 0, fa = 0; const rows = [];
  cases.forEach(([t, e, a = ''], i) => {
    const isUrl = /^https?:\/\/\S+$/.test(t);
    const r = isUrl ? E.analyzeUrl(t) : E.analyzeMsg(t, {});
    const c = cls(r.score);
    if (c === e || a.includes(c)) ok++;
    else { if (e === 'x' && c === 's') missed++; if (e === 's' && c === 'x') fa++;
      rows.push(`#${i + 1} want ${e}${a ? '/' + a : ''} got ${c} (${r.score}) :: ${t.slice(0, 70)}`); }
  });
  console.log(`Blind set 6: ${cases.length} cases | correct ${ok} | accuracy ${(ok / cases.length * 100).toFixed(1)}% | missed scams ${missed} | false alarms ${fa}`);
  rows.forEach(r => console.log(' ✗', r));
}
