const R=require('../public/registry.js'),C=require('../public/engine.js');const E=C((a,e)=>e,()=>1,R);
const scam=['آپ کا اکاؤنٹ بلاک ہو جائے گا، فوراً اپنا OTP بھیجیں','आपका खाता ब्लॉक हो जाएगा, तुरंत अपना OTP भेजें','Na-block ang account mo. Ipadala agad ang OTP mo sa loob ng 2 oras','Aapka account band ho jayega, jaldi OTP bhejein'];
const safe=['Kumusta ka? Kita tayo bukas sa mall.','आप कैसे हैं? कल मिलते हैं।','آپ کیسے ہیں؟ کل ملتے ہیں۔','Your DHL parcel was delivered. Thank you.'];
let bad=0;scam.forEach(x=>{if(E.analyzeMsg(x).score<60){bad++;console.log('MISSED',x)}});safe.forEach(x=>{if(E.analyzeMsg(x).score>=30){bad++;console.log('FALSE',x)}});
const X=require('../public/i18n-x.js');['ur','hi','tl'].forEach(l=>{if(Object.keys(X[l]).length<250){bad++;console.log('dict small',l)}});
console.log(bad?'MULTI FAIL':'MULTI PASS');process.exit(bad?1:0);
