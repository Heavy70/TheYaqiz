/* Blind set 7 (25 Nov 2026): look-alike domains, Google redirects, fake service numbers, prizes asking for ID.
   Format: [text, expected ('x' scam | 'w' suspicious | 's' safe), allowed alternatives]. Part of cases-all.js. */
const cases = [
['https://xn--dcb-9ve.com/login','w','x'],
['https://аdcb-secure.com/verify','x'],
['https://emirates-nbd.cоm/login','x'],
['https://xn--uaepass-9ya.com/signin','x'],
['https://www.google.com/url?q=https://adcb-verify-login.top/secure&sa=D','x'],
['https://www.google.com/url?sa=t&url=http%3A%2F%2Fdewa-pay-now.xyz%2Fbill','x'],
['https://www.google.com/url?q=https://www.adcb.com/&sa=D','s'],
['https://www.google.com/search?q=adcb+branches','s'],
['ADCB customer care: to cancel the suspicious transaction on your account call our new service number 050 123 4567 immediately.','x'],
['خدمة عملاء بنك الإمارات دبي الوطني: لإيقاف عملية مشبوهة اتصل فورًا على رقم الخدمة الجديد 0501234567.','x'],
['Etisalat support: your SIM will be disabled. Call our new support line 971 55 987 6543 to keep your number.','x'],
['Etisalat support: your SIM will be disabled. Call our new support line +971 55 987 6543 to keep your number.','x'],
['ADCB: for card queries call 600 5 00005 or visit adcb.com. Never share your OTP.','s'],
['Congratulations! You won AED 10,000 in the Dubai Shopping draw. Reply with a photo of your Emirates ID and full name to claim your prize.','x'],
['مبروك! ربحت 10000 درهم في سحب مهرجان دبي للتسوق. أرسل صورة هويتك الإماراتية واسمك الكامل لاستلام الجائزة.','x'],
['You have been selected to receive a free iPhone 16. Send your passport copy and bank card number to confirm delivery.','x'],
['Your appointment at the ICP centre is confirmed for tomorrow. Please bring your original Emirates ID.','s'],
];
module.exports = cases;
