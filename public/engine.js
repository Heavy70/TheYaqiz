/* Yaqiz detection engine (on-device). Pure functions: no DOM. Used by the app and by tests/run.js.
   createEngine(T, LI, R): T(ar,en) picks the language, LI() returns 0 (ar) or 1 (en), R is the registry. */
(function (root) {
  function createEngine(T, LI, R, TX) {
    TX = TX || function (s) { return s; };

    /* ===== Arabic normalisation with index map ===== */
    function normMap(s0) {
      let s = '', map = [];
      for (let i = 0; i < s0.length; i++) {
        let c = s0[i]; if (/[ً-ْـ\u200b\u200e\u200f\u202a-\u202e\u2060\ufeff]/.test(c)) continue;
        let l = c.toLowerCase(); if (l.length !== 1) l = c;
        l = l.replace(/[أإآ]/, 'ا').replace('ى', 'ي').replace('ة', 'ه');
        const d = '٠١٢٣٤٥٦٧٨٩'.indexOf(l); if (d >= 0) l = String(d);
        s += l; map.push(i);
      }
      return { s, map };
    }

    /* ===== wording rules ===== */
    const CODES = '(otp|رمز (ال)?(تحقق|تفعيل|تاكيد|امان)|كود (ال)?(تحقق|تفعيل)|verification code|security code|one[- ]time (pass)?code|\\bpin\\b|cvv|password|كلمه (ال)?(مرور|سر)|الرقم السري|رقم سري|رقم (ال)?بطاق|بيانات (ال)?بطاق|تاريخ (ال)?انتهاء|card (number|details)|iban|ايبان|رقم (ال)?حساب|account number)';
    const VERBS = '(send|share|give|provide|reply|enter|confirm|tell|forward|read out|type|submit|ارسل|شارك|زودنا|زودني|اعطنا|اعطني|ادخل|اكتب|اخبرنا|اخبرني|ابعث|اكد|قدم)';
    const SV = '(send|share|give|provide|tell|reply|forward|read out|ارسل|ارسال|شارك|مشاركه|زودنا|تزويد|اعطنا|اعطني|اعطاء|اخبرنا|اخبرني|قول|هات|ابعث)';
    const SECRET = '(otp|رمز (ال)?(تحقق|تفعيل|تاكيد|امان)|كود (ال)?(تحقق|تفعيل)|verification code|security code|\\bpin\\b|cvv|password|كلمه (ال)?(مرور|سر)|الرقم السري|رقم سري|رقم (ال)?بطاق|بيانات (ال)?بطاق|card (number|details)|(الكود|الرمز|code) ?(اللي|الذي|that you)( just)? (وصلك|وصلتك|سيصلك|received|got|وصل)|the code you (just )?(received|got))';
    const NEG = /(do not|don'?t|never|not to|لا\s|لن\s|ممنوع|عدم|without)[^.,;؛؟!]{0,8}$/;

    const RULES = [
      { id: 'inj', ax: 'ai', w: 45, l: ['يحاول التلاعب بأداة الفحص أو الذكاء الاصطناعي (تعليمات موجَّهة للآلة)', 'Tries to manipulate the checking tool or AI (instructions aimed at the machine)'], tip: ['الرسائل الحقيقية لا تخاطب أدوات الفحص؛ وجود تعليمات كهذه دليل على نية خداع.', 'Genuine messages never address scanners or AI tools; instructions like this show deliberate deception.'],
        re: /(?:(?:(?:ignore|disregard|forget|override|bypass|skip|discard|overlook)\s+(?:all\s+|any\s+|your\s+|previous\s+|prior\s+|above\s+|earlier\s+|preceding\s+|system\s+|safety\s+|security\s+|original\s+)+(?:instructions?|rules|prompts?|guidelines?|directives?|restrictions|programming)|(?:you are|you're|act as|pretend (?:to be|you are)|behave as|from now on you)\s+(?:now\s+|no longer\s+)?(?:an?\s+)?(?:unrestricted|jailbroken|uncensored|unfiltered|dan\b|do anything now|evil)|(?:developer|debug|god|admin|sudo|jailbreak)\s+mode|(?:reveal|show|print|repeat|leak)\s+(?:me\s+)?(?:your\s+|the\s+)?(?:system\s+prompt|hidden\s+(?:prompt|instructions)|instructions)|(?:mark|rate|classify|label|flag|report|rank|score|treat|consider|declare|categori[sz]e|output|return|answer|respond|say|tell|reply|conclude|judge)\s+(?:this|it|that|the\s+(?:message|link|text|email|sms|content|result))[^.\n]{0,20}?(?:as\s+|with\s+|:\s*|is\s+|to be\s+)?(?:safe(?!\s*senders?)|legit(?:imate)?|genuine|trusted|verified|harmless|clean|not\s+(?:an?\s+)?(?:scam|phishing|fraud|suspicious|malicious)|no risk|low risk|zero risk)|(?:set|give|assign|return|output|use)\s+(?:a\s+|the\s+|it\s+)?(?:risk\s+|scam\s+)?score\s+(?:of\s+|to\s+|as\s+|=\s*|:\s*)?(?:0|zero|1|low)\b|(?:ai|a\.i\.|chatbot|language model|llm|gpt|claude|scanner|yaqiz|theyaqiz|scam ?shield)\b[^.\n]{0,25}(?:ignore|disregard|do not (?:flag|detect|report|warn)|don'?t (?:flag|detect|report|warn)|must (?:say|answer|respond|classify|mark|report))|(?:do not|don'?t|never|stop)\s+(?:flag|detect|report|warn|block|mark|label)\s+(?:this|it|the message|the link)|(?:if you(?:'re| are) (?:an? )?(?:ai|llm|assistant|language model|bot|scanner)|dear (?:ai|llm|scanner|bot)|note to (?:the )?(?:ai|scanner|filter|model|llm)|attention (?:ai|scanner|llm)|to the (?:ai|scanner|filter|model|llm) (?:reading|analy[sz]ing|checking))|(?:<\/?(?:system|instructions?|prompt|assistant)>|\[\/?(?:system|inst)\]|<\|im_(?:start|end)\|>|#{2,3}\s*(?:system|instructions?)\b))|(?:(?:تجاهل|تناسي|انس|اهمل|الغ|تخط|تجاوز|تخل|اترك)\w*\s*(?:كل\s+|جميع\s+|اي\s+|هذه\s+|ما\s+)?(?:ال)?(?:تعليمات|اوامر|قواعد|توجيهات|ضوابط|قيود|برمجتك)|(?:اعتبر|صنف|قيم|احكم|اخبر|قل|قول|اجب|اجعل|اعط|اكتب|رد|اظهر|اعلن)\w*[^.\n]{0,25}(?:الرساله|الرابط|المحتوي|النتيجه|هذه|هذا|ها\b)[^.\n]{0,25}(?:امن|امنه|سليم\w*|موثوق\w*|غير\s+(?:مشبوه|احتيال)\w*|ليس\w*\s+(?:احتيال|مشبوه|خطر|نصب)\w*|بدون\s+خطر|خطر\s+(?:منخفض|صفر)|صفر\s*%?)|(?:ايها|يا)\s+(?:ال)?(?:ذكاء\s+(?:ال)?اصطناعي|روبوت|يقظ)|اذا\s+كنت\s+(?:ال)?(?:ذكاء\s+اصطناعي|نموذج|مساعد|روبوت)|ملاحظه\s+(?:الي|ل)\s*(?:ال)?(?:ذكاء\s+(?:ال)?اصطناعي|فاحص\s+(?:ال)?رسائل|ماسح\s+(?:ال)?رسائل)|لا\s+(?:تبلغ|تحذر|تصنف|تكتشف|تحظر|تنبه)[^.\n]{0,20}(?:هذه|الرساله|الاحتيال|كاحتيال|كمشبوه|عنها)|وضع\s+(?:ال)?مطور|موجه\s+(?:ال)?نظام|(?:اظهر|اكشف|اعرض)\s+(?:لي\s+)?(?:تعليماتك|موجهك)|(?:ال)?ذكاء\s+(?:ال)?اصطناعي[^.\n]{0,20}(?:تجاهل|لا\s+تبلغ|لا\s+تحذر))|(?:(?:تمام|سب|پچھلی|اوپر کی|سابقہ|ساری)\s*ہدایات[^.\n]{0,12}(?:نظر انداز|بھول|چھوڑ|مت مان)|ہدایات\s*(?:کو\s*)?(?:نظر انداز|بھول)|(?:اسے|اس پیغام کو|یہ پیغام|اس لنک کو|لنک کو)[^.\n]{0,20}(?:محفوظ|سیف|درست|اصلی|جائز)[^.\n]{0,12}(?:قرار|بتائیں|لکھیں|کہیں|درجہ|سمجھیں)|دھوکہ نہیں\s*(?:ہے\s*)?(?:بتائیں|لکھیں|کہیں)|(?:اے آئی|اسسٹنٹ|مصنوعی ذہانت)[^.\n]{0,20}(?:نظر انداز|رپورٹ نہ|وارننگ نہ|خبردار نہ)|(?:sab|saari|pichli|upar ki)\s+(?:hidayat|hidayaat|instructions?)[^.\n]{0,15}(?:ignore|nazar andaz|bhool)|nazar andaz kar|ignore kar(?:o|do|na)|(?:isko|ise)\s+(?:safe|sahi|asli)\s+(?:batao|likho|bolo|mark kar|samjho))|(?:(?:सभी|सारे|पिछले|ऊपर के|पहले के)\s*(?:निर्देश|निर्देशों|आदेश)[^.\n]{0,12}(?:अनदेखा|नज़रअंदाज़|नजरअंदाज|भूल|मत मान)|निर्देशों को\s*(?:अनदेखा|नज़रअंदाज़|नजरअंदाज|भूल)|(?:इसे|इस संदेश को|इस मैसेज को|लिंक को|इस लिंक को)[^.\n]{0,20}(?:सुरक्षित|सही|असली|वैध|स्कैम नहीं|धोखा नहीं)[^.\n]{0,12}(?:बताएं|बताओ|लिखें|कहें|मानें|घोषित|समझें)|(?:एआई|ए आई|असिस्टेंट|चैटबॉट)[^.\n]{0,20}(?:अनदेखा|रिपोर्ट न|चेतावनी न|नज़रअंदाज़))|(?:(?:huwag pansinin|wag pansinin|balewalain|kalimutan|ignore)\s+(?:mo\s+)?(?:ang\s+)?(?:lahat\s+ng\s+)?(?:mga\s+)?(?:nakaraang\s+|naunang\s+)?(?:utos|tagubilin|instruksyon|panuto|instructions?)|(?:markahan|itala|ideklara|sabihing|ituring|i-?mark)\s+(?:mo\s+)?(?:ito|ang mensaheng ito|ang link)?[^.\n]{0,20}(?:ligtas|lehitimo|tunay|hindi\s+scam)|(?:huwag|wag)\s+(?:mong\s+)?(?:i-?flag|i-?report|balaan|i-?block)|(?:ai|assistant|chatbot)\b[^.\n]{0,25}(?:huwag|wag|balewalain|pansinin)))/ },
      { id: 'cred', ax: 'sens', w: 30, neg: NEG, l: ['يطلب رمز تحقق (OTP) أو كلمة مرور أو بيانات بطاقة', 'Asks for a verification code (OTP), password or card details'], tip: ['لا توجد جهة رسمية أو بنك يطلب منك رمز التحقق أو الرقم السري أبدًا.', 'No bank or government entity ever asks for your OTP or PIN.'],
        re: new RegExp('(?:' + VERBS + '[^.؟!\\n]{0,45}?' + CODES + ')|(?:' + CODES + '[^]{0,90}?(?:send|share|forward|read|tell|give)\\w* (?:it|them|that|the code) (?:back )?to me)|(?:(?:send|tell|give|share) me (?:the |that |this |your )?(?:code|otp|pin|password))') },
      { id: 'credx', ax: 'sens', w: 25, neg: NEG, skipIf: /(courier|driver|delivery (agent|partner|man|person|boy)|rider|مندوب|سائق|التوصيل)/, l: ['يطلب منك إرسال أو قول رمز سرّي أو كلمة مرور', 'Asks you to send or tell a secret code or password'], tip: ['لا يطلب أحد منك قول الرمز أو كلمة المرور؛ من يفعل فهو محتال.', 'Nobody legitimate asks you to say or send a code or password — whoever does is a scammer.'],
        re: new RegExp('(?:' + SV + '[^.؟!\\n]{0,45}?' + SECRET + ')|(?:' + SECRET + '[^]{0,90}?(?:send|share|forward|read|tell|give)\\w* (?:it|them|that|the code) (?:back )?to me)|(?:(?:send|tell|give|share) me (?:the |that |this |your )?(?:code|otp|pin|password))') },
      { id: 'update', ax: 'sens', w: 12, l: ['يطلب تحديث بيانات أو تفعيل حساب عبر رابط', 'Asks you to update details or activate an account via a link'], tip: ['تحديث البيانات يتم من التطبيق الرسمي مباشرة لا من رابط في رسالة.', 'Update details in the official app — never via a link in a message.'],
        re: /(حدث بياناتك|تحديث (البيانات|بياناتك|الحساب)|تفعيل (حسابك|البطاقه)|تاكيد (هويتك|بياناتك)|verify your (account|identity|details|information)|update your (details|account|information|records)|confirm your (identity|account|details)|re-?activate (your|the) (account|card)|تحقق من (حسابك|بياناتك|هويتك))/ },
      { id: 'payupd', ax: 'sens', w: 25, neg: NEG, l: ['يطلب تحديث أو تأكيد بيانات الدفع أو البطاقة', 'Asks you to update or confirm payment or card details'], tip: ['حدّث بيانات الدفع من التطبيق أو الموقع الرسمي الذي تكتبه بنفسك، لا من زر أو رابط في رسالة.', 'Update payment details only in the official app or a website you type yourself — never from a button or link in a message.'],
        re: /((update|confirm|verify|re-?enter|re-?add|add|provide|fix|correct|enter|renew)\s+(your\s+|a\s+|the\s+|new\s+)*(payment|billing|card|credit card|debit card|bank card)\b|(حدث|تحديث|اكد|تاكيد|ادخل|ادخال|اضف|اضافه|جدد|تجديد)\s+(طريقه|وسيله|بيانات|معلومات|تفاصيل)\s+(ال)?(دفع|بطاقتك|بطاقه|البطاقه|الفوتره|السداد)|(اكد|ادخل|حدث)\s+بيانات\s+بطاقتك)/ },
      { id: 'bill', ax: 'press', w: 20, l: ['ذريعة فشل الدفع أو انتهاء الاشتراك أو امتلاء التخزين أو حذف الملفات', 'Failed-payment, expired-subscription, full-storage or file-deletion pretext'], tip: ['رسائل «فشل الدفع» و«امتلاء التخزين» من أشهر طُعوم سرقة البطاقات؛ افتح التطبيق الرسمي بنفسك لتتأكد.', '“Payment failed” and “storage full” messages are top card-theft lures — open the official app yourself to check.'],
        re: /(payment( method| details| card| information)? (has |have |was |is )?(expired|declined|failed|unsuccessful|invalid|outdated|not (been )?processed)|payment (failed|declined|unsuccessful)|(couldn'?t|could not|unable to|were unable to|failed to) (process|complete|charge|verify|renew) (your |the )?(last |recent |latest )?(payment|card|billing|subscription)|card (has )?(expired|was declined)|billing (problem|issue|failure|error)|subscription (has |is |was )?(expired|ended|cancell?ed|suspended|on hold|paused|will be (cancell?ed|suspended|terminated|deactivated))|membership (payment )?(has |is |was )?(expired|failed|on hold|suspended|cancell?ed)|(storage|cloud|icloud|drive|mailbox|inbox)( space)? (is )?(almost |nearly |now |completely )?full|out of (storage|space)|(photos|videos|files|data|documents|emails?|messages|backups?)( and (photos|videos|files|data|documents|emails?|messages))? (will|may|could) be (permanently )?(deleted|removed|lost|erased)|(account|profile|files|data) will be (permanently )?(deleted|removed|closed|terminated)|avoid (any )?(service |account )?(interruption|suspension|disruption|deactivation|termination|cancell?ation)|avoid losing|service (interruption|disruption)|backup (has )?stopped|(has been|was) renewed for|(storage|space|mailbox|quota)( usage)? limit (has been |is )?(reached|exceeded)|(trouble|problem|issue) with (your )?(current )?(billing|payment)|(subscription|membership|plan) (expires|will expire|is expiring|ends) (today|tomorrow|soon|in)|to keep (your )?(chats|photos|videos|files|data|account|access|emails|messages|service|line)|(your )?card (was |has been )?(declined|rejected)|(تم )?رفض (بطاقتك|البطاقه|بطاقه)|(بريدك|حسابك|صندوق (ال)?بريد|البريد (ال)?الكتروني)[^.\n]{0,30}ممتلئ|حتي لا (تفقد|يتم حذف)|(اشتراكك|عضويتك)[^.\n]{0,20}ينتهي|انتهت صلاحيه (طريقه|وسيله|بطاقه|بيانات) (ال)?(دفع|سداد)|(طريقه|وسيله) (ال)?دفع (منتهيه|مرفوضه|غير صالحه)|(فشل|فشلت|تعذر|لم تتم|لم يتم) (اتمام |تنفيذ )?(عمليه )?(ال)?(دفع|سداد|خصم|تحصيل)|تعذر (تحصيل|خصم)|(اشتراكك|عضويتك|الاشتراك|اشتراك)[^.\n]{0,25}?(انتهي|منتهي|متوقف|معلق|موقوف|سينتهي|سيتم (ايقاف|الغاء|تعليق))|مساحه (ال)?تخزين( (ال)?سحابيه)? (ممتلئه|نفدت|امتلات|على وشك)|سيتم حذف (صورك|ملفاتك|بياناتك|حسابك|رسائلك|رسايلك)|(قبل|لتجنب) (حذف|فقدان)|لتجنب (انقطاع|توقف|ايقاف|تعليق) (ال)?(خدمه|حسابك|اشتراكك))/ },
      { id: 'urg', ax: 'press', w: 15, l: ['لغة استعجال وضغط زمني', 'Urgency and time pressure'], tip: ['الضغط الزمني يمنعك من التفكير والتحقق.', 'Time pressure stops you from thinking and checking.'],
        re: /(عاجل|فورا|حالا|بسرعه|خلال \d+ ?(ساعه|ساعات|ساعتين|دقيقه|دقائق|يوم)|خلال ساعتين|اخر فرصه|قبل فوات|ينتهي اليوم|urgent|immediately|within \d+ ?(hours?|minutes?|days?)|last chance|expires? today|act now|final (notice|warning)|last warning|اشعار نهائي|تحذير اخير)/ },
      { id: 'threat', ax: 'press', w: 18, l: ['تهديد بإيقاف أو تجميد أو غرامة أو قبض', 'Threat of suspension, freezing, fines or arrest'], tip: ['التهديد يدفعك للتصرف بخوف؛ الجهات الرسمية تبلغك عبر قنواتها الموثقة.', 'Threats push you to act out of fear; official bodies contact you through verified channels.'],
        re: /(تجميد|ايقاف (حسابك|خدمتك|بطاقتك|هويتك)|سيتم (ايقاف|تعليق|حظر|اغلاق|القبض)|تعليق (حساب|الخدمه|هويتك)|حظر (حسابك|بطاقتك)|غرامه (غير|متاخره|مروريه)|مخالفه (غير|مروريه)|قضيه|القبض|بلاغ ضدك|اجراء قانوني|مصادره|will be (suspended|blocked|closed|cancelled|terminated)|has been (suspended|blocked|frozen|locked)|is (suspended|blocked|frozen|locked)|frozen|freeze|deactivat|legal action|arrest|penalty|unpaid (traffic )?fine|warrant|تتضاعف|مضاعفه الغرامه)/ },
      { id: 'secret', ax: 'press', w: 12, l: ['يطلب السرية أو عدم إخبار أحد', 'Asks for secrecy or tells you not to tell anyone'], tip: ['المحتال يعزلك عن أسرتك وبنكك كي لا ينبهك أحد.', 'Scammers isolate you from family and your bank so no one warns you.'],
        re: /(لا تخبر (احد|احدا|اي)|سري للغايه|لا تشارك هذه الرساله|بيننا|don'?t tell (anyone|anybody|your)|keep (this|it) (secret|confidential))/ },
      { id: 'prize', ax: 'lure', w: 20, l: ['وعد بجائزة أو ربح أو مبلغ غير متوقع', 'Promises a prize, winnings or unexpected money'], tip: ['لا يمكنك الفوز بسحب لم تشترك فيه.', 'You can’t win a draw you never entered.'],
        re: /(مبروك|تهانينا|فزت|ربحت|جائزه|سحب على|مكافاه|استرداد مبلغ|congratulations|you (have )?won|winner|you('ve| have) been selected|lottery|claim your (prize|reward|gift)|cashback offer|gift card|free (recharge|data|gift|iphone|voucher|credit)|شحن (ال)?مجاني|رصيد (ال)?مجاني|قسيمه شراء)/ },
      { id: 'job', ax: 'lure', w: 30, l: ['عرض عمل أو استثمار بعائد مغرٍ', 'Job or investment offer with tempting returns'], tip: ['الأرباح المضمونة والعمل من المنزل براتب مرتفع دون مقابلة من أشهر الطُعوم.', 'Guaranteed profits and high-paid home jobs without an interview are classic bait.'],
        re: /(وظيفه براتب|عمل من المنزل|دخل يومي|ارباح يوميه|ربح مضمون|عائد مضمون|استثمار مضمون|عملات رقميه|بيتكوين|كريبتو|لايك|مهام بسيطه|work from home|daily (income|profit)|guaranteed (return|profit)|\binvest(ment)? (now|opportunity)|crypto|bitcoin|forex|part[- ]time job|earn \d+)/ },
      { id: 'rent', ax: 'lure', w: 18, l: ['عرض سكن أو سيارة بسعر أقل من السوق مع دفعة مقدّمة', 'Below-market rental or car with an upfront deposit'], tip: ['لا تدفع عربونًا قبل المعاينة والتأكد من عقد مسجّل.', 'Never pay a deposit before viewing and checking a registered contract.'],
        re: /(عربون|دفعه مقدمه|ايجار (رخيص|مخفض)|deposit (first|now)|advance payment|cheap rent)/ },
      { id: 'hold', ax: 'lure', w: 15, l: ['ذريعة شحنة معلّقة أو عنوان ناقص لدفعك لفتح رابط', 'Parcel-on-hold or incomplete-address pretext to push you to a link'], tip: ['شركات الشحن الحقيقية لا تطلب منك إكمال بيانات أو دفع رسوم عبر رابط في رسالة.', 'Real couriers don’t ask you to complete details or pay via a link in a message.'],
        re: /(on hold|delivery (failed|attempt|is currently)|address (information )?(is )?incomplete|incomplete (delivery )?address|complete (the |your )?(delivery (address|details)|address)|reschedule (your )?delivery|شحنه (معلقه|محتجزه)|تعذر (التسليم|توصيل)|عنوان (التوصيل )?(غير مكتمل|ناقص))/ },
      { id: 'imp', ax: 'imp', w: 12, withOthers: true, l: ['ينتحل صفة جهة رسمية أو بنك أو شركة شحن', 'Impersonates a government body, bank or courier'], tip: ['الاسم الرسمي في الرسالة لا يعني أنها رسمية؛ تحقق من المرسل والرابط.', 'An official name in a message doesn’t make it official — check the sender and link.'],
        re: /(شرطه|النيابه|وزاره الداخليه|المصرف المركزي|البنك المركزي|الهويه والجنسيه|الجمارك|uae ?pass|بريد الامارات|emirates ?post|aramex|ارامكس|\bdhl\b|fedex|police|ministry|central bank|\bicp\b|etisalat|tamm|بنك|\bbank\b)/ },
      { id: 'family', ax: 'imp', w: 22, l: ['ينتحل صفة قريب أو صديق برقم جديد', 'Pretends to be a relative or friend with a new number'], tip: ['اتصل بالرقم القديم المعروف للتحقق قبل أي تحويل.', 'Call their old, known number to check before sending money.'],
        re: /(رقمي الجديد|هذا رقمي|تلفوني (انكسر|خرب|ضاع)|جوالي (انكسر|خرب|ضاع)|my new number|this is my new|lost my phone|broke my phone|(ماما|بابا|اخوي|mum|mom|dad).{0,40}(حول|ارسل|send|transfer))/ },
      { id: 'chan', ax: 'imp', w: 10, l: ['ينقلك إلى واتساب/تيليجرام أو رقم شخصي', 'Moves you to WhatsApp/Telegram or a personal number'], tip: ['الجهات الرسمية لا تتابع قضاياك عبر حساب واتساب شخصي.', 'Official bodies don’t handle your case via a personal WhatsApp account.'],
        re: /(تواصل (معنا )?(عبر|على) (واتساب|واتس اب|تيليجرام|تلجرام)|contact (us )?(on|via) (whatsapp|telegram)|wa\.me|t\.me)/ },
      { id: 'acct', ax: 'money', w: 20, l: ['يطلب التحويل إلى حساب شخصي', 'Asks you to transfer to a personal account'], tip: ['الجهات الرسمية لا تطلب تحويلات إلى حسابات أشخاص.', 'Organisations don’t ask for transfers to individuals’ accounts.'],
        re: /(to my (personal |bank )?(account|number)|على حسابي|الى حسابي|لحسابي|to this (personal )?account number)/ },
      { id: 'advfee', ax: 'money', w: 20, l: ['رسوم مقدّمة مقابل وظيفة أو تأشيرة أو جائزة', 'Upfront fee in exchange for a job, visa or prize'], tip: ['أي جهة حقيقية لا تأخذ رسوم تسجيل أو معالجة مقدّمًا مقابل وعد بشيء.', 'No genuine party takes a registration or processing fee upfront for a promise.'],
        re: /((registration|processing|admin|clearance|release|insurance|visa|application|handling) fees?|رسوم (التسجيل|المعالجه|التاشيره|الافراج|التخليص))/ },
      { id: 'tech', ax: 'sens', w: 25, l: ['ادّعاء إصابة الجهاز بفيروس أو طلب وصول عن بُعد', 'Claims your device has a virus or asks for remote access'], tip: ['لا تتصل بأرقام تظهر في رسالة أو نافذة منبثقة، ولا تثبّت برامج تحكم عن بُعد.', 'Never call numbers from a message or pop-up and never install remote-control tools.'],
        re: /(virus (was )?(detected|found)|detected (a )?virus|(device|computer|pc|phone) (is|has been|was) (infected|hacked|compromised)|remote access|anydesk|teamviewer|فيروس|جهازك مصاب|تم اختراق جهازك)/ },
      { id: 'pay', ax: 'money', w: 15, l: ['يطلب دفع رسوم أو تحويل أموال', 'Asks you to pay fees or transfer money'], tip: ['دفع «رسوم» صغيرة لاستلام شحنة أو جائزة أو وظيفة علامة احتيال كلاسيكية.', 'Paying a small “fee” to release a parcel, prize or job is a classic scam sign.'],
        re: /(ادفع|(?<![؀-ۿ])سدد(?![؀-ۿ])|سداد|رسوم|حول (المبلغ|لي)|حولي|حساب امن|pay (now|the|your|within|a|an|some)\b|pay (the |your |a |an |some )?(\w+ )?(fees?|charges?|fine|tax|duty|duties)|(ارسل|حول|ادفع)( لي)? (ال)?(عربون|دفعه مقدمه|مبلغ)|payment (link|required|is required|due)|unpaid|customs (fee|duty|charge)|delivery (charge|fee)|[\d,. ]+(aed|dirhams?|usd|\$)( \w+)? (fee|fees|charge|deposit|tax)|pay [\d,. ]+(aed|dirhams?|usd|\$)|بالدفع|الدفع (الان|فورا)|\bwire\b|safe account|transfer [\d,. ]*(aed|dirhams?|usd|\$)|transfer (the|your|a) (money|amount|fee))/ }
    ];

    /* ===== community-language keywords (Urdu, Hindi, Tagalog, Persian, Amharic, Luganda + romanised Urdu/Hindi) merged into the base rules by id ===== */
    const SECX = '(otp|pin|cvv|password|پاس ?ورڈ|کوڈ|پن|ओटीपी|कोड|पासवर्ड|पिन|code|verification|beripikasyon|bank details|card (number|details))';
    const EXTRA = {
      cred: [
        '(?:' + SECX + '[^.\\n]{0,40}?(?:بھیج|بتا|شیئر|دیں|دو|भेज|बता|शेयर|दें|दो|bhej|batao|bata|share|ipadala|ibigay|sabihin|ipasa))',
        '(?:(?:بھیج|بتا|شیئر|भेज|बता|शेयर|bhej|batao|ipadala|ibigay|sabihin)[^.\\n]{0,40}?' + SECX + ')',
        '(?:send|share|ibigay|ipadala)[^.\\n]{0,20}(?:otp|pin|password|code)'
      ],
      update: ['(?:اکاؤنٹ (اپ ?ڈیٹ|فعال|ویریفائی)|معلومات اپ ?ڈیٹ|खाता (अपडेट|चालू|सत्यापित)|केवाईसी|kyc (update|verify)|account (update|verify) karein|i-?update (ang|mo)|i-?verify (ang|mo)|ma-?block ang account)'],
      urg: ['(?:فوراً?|جلدی|ابھی|अभी|तुरंत|जल्दी|फौरन|jaldi|foran|abhi|turant|agad|kaagad|ngayon din|sa loob ng \\d+ ?(oras|araw|minuto))'],
      threat: ['(?:بند ہو|بلاک ہو|معطل|منجمد|گرفتار|جرمانہ|ब्लॉक हो|बंद हो|निलंबित|फ्रीज|गिरफ्तार|जुर्माना|block ho (jayega|jaye)|band ho (jayega|jaye)|giraftar|na-?block|ma-?block|masususpinde|ma-?freeze|aarestuhin|ipapa-?aresto|multa)'],
      secret: ['(?:کسی کو (مت|نہ) بتا|راز|किसी को (मत|न) बता|गोपनीय|kisi ko (mat|na) bata|huwag (mong )?sabihin (kanino|sa kahit)|walang makakaalam)'],
      prize: ['(?:انعام|جیت|لاٹری|इनाम|जीत|लॉटरी|inaam|jeet(a|e|ey)|lottery|nanalo ka|premyo|napanalunan|raffle)'],
      job: ['(?:نوکری|ملازمت|گھر بیٹھے|नौकरी|घर बैठे|naukri|ghar baithe|trabaho|work from home|sahod|part-?time job)'],
      hold: ['(?:پارسل (رک|روک)|کسٹم (فیس|ڈیوٹی)|पार्सल (रुक|अटक)|कस्टम (फीस|शुल्क)|parcel (ruk|atak)|na-?hold ang (parcel|package)|naharang ang (parcel|package)|kulang ang address)'],
      family: ['(?:نیا نمبر|میں .{0,12}(بیٹا|بھائی|دوست)|नया नंबर|मैं .{0,12}(बेटा|भाई|दोस्त)|naya number|bagong number|ako (to|ito) ang (anak|kapatid|kaibigan))'],
      chan: ['(?:واٹس ?ایپ|ٹیلیگرام|व्हाट्सऐप|टेलीग्राम|whatsapp|telegram|viber|messenger)(?=[^.\\n]{0,30}(?:پر|رابطہ|पर|संपर्क|contact|message|mag-?message))'],
      acct: ['(?:اس اکاؤنٹ میں|اس نمبر پر) (رقم )?(بھیج|ٹرانسفر)|इस (खाते|नंबर) (में|पर) (पैसे )?(भेज|ट्रांसफर)|(?:i-?transfer|ipadala) (sa|mo sa) (account|gcash|maya)'],
      advfee: ['(?:رجسٹریشن فیس|پروسیسنگ فیس|پیشگی (فیس|رقم)|रजिस्ट्रेशन फीस|प्रोसेसिंग फीस|अग्रिम (फीस|राशि)|registration fee|processing fee|paunang bayad|downpayment|fee para (sa|makuha))'],
      tech: ['(?:وائرس|ریموٹ|اینی ?ڈیسک|ٹیم ?ویور|वायरस|रिमोट|एनीडेस्क|टीमव्यूअर|anydesk|teamviewer|may virus|na-?hack)'],
      pay: ['(?:ادائیگی|فیس (جمع|ادا)|رقم (بھیج|جمع)|भुगतान|फीस (जमा|भरें)|पैसे (भेज|जमा)|fees? (jama|bharein)|bayaran|magbayad|bayad (na|ngayon)|ipadala ang bayad)'],
      bill: ['(?:ادائیگی (ناکام|مسترد)|سبسکرپشن (ختم|معطل)|स्टोरेज (भर|फुल)|भुगतान (विफल|असफल)|सब्सक्रिप्शन (समाप्त|बंद)|payment (fail|failed) (ho|hua)|nabigo ang (bayad|payment)|puno na ang storage|mabubura ang (iyong )?(mga )?(larawan|file))'],
      payupd: ['(?:کارڈ (کی )?(تفصیلات|معلومات) (اپ ?ڈیٹ|درج)|कार्ड (की )?(जानकारी|डिटेल) (अपडेट|दर्ज)|i-?update ang (iyong )?(payment|card|bayad))'],
      imp: ['(?:ابوظہبی پولیس|مرکزی بینک|अबू धाबी पुलिस|सेंट्रल बैंक|pulis ng abu dhabi)']
    };
    /* Persian, Amharic and Luganda wording (same merge-by-id mechanism). Persian: ZWNJ-tolerant, digits ۰-۹. */
    const Z = '[\\u200c ]?';
    const SECX_FA = '(?:رمز (?:یک ?بار ?مصرف|عبور|دوم|پویا|امنیتی|کارت)|رمز(?= را| خود| شما)|کد (?:تایید|فعال ?سازی|امنیتی|پیامک[یی]?)|پین|شماره کارت|اطلاعات (?:کارت|بانکی)|cvv2?|otp)';
    const VB_FA = '(?:ارسال|بفرست|بگو|اعلام|وارد|ثبت ?کن|در اختیار|به اشتراک|می' + Z + 'فرست|می' + Z + 'خواه|بدهید|بده)';
    const SECX_AM = '(?:otp|pin|cvv|password|ሚስጥር ቁጥር|የይለፍ ?ቃል|የማረጋገጫ ኮድ|ኮድ|ፒን|የካርድ (?:ቁጥር|ዝርዝር)|የባንክ (?:ዝርዝር|መረጃ))';
    const VB_AM = '(?:ላክ|ላኩ|ይላኩ|ንገር|ንገሩ|ይንገሩ|አጋራ|አጋሩ|ስጡ|ይስጡ|ስጠኝ|ያስገቡ|አስገባ)';
    const SECX_LG = '(?:\\botp\\b|\\bpin\\b|cvv|password|ekigambo ekikuumi|koodi|ebikwata ku (?:kaadi|banka)|namba ya kaadi)';
    const VB_LG = '(?:weereza|tuma|buulira|tubuulire|gabana|sindika|mpa|wandiika|saba)';
    const EXTRA2 = {
      cred: [
        '(?:' + SECX_FA + '[^.\\n]{0,40}?' + VB_FA + ')', '(?:' + VB_FA + '[^.\\n]{0,40}?' + SECX_FA + ')',
        '(?:' + SECX_AM + '[^.\\n]{0,40}?' + VB_AM + ')', '(?:' + VB_AM + '[^.\\n]{0,40}?' + SECX_AM + ')',
        '(?:' + SECX_LG + '[^.\\n]{0,40}?' + VB_LG + ')', '(?:' + VB_LG + '[^.\\n]{0,40}?' + SECX_LG + ')'
      ],
      update: ['(?:به' + Z + 'روز ?رسانی (?:حساب|اطلاعات)|احراز هویت|تایید (?:حساب|هویت)|فعال ?سازی (?:مجدد )?حساب|መለያ(?:ዎን|ህን|ሽን)? (?:አዘምን|ያዘምኑ|አረጋግጥ|ያረጋግጡ|ያግብሩ)|ddamu ebikwata|zuukiza akawunti|kakasa akawunti)'],
      urg: ['(?:فوری|فورا|بلافاصله|همین (?:حالا|الان)|ظرف [\\d۰-۹]+ (?:ساعت|دقیقه|روز)|تا [\\d۰-۹]+ ساعت|አስቸኳይ|ወዲያውኑ|አሁኑኑ|በ\\d+ (?:ሰዓት|ሰአት|ደቂቃ|ቀን) ውስጥ|amangu|mu bwangu|mangu ddala|kati ddala|mu ssaawa \\d+|mu ddakiika \\d+)'],
      threat: ['(?:مسدود (?:می' + Z + 'شود|خواهد شد|شد)|مسدودی|تعلیق|معلق|بلوکه|توقیف|جریمه|دستگیر|بازداشت|ይታገዳል|ይዘጋል|ታግዷል|ይቀዘቅዛል|ይታሰራ|ቅጣት|ejja (?:kuggalwa|kukwatibwa|kuyimirizibwa)|ojja kusibibwa|okusibibwa|engassi)'],
      secret: ['(?:به (?:هیچ ?کس|کسی) (?:نگو|نگویید|نگین)|محرمانه|ለማንም (?:አትንገር|አትንገሩ|እንዳትነግር|እንዳትነግሩ)|ሚስጥር|tobuulira (?:muntu|yenna)|kuuma ekyama)'],
      prize: ['(?:جایزه|برنده (?:شده|شدید)|قرعه ?کشی|بخت ?آزمایی|لاتاری|ሽልማት|አሸንፈዋል|አሸናፊ|ዕጣ|እጣ|ሎተሪ|ekirabo|wawangudde|owangudde|obululu|lottery)'],
      job: ['(?:فرصت شغلی|کار در منزل|درآمد (?:بالا|میلیونی|روزانه)|سود (?:تضمین|تضمینی|روزانه)|የሥራ (?:ማስታወቂያ|ዕድል)|ከቤት ሆነው|የተረጋገጠ ትርፍ|በየቀኑ ትርፍ|amagoba (?:agakakasibwa|buli lunaku)|okussa ssente|omulimu ogw[’\\x27]okukola mu maka)'],
      hold: ['(?:بسته (?:شما )?(?:متوقف|نگه|مرجوع)|هزینه (?:گمرک|ترخیص|پست)|آدرس (?:ناقص|نامعتبر)|እሽግ (?:ታግዷል|ተይዟል|ተያዘ)|የጉምሩክ (?:ክፍያ|ቀረጥ)|አድራሻ (?:ያልተሟላ|ጎድሏል)|ekipapula (?:kikwatiddwa|kiyimiridde)|endagiriro etali nnambulukufu)'],
      family: ['(?:شماره (?:ی )?جدید(?:م)?|گوشی ?ام (?:خراب|شکست)|አዲስ ቁጥር|አዲሱ ቁጥሬ|ስልኬ (?:ተበላሽቷል|ጠፍቷል)|namba yange empya|ssimu yange (?:emenyese|ebuze))'],
      chan: ['(?:واتس ?اپ|تلگرام)(?=[^.\\n]{0,30}(?:پیام|تماس|ارتباط|بفرست|مراجعه))|(?:ዋትስአፕ|ቴሌግራም)(?=[^.\\n]{0,30}(?:ያነጋግሩ|ይላኩ|መልእክት|ይደውሉ))|(?:whatsapp|telegram)(?=[^.\\n]{0,30}(?:tuukirira|tuma|kuba|ssimu))'],
      acct: ['(?:به (?:این )?(?:حساب|شماره حساب|شماره کارت)[^.\\n]{0,20}(?:واریز|انتقال|بفرست)|ወደ (?:ዚህ|ይህ) (?:መለያ|ቁጥር|አካውንት) (?:ገንዘብ )?(?:ላክ|ላኩ|አስተላልፍ|አስተላልፉ)|sindika ssente (?:ku|mu) (?:akawunti|namba)|teeka ssente mu akawunti)'],
      advfee: ['(?:هزینه (?:ثبت ?نام|پردازش|ویزا|ترخیص)|حق ?ثبت ?نام|پیش ?پرداخت|የምዝገባ ክፍያ|የማስኬጃ ክፍያ|ቅድመ ክፍያ|የቪዛ ክፍያ|ffiizi y[’\\x27]okuwandiisa|ssente ezisooka)'],
      tech: ['(?:ویروس|هک (?:شده|شد)|اینی ?دسک|تیم ?ویور|ቫይረስ|የርቀት መዳረሻ|ተጠልፏል|akawuka)'],
      pay: ['(?:پرداخت (?:کنید|نمایید|فوری)|واریز (?:کنید|نمایید)|کارمزد|ክፍያ (?:ይክፈሉ|ይፈጽሙ|ያድርጉ)|ይክፈሉ|ገንዘብ (?:ላኩ|ላክ|አስተላልፉ)|sasula (?:kati|mangu|ssente|ffiizi)|sindika ssente|ffiizi)'],
      bill: ['(?:پرداخت (?:ناموفق|رد شد)|اشتراک (?:شما )?(?:منقضی|به پایان|تمام)|فضای (?:ذخیره|ذخیره' + Z + 'سازی) (?:پر|تمام)|ክፍያ (?:አልተሳካም|ወድቋል)|ማከማቻ (?:ሞልቷል|ሞላ)|okusasula (?:kulemeddwa|kuremye)|ekifo ky[’\\x27]okutereka kijjudde)'],
      payupd: ['(?:اطلاعات (?:کارت|پرداخت) (?:را )?(?:به' + Z + 'روز|وارد)|የካርድ (?:መረጃ|ዝርዝር) (?:ያዘምኑ|ያስገቡ)|ddamu ebikwata ku kaadi|kyusa ebikwata ku kaadi)'],
      imp: ['(?:پلیس ابوظبی|بانک مرکزی|የአቡ ዳቢ ፖሊስ|ማዕከላዊ ባንክ|poliisi ya abu dhabi|banka enkulu)']
    };
    Object.keys(EXTRA2).forEach(k => { EXTRA[k] = (EXTRA[k] || []).concat(EXTRA2[k]); });
    RULES.forEach(r => {
      const x = EXTRA[r.id]; if (!x) return;
      r.re = new RegExp(r.re.source + '|' + x.join('|'), r.re.flags.indexOf('g') >= 0 ? r.re.flags : r.re.flags + 'g');
    });
    const AXES = { sens: [['طلب بيانات حساسة', 'Sensitive data request'], 42], press: [['ضغط وتهديد', 'Pressure & threats'], 45], lure: [['إغراء مالي', 'Financial lure'], 48], imp: [['انتحال صفة', 'Impersonation'], 47], money: [['طلب أموال', 'Money request'], 15], link: [['رابط خطِر', 'Risky link'], 60], ai: [['التلاعب بأداة الفحص', 'Manipulating the checker'], 60] };

    /* ===== registry-derived sets ===== */
    const OFFICIAL = Array.from(new Set(R.official.concat(...R.entities.map(e => e.d))));
    const ENT = R.entities.map(e => Object.assign({}, e, { rx: new RegExp(e.re) }));
    function isGov(h) { return R.govSuffixes.some(g => h === g || h.endsWith('.' + g)); }
    function isOfficial(h) { return OFFICIAL.some(o => h === o || h.endsWith('.' + o)); }
    function regDomain(h) { const p = h.split('.'); if (p.length >= 3 && ['gov', 'ac', 'co', 'net', 'org', 'sch', 'mil', 'com'].includes(p[p.length - 2]) && p[p.length - 1].length === 2) return p.slice(-3).join('.'); return p.slice(-2).join('.'); }
    function lev(a, b) { const m = []; for (let i = 0; i <= a.length; i++) m[i] = [i]; for (let j = 1; j <= b.length; j++) m[0][j] = j; for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++) m[i][j] = Math.min(m[i - 1][j] + 1, m[i][j - 1] + 1, m[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)); return m[a.length][b.length]; }
    function brandIn(host, path) {
      const toks = (host + '/' + path).toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
      const joined = host.toLowerCase().replace(/[^a-z0-9]/g, '');
      return R.brandTokens.find(b => { const bb = b.replace(/[^a-z0-9]/g, ''); return toks.includes(bb) || (bb.length >= 7 && joined.includes(bb)); });
    }

    /* ===== URL engine ===== */
    function analyzeUrl(raw) {
      let s = raw.trim(); if (!s) return null; const flags = []; let score = 0;
      if (!/^[a-z]+:\/\//i.test(s)) s = 'http://' + s;
      let u; try { u = new URL(s); } catch (e) { return { score: 40, flags: [{ l: T('الرابط غير صالح أو مشوَّه عمدًا', 'The link is invalid or deliberately malformed'), w: 40 }], host: raw, evidence: [] }; }
      const host = u.hostname.toLowerCase().replace(/^www\./, '').replace(/\.$/, ''), reg = regDomain(host);
      const add = (w, a, e) => { score += w; flags.push({ l: T(a, e), w }); };
      if (isGov(host)) return { score: 0, flags: [{ l: T('نطاق حكومي مقيَّد (', 'Government-restricted domain (') + reg + T(') — لا يستطيع تسجيله إلا جهة حكومية', ') — only a government body can register it'), w: 0, good: true }], host, reg, official: true, gov: true, evidence: [{ id: 'dom', st: 'ok', t: T('النطاق', 'Domain'), v: host + ' · ' + T('حكومي مقيَّد', 'government-restricted') }] };
      if (isOfficial(host)) return { score: 0, flags: [{ l: T('النطاق يطابق موقعًا رسميًا معروفًا (', 'The domain matches a known official site (') + reg + ')', w: 0, good: true }], host, reg, official: true, evidence: [{ id: 'dom', st: 'ok', t: T('النطاق', 'Domain'), v: host + ' · ' + T('رسمي معروف', 'known official') }] };
      if (u.protocol !== 'https:') add(10, 'الاتصال غير مشفّر (لا يبدأ بـ https)', 'Unencrypted connection (doesn’t start with https)');
      if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) add(35, 'يستخدم عنوان IP بدل اسم نطاق', 'Uses a raw IP address instead of a domain name');
      if (host.includes('xn--')) add(30, 'حروف مموَّهة (Punycode) تقلّد اسمًا معروفًا', 'Disguised characters (Punycode) mimicking a known name');
      if (R.shorteners.includes(host)) add(25, 'رابط مختصر يخفي الوجهة الحقيقية', 'Shortened link hides the real destination');
      const tld = host.split('.').pop(); if (R.highRiskTlds.includes(tld)) add(35, 'امتداد نطاق شديد الارتباط بحملات الاحتيال (.' + tld + ')', 'Domain extension heavily tied to scam campaigns (.' + tld + ')'); else if (R.badTlds.includes(tld)) add(20, 'امتداد نطاق شائع في حملات الاحتيال (.' + tld + ')', 'Domain extension common in scam campaigns (.' + tld + ')');
      const hb = brandIn(host, u.pathname);
      if (hb) add(35, 'يستخدم اسم جهة معروفة (' + hb + ') في رابط غير رسمي', 'Uses a known brand name (' + hb + ') in an unofficial link');
      if (/gov.?ae/.test(host) && !host.endsWith('.gov.ae')) add(25, 'يقلّد صيغة النطاق الحكومي gov.ae دون أن يكون حكوميًا', 'Imitates the gov.ae government format without being one');
      const core = reg.split('.')[0];
      const near = OFFICIAL.map(o => [o, lev(core, o.split('.')[0])]).filter(([o, d]) => d > 0 && d <= 2 && core.length > 4).sort((a, b) => a[1] - b[1])[0];
      if (near) add(30, 'اسم النطاق قريب جدًا من ' + near[0] + ' (تشابه حرفي مقصود)', 'Domain name is very close to ' + near[0] + ' (deliberate look-alike)');
      if (/[a-z]/.test(core) && /[0135]/.test(core) && !/^\d/.test(core)) add(8, 'أرقام تحل محل حروف في اسم النطاق', 'Digits replacing letters in the domain name');
      if ((host.match(/-/g) || []).length >= 2) add(10, 'عدة شرطات في اسم النطاق', 'Several hyphens in the domain name');
      if (host.split('.').length >= 5) add(10, 'نطاقات فرعية كثيرة لإخفاء الاسم الحقيقي', 'Many subdomains hiding the real name');
      if (u.username || raw.includes('@')) add(25, 'يحتوي رمز @ لتضليل الوجهة', 'Contains @ to disguise the destination');
      if (/(login|signin|verify|update|secure|account|pay|payment|otp|wallet|fine|customs|refund)/i.test(u.pathname + u.search)) add(10, 'المسار يحتوي كلمات دخول أو دفع أو تحقق', 'Path contains login, payment or verification words');
      if (s.length > 120) add(5, 'رابط طويل بشكل غير معتاد', 'Unusually long link');
      /* decisive: embedding an official/famous domain inside an unrelated one, or an official brand name in a non-official domain */
      const embeds = OFFICIAL.concat(R.govSuffixes.filter(g => g.includes('.')), R.globalBrands).find(o => host.includes(o + '.') || host.includes('.' + o + '.'));
      let decisive = false;
      if (embeds) { add(40, 'يضع نطاقًا رسميًا معروفًا (' + embeds + ') داخل نطاق مختلف لخداعك', 'Puts a well-known official domain (' + embeds + ') inside a different domain to fool you'); decisive = true; }
      if (hb && !R.softBrands.includes(hb)) decisive = true;
      if (near && (near[1] === 1 || core.length >= 9)) decisive = true;
      if (decisive) score = Math.max(score, 62);
      const risky = flags.length > 0;
      if (!risky) flags.push({ l: T('لم تظهر علامات خطر، لكن لا يمكن تأكيد أن النطاق رسمي: ', 'No risk signs found, but the domain can’t be confirmed as official: ') + host, w: 0, neutral: true, tip: T('تأكد من الجهة عبر رقمها أو تطبيقها الرسمي قبل إدخال أي بيانات.', 'Confirm with the organisation through its official number or app before entering any details.') });
      return { score: Math.min(100, score), flags, host, reg, unverified: !risky, decisive, evidence: [{ id: 'dom', st: risky ? 'bad' : 'unk', t: T('النطاق', 'Domain'), v: host + ' · ' + (risky ? T('علامات مريبة', 'suspicious signs') : T('غير مؤكَّد كرسمي', 'not confirmed official')) }], pending: [host], pendingUrl: u.href };
    }
    const URL_RE = /((https?:\/\/)|www\.)[^\s]+|\b[a-z0-9-]+(\.[a-z0-9-]+)*\.(com|ae|net|org|xyz|top|click|live|shop|info|site|online|vip|me|ly|cc|co|io|help|link|support|cfd|today|life|store|fit|quest|bond|sbs|cyou|icu|buzz|rest|work|win|loan|pw|zip|gov|sa|kw|qa|om|bh|eg|uk|in)(\/[^\s]*)?/gi;

    /* ===== sender check ===== */
    const COURIER = ['empost', 'aramex', 'dhl', 'fedex', 'ups', 'smsa'];
    function senderInfo(raw) {
      const v = (raw || '').trim(); if (!v) return null;
      const dg = v.replace(/[\s()\-.]/g, '');
      if (/^(\+|00)?\d{7,15}$/.test(dg)) {
        const d = dg.replace(/^(\+|00)/, '');
        if (/^(971|0)?(800|600)\d+$/.test(d)) return { k: 'service', v };
        if (/^(971|0)?5[024568]\d{7}$/.test(d)) return { k: 'mobile', v };
        if (/^(971|0)?[234679]\d{7}$/.test(d)) return { k: 'landline', v };
        return { k: 'foreign', v };
      }
      if (/^\d{3,6}$/.test(dg)) return { k: 'short', v };
      return { k: 'alpha', v };
    }
    function senderMatches(e, v) {
      const a = v.toLowerCase().replace(/[^a-z0-9ء-ي]/g, '');
      const keys = [e.id].concat(e.d.map(x => x.split('.')[0]), e.n[1].toLowerCase().split(/[^a-z0-9]+/).filter(w => w.length > 2));
      return keys.some(k => k.length > 1 && a.includes(k.toLowerCase().replace(/[^a-z0-9]/g, '')));
    }

    /* ===== message engine ===== */
    function analyzeMsg(txt, opts) {
      opts = opts || {};
      const { s, map } = normMap(txt); const flags = [], ranges = [], axes = {}; let score = 0;
      /* 1) links first: hard evidence about where the message leads */
      const links = []; const re = new RegExp(URL_RE.source, 'gi'); let m;
      while ((m = re.exec(txt))) { const raw = m[0].replace(/[.,;:!؟،)\]]+$/, ''); const r = analyzeUrl(raw); if (r) { links.push(Object.assign(r, { raw })); if (!r.official && r.score >= 20) ranges.push([m.index, m.index + raw.length]); } }
      const bad = links.filter(l => !l.official), allVerified = links.length > 0 && bad.length === 0;
      /* 2) wording rules */
      const hits = [];
      RULES.forEach(r => {
        const g = new RegExp(r.re.source, 'g'); let mm, hit = false;
        while ((mm = g.exec(s))) {
          if (!mm[0].length) { g.lastIndex++; continue; }
          if (r.neg && r.neg.test(s.slice(Math.max(0, mm.index - 25), mm.index))) continue;
          if (r.skipIf && r.skipIf.test(s)) continue;
          hit = true; ranges.push([map[mm.index], map[mm.index + mm[0].length - 1] + 1]);
        }
        if (hit) hits.push(r);
      });
      const strong = hits.filter(r => !r.withOthers);
      hits.forEach(r => {
        if (r.withOthers && (allVerified || !strong.length)) return;
        score += r.w; axes[r.ax] = (axes[r.ax] || 0) + r.w; flags.push({ l: TX(r.l[LI()]), w: r.w, tip: TX(r.tip[LI()]), rule: r.id });
      });
      /* 3) link evidence */
      const worst = bad.slice().sort((a, b) => b.score - a.score)[0];
      if (allVerified) flags.push({ l: T('الرابط يعود لنطاق رسمي موثّق: ', 'The link belongs to a verified official domain: ') + links[0].host, w: 0, good: true });
      if (worst) {
        if (worst.score > 0) { const w = Math.max(10, Math.round(worst.score * .6)); score += w; axes.link = worst.score; flags.push({ l: T('يحتوي رابطًا مشبوهًا: ', 'Contains a suspicious link: ') + worst.host, w, tip: worst.flags.map(f => f.l).join(T('، ', '; ')), rule: 'link' }); }
        else flags.push({ l: T('رابط لا يمكن تأكيد أنه رسمي: ', 'A link that can’t be confirmed as official: ') + worst.host, w: 0, neutral: true, tip: T('لا علامات خطر ظاهرة فيه، لكن تأكد من الجهة عبر قناتها الرسمية.', 'No visible risk signs, but confirm with the organisation through its official channel.') });
      }
      /* 4) decisive evidence: names an organisation but the link is not that organisation's domain */
      let mism = null;
      if (bad.length) { const e = ENT.find(x => x.rx.test(s)); if (e) mism = { e, l: bad[0] }; }
      const evidence = [];
      links.slice(0, 3).forEach(l => evidence.push(l.evidence[0]));
      if (mism) {
        const w = mism.e.soft ? 20 : 35; score += w; axes.link = Math.max(axes.link || 0, mism.e.soft ? 50 : 80); axes.imp = (axes.imp || 0) + w;
        flags.unshift({ l: T('الرسالة تنسب نفسها إلى ' + mism.e.n[0] + ' لكن الرابط (' + mism.l.host + ') ليس نطاقها الرسمي', 'The message claims to be from ' + mism.e.n[1] + ' but its link (' + mism.l.host + ') is not its official domain'), w, tip: T('النطاقات الرسمية لهذه الجهة: ', 'Official domains of this organisation: ') + mism.e.d.join(', '), rule: 'mism' });
        evidence.push({ id: 'match', st: 'bad', t: T('تطابق الجهة والرابط', 'Organisation ↔ link'), v: TX(mism.e.n[LI()]) + ' ≠ ' + mism.l.host });
      } else if (allVerified) {
        const e = ENT.find(x => x.rx.test(s));
        if (e) evidence.push({ id: 'match', st: 'ok', t: T('تطابق الجهة والرابط', 'Organisation ↔ link'), v: TX(e.n[LI()]) + ' ✓' });
      }
      const sens = flags.some(f => f.rule === 'cred' || f.rule === 'update' || f.rule === 'payupd'), money = flags.some(f => f.rule === 'pay');
      evidence.push({ id: 'ask', st: sens || money ? 'bad' : 'ok', t: T('طلب بيانات أو أموال', 'Asks for data or money'), v: sens || money ? (sens ? T('يطلب بيانات حساسة', 'asks for sensitive data') : T('يطلب دفعًا', 'asks for payment')) : T('لا يوجد', 'none') });
      /* sender evidence (optional field) */
      const snd = senderInfo(opts.sender), entHit = ENT.find(x => x.rx.test(s));
      let sndFloor = 0;
      if (snd) {
        const personal = snd.k === 'mobile' || snd.k === 'foreign';
        const kindTxt = { mobile: T('رقم جوال شخصي', 'a personal mobile number'), foreign: T('رقم أجنبي', 'a foreign number'), landline: T('رقم أرضي', 'a landline'), service: T('رقم خدمة (800/600)', 'a service number (800/600)'), short: T('رمز قصير', 'a short code'), alpha: T('اسم مرسل نصّي', 'a text sender ID') }[snd.k];
        const GEN_ORG = /(شرطه|الداخليه|وزاره|النيابه|المحكمه|القضاء|الجمارك|الضرايب|الضرائب|البنك|مصرف|حسابك|بطاقتك|الاتصالات|بريد|police|prosecut|ministry|court|customs|\bbank\b|your account|your card|telecom|courier|government)/;
        if (!entHit && personal && GEN_ORG.test(s)) {
          const w = 35; score += w; axes.imp = (axes.imp || 0) + w;
          flags.unshift({ l: T('يدّعي صفة جهة رسمية أو بنك لكنه يتصل أو يراسل من ' + kindTxt, 'Claims to be an official body or bank but is using ' + kindTxt), w, tip: T('الشرطة والبنوك لا تطلب منك مالًا أو رمزًا عبر مكالمة من رقم جوال شخصي. أنهِ المكالمة واتصل بالجهة على رقمها الرسمي.', 'Police and banks do not ask for money or codes in a call from a personal mobile number. Hang up and call the organisation on its official number.'), rule: 'sndr' });
          evidence.push({ id: 'sender', st: 'bad', t: T('المرسل', 'Sender'), v: snd.v + ' · ' + kindTxt });
          sndFloor = 70;
        } else if (entHit && personal) {
          const strict = !entHit.soft && !COURIER.includes(entHit.id), w = strict ? 35 : 10;
          score += w; axes.imp = (axes.imp || 0) + w;
          flags.unshift({ l: T('الرسالة تنسب نفسها إلى ' + entHit.n[0] + ' لكنها وصلت من ' + kindTxt, 'The message claims to be from ' + entHit.n[1] + ' but came from ' + kindTxt), w, tip: T('البنوك والجهات الرسمية ترسل باسم معرِّف مسجَّل لا من أرقام جوالات.', 'Banks and official bodies send under a registered sender name, not from mobile numbers.'), rule: 'sndr' });
          evidence.push({ id: 'sender', st: strict ? 'bad' : 'warn', t: T('المرسل', 'Sender'), v: snd.v + ' · ' + kindTxt });
          if (strict) sndFloor = 85;
        } else if (entHit && snd.k === 'alpha') {
          const ok = senderMatches(entHit, snd.v);
          evidence.push({ id: 'sender', st: ok ? 'unk' : 'warn', t: T('المرسل', 'Sender'), v: snd.v + ' · ' + (ok ? T('يطابق الجهة، لكن الأسماء قابلة للتزوير', 'matches the organisation, but sender names can be spoofed') : T('لا يطابق اسم الجهة', 'does not match the organisation’s name')) });
        } else evidence.push({ id: 'sender', st: 'unk', t: T('المرسل', 'Sender'), v: snd.v + ' · ' + kindTxt });
      }
      const others = flags.filter(f => f.w > 0 && !['mism', 'imp', 'link', 'sndr'].includes(f.rule)).length;
      if (flags.filter(f => f.w > 0).length >= 3) score += 10;
      if (mism && !mism.e.soft) score = Math.max(score, others ? 90 : 62);
      if (sndFloor) score = Math.max(score, others ? 92 : sndFloor);
      /* convergence: independent scam signals that rarely coexist in genuine messages */
      const ids = new Set(flags.filter(f => f.w > 0).map(f => f.rule)), has = (...a) => a.some(x => ids.has(x));
      const linkScore = worst ? worst.score : 0;
      if (linkScore >= 60) score = Math.max(score, linkScore);
      if (linkScore >= 20 && (others >= 1 || mism)) score = Math.max(score, 62);
      /* prompt injection / addressing the checker: genuine senders never do this */
      if (has('inj')) score = Math.max(score, 70);
      if (has('cred', 'credx') && has('urg', 'threat', 'secret')) score = Math.max(score, 70);
      if (has('credx')) score = Math.max(score, 62);
      if (has('family') && has('pay', 'urg')) score = Math.max(score, 62);
      if (has('acct') && has('pay')) score = Math.max(score, 62);
      if (has('advfee') && has('pay') && /(job|offer|visa|vacanc|prize|winner|وظيف|تاشير|جائز|عرض)/.test(s)) score = Math.max(score, 62);
      if (has('prize', 'job', 'rent', 'hold') && has('pay')) score = Math.max(score, 62);
      /* billing / subscription / storage / account-lock lures (often a screenshot with a button and no visible link):
         a pretext + a request to act, with no pointer to the official app/settings, rarely comes from a genuine company */
      const officialRef = /(in (the )?settings|settings ?>|(in|via|from|using|through|open) (the )?(official )?([a-z0-9+&]+ ){0,2}app\b|app store app|من (خلال )?(ال)?تطبيق|عبر (ال)?تطبيق|في (ال)?تطبيق|(افتح|من|في) (ال)?اعدادات)/.test(s);
      const cta = /(click|tap|press|upgrade|renew|update|verify|confirm|claim|get|restore|resume|unlock|reactivate)\b[^.\n]{0,25}\b(now|here|below|button|today|account|storage|access|watching|method|free)|\b(update|fix|verify|confirm|pay) (it|them|now)\b|اضغط|انقر|اضغط هنا|للترقيه|رقي|استعاده|استعد/.test(s);
      if (!allVerified && !officialRef) {
        if (has('payupd') && has('bill', 'threat', 'urg')) score = Math.max(score, 72);
        else if (has('payupd') && cta) score = Math.max(score, 62);
        if (has('bill') && has('update', 'cred', 'credx', 'threat', 'urg', 'pay')) score = Math.max(score, 62);
        if (has('bill') && cta) score = Math.max(score, 62);
        if (has('update') && has('threat')) score = Math.max(score, 62);
        /* fake renewal / refund callback: "renewed for 1,499 AED — if you did not authorise this, call our refund team" */
        if (has('bill') && /((did not|didn'?t|not) (authori[sz]e|make|recogni[sz]e|order|request|place)[^.\n]{0,60}(call|contact|reach|refund)|refund (team|department|desk|center|centre)|(لم تقم|لم تطلب)[^.\n]{0,40}(اتصل|تواصل))/.test(s)) score = Math.max(score, 62);
      } else if (officialRef && !allVerified) {
        /* the message itself sends you to the official app/settings: a billing pretext alone is not proof of a scam */
        const soft = ['bill', 'payupd', 'update', 'urg', 'link', 'hold'];
        if (flags.filter(f => f.w > 0).every(f => soft.includes(f.rule)) && linkScore < 30) score = Math.min(score, 45);
      }
      const out = { score: Math.min(100, score), flags, ranges, axes, text: txt, evidence };
      if (allVerified && out.score < 25) {
        /* every link is an exact verified official domain and nothing serious was found: a trusted site scores 0 (weak wording cues such as "congratulations" are dropped, not counted) */
        out.verified = true; out.score = 0; out.flags = flags.filter(f => !(f.w > 0));
      }
      const pend = Array.from(new Set(bad.map(l => l.host))).slice(0, 3);
      if (pend.length) { out.pending = pend; out.pendingUrl = (bad.find(l => l.host === pend[0]) || bad[0]).raw; }
      return out;
    }

    /* ===== external facts (domain age, reputation) merged into a result ===== */
    const WEAK_LISTS = ['Phishunt', 'PhishDestroy', 'Scam-Blocklist'];
    function applyFacts(res, facts) {
      const r = Object.assign({}, res, { flags: res.flags.slice(), evidence: (res.evidence || []).filter(e => e.st !== 'load'), axes: Object.assign({}, res.axes || {}) });
      let add = 0, floor = 0;
      (facts || []).forEach(f => {
        if (!f || !f.d) return;
        const gThreat = f.sb === 'threat' || f.wr === 'threat', gClean = !gThreat && (f.sb === 'clean' || f.wr === 'clean');
        const lists = Array.isArray(f.fd) ? f.fd : null;
        if (gThreat) {
          add += 60; floor = Math.max(floor, 92); r.axes.link = 100;
          r.flags.unshift({ l: T('نطاق مُبلَّغ عنه في قاعدة بيانات التصفح الآمن (Google): ', 'Domain flagged by Google Safe Browsing: ') + f.d, w: 60, rule: 'sb' });
          r.evidence.push({ id: 'sb', st: 'bad', t: T('سمعة الرابط (Google)', 'Link reputation (Google)'), v: f.d + ' · ' + T('مُبلَّغ عنه', 'flagged') });
        } else if (gClean) {
          r.evidence.push({ id: 'sb', st: 'ok', t: T('سمعة الرابط (Google)', 'Link reputation (Google)'), v: T('لا بلاغات معروفة', 'no known reports') });
        }
        const weak = lists ? lists.filter(n => WEAK_LISTS.includes(n)) : [], strongL = lists ? lists.filter(n => !WEAK_LISTS.includes(n)) : [];
        const oldClean = typeof f.age === 'number' && f.age >= 1095 && gClean;      /* community lists are noisier: an old domain Google calls clean is not condemned by them alone */
        if (strongL.length) {
          if (!gThreat) { add += 60; floor = Math.max(floor, 90); r.axes.link = 100; r.flags.unshift({ l: T('النطاق مدرج في قوائم التصيّد العامة: ', 'Domain listed on public phishing lists: ') + f.d + ' (' + lists.join(', ') + ')', w: 60, rule: 'sb' }); }
          r.evidence.push({ id: 'lists', st: 'bad', t: T('قوائم التهديدات العامة', 'Public threat lists'), v: f.d + ' · ' + lists.join(', ') });
        } else if (weak.length && !oldClean) {
          if (!gThreat) { add += 35; floor = Math.max(floor, 62); r.axes.link = Math.max(r.axes.link || 0, 85); r.flags.unshift({ l: T('النطاق مدرج في قوائم مجتمعية للاحتيال: ', 'Domain listed on community scam lists: ') + f.d + ' (' + weak.join(', ') + ')', w: 35, rule: 'lists' }); }
          r.evidence.push({ id: 'lists', st: 'bad', t: T('قوائم التهديدات العامة', 'Public threat lists'), v: f.d + ' · ' + weak.join(', ') });
        } else if (weak.length) {
          r.evidence.push({ id: 'lists', st: 'warn', t: T('قوائم التهديدات العامة', 'Public threat lists'), v: T('مدرج في قائمة مجتمعية (' + weak.join(', ') + ') لكنه قديم وسمعته عند Google نظيفة — لا يُعتدّ به وحده', 'on a community list (' + weak.join(', ') + ') but old and Google-clean — not counted against it on its own') });
        } else if (lists) {
          r.evidence.push({ id: 'lists', st: 'ok', t: T('قوائم التهديدات العامة', 'Public threat lists'), v: T('غير مدرج', 'not listed') });
        }
        if (typeof f.age === 'number') {
          const d = f.age, yrs = d / 365;
          const txt = d >= 365 ? yrs.toFixed(1) + T(' سنة', ' years') : d + T(' يومًا', ' days');
          if (d < 30) { add += 30; r.axes.link = Math.max(r.axes.link || 0, 70); r.flags.unshift({ l: T('نطاق مسجَّل حديثًا جدًا (', 'Very recently registered domain (') + f.d + T(') منذ ', ') ') + txt + T('', ' ago'), w: 30, tip: T('مواقع الاحتيال تُسجَّل عادةً قبل الحملة بأيام.', 'Scam sites are usually registered days before a campaign.'), rule: 'age' }); r.evidence.push({ id: 'age', st: 'bad', t: T('عمر النطاق', 'Domain age'), v: txt }); }
          else if (d < 180) { add += 18; r.axes.link = Math.max(r.axes.link || 0, 50); r.flags.unshift({ l: T('نطاق حديث التسجيل (', 'Recently registered domain (') + f.d + T(') منذ ', ') ') + txt + T('', ' ago'), w: 18, rule: 'age' }); r.evidence.push({ id: 'age', st: 'warn', t: T('عمر النطاق', 'Domain age'), v: txt }); }
          else r.evidence.push({ id: 'age', st: 'ok', t: T('عمر النطاق', 'Domain age'), v: txt });
        } else if (f.age === null) r.evidence.push({ id: 'age', st: 'unk', t: T('عمر النطاق', 'Domain age'), v: T('غير متاح لهذا الامتداد', 'not published for this extension') });
      });
      r.score = Math.min(100, Math.max(floor, res.score + add));
      return r;
    }


    /* ===== what actually happens when the link is opened ===== */
    function applyOpen(res, o) {
      const r = Object.assign({}, res, { flags: res.flags.slice(), evidence: (res.evidence || []).filter(e => e.id !== 'open' && e.id !== 'load') });
      const row = (st, v) => r.evidence.push({ id: 'open', st, t: T('فتح الرابط فعليًا', 'Opening the link'), v });
      if (!o || !o.ok) { row('unk', T('تعذّر فتحه من الخادم (محجوب أو بطيء أو لا يعمل) — لا يغيّر الحكم', 'could not be opened (blocked, slow or down) — verdict unchanged')); return r; }
      const fh = o.host, chain = (o.hops || []).map(h => h.host).filter((h, i, a) => i === 0 || h !== a[i - 1]);
      const fin = analyzeUrl(o.url), off = !!(fin && fin.official);
      const hard = (r.flags || []).some(f => f.w > 0 && ['cred', 'credx', 'pay', 'payupd', 'bill', 'advfee', 'secret', 'family', 'acct', 'threat', 'sndr', 'sb', 'lists'].includes(f.rule));
      if (chain.length > 1) row(off ? 'ok' : 'warn', chain.join(' → '));
      if (off) {
        if (!hard) {
          r.flags = r.flags.filter(f => f.rule && f.rule !== 'link' && f.rule !== 'age' && !f.neutral);
          r.flags.unshift({ l: T('الرابط يفتح فعليًا على نطاق رسمي موثّق: ', 'The link really opens on a verified official domain: ') + fh, w: 0, good: true, rule: 'open' });
          r.score = Math.min(r.score, 18); r.verified = true; delete r.unverified;
        }
        row('ok', T('الوجهة النهائية نطاق رسمي: ', 'final destination is an official domain: ') + fh + (o.title ? ' · ' + o.title : ''));
        return r;
      }
      let add = 0, floor = 0;
      if (o.pw || o.sens) { add += 35; floor = Math.max(floor, 62); r.flags.unshift({ l: T('الصفحة المفتوحة تطلب كلمة مرور أو بيانات بطاقة أو رمز تحقق وهي على نطاق غير رسمي: ', 'The opened page asks for a password, card details or an OTP on a non-official domain: ') + fh, w: 35, rule: 'link' }); }
      const tt = normMap(o.title || '').s;
      const imp = tt && ENT.find(e => e.rx.test(tt) && !e.d.some(d => fh === d || fh.endsWith('.' + d)));
      if (imp) { add += 40; floor = Math.max(floor, 70); r.flags.unshift({ l: T('عنوان الصفحة يدّعي أنها «', 'The page title claims to be “') + TX(imp.n[LI()]) + T('» لكن النطاق الحقيقي غير رسمي: ', '” but the real domain is not official: ') + fh, w: 40, rule: 'mism' }); }
      row(add ? 'bad' : 'unk', (o.title ? '«' + o.title + '» · ' : '') + fh + ' · ' + (o.pw || o.sens ? T('تطلب بيانات حساسة', 'asks for sensitive data') : T('لا نموذج دخول ظاهر — الفتح وحده لا يثبت الأمان', 'no login form seen — opening alone does not prove safety')));
      r.score = Math.min(100, Math.max(floor, res.score + add));
      return r;
    }

    /* ===== merge an AI verdict into a local result (conservative) ===== */
    /* verifiable evidence = something we can check ourselves, not just a model's impression */
    const HARD = ['mism', 'sb', 'age', 'link', 'sndr', 'lists', 'cred', 'credx', 'pay', 'payupd', 'bill', 'advfee', 'secret', 'family', 'acct', 'threat', 'inj'];
    function hardEvidence(res) { return (res.flags || []).some(f => f.w > 0 && HARD.includes(f.rule)); }
    function applyAi(res, j) {
      const r = Object.assign({}, res, { flags: res.flags.slice(), evidence: (res.evidence || []).filter(e => e.st !== 'load') });
      let a = Math.max(0, Math.min(100, Math.round(+j.score || 0)));
      if (res.verified && a < 60 && !hardEvidence(res)) {
        /* trusted-domain rule, applied on every path (server AI, on-device AI, screenshot): every link is an exact verified official domain, so the model's impression is not shown as suspicion */
        j.score = a = 0; j.verdict = T('آمن غالبًا', 'Likely safe'); j.type = T('ليست احتيالًا', 'Not a scam'); j.red_flags = [];
        j.explanation = T('كل الروابط في هذه الرسالة تعود لنطاقات رسمية موثّقة، ولا تطلب بيانات حساسة أو دفعًا.', 'Every link in this message belongs to a verified official domain, and no sensitive data or payment is requested.');
      }
      r.evidence.push({ id: 'ai', st: a >= 60 ? 'bad' : a >= 25 ? 'warn' : 'ok', t: T('تحليل الذكاء الاصطناعي', 'AI analysis'), v: String(j.verdict || '') + ' · ' + a + '/100' });
      const hard = hardEvidence(res);
      if (a >= 60 && hard) { r.score = Math.max(res.score, 62, Math.min(a, 95)); r.flags.unshift({ l: T('التحليل المعمّق بالذكاء الاصطناعي يؤكد الاشتباه', 'The deep AI analysis confirms the suspicion'), w: 0, rule: 'ai', tip: j.explanation || '' }); }
      else if (a >= 60 && res.verified) {
        /* every link is a verified official domain and nothing checkable is wrong: the model's impression does not turn a genuine message into a scam */
        r.flags.unshift({ l: T('الذكاء الاصطناعي متحفّظ، لكن الروابط كلها رسمية موثّقة ولا طلب لبيانات حساسة', 'The AI is cautious, but every link is a verified official domain and nothing sensitive is requested'), w: 0, good: true, rule: 'ai', tip: j.explanation || '' });
      }
      else if (a >= 60) {
        /* the model alone is not enough to call a message a scam: without evidence we can verify, it stays "suspicious – verify" */
        r.score = Math.min(Math.max(res.score, 40), 55); r.verified = false;
        r.flags.unshift({ l: T('يشتبه الذكاء الاصطناعي في الرسالة، لكن لا يوجد دليل يمكن التحقق منه؛ تحقّق عبر القناة الرسمية', 'The AI is suspicious, but there is no verifiable evidence: check through the official channel'), w: 0, rule: 'ai', tip: j.explanation || '' });
      }
      else if (a >= 25 && !res.verified && res.score < 25) {
        /* the AI sees something the on-device rules missed: never show "no risk signals" while the AI says "suspicious" */
        r.score = Math.max(res.score, Math.min(a, 55), 30);
        r.flags.unshift({ l: T('التحليل المعمّق بالذكاء الاصطناعي يرى علامات مريبة؛ تحقّق عبر القناة الرسمية قبل أي خطوة', 'The deep AI analysis sees suspicious signs: check through the official channel before doing anything'), w: 0, rule: 'ai', tip: j.explanation || '' });
      }
      else if (a <= 15 && res.score <= 44 && !hard) { r.score = Math.min(res.score, 24); r.flags.unshift({ l: T('التحليل المعمّق بالذكاء الاصطناعي لم يجد ما يدعو للقلق', 'The deep AI analysis found nothing worrying'), w: 0, good: true, rule: 'ai' }); }
      return r;
    }

    return { analyzeMsg, analyzeUrl, applyFacts, applyOpen, applyAi, hardEvidence, senderInfo, normMap, RULES, AXES, isGov, isOfficial, regDomain, OFFICIAL, ENT };
  }
  if (typeof module !== 'undefined' && module.exports) module.exports = createEngine;
  else root.createEngine = createEngine;
})(typeof window !== 'undefined' ? window : globalThis);
