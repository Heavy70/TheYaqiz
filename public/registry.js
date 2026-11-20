/* Yaqiz registry: single source of truth for official domains and organisations.
   Used by the app (engine.js), the server (server.js) and the test suite.
   Arabic patterns are written in NORMALISED form: ا for أإآ، ي for ى، ه for ة، no diacritics. */
(function (root) {
  const R = {
    version: '2026-11-20',

    /* Registry-restricted government suffixes: only a government body can register them. */
    govSuffixes: [
      'gov.ae', 'gov.sa', 'gov.kw', 'gov.bh', 'gov.qa', 'gov.om', 'gov.eg', 'gov.jo', 'gov.lb', 'gov.iq', 'gov.ma', 'gov.tn', 'gov.dz', 'gov.ly', 'gov.sd', 'gov.ye', 'gov.ps',
      'gov.tr', 'gov.in', 'gov.pk', 'gov.bd', 'gov.lk', 'gov.sg', 'gov.my', 'gov.hk', 'gov.cn', 'gov.ph', 'gov.id', 'gov.vn', 'gov.th', 'go.th', 'go.id', 'go.jp', 'go.kr',
      'gov.uk', 'gov.au', 'gov.nz', 'gov.ie', 'gov.za', 'gov.ng', 'gov.ke', 'gov.br', 'gov.mx', 'gov.ar', 'gov.ru', 'gov.it', 'gov.gr', 'gov.pl', 'gov.il',
      'gc.ca', 'gouv.fr', 'gob.es', 'bund.de', 'admin.ch', 'europa.eu', 'gov', 'mil'
    ],

    /* Organisation-specific official domains that are not government suffixes. */
    official: [
      'u.ae', 'tamm.abudhabi', 'abudhabi.ae', 'dubai.ae', 'nmkenglish.com'
    ],

    /* Organisations scammers impersonate. If a message names one of them and links elsewhere, that is decisive evidence. */
    entities: [
      { id: 'icp', n: ['الهيئة الاتحادية للهوية والجنسية (ICP)', 'the Federal Authority for Identity & Citizenship (ICP)'], re: '(الهيئه الاتحاديه للهويه|الهويه والجنسيه|\\bicp\\b|امن المنافذ|emirates id card renewal)', d: ['icp.gov.ae', 'icp.ae'] },
      { id: 'police', n: ['الشرطة', 'the Police'], re: '(شرطه (ابوظبي|دبي|الشارقه|عجمان|راس الخيمه|الفجيره|ام القيوين)|abu dhabi police|dubai police|sharjah police|ajman police|rak police|ras al khaimah police|النيابه العامه|public prosecution)', d: ['adpolice.gov.ae', 'dubaipolice.gov.ae', 'shjpolice.gov.ae', 'ajmanpolice.gov.ae', 'rakpolice.gov.ae', 'moi.gov.ae'] },
      { id: 'moi', n: ['وزارة الداخلية', 'the Ministry of Interior'], re: '(وزاره الداخليه|ministry of interior)', d: ['moi.gov.ae'] },
      { id: 'uaepass', n: ['الهوية الرقمية UAE PASS', 'UAE PASS'], re: '(uae ?pass|الهويه الرقميه)', d: ['uaepass.ae', 'u.ae'] },
      { id: 'tdra', n: ['هيئة تنظيم الاتصالات (TDRA)', 'the TDRA'], re: '(\\btdra\\b|هيئه تنظيم الاتصالات)', d: ['tdra.gov.ae', 'u.ae'] },
      { id: 'mohre', n: ['وزارة الموارد البشرية والتوطين', 'MOHRE'], re: '(\\bmohre\\b|وزاره الموارد البشريه)', d: ['mohre.gov.ae'] },
      { id: 'customs', n: ['جمارك دبي', 'Dubai Customs'], re: '(dubai customs|جمارك دبي|federal customs)', d: ['dubaicustoms.gov.ae', 'customs.gov.ae'] },
      { id: 'empost', n: ['بريد الإمارات', 'Emirates Post'], re: '(emirates ?post|بريد الامارات)', d: ['emiratespost.ae'] },
      { id: 'aramex', n: ['أرامكس', 'Aramex'], re: '(aramex|(?<![ء-ي])ارامكس(?![ء-ي]))', d: ['aramex.com'] },
      { id: 'dhl', n: ['DHL', 'DHL'], re: '\\bdhl\\b', d: ['dhl.com', 'dhl.ae'] },
      { id: 'fedex', n: ['فيديكس', 'FedEx'], re: '(fedex|(?<![ء-ي])فيديكس(?![ء-ي]))', d: ['fedex.com'] },
      { id: 'ups', n: ['UPS', 'UPS'], re: '\\bups\\b', d: ['ups.com'] },
      { id: 'smsa', n: ['سمسا', 'SMSA Express'], re: '(\\bsmsa\\b|(?<![ء-ي])سمسا(?![ء-ي]))', d: ['smsaexpress.com'] },
      { id: 'etisalat', n: ['اتصالات / e&', 'Etisalat / e&'], re: '(etisalat|(?<![ء-ي])اتصالات(?![ء-ي])|\\be&|\\beand\\b)', d: ['etisalat.ae', 'eand.com'] },
      { id: 'du', n: ['دو (du)', 'du'], re: '(\\bdu telecom\\b|شركه دو|\\bdu (customer|bill|offer)|\\bدو\\b (للاتصالات|فاتوره))', d: ['du.ae'] },
      { id: 'cbuae', n: ['المصرف المركزي', 'the Central Bank'], re: '(المصرف المركزي|البنك المركزي|central bank)', d: ['centralbank.ae'] },
      { id: 'rta', n: ['هيئة الطرق والمواصلات', 'RTA'], re: '(\\brta\\b|هيئه الطرق)', d: ['rta.ae'] },
      { id: 'salik', n: ['سالك', 'Salik'], re: '(salik|(?<![ء-ي])سالك(?![ء-ي]))', d: ['salik.ae'] },
      { id: 'dewa', n: ['هيئة كهرباء ومياه دبي', 'DEWA'], re: '(\\bdewa\\b|هيئه كهرباء ومياه دبي)', d: ['dewa.gov.ae'] },
      { id: 'adcb', n: ['بنك أبوظبي التجاري', 'ADCB'], re: '(\\badcb\\b|بنك ابوظبي التجاري)', d: ['adcb.com'] },
      { id: 'fab', n: ['بنك أبوظبي الأول', 'First Abu Dhabi Bank'], re: '(first abu dhabi bank|بنك ابوظبي الاول|bankfab|\\bfab\\b bank)', d: ['bankfab.com'] },
      { id: 'enbd', n: ['الإمارات دبي الوطني', 'Emirates NBD'], re: '(emirates ?nbd|الامارات دبي الوطني)', d: ['emiratesnbd.com', 'emiratesnbd.ae'] },
      { id: 'eib', n: ['مصرف الإمارات الإسلامي', 'Emirates Islamic'], re: '(emirates islamic|الامارات الاسلامي)', d: ['emiratesislamic.ae'] },
      { id: 'mashreq', n: ['بنك المشرق', 'Mashreq'], re: '(mashreq|بنك المشرق)', d: ['mashreq.com'] },
      { id: 'rak', n: ['راك بنك', 'RAKBANK'], re: '(rakbank|راك بنك)', d: ['rakbank.ae'] },
      { id: 'adib', n: ['مصرف أبوظبي الإسلامي', 'ADIB'], re: '(\\badib\\b|مصرف ابوظبي الاسلامي)', d: ['adib.ae'] },
      { id: 'dib', n: ['بنك دبي الإسلامي', 'Dubai Islamic Bank'], re: '(dubai islamic bank|بنك دبي الاسلامي|\\bdib\\b)', d: ['dib.ae'] },
      { id: 'cbd', n: ['بنك دبي التجاري', 'Commercial Bank of Dubai'], re: '(commercial bank of dubai|بنك دبي التجاري|\\bcbd\\b)', d: ['cbd.ae'] },
      { id: 'sib', n: ['مصرف الشارقة الإسلامي', 'Sharjah Islamic Bank'], re: '(sharjah islamic|مصرف الشارقه الاسلامي)', d: ['sib.ae'] },
      { id: 'hsbc', n: ['HSBC', 'HSBC'], re: '\\bhsbc\\b', d: ['hsbc.ae', 'hsbc.com'] },
      { id: 'scb', n: ['ستاندرد تشارترد', 'Standard Chartered'], re: '(standard chartered|ستاندرد تشارترد)', d: ['sc.com', 'standardchartered.com'] },
      { id: 'fta', n: ['الهيئة الاتحادية للضرائب', 'the Federal Tax Authority'], re: '(الهيئه الاتحاديه للضرائب|federal tax authority|emaratax|\\bfta\\b)', d: ['tax.gov.ae', 'emaratax.ae'] },
      { id: 'mof', n: ['وزارة المالية', 'the Ministry of Finance'], re: '(وزاره الماليه|ministry of finance)', d: ['mof.gov.ae'] },
      { id: 'health', n: ['الجهات الصحية (وزارة الصحة / هيئة الصحة بدبي / دائرة الصحة)', 'the health authorities (MOHAP / DHA / DoH)'], re: '(\\bmohap\\b|وزاره الصحه (ووقايه|والوقايه)|\\bdha\\b|هيئه الصحه بدبي|dubai health authority|department of health.{0,3}abu dhabi|دائره الصحه)', d: ['mohap.gov.ae', 'dha.gov.ae', 'doh.gov.ae'] },
      { id: 'dld', n: ['دائرة الأراضي والأملاك في دبي', 'Dubai Land Department'], re: '(dubai land department|دائره الاراضي والاملاك|\\bdld\\b)', d: ['dubailand.gov.ae'] },
      { id: 'darb', n: ['نظام درب للرسوم', 'Darb toll system'], re: '(\\bdarb\\b|نظام درب|رسوم درب|مخالفه درب)', d: ['admobility.gov.ae', 'itc.gov.ae'] },
      { id: 'nbf', n: ['بنك الفجيرة الوطني', 'National Bank of Fujairah'], re: '(national bank of fujairah|\\bnbf\\b|بنك الفجيره الوطني)', d: ['nbf.ae'] },
      { id: 'ajman', n: ['مصرف عجمان', 'Ajman Bank'], re: '(ajman bank|مصرف عجمان)', d: ['ajmanbank.ae'] },
      { id: 'alhilal', n: ['بنك الهلال', 'Al Hilal Bank'], re: '(al hilal bank|بنك الهلال)', d: ['alhilalbank.ae'] },
      { id: 'bos', n: ['بنك الشارقة', 'Bank of Sharjah'], re: '(bank of sharjah|بنك الشارقه)', d: ['bankofsharjah.com'] },
      { id: 'cbi', n: ['البنك التجاري الدولي', 'Commercial Bank International'], re: '(commercial bank international|البنك التجاري الدولي)', d: ['cbiuae.com'] },
      { id: 'virgin', n: ['فيرجن موبايل', 'Virgin Mobile UAE'], re: '(virgin mobile|فيرجن موبايل)', d: ['virginmobile.ae'] },
      { id: 'emauction', n: ['مزادات الإمارات', 'Emirates Auction'], re: '(emirates auctions?|مزادات الامارات|مزاد الامارات|emirates real estate auction)', d: ['emiratesauction.com', 'emiratesauction.ae', 'auctions.ae', 'ersa.ae'] },
      { id: 'amazon', soft: true, n: ['أمازون', 'Amazon'], re: '(\\bamazon\\b|(?<![ء-ي])امازون(?![ء-ي]))', d: ['amazon.ae', 'amazon.com', 'amazon.sa', 'amzn.to', 'a.co'] },
      { id: 'noon', soft: true, n: ['نون', 'noon'], re: '(\\bnoon\\.com|\\bnoon (order|delivery|shipment))', d: ['noon.com'] },
      { id: 'careem', soft: true, n: ['كريم', 'Careem'], re: '(careem)', d: ['careem.com'] },
      { id: 'etihad', soft: true, n: ['الاتحاد للطيران', 'Etihad Airways'], re: '(etihad|الاتحاد للطيران)', d: ['etihad.com'] },
      { id: 'emirates', soft: true, n: ['طيران الإمارات', 'Emirates Airline'], re: '(emirates (airline|skywards)|skywards|طيران الامارات)', d: ['emirates.com'] },
      { id: 'flydubai', soft: true, n: ['فلاي دبي', 'flydubai'], re: '(flydubai|فلاي دبي)', d: ['flydubai.com'] },
      { id: 'whatsapp', soft: true, n: ['واتساب', 'WhatsApp'], re: '(whatsapp support|whatsapp verification|دعم واتساب)', d: ['whatsapp.com', 'wa.me'] }
    ],

    shorteners: ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'cutt.ly', 'is.gd', 'rb.gy', 'shorturl.at', 'ow.ly', 's.id', 'tiny.cc', 'rebrand.ly', 't.ly', 'v.gd', 'bitly.com', 'lnkd.in', 'qr.ae', 'shorturl.asia'],

    badTlds: ['xyz', 'top', 'click', 'live', 'shop', 'icu', 'buzz', 'cc', 'tk', 'ml', 'ga', 'cf', 'gq', 'info', 'site', 'online', 'vip', 'rest', 'cyou', 'sbs', 'monster', 'support', 'help', 'link', 'lol', 'work', 'loan', 'win', 'bond', 'cfd', 'fit', 'quest', 'today', 'life', 'store', 'wang', 'pw', 'men', 'zip', 'mov'],

    /* Extensions overwhelmingly used by scam campaigns (weighed heavier than the general list above). */
    highRiskTlds: ['xyz', 'top', 'click', 'icu', 'buzz', 'cyou', 'sbs', 'cfd', 'quest', 'monster', 'vip', 'rest', 'bond', 'tk', 'ml', 'ga', 'cf', 'gq', 'zip', 'mov', 'wang', 'pw'],

    /* Famous global domains scammers embed inside other domains (google.com.verify.top). */
    globalBrands: ['google.com', 'apple.com', 'microsoft.com', 'paypal.com', 'netflix.com', 'facebook.com', 'instagram.com', 'whatsapp.com', 'linkedin.com', 'dropbox.com', 'icloud.com', 'amazon.com', 'amazon.ae', 'dhl.com', 'fedex.com', 'visa.com', 'mastercard.com'],

    /* Brand tokens whose mere presence is common in unrelated legitimate sites (lower weight). */
    softBrands: ['amazon', 'noon', 'careem'],

    /* Brand words that must not appear inside an unrelated domain. */
    brandTokens: ['adpolice', 'police', 'uaepass', 'uae-pass', 'emiratespost', 'emirates-post', 'empost', 'aramex', 'dhl', 'fedex', 'etisalat', 'tamm', 'icp', 'salik', 'rta', 'emiratesnbd', 'adcb', 'bankfab', 'adib', 'mashreq', 'rakbank', 'centralbank', 'mohre', 'emaratax', 'darb', 'mohap', 'dubailand', 'virginmobile', 'emiratesauction', 'gov-ae', 'govae', 'tdra', 'dewa', 'moi-gov', 'amazon', 'noon', 'careem']
  };

  if (typeof module !== 'undefined' && module.exports) module.exports = R;
  else root.YAQIZ_REGISTRY = R;
})(typeof window !== 'undefined' ? window : globalThis);
