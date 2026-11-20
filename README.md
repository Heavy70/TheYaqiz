# TheYaqiz (يقِظ) — AI Scam Shield

**Live app:** https://www.theyaqiz.com
**Hackathon:** ScamShield AI — Abu Dhabi Police × 42 Abu Dhabi (24–30 Nov 2026)
**Developer:** Khaldun Abdalhadi

> يقِظ تطبيق ذكي ثنائي اللغة (عربي/إنجليزي) يكشف الاحتيال الإلكتروني قبل أن يقع: الصق أي رسالة أو رابط مشبوه، فيفتح يقِظ الرابط ويتحقق منه ويعطيك حكمًا واضحًا مع الأدلة.

---

## 1. The problem

People in the UAE receive a steady flow of fraudulent SMS, WhatsApp messages and links: fake parcel fees "from Emirates Post", fake police fines, bank "account suspended" alerts, prize and job scams. They look official, they create urgency, and the victim has seconds to decide.

Most people cannot tell whether a link is real. Existing checkers are English-only and judge a single link in isolation. They also tend to treat every non-UAE site as suspicious, so they flag genuine Gulf and global shops and lose the user's trust.

## 2. The solution

TheYaqiz is a bilingual Progressive Web App (works on Android, iPhone and desktop, no install needed). The user pastes a message, pastes or scans a link (QR code), or uploads a screenshot. Seconds later they get:

- **A clear verdict:** Likely safe / Suspicious / Likely scam, with a 0–100 risk score.
- **The evidence behind it:** which signals fired (credential request, urgency, brand mismatch, new domain, threat-list hit…).
- **Practical advice** on what to do next.

### How a check works (layered defence)

| Layer | Where it runs | What it does |
|---|---|---|
| 1. On-device rule engine (`public/engine.js`) | User's phone | Arabic-aware text normalisation, scam-wording rules (OTP/password requests, fees, threats, secrecy, family-emergency…), sender checks, brand-vs-domain mismatch against the official-domain registry. Instant and works offline. |
| 2. Official-domain registry (`public/registry.js`) | Phone + server | Single source of truth for official UAE, Gulf and global domains, plus restricted government suffixes (gov.ae, gov.sa…). |
| 3. Link opening (`/api/open`) | Server | Safely follows the link (up to 7 redirects, private IPs blocked, DNS-rebinding protected), then reads the final host, page title, and whether the page asks for a password, card number or OTP. |
| 4. Verified facts (`/api/domain`) | Server | Domain registration age via RDAP (registry first, rdap.org fallback), Google Web Risk, optional Google Safe Browsing, and public phishing lists: OpenPhish, Phishunt, PhishDestroy, Scam-Blocklist, URLhaus. |
| 5. AI analysis (`/api/analyze`) | Server → Claude | Claude reviews the content together with the verified facts under strict scoring rules (evidence, not suspicion), in Arabic or English. |

The final verdict combines the layers. Hard evidence (threat-list hit, credential request, brand mismatch) cannot be overruled by a "safe-sounding" message.

## 3. Technical choices and reasoning

- **Zero npm dependencies.** The server uses only built-in Node.js modules (`http`, `fetch`). This makes the attack surface small, starts fast on Cloud Run and is easy to audit.
- **On-device engine first.** Most scams are caught instantly on the phone, without sending anything. The AI and server checks add depth, but the app still gives a useful verdict if they are unavailable.
- **Model choice: Claude (Haiku class by default, configurable via `YAQIZ_MODEL`).** It is fast and low-cost per check, and it reads Arabic and English messages and screenshots well. The model is given *verified facts* from the server (domain age, list hits), so it reasons over evidence instead of guessing.
- **Evidence over suspicion.** The scoring rules stop the "everything foreign is suspicious" failure: an old domain that matches the named brand with no sensitive request is scored safe. A message claiming to be the police, ICP, Emirates Post or a bank, but linking to a domain that is not theirs, is scored as a scam.
- **Threat lists matched locally.** Public feeds are downloaded by the server and checked in memory, streamed line by line so memory stays flat. The user's link is never sent to those list providers.
- **Cost guards.** Per-IP and global daily limits for AI checks; Web Risk has a hard monthly cap below the free tier so it can never bill.

## 4. Privacy design

- No accounts, no sign-in, no tracking, no analytics.
- Messages and screenshots are **not stored** by the server and are not written to a database. They are used for the single analysis request and discarded; server logs record technical errors only.
- The only third-party content the page loads is Google Fonts.
- The on-device engine needs no network at all.
- Threat-list matching happens on our server; only Google Web Risk / Safe Browsing receive a hostname (not the message).
- All API keys live in Google Secret Manager / environment variables. **No secret is in this repository.**
- Strict security headers: CSP, HSTS, `X-Frame-Options: DENY`, no camera/microphone/location permissions requested by the page.

## 5. Accuracy testing

An automated accuracy gate runs the on-device engine against a labelled set of real-world style scam and genuine messages and links (Arabic and English):

```
npm test
```

Current result: **242 cases, 100% correct, 0 missed scams, 0 false alarms.** The test fails if any scam is judged safe, if any genuine message is judged a scam, or if accuracy drops below 95%. `tests/facts.js` checks the verified-facts logic.

## 6. How to run

Requirements: **Node.js 20 or newer**. No `npm install` is needed.

```bash
git clone https://github.com/Heavy70/TheYaqiz.git
cd TheYaqiz
npm test            # accuracy gate
node server.js      # http://localhost:8080
```

Without any keys the app runs with the on-device engine, RDAP domain age, link opening and the public phishing lists. Optional environment variables:

| Variable | Purpose |
|---|---|
| `ANTHROPIC_API_KEY` | Enables the Claude AI analysis |
| `YAQIZ_MODEL` | Claude model id (default `claude-haiku-5-5`) |
| `WEBRISK_API_KEY` | Google Web Risk lookups |
| `GSB_API_KEY` | Google Safe Browsing lookups |
| `URLHAUS_AUTH_KEY` | abuse.ch URLhaus feed |
| `YAQIZ_PER_IP_DAY` / `YAQIZ_GLOBAL_DAY` | Daily AI-check limits (default 25 / 500) |
| `YAQIZ_WR_MONTH_CAP` | Monthly Web Risk cap (default 90000) |

### Deploy (Google Cloud Run)

```bash
gcloud run deploy yaqiz --source . --region europe-west1 \
  --set-secrets ANTHROPIC_API_KEY=<your-secret>:latest
```

## 7. Project structure

```
server.js              Node server: static PWA + /api/analyze, /api/domain, /api/open, /api/health
public/index.html      Bilingual app UI (Arabic/English)
public/engine.js       On-device detection engine (shared with tests)
public/registry.js     Official-domain registry
public/sw.js           Service worker (offline / installable PWA)
public/jsQR.js         QR-code reader (third-party, see jsQR.LICENSE.txt)
tests/                 Accuracy gate and fact tests
```

## 8. Trade-offs, what was left out, and next steps

- **Trade-off:** rules plus AI instead of a custom-trained model. With no large labelled UAE scam dataset available in a hackathon timeframe, explainable rules and an LLM grounded on verified facts give higher, auditable accuracy. A trained classifier is a natural next step once data is collected with consent.
- **Left out:** user accounts, report history and a reporting channel to the authorities, to keep the MVP private by design.
- **With more time:**
  - One-tap "Report to Abu Dhabi Police / eCrime" with the evidence pre-filled.
  - A WhatsApp / share-sheet entry point so users can check a message without opening the app.
  - An anonymised, opt-in feed of newly seen scam domains to help authorities act earlier.
  - Coverage of more resident languages (Urdu, Hindi, Tagalog…).
  - A larger, independently labelled test set and third-party evaluation.

---

Third-party: jsQR (Apache-2.0), see `public/jsQR.LICENSE.txt`.
