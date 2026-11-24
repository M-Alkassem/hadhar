// Hadhar scam engine: pure functions, no I/O, no dependencies.
// The same file is unit-tested in Node and embedded into the n8n Code nodes
// by scripts/build-workflow.mjs (the `export` keywords are stripped there).

export const THRESHOLDS = { red: 40, amber: 20 };

// ---------------------------------------------------------------- text utils

export function normalizeText(s = '') {
  return String(s)
    .normalize('NFKC')
    .replace(/[ً-ٰٟـ]/g, '') // tashkeel + tatweel
    .replace(/[أإآٱ]/g, 'ا')
    .replace(/ى/g, 'ي')
    .replace(/ة/g, 'ه')
    .replace(/[٠-٩]/g, (d) => String('٠١٢٣٤٥٦٧٨٩'.indexOf(d)))
    .toLowerCase();
}

export function detectLang(text = '') {
  const letters = (String(text).match(/\p{L}/gu) || []).length;
  if (!letters) return 'en';
  const arabic = (String(text).match(/[؀-ۿ]/g) || []).length;
  return arabic / letters > 0.3 ? 'ar' : 'en';
}

// ------------------------------------------------------------- url handling

const TLDS =
  'com|net|org|info|top|xyz|click|link|online|site|shop|live|icu|vip|app|co|io|me|ly|gl|gd|cc|tk|cn|ru|sa|ae|eg|sy|tr|uk|de|us|ws|su|support|help|website|store|life|work|club|cfd|sbs|rest|cyou|bond|buzz|monster|ml|ga|cf|gq|page|dev|cloud|today|world|digital|services|finance|bank|pro|biz|mobi|tv|fm|to|ai|is|in|id|kw|qa|bh|om|jo|lb|iq|ma|dz|tn|ps|ye|ly';

const URL_RE = new RegExp(
  '(?:https?:\\/\\/|www\\.)[^\\s<>"\'،؛«»()\\[\\]{}]+' +
    '|(?<![@\\w.-])[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\\.(?:' +
    TLDS +
    ')(?![a-z0-9-])(?:\\/[^\\s<>"\'،؛«»()\\[\\]{}]*)?',
  'gi'
);

export function extractUrls(text = '') {
  const found = [];
  const seen = new Set();
  const src = String(text);
  for (const m of src.matchAll(URL_RE)) {
    let u = m[0].replace(/[.,;:!?'"،؛؟)]+$/u, '');
    if (!u) continue;
    // skip email addresses: the char right before a bare domain is "@"
    if (m.index > 0 && src[m.index - 1] === '@') continue;
    const key = u.toLowerCase();
    if (!seen.has(key)) {
      seen.add(key);
      found.push(u);
    }
  }
  return found;
}

// n8n's Code-node sandbox has no `URL` class, so URLs are parsed by hand here.
// Numeric hosts are normalised the way browsers do (decimal, hex, octal, short forms)
// so that "http://2130706433/" or "http://0x7f.1/" cannot sneak past the private-address guard.
export function normalizeIPv4(host) {
  if (!/^(?:0x[0-9a-f]*|\d+)(?:\.(?:0x[0-9a-f]*|\d+)){0,3}$/i.test(host)) return null;
  const parts = host.split('.');
  const nums = [];
  for (const p of parts) {
    let n;
    if (/^0x/i.test(p)) n = p.length === 2 ? 0 : parseInt(p.slice(2), 16);
    else if (p.length > 1 && p[0] === '0') { if (/[89]/.test(p)) return null; n = parseInt(p, 8); }
    else n = parseInt(p, 10);
    if (!Number.isFinite(n)) return null;
    nums.push(n);
  }
  const last = nums.pop();
  if (nums.some((n) => n > 255) || last >= Math.pow(256, 4 - nums.length)) return null;
  let value = last;
  nums.forEach((n, i) => { value += n * Math.pow(256, 3 - i); });
  return [Math.floor(value / 16777216) % 256, Math.floor(value / 65536) % 256, Math.floor(value / 256) % 256, value % 256].join('.');
}

export function parseUrl(raw) {
  let s = String(raw).trim().replace(/#.*$/, '');
  let schemeGuessed = false;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
    s = 'http://' + s;
    schemeGuessed = true;
  }
  const m = s.match(/^([a-z][a-z0-9+.-]*):\/\/([^/?]*)([^?]*)(\?.*)?$/i);
  if (!m) return null;
  const protocol = m[1].toLowerCase() + ':';
  if (protocol !== 'http:' && protocol !== 'https:') return null;
  let authority = m[2];
  let userinfo = '';
  const at = authority.lastIndexOf('@');
  if (at >= 0) { userinfo = authority.slice(0, at); authority = authority.slice(at + 1); }
  let host = authority;
  let port = '';
  if (authority.startsWith('[')) {
    const end = authority.indexOf(']');
    if (end < 0) return null;
    host = authority.slice(1, end);
    port = authority.slice(end + 1).replace(/^:/, '');
  } else {
    const c = authority.lastIndexOf(':');
    if (c >= 0) { port = authority.slice(c + 1); host = authority.slice(0, c); }
  }
  if (port && !/^\d{1,5}$/.test(port)) return null;
  host = host.toLowerCase().replace(/\.$/, '');
  if (!host || /[\s<>"{}|\\^`]/.test(host)) return null;
  const ip4 = normalizeIPv4(host);
  if (ip4) host = ip4;
  const pathname = m[3] || '/';
  const search = m[4] || '';
  const shownHost = host.includes(':') ? `[${host}]` : host;
  return {
    href: `${protocol}//${userinfo ? userinfo + '@' : ''}${shownHost}${port ? ':' + port : ''}${pathname}${search}`,
    protocol,
    host,
    path: pathname + search,
    hasUserinfo: Boolean(userinfo),
    unicodeHost: /[^\x00-\x7f]/.test(host),
    schemeGuessed,
  };
}

// Resolve a redirect `Location` value against the URL it came from. Returns an absolute http(s) href or null.
export function resolveRelative(loc, baseHref) {
  const base = parseUrl(baseHref);
  const l = String(loc).trim();
  if (!base || !l) return null;
  if (/^[a-z][a-z0-9+.-]*:/i.test(l)) return parseUrl(l)?.href ?? null;
  const origin = base.href.slice(0, base.href.indexOf('/', base.protocol.length + 2) === -1 ? undefined : base.href.indexOf('/', base.protocol.length + 2));
  if (l.startsWith('//')) return parseUrl(base.protocol + l)?.href ?? null;
  if (l.startsWith('/')) return parseUrl(origin + l)?.href ?? null;
  const basePath = base.path.split('?')[0];
  if (l.startsWith('?')) return parseUrl(origin + basePath + l)?.href ?? null;
  const dir = basePath.slice(0, basePath.lastIndexOf('/') + 1);
  const segs = (dir + l).split('/');
  const out = [];
  for (const seg of segs) { if (seg === '..') { if (out.length > 1) out.pop(); } else if (seg !== '.') out.push(seg); }
  return parseUrl(origin + out.join('/'))?.href ?? null;
}

const TWO_PART_SUFFIXES = new Set(
  (
    'co.uk org.uk ac.uk gov.uk com.au net.au org.au co.nz co.jp co.in com.br com.sa net.sa org.sa gov.sa edu.sa ' +
    'com.eg gov.eg com.tr com.sy gov.sy co.za com.kw com.qa com.bh com.om com.jo com.lb com.iq com.sg com.hk ' +
    'com.cn com.mx com.ar com.co co.id co.kr com.pk com.bd com.ng co.ke com.ua co.ae com.ma com.dz com.tn com.ps'
  ).split(' ')
);

const FREE_HOSTING = new Set(
  (
    'github.io pages.dev web.app firebaseapp.com blogspot.com weebly.com wixsite.com netlify.app vercel.app herokuapp.com ' +
    'workers.dev glitch.me 000webhostapp.com godaddysites.com sites.google.com forms.gle r2.dev replit.app ' +
    'framer.website webflow.io carrd.co linktr.ee my.canva.site notion.site'
  ).split(' ')
);

export function isIpHost(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':');
}

export function registrableDomain(host) {
  if (isIpHost(host)) return { domain: host, label: host, freeHosting: false, ip: true };
  const parts = host.split('.');
  if (parts.length <= 2) {
    return { domain: host, label: parts[0], freeHosting: false, ip: false };
  }
  const last2 = parts.slice(-2).join('.');
  const last3 = parts.slice(-3).join('.');
  if (FREE_HOSTING.has(last2)) {
    return { domain: last3, label: parts[parts.length - 3], freeHosting: true, ip: false };
  }
  if (FREE_HOSTING.has(host)) {
    return { domain: host, label: parts[0], freeHosting: true, ip: false };
  }
  if (TWO_PART_SUFFIXES.has(last2)) {
    return { domain: last3, label: parts[parts.length - 3], freeHosting: false, ip: false };
  }
  return { domain: last2, label: parts[parts.length - 2], freeHosting: false, ip: false };
}

// SSRF guard: never let the bot fetch internal addresses on a user's behalf.
export function isPrivateHost(host) {
  const h = String(host).toLowerCase().replace(/^\[|\]$/g, '');
  if (!h) return true;
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.lan') || h.endsWith('.home') || h.endsWith('.corp')) return true;
  if (!h.includes('.') && !h.includes(':')) return true; // single-label names resolve internally
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const [a, b] = [Number(m[1]), Number(m[2])];
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true; // link-local + cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    if (a >= 224) return true; // multicast + reserved
    return false;
  }
  if (h.includes(':')) {
    if (h === '::1' || h === '::') return true;
    if (/^f[cd]/.test(h) || /^fe[89ab]/.test(h)) return true; // ULA + link-local
    if (h.startsWith('::ffff:')) return true; // v4-mapped: refuse rather than parse
    return false;
  }
  return false;
}

// -------------------------------------------------------------------- brands

const BRANDS = {
  paypal: ['paypal.com', 'paypal.me'],
  apple: ['apple.com', 'icloud.com', 'apple.news', 'apple-dns.net', 'apple-dns.cn', 'mzstatic.com'],
  icloud: ['icloud.com', 'apple.com'],
  google: ['google.com', 'googleadservices.com', 'googlesyndication.com', 'googletagmanager.com', 'google-analytics.com', 'googlevideo.com', 'googletagservices.com', 'googleapis.cn', 'google.ae', 'google.com.sa', 'google.com.eg', 'googleusercontent.com', 'googleapis.com', 'google.co.uk', 'google.de', 'google.com.tr'],
  microsoft: ['microsoft.com', 'microsoftonline.com', 'live.com', 'office.com'],
  netflix: ['netflix.com'],
  amazon: ['amazon.com', 'amazon-adsystem.com', 'amazontrust.com', 'amazonvideo.com', 'amazonpay.com', 'amazon.ae', 'amazon.sa', 'amazon.eg', 'amazon.co.uk', 'amazon.de', 'amazonaws.com', 'amazon.in'],
  facebook: ['facebook.com', 'fb.com', 'facebook.net'],
  instagram: ['instagram.com'],
  whatsapp: ['whatsapp.com', 'whatsapp.net', 'wa.me'],
  telegram: ['telegram.org', 't.me', 'telegram.me'],
  binance: ['binance.com', 'binance.us'],
  dhl: ['dhl.com', 'dhl.de'],
  fedex: ['fedex.com'],
  aramex: ['aramex.com'],
  smsa: ['smsaexpress.com'],
  mobily: ['mobily.com.sa'],
  zain: ['zain.com', 'sa.zain.com', 'jo.zain.com', 'kw.zain.com'],
  syriatel: ['syriatel.sy'],
  etisalat: ['etisalat.ae', 'etisalat.com'],
  alrajhi: ['alrajhibank.com.sa'],
  stcpay: ['stcpay.com.sa'],
  roblox: ['roblox.com'],
  discord: ['discord.com', 'discord.gg', 'discordapp.com'],
  spotify: ['spotify.com', 'scdn.co'],
  metamask: ['metamask.io', 'consensys.io', 'consensys.net'],
  coinbase: ['coinbase.com'],
  ledger: ['ledger.com'],
  linkedin: ['linkedin.com', 'licdn.com'],
  tiktok: ['tiktok.com', 'tiktokcdn.com'],
  shopee: ['shopeemobile.com', 'shopee.com', 'shopee.sg', 'shopee.co.id', 'shopee.ph', 'shopee.vn', 'shopee.tw', 'shopee.com.my', 'shopee.co.th'],
  wellsfargo: ['wellsfargo.com'],
  chase: ['chase.com', 'jpmorganchase.com'],
  usps: ['usps.com'],
  royalmail: ['royalmail.com'],
};

export function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i]);
  for (let j = 1; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
  }
  return dp[a.length][b.length];
}

// Returns {brand, kind} when the host pretends to be a known brand, else null.
export function brandLookalike(host) {
  const reg = registrableDomain(host);
  if (reg.ip) return null;
  const tld = reg.domain.split('.').pop();
  const hostTokens = host.split(/[^a-z0-9]+/).filter(Boolean);
  for (const [brand, official] of Object.entries(BRANDS)) {
    const isOfficial = official.some((d) => reg.domain === d || host === d || host.endsWith('.' + d));
    if (isOfficial || tld === brand) continue; // brand-owned TLDs such as .microsoft
    // the brand's own name under a normal TLD (amazon.co.jp, paypal.de) is theirs; under .top/.shop etc. it is not
    if (reg.label === brand && !reg.freeHosting && (tld.length === 2 || ['com', 'net', 'org'].includes(tld))) continue;
    if (hostTokens.includes(brand)) return { brand, kind: 'brand-in-hostname' };
    if (brand.length >= 6 && host.includes(brand)) return { brand, kind: 'brand-substring' };
    if (brand.length >= 5 && !reg.freeHosting) {
      const swapped = reg.label.replace(/[0-9]/g, (d) => ({ 0: 'o', 1: 'l', 3: 'e', 4: 'a', 5: 's', 7: 't' }[d] || d));
      const digitSwap = swapped !== reg.label && levenshtein(swapped, brand) <= 1;
      const edit1 = brand.length >= 6 && Math.abs(reg.label.length - brand.length) <= 1 && levenshtein(reg.label, brand) === 1;
      if (reg.label !== brand && (digitSwap || edit1)) return { brand, kind: 'typosquat' };
    }
  }
  return null;
}

// Brand names in the PATH only matter on low-reputation hosts (free hosting, shorteners, risky TLDs).
export function brandInPath(parsed) {
  const reg = registrableDomain(parsed.host);
  const low = reg.freeHosting || isShortener(parsed.host) || RISKY_TLDS.has(reg.domain.split('.').pop());
  if (!low) return null;
  const tokens = parsed.path.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  for (const brand of Object.keys(BRANDS)) {
    if (tokens.includes(brand) || (brand.length >= 6 && parsed.path.toLowerCase().includes(brand))) return brand;
  }
  return null;
}

// Machine-generated looking hostnames: long, digit-heavy, dates, or many hyphen chunks on free hosting.
export function randomLookingHost(host) {
  const reg = registrableDomain(host);
  if (reg.ip) return null;
  const left = host.slice(0, host.length - reg.domain.length).replace(/\.$/, '');
  const labels = [...left.split('.').filter(Boolean), reg.label];
  for (const l of labels) {
    const digits = (l.match(/\d/g) || []).length;
    const hyphens = (l.match(/-/g) || []).length;
    if (l.length >= 16 && digits / l.length >= 0.3) return 'A';
    if (/\d{1,2}-\d{1,2}-20\d\d/.test(l)) return 'A';
    if (reg.freeHosting && l.length >= 20 && hyphens >= 3) return 'B';
  }
  return null;
}

const SHORTENERS = new Set(
  'bit.ly t.co tinyurl.com goo.gl ow.ly is.gd cutt.ly rb.gy shorturl.at tiny.cc rebrand.ly buff.ly lnkd.in t.ly s.id bit.do v.gd adf.ly shorte.st tr.ee qr.ae l.ead.me ift.tt shrtco.de'.split(' ')
);

const RISKY_TLDS = new Set('top xyz click link icu vip cfd sbs rest cyou bond monster buzz gq tk ml ga cf support'.split(' '));

export function isShortener(host) {
  return SHORTENERS.has(registrableDomain(host).domain) || SHORTENERS.has(host);
}

// ------------------------------------------------------------------- signals

function sig(id, weight, en, ar, extra) {
  return { id, weight, en, ar, ...(extra || {}) };
}

// info: {url, host?, chain?, ageDays?, blocklisted?, error?}
export function urlSignals(info) {
  const out = [];
  const first = parseUrl(info.url);
  if (!first) return out;
  const chain = info.chain && info.chain.length ? info.chain : [first.href];
  const finalUrl = info.chain && info.chain.length > 1 ? parseUrl(chain[chain.length - 1]) || first : first; // no redirects: keep the original (so a guessed scheme stays guessed)
  const reg = registrableDomain(finalUrl.host);
  const shown = finalUrl.host;

  if (info.blocklisted) {
    out.push(sig('blocklisted', 70, `${shown} is on a public phishing blocklist`, `${shown} موجود في قائمة حظر عامة للتصيّد الاحتيالي`));
  }
  if (isShortener(first.host)) {
    out.push(sig('shortener', 12, 'The link is shortened, so its real destination is hidden', 'الرابط مختصر، فوجهته الحقيقية مخفية'));
  }
  const hops = chain.length - 1;
  if (hops >= 3) {
    out.push(sig('many_redirects', 15, `The link bounces through ${hops} redirects before landing`, `الرابط يعبر ${hops} عمليات إعادة توجيه قبل أن يصل`));
  }
  if (hops >= 1 && registrableDomain(first.host).domain !== reg.domain && !isShortener(first.host)) {
    out.push(sig('cross_domain_redirect', 8, `It redirects to a different site (${shown})`, `يعيد التوجيه إلى موقع مختلف (${shown})`));
  }
  if (reg.ip) {
    out.push(sig('ip_host', 30, 'The link points to a raw IP address, not a website name', 'الرابط يشير إلى عنوان IP مباشر وليس اسم موقع'));
  }
  if (finalUrl.host.includes('xn--') || first.host.includes('xn--') || first.unicodeHost || finalUrl.unicodeHost) {
    out.push(sig('punycode', 25, 'The address uses look-alike international characters', 'العنوان يستخدم أحرفاً دولية مشابهة في الشكل لأحرف مألوفة'));
  }
  if (first.hasUserinfo || finalUrl.hasUserinfo) {
    out.push(sig('userinfo', 25, 'The link hides its real host behind an "@" trick', 'الرابط يخفي وجهته الحقيقية بخدعة علامة "@"'));
  }
  const lookalike = brandLookalike(finalUrl.host) || brandLookalike(first.host);
  if (lookalike) {
    out.push(
      sig(
        'brand_lookalike',
        lookalike.kind === 'brand-in-hostname' ? 40 : lookalike.kind === 'typosquat' ? 35 : 25,
        `The address imitates ${lookalike.brand} but is not its real website`,
        `العنوان ينتحل اسم ${lookalike.brand} وليس موقعه الحقيقي`,
        { brand: lookalike.brand }
      )
    );
  }
  const bip = brandInPath(finalUrl) || brandInPath(first);
  if (bip && !lookalike) {
    out.push(sig('brand_in_path', 25, `The link uses the name ${bip} on a site that is not theirs`, `الرابط يستخدم اسم ${bip} على موقع ليس لهم`, { brand: bip }));
  }
  const rnd = randomLookingHost(finalUrl.host);
  if (rnd) {
    out.push(sig('random_host', rnd === 'A' ? 25 : 20, 'The address looks machine-generated, not like a real business name', 'العنوان يبدو مولّداً آلياً وليس اسم نشاط حقيقي'));
  }
  const subdomains = finalUrl.host.split('.').length - reg.domain.split('.').length;
  if (subdomains >= 3) {
    out.push(sig('deep_subdomains', 10, 'The address stacks many sub-domains to look official', 'العنوان يكدّس نطاقات فرعية كثيرة ليبدو رسمياً'));
  }
  const tld = reg.domain.split('.').pop();
  if (RISKY_TLDS.has(tld)) {
    out.push(sig('risky_tld', 10, `".${tld}" addresses are heavily used in scams`, `نطاقات ".${tld}" تُستخدم كثيراً في الاحتيال`));
  }
  if (reg.freeHosting) {
    out.push(sig('free_hosting', 8, 'The page sits on a free hosting service, not a company site', 'الصفحة على استضافة مجانية وليست موقع شركة'));
  }
  if (finalUrl.protocol === 'http:' && !finalUrl.schemeGuessed) {
    out.push(sig('no_https', 8, 'The page is not encrypted (http, not https)', 'الصفحة غير مشفّرة (http وليست https)'));
  }
  if (typeof info.ageDays === 'number') {
    if (info.ageDays < 7) out.push(sig('domain_new', 40, `The website was created ${Math.max(0, Math.floor(info.ageDays))} day(s) ago`, `الموقع أُنشئ قبل ${Math.max(0, Math.floor(info.ageDays))} يوم`));
    else if (info.ageDays < 30) out.push(sig('domain_young', 30, `The website is only ${Math.floor(info.ageDays)} days old`, `عمر الموقع ${Math.floor(info.ageDays)} يوماً فقط`));
    else if (info.ageDays < 90) out.push(sig('domain_recent', 12, `The website is only ${Math.floor(info.ageDays)} days old`, `عمر الموقع ${Math.floor(info.ageDays)} يوماً فقط`));
  }
  return out;
}

const ASK =
  'send|reply|share|provide|give|tell|enter|confirm|verify|update|submit|forward|reset|read out|' +
  'ارسال|ارسل|ارسلي|تزويد|زودنا|زودني|شارك|اعطني|اعطنا|ادخل|ادخال|اكد|تاكيد|حدث|تحديث|ابعت|بعت|رد برمز|قم بارسال|اكتب';
const ASK_RE = new RegExp('(?:' + ASK + ')');
const CRED_RE = /(?:\botp\b|one[- ]time (?:pass)?code|verification code|security code|passcode|\bpin\b|\bcvv\b|\bpassword\b|card number|login details|\d[- ]?digit code|(?:the|that|your) code you (?:just )?(?:received|got)|\bssn\b|social security|date of birth|\bdob\b|passport number|bank details|bank account (?:number|details)|routing number|\biban\b|national id|رمز التحقق|رمز التاكيد|رمز التفعيل|كلمه المرور|كلمه السر|الرقم السري|رقم البطاقه|رقم الكرت|رمز الامان|كود التحقق|كود التفعيل|رقم سري|رمز سري|الكود|الرمز الذي وصلك|رمز الدخول|رقم الهويه|رقم الحساب البنكي|رقم حسابك|بيانات (?:البطاقه|حسابك|الحساب البنكي)|رقم جواز|الرقم القومي)/g;
const WARN_RE = /(?:do not share|don'?t share|never share|do not give|do not tell|do not disclose|لا تشارك|لا تخبر|لا تعطي|لا تفصح|لا تعط|ولا تشاركه|لا تشاركه)/;

const TEXT_RULES = [
  {
    id: 'urgency_threat', weight: 15,
    en: 'It pressures you to act fast or threatens to lock something',
    ar: 'يضغط عليك للتصرف بسرعة أو يهدد بإيقاف شيء ما',
    re: /\b(?:urgent(?:ly)?|immediately|within \d+ (?:hours?|minutes?|days?)|last (?:warning|notice|chance)|final notice|act now|expires? (?:today|soon|tonight)|will be (?:suspended|blocked|closed|terminated|deactivated|locked|cancell?ed)|has been (?:suspended|blocked|locked|restricted|limited|compromised|deactivated)|suspicious (?:activity|login|sign[- ]?in)|unauthori[sz]ed (?:access|login|transaction))\b|عاجل|فورا|خلال \d+ (?:ساعه|ساعات|دقيقه|يوم|ايام)|اخر تحذير|اخر فرصه|سيتم (?:ايقاف|تعليق|اغلاق|حظر|الغاء|تجميد)|تم (?:ايقاف|تعليق|حظر|تجميد|تقييد|الغاء)|نشاط مشبوه|دخول مشبوه|محاوله دخول|اخر انذار|مستعجل/,
  },
  {
    id: 'prize_reward', weight: 25,
    en: 'It says you won something or are owed a refund',
    ar: 'يدّعي أنك ربحت شيئاً أو لك مبلغ مسترد',
    re: /\b(?:you(?:'ve| have)? won|congrat(?:s|ulations)|winner|free entry|claim your (?:prize|reward|gift|refund)|free (?:gift|iphone|ipad|samsung)|lucky draw|you(?:'re| are) (?:selected|eligible)|refund (?:is )?(?:pending|available|waiting)|(?:win|won|awarded|selected)\b.{0,60}(?:\$|£|€|cash|prize|voucher|holiday|ipod|iphone|nokia|laptop|car))\b|مبروك|ربحت|فزت|جايزه|جائزه|سحب على|هديه مجانيه|تم اختيارك|استرداد (?:مبلغ|اموال)/,
  },
  {
    id: 'delivery_fee', weight: 20,
    en: 'It claims a parcel, toll or fine is waiting for a payment',
    ar: 'يدّعي وجود شحنة أو غرامة بانتظار دفع مبلغ',
    re: /\b(?:package|parcel|shipment|delivery|customs)\b.{0,50}\b(?:fee|on hold|held|failed|unable|reschedule|address|pending|pay|unpaid)\b|\bredelivery\b|\b(?:unpaid|outstanding) (?:toll|fine|balance)\b|\btoll (?:balance|fee)\b|(?:شحنتك|طردك|الشحنه|طرد).{0,50}(?:رسوم|معلقه|تعذر|فشل|تحديث|عنوان|سداد|دفع)|مخالفه مروريه|رسوم (?:التوصيل|الجمارك|الشحن)|غرامه (?:مروريه|مستحقه)/,
  },
  {
    id: 'untraceable_payment', weight: 25,
    en: 'It asks for gift cards, crypto or a wire transfer',
    ar: 'يطلب بطاقات هدايا أو عملات رقمية أو حوالة',
    re: /\b(?:gift ?cards?|itunes card|google play card|steam card|bitcoin|btc|usdt|crypto(?:currency)?|western union|moneygram|wire transfer|zelle|cash ?app)\b|بطاقات? (?:هدايا|ايتونز|قوقل بلاي|جوجل بلاي)|عمله رقميه|عملات رقميه|بيتكوين|يو اس دي تي|ويسترن يونيون|حواله بنكيه/,
  },
  {
    id: 'too_good_offer', weight: 20,
    en: 'It promises easy money, guaranteed returns or a no-experience job',
    ar: 'يعد بمال سهل أو أرباح مضمونة أو وظيفة بلا خبرة',
    re: /\b(?:work from home|earn \$?\d+|(?:make|earn) .{0,15}(?:per|a) (?:day|week|hour)|guaranteed (?:returns?|profit)|double your|risk[- ]free|investment (?:opportunity|plan)|part[- ]time job|no experience (?:needed|required)|\d+% (?:daily|weekly|monthly))\b|عمل من المنزل|ربح مضمون|ارباح مضمونه|استثمار مضمون|مضاعفه (?:اموالك|راس المال)|وظيفه (?:جزئيه|من البيت)|بدون خبره|راتب (?:اسبوعي|يومي)|\d+ ?% ?(?:يوميا|اسبوعيا|شهريا)|ارباح (?:يوميه|مضمونه)/,
  },
  {
    id: 'move_to_chat', weight: 15,
    en: 'It tries to move you to WhatsApp or Telegram',
    ar: 'يحاول نقلك إلى واتساب أو تلغرام',
    re: /\b(?:message|contact|text|add|reach) (?:me |us )?(?:on|via|at) (?:whatsapp|telegram)\b|\bjoin (?:our|my|the) (?:telegram|whatsapp)|(?:انضم|ادخل|انضمو).{0,30}(?:تلغرام|تيليجرام|واتساب)|تواصل (?:معنا |معي )?(?:على|عبر) (?:واتساب|واتس|تلغرام|تيليجرام)|راسلنا (?:على|عبر)/,
  },
  {
    id: 'tech_support', weight: 35,
    en: 'It claims your device is infected and tells you to call "support"',
    ar: 'يدّعي أن جهازك مصاب ويطلب منك الاتصال بـ"الدعم"',
    re: /\b(?:virus|malware|infected|hacked|compromised)\b.{0,80}\b(?:call|contact|phone)\b|\b(?:call|contact)\b.{0,60}\b(?:microsoft|apple|windows) (?:support|helpline|technician)|فيروس.{0,60}(?:اتصل|تواصل)|(?:اتصل|تواصل).{0,40}(?:دعم|مايكروسوفت|ابل)/,
  },
  {
    id: 'wrong_number_chat', weight: 20,
    en: 'It starts a "wrong number" chat, a common opening for romance and investment scams',
    ar: 'يبدأ بمحادثة "رقم خاطئ"، وهي بداية شائعة للاحتيال العاطفي والاستثماري',
    re: /\b(?:wrong number|sorry,? (?:i )?(?:think )?(?:i )?(?:have|got) the wrong)\b|رقم خاطئ|رقم غلط/,
  },
  {
    id: 'premium_rate', weight: 25,
    en: 'It asks you to text or call a premium-rate number',
    ar: 'يطلب منك إرسال رسالة أو الاتصال برقم مدفوع',
    re: /\b(?:txt|text|reply|send)\b.{0,40}\bto\b\s?\d{5}\b|\b0(?:8\d{2}|9\d{2})\s?\d{3}\s?\d{3,4}\b|\b\d{1,3}p\s?\/?\s?(?:msg|min|ppm|per min)|\bstd txt rate\b|\bt ?& ?cs?\b.{0,12}apply|\bcall ?free ?fone\b/,
  },
  {
    id: 'money_request', weight: 15,
    en: 'It asks you to send money',
    ar: 'يطلب منك إرسال مال',
    re: /\b(?:send|transfer|wire|pay)\b.{0,30}(?:\bmoney\b|\$\s?\d+|\bbill\b|\d{3,} (?:dollars|usd|pounds|euros))|\bcan you (?:transfer|send|pay)\b|حول(?:ي|لي)?.{0,30}(?:مبلغ|مصاري|فلوس|رصيد)|(?:مبلغ|مصاري|فلوس).{0,20}(?:ضروري|مستعجل|عاجل)|ارسل (?:لي )?(?:مبلغ|فلوس)|لازم تحول/,
  },
  {
    id: 'authority', weight: 8,
    en: 'It speaks in the name of a bank, tax office or authority',
    ar: 'يتحدث باسم بنك أو جهة ضريبية أو سلطة رسمية',
    re: /\b(?:your bank|bank of|central bank|apple id|icloud|netflix|paypal|tax (?:office|authority|refund)|\birs\b|police|interpol|customs|ministry)\b|البنك|المصرف|الشرطه|الجمارك|وزاره|ضريبه|حسابك المصرفي|بطاقتك/,
  },
];

export function textSignals(text, opts = {}) {
  const t = normalizeText(text);
  const out = [];

  // credential request: a credential word near an "ask" verb, unless the text warns "do not share"
  CRED_RE.lastIndex = 0;
  let m;
  let credHit = false;
  while ((m = CRED_RE.exec(t))) {
    const from = Math.max(0, m.index - 60);
    const win = t.slice(from, m.index + m[0].length + 60);
    if (ASK_RE.test(win)) {
      credHit = true;
      break;
    }
  }
  if (credHit && !WARN_RE.test(t)) {
    out.push(sig('credential_ask', 35, 'It asks you to send or enter a code, PIN or password', 'يطلب منك إرسال أو إدخال رمز أو رقم سري أو كلمة مرور'));
  }

  for (const rule of TEXT_RULES) {
    if (rule.re.test(t)) out.push(sig(rule.id, rule.weight, rule.en, rule.ar));
  }


  // family impersonation: a relative cue + "my phone changed/broke" story
  const relative = /\b(?:mum|mom|mummy|dad|daddy|mother|father|son|daughter|it'?s me|this is me)\b|ماما|بابا|ابي|امي|يمه|يابا|اختك|اخوك|اخي|ابنك|بنتك/.test(t);
  const phoneStory = /\b(?:new (?:phone )?number|temporary number|temp(?:orary)? phone|other number|changed my number|lost my phone|phone (?:broke|is broken|got broken|was stolen)|got a new phone|my phone (?:died|broke))\b|رقمي الجديد|رقم جديد|غيرت رقمي|(?:جوالي|تلفوني|هاتفي|موبايلي).{0,20}(?:خربان|ضاع|انكسر|تعطل|اتكسر|انسرق)/.test(t);
  if (relative && phoneStory) {
    out.push(sig('family_impersonation', 30, 'It looks like someone posing as a relative whose phone changed', 'تبدو كرسالة من شخص ينتحل صفة قريب غيّر رقمه أو تعطل هاتفه'));
  }

  if (opts.hasUrl) {
    if (/\b(?:click|tap|open|visit|log ?in|sign ?in|verify|confirm|update|download|track|pay)\b|اضغط|انقر|افتح|ادخل|سجل|حدث|اكد|فعل|تتبع|سدد/.test(t)) {
      out.push(sig('link_pressure', 10, 'It tells you to open a link and act on it', 'يطلب منك فتح رابط والتصرف بناءً عليه'));
    }
  }
  return out;
}

// ------------------------------------------------------------------- scoring

export function scoreSignals(signals) {
  const raw = signals.reduce((a, s) => a + s.weight, 0);
  const forcedRed = signals.some((s) => s.id === 'blocklisted');
  const score = Math.min(100, raw);
  let verdict = score >= THRESHOLDS.red ? 'red' : score >= THRESHOLDS.amber ? 'amber' : 'green';
  if (forcedRed) verdict = 'red';
  return { score, verdict };
}

// urlInfos: [{url, chain?, ageDays?, blocklisted?, skipped?}]
export function buildResult(text, urlInfos = []) {
  const lang = detectLang(text);
  const signals = [];
  for (const info of urlInfos) signals.push(...urlSignals(info));
  signals.push(...textSignals(text, { hasUrl: urlInfos.length > 0 }));
  // de-duplicate by id (several links often trip the same signal)
  const seen = new Set();
  const unique = signals.filter((s) => (seen.has(s.id) ? false : seen.add(s.id)));
  unique.sort((a, b) => b.weight - a.weight);
  const { score, verdict } = scoreSignals(unique);
  return { verdict, score, lang, signals: unique, urls: urlInfos.map((i) => i.url) };
}

// ------------------------------------------------------------------- replies

const ICON = { red: '🔴', amber: '🟠', green: '🟢' };

const TEXT = {
  en: {
    title: { red: 'Very likely a scam', amber: 'Be careful: warning signs found', green: 'No warning signs found' },
    why: 'Why:',
    todo: 'What to do:',
    red: ['Do not click, reply or send any code.', 'If it claims to be your bank or a company, call them on the number printed on your card or their official website.', 'If you already clicked or shared something: change that password now and call your bank.'],
    amber: ['Do not click or reply yet.', 'Contact the sender through a way you already trust and ask if they sent it.'],
    green: ['This is not a guarantee. If anything still feels wrong, do not click or pay, and ask someone you trust.'],
    none: 'Nothing suspicious in the text or links.',
  },
  ar: {
    title: { red: 'احتيال على الأغلب', amber: 'احذر: وُجدت علامات تحذير', green: 'لم نجد علامات تحذير' },
    why: 'السبب:',
    todo: 'ماذا تفعل:',
    red: ['لا تضغط على أي رابط ولا ترد ولا ترسل أي رمز.', 'إذا ادّعت الرسالة أنها من بنك أو شركة، اتصل بهم على الرقم المطبوع على بطاقتك أو في موقعهم الرسمي.', 'إذا ضغطت على الرابط أو أرسلت شيئاً: غيّر كلمة المرور فوراً واتصل بالبنك.'],
    amber: ['لا تضغط ولا ترد الآن.', 'تواصل مع المرسل بطريقة تثق بها واسأله إن كان هو من أرسلها.'],
    green: ['هذا ليس ضماناً. إن بقي شيء غير مريح فلا تضغط ولا تدفع، واسأل شخصاً تثق به.'],
    none: 'لا شيء مريب في النص أو الروابط.',
  },
};

export function formatReply(result, lang) {
  const l = lang || result.lang || 'en';
  const T = TEXT[l] || TEXT.en;
  const lines = [`${ICON[result.verdict]} ${T.title[result.verdict]}  (${result.score}/100)`];
  const shown = result.signals.slice(0, 4);
  lines.push('', T.why);
  if (shown.length) for (const s of shown) lines.push(`• ${s[l] || s.en}`);
  else lines.push(`• ${T.none}`);
  if (result.llm && result.llm.explanation) lines.push('', `🤖 ${result.llm.explanation}`);
  lines.push('', T.todo);
  for (const step of T[result.verdict]) lines.push(`• ${step}`);
  return lines.join('\n');
}

export function snippet(text, max = 160) {
  const s = String(text).replace(/\s+/g, ' ').trim();
  // never forward long digit runs (card numbers, codes) to a second person
  const safe = s.replace(/\d{4,}/g, (d) => '•'.repeat(d.length));
  return safe.length > max ? safe.slice(0, max - 1) + '…' : safe;
}

export function familyAlert(result, who, text, lang = 'en') {
  const name = who || (lang === 'ar' ? 'أحد أفراد العائلة' : 'A family member');
  const head =
    lang === 'ar'
      ? `${ICON[result.verdict]} ${name} تلقّى رسالة ${result.verdict === 'red' ? 'احتيالية على الأغلب' : 'مشبوهة'}.`
      : `${ICON[result.verdict]} ${name} received a ${result.verdict === 'red' ? 'very likely scam' : 'suspicious'} message.`;
  const top = result.signals.slice(0, 2).map((s) => `• ${s[lang] || s.en}`);
  const cta = lang === 'ar' ? 'اتصل بهم قبل أن يضغطوا أو يردوا.' : 'Call them before they click or reply.';
  return [head, '', `“${snippet(text)}”`, '', ...top, '', cta].join('\n');
}
