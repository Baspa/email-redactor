#!/usr/bin/env python3
"""
redact_emails.py - pseudonymize customer emails locally so they can be used as
few-shot examples / eval data for an LLM agent.

* Runs fully offline. Nothing is sent anywhere.
* Consistent: the same real value always maps to the same fake (mapping.json),
  so threads, quoted replies and references stay coherent.
* Format-preserving: IBANs and national IDs (TR TCKN, CO NIT) keep valid
  checksums, phones keep their country code, fake names match the culture of
  the email (Turkish name -> Turkish fake, Colombian -> Spanish two surnames).
* Writes a review file per email with a leak check and suspicious leftovers.
  Always read it: regexes and NER WILL miss things.

Usage:
    python redact_emails.py INPUT_DIR OUTPUT_DIR [--config config.json]
        [--entities known_entities.csv] [--mapping mapping.json]
        [--ner spacy:xx_ent_wiki_sm | --ner gliner]

Input files: .eml, .txt, .msg (needs `pip install extract-msg`)
Optional:    `pip install faker` for large locale-aware name pools.
"""
from __future__ import annotations

import argparse
import csv
import email
import hashlib
import json
import os
import random
import re
import secrets
import string
import sys
from email import policy
from email.utils import getaddresses
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

# --------------------------------------------------------------------------- #
# Character classes (Latin script incl. Turkish, Polish, Spanish, German, ...)
# --------------------------------------------------------------------------- #
UP = "A-ZÀ-ÖØ-ÞĀĂĄĆČĎĐĒĖĘĚĞĪİĶĹĽŁŃŇŌŐŒŔŘŚŞŠŢŤŪŮŰŲŹŻŽ"
LO = "a-zß-öø-ÿāăąćčďđēėęěğīıķĺľłńňōőœŕřśşšţťūůűųźżž"
CAP_WORD = rf"[{UP}][{LO}'’\-]+"
LETTER_BOUNDARY_L = r"(?<![^\W\d_])"
LETTER_BOUNDARY_R = r"(?![^\W\d_])"

PARTICLES = {"van", "de", "der", "den", "ten", "ter", "te", "het", "von", "vom", "zu",
             "du", "da", "di", "del", "della", "la", "le", "las", "los", "y", "e",
             "dos", "das", "do", "bin", "ibn", "al", "el"}
TITLES = r"(?:Dhr\.?|Mevr\.?|Mw\.?|Heer|Mevrouw|Herr|Frau|Mr\.?|Mrs\.?|Ms\.?|Miss|Dr\.?|Ing\.?|Ir\.?|" \
         r"Sr\.?|Sra\.?|Srta\.?|Señor|Señora|Don|Doña|Lic\.?|Sayın|Pan|Pani|M\.|Mme\.?|Monsieur|Madame)"
GREETINGS = r"(?:Beste|Geachte|Hoi|Hallo|Dag|Dear|Hi|Hello|Hey|Liebe[rs]?|Sehr geehrte[rs]?|Hola|" \
            r"Estimad[oa]s?|Buen(?:os|as) d[ií]as|Buenas tardes|Merhaba|Selam|İyi günler|Dzień dobry|" \
            r"Szanown[ya]|Bonjour|Cher|Chère)"
ROLE_WORDS = {"team", "afdeling", "department", "desk", "customer", "klantenservice", "kundenservice", "servicio",
              "departamento", "ekibi", "departmanı", "group", "groep", "noreply", "notifications"}
HONORIFICS = {"bey", "hanım", "hanim", "efendi", "san", "sama"}
SALUTATION_NOUNS = {"klant", "klanten", "heer", "mevrouw", "collega", "collega's", "allen", "team",
                    "customer", "sir", "madam", "all", "everyone", "cliente", "clientes", "señor",
                    "señores", "señora", "equipo", "todos", "efendim", "arkadaşlar", "kunde", "damen",
                    "herren", "zusammen", "team,", "partner", "müşterimiz", "hanım", "bey",
                    "monsieur", "madame", "państwo", "sales", "verkoop"}
CLOSINGS = re.compile(
    r"^\s*(?:met vriendelijke groet(?:en)?|vriendelijke groet(?:en)?|mvg|groet(?:en|jes)?|"
    r"kind regards|best regards|warm regards|regards|best|cheers|thanks|thank you|"
    r"mit freundlichen grüßen|freundliche grüße|viele grüße|beste grüße|mfg|lg|"
    r"saludos(?: cordiales)?|un saludo|cordialmente|atentamente|quedo atent[oa]|gracias|"
    r"saygılarımla|saygılar|iyi çalışmalar|teşekkürler|teşekkür ederim|kolay gelsin|"
    r"pozdrawiam|z poważaniem|cordialement|bien à vous)\b[\s,.!]*$", re.I | re.M)

LEGAL_SUFFIX = (
    r"(?:(?:San\.?\s*(?:ve\s*)?)?Tic\.?\s*(?:Ltd\.?\s*Şti\.?|A\.?\s?Ş\.?)|Ltd\.?\s*Şti\.?|A\.\s?Ş\.|AŞ|"
    r"S\.?\s?A\.?\s?S\.?|S\.?\s?A\.?(?:\s+de\s+C\.?\s?V\.?)?|S\.?\s?L\.?U?\.?|Ltda\.?|S\.?\s?R\.?\s?L\.?|"
    r"S\.?p\.?A\.?|Sp\.?\s?z\s?o\.?\s?o\.?|S\.?A\.?R\.?L\.?|GmbH(?:\s*&\s*Co\.?\s*KG)?|AG|KG|e\.K\.|"
    r"B\.\s?V\.|BV|N\.\s?V\.|NV|V\.O\.F\.|VOF|BVBA|Ltd\.?|Limited|LLC|Inc\.?|PLC|s\.r\.o\.|Oy|AB|A/S|ApS)"
)
LEGAL_SUFFIX_END = re.compile(rf"(?:\s+|\s*,\s*)({LEGAL_SUFFIX})\s*$")
COMPANY_INLINE = re.compile(rf"((?:{CAP_WORD}|[{UP}]{{2,}}|&)(?:[ \t]+(?:{CAP_WORD}|[{UP}]{{2,}}|&|ve|en|und|y)){{0,4}})"
                            rf"(?:[ \t]+|[ \t]*,[ \t]*)({LEGAL_SUFFIX})(?![\w])")

GENERIC_LOCALS = {"info", "sales", "verkoop", "inkoop", "purchase", "purchasing", "admin", "administratie",
                  "support", "service", "contact", "office", "noreply", "no-reply", "mail", "orders", "order",
                  "finance", "boekhouding", "invoice", "invoices", "facturen", "hr", "logistics", "planning",
                  "export", "import", "parts", "onderdelen", "ventas", "compras", "satis", "satış", "muhasebe",
                  "iletisim", "bilgi", "contabilidad", "facturacion", "verkauf", "einkauf", "buchhaltung"}

# --------------------------------------------------------------------------- #
# Locale packs: fake-name pools (used when Faker isn't installed) + detection
# --------------------------------------------------------------------------- #
POOLS = {
    "nl": dict(first="Pieter Sanne Joris Lotte Bram Femke Thijs Iris Ruben Noor Daan Eva Stijn Lieke Koen Anouk Niels Maud Wouter Roos Jeroen Fleur Sven Ilse",
               last="Visser Bakker Mulder Smit Meijer Kok Postma Hendriks Dekker Brouwer Wolters Kuipers Veenstra Scholten Prins Huisman Kramer Vos Hoekstra Koster Verbeek Blom Schouten Timmer",
               words="Transport Logistiek Handel Techniek Verhuur Groep Trucks Machines",
               streets="Lindenlaan Molenweg Kastanjestraat Havenkade Beukenlaan Dorpsstraat Esdoornweg Wilgenlaan"),
    "de": dict(first="Lukas Anna Felix Lea Jonas Marie Paul Sophie Tim Laura Jan Hannah Max Julia Niklas Lena Moritz Clara",
               last="Müller Schmidt Schneider Fischer Weber Becker Wagner Hoffmann Schäfer Koch Richter Klein Wolf Neumann Braun Krüger Hartmann Lange",
               words="Transporte Logistik Handel Technik Spedition Fahrzeuge Maschinenbau",
               streets="Lindenstraße Mühlenweg Bahnhofstraße Gartenweg Birkenallee Schulstraße"),
    "en": dict(first="James Emma Oliver Sophie Harry Grace Jack Chloe George Lucy Thomas Emily Daniel Hannah",
               last="Walker Harris Clarke Lewis Robinson Wright Hall Green Baker Turner Hill Cooper Ward Morris",
               words="Logistics Transport Trading Haulage Machinery Services Freight",
               streets="Oak Mill Church Station Park Queen Victoria Elm"),
    "tr": dict(first="Mehmet Ayşe Mustafa Fatma Ahmet Emine Ali Hatice Hüseyin Zeynep Hasan Elif İbrahim Merve Murat Özlem Emre Gülşen Burak Şule Oğuz Çağla",
               last="Yılmaz Kaya Demir Şahin Çelik Yıldız Yıldırım Öztürk Aydın Özdemir Arslan Doğan Kılıç Aslan Çetin Kara Koç Kurt Özkan Şimşek Polat Güneş",
               words="Lojistik Nakliyat Otomotiv Ticaret Makina İnşaat Taşımacılık",
               streets="Atatürk Cumhuriyet Gazi Lale Çınar Menekşe Barış Zafer Gül İstiklal"),
    "es": dict(first="Juan Carlos Andrés Camila Valentina Santiago Daniela Sebastián Mariana Felipe Laura Alejandro Natalia Julián Paula Mateo Luisa Diego Sofía",
               last="García Rodríguez Martínez López González Hernández Pérez Sánchez Ramírez Torres Gómez Díaz Vargas Castro Rojas Moreno Restrepo Ospina Cárdenas Salazar Mejía Quintero",
               words="Transportes Logística Comercial Maquinaria Distribuciones Inversiones Automotores",
               streets="Mayor Real Libertad Bolívar Nariño Santander Alameda Rosales"),
    "pl": dict(first="Piotr Anna Krzysztof Katarzyna Tomasz Magdalena Paweł Agnieszka Michał Joanna Łukasz Monika",
               last="Nowak Kowalski Wiśniewski Wójcik Kowalczyk Kamiński Lewandowski Zieliński Szymański Woźniak Dąbrowski",
               words="Transport Logistyka Handel Spedycja Maszyny",
               streets="Lipowa Polna Leśna Słoneczna Krótka Szkolna"),
    "fr": dict(first="Louis Camille Hugo Léa Lucas Chloé Jules Manon Arthur Inès Théo Sarah",
               last="Martin Bernard Dubois Thomas Robert Richard Petit Durand Leroy Moreau Simon Laurent",
               words="Transports Logistique Négoce Services Distribution",
               streets="Victor-Hugo Pasteur Gambetta Jean-Jaurès Voltaire Moulin"),
}
POOLS = {k: {kk: vv.split() for kk, vv in v.items()} for k, v in POOLS.items()}

# country/locale code -> name pool
LOCALE_POOL = {"nl": "nl", "be": "nl", "de": "de", "at": "de", "ch": "de", "en": "en", "gb": "en", "us": "en",
               "ie": "en", "tr": "tr", "es": "es", "co": "es", "mx": "es", "ar": "es", "cl": "es", "pe": "es",
               "ec": "es", "pl": "pl", "fr": "fr"}
FAKER_LOCALE = {"nl": "nl_NL", "be": "nl_BE", "de": "de_DE", "at": "de_AT", "ch": "de_CH", "en": "en_GB",
                "gb": "en_GB", "us": "en_US", "ie": "en_IE", "tr": "tr_TR", "es": "es_ES", "co": "es_CO",
                "mx": "es_MX", "ar": "es_AR", "cl": "es_CL", "pe": "es_ES", "ec": "es_ES", "pl": "pl_PL",
                "fr": "fr_FR"}
TLD_LOCALE = {"nl": "nl", "be": "be", "de": "de", "at": "at", "ch": "ch", "uk": "gb", "ie": "ie", "tr": "tr",
              "es": "es", "co": "co", "mx": "mx", "ar": "ar", "cl": "cl", "pe": "pe", "ec": "ec", "pl": "pl",
              "fr": "fr"}
CC_LOCALE = {"31": "nl", "32": "be", "49": "de", "43": "at", "41": "ch", "44": "gb", "353": "ie", "1": "us",
             "90": "tr", "34": "es", "57": "co", "52": "mx", "54": "ar", "56": "cl", "51": "pe", "593": "ec",
             "48": "pl", "33": "fr"}
COUNTRY_CODES = set(CC_LOCALE) | {"7", "20", "27", "30", "36", "39", "40", "45", "46", "47", "55", "58", "60",
                                  "61", "62", "63", "64", "65", "66", "81", "82", "84", "86", "91", "92", "212",
                                  "213", "216", "351", "352", "358", "359", "370", "371", "372", "380", "381",
                                  "385", "386", "420", "421", "966", "971", "972", "974"}
STOPWORDS = {
    "nl": "de het een en van ik je we wij u uw voor met op niet graag bedankt groet vriendelijke hierbij zijn".split(),
    "de": "der die das und ist ich sie wir für mit nicht bitte danke grüße vielen ihre unsere".split(),
    "en": "the and is are you we for with not please thanks regards our your this that".split(),
    "tr": "ve bir bu için ile de da çok teşekkürler merhaba saygılarımla rica ederim olarak var mı".split(),
    "es": "el la los las y es un una para con por que no gracias saludos cordialmente usted nuestro favor".split(),
    "pl": "i w na z do że się nie jest dziękuję pozdrawiam proszę".split(),
    "fr": "le la les et est un une pour avec ne pas merci cordialement nous vous".split(),
}

# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
PH_OPEN, PH_CLOSE = "\uE000", "\uE001"
PH_DIGITS = "".join(chr(0xE010 + i) for i in range(16))
PH_RE = re.compile(f"{PH_OPEN}([{PH_DIGITS}]+){PH_CLOSE}")


def ph_encode(n: int) -> str:
    return PH_OPEN + "".join(PH_DIGITS[int(c, 16)] for c in format(n, "x")) + PH_CLOSE


def ph_decode(s: str) -> int:
    return int("".join(format(PH_DIGITS.index(c), "x") for c in s), 16)


def scramble(s: str, rng: random.Random, keep: int = 0, letters: bool = False) -> str:
    """Replace digits (and optionally ASCII letters) keeping length, case and separators."""
    out = []
    for i, ch in enumerate(s):
        if i < keep:
            out.append(ch)
        elif ch.isdigit():
            out.append(rng.choice(string.digits))
        elif letters and ch.isascii() and ch.isalpha():
            out.append(rng.choice(string.ascii_uppercase if ch.isupper() else string.ascii_lowercase))
        else:
            out.append(ch)
    return "".join(out)


def reapply_format(template: str, digits: str) -> str:
    """Put `digits` (alnum chars) back into the separators of `template`."""
    it = iter(digits)
    return "".join(next(it) if ch.isalnum() else ch for ch in template)


def tr_upper(s: str) -> str:
    return s.replace("i", "İ").replace("ı", "I").upper()


def is_upper_word(s: str) -> bool:
    letters = [c for c in s if c.isalpha()]
    return len(letters) > 1 and all(c.isupper() for c in letters)


# --- checksummed identifiers ------------------------------------------------ #
def iban_valid(raw: str) -> bool:
    s = raw.replace(" ", "").upper()
    if not (15 <= len(s) <= 34) or not s.isalnum():
        return False
    return int("".join(str(int(c, 36)) for c in s[4:] + s[:4])) % 97 == 1


def fake_iban(orig: str, rng: random.Random) -> str:
    compact = orig.replace(" ", "").upper()
    cc, bban = compact[:2], compact[4:]
    new_bban = bban[:4] + scramble(bban[4:], rng, letters=True)  # keep bank code
    check = 98 - int("".join(str(int(c, 36)) for c in new_bban + cc + "00")) % 97
    return reapply_format(orig, f"{cc}{check:02d}{new_bban}")


def tckn_valid(s: str) -> bool:
    if len(s) != 11 or not s.isdigit() or s[0] == "0":
        return False
    d = [int(c) for c in s]
    return (sum(d[0:9:2]) * 7 - sum(d[1:8:2])) % 10 == d[9] and sum(d[:10]) % 10 == d[10]


def fake_tckn(orig: str, rng: random.Random) -> str:
    d = [rng.randint(1, 9)] + [rng.randint(0, 9) for _ in range(8)]
    d.append((sum(d[0:9:2]) * 7 - sum(d[1:8:2])) % 10)
    d.append(sum(d) % 10)
    return "".join(map(str, d))


NIT_W = [3, 7, 13, 17, 19, 23, 29, 37, 41, 43, 47, 53, 59, 67, 71]


def nit_dv(num: str) -> int:
    s = sum(int(c) * NIT_W[i] for i, c in enumerate(reversed(num))) % 11
    return s if s < 2 else 11 - s


def fake_nit(orig: str, rng: random.Random) -> str:
    digits = re.sub(r"\D", "", orig)
    base = digits[0] + "".join(rng.choice(string.digits) for _ in digits[1:-1])  # keep type digit
    return reapply_format(orig, base + str(nit_dv(base)))


# --------------------------------------------------------------------------- #
# Persistent real -> fake mapping
# --------------------------------------------------------------------------- #
class Mapper:
    def __init__(self, path: Path):
        self.path = path
        if path.exists():
            self.data = json.loads(path.read_text("utf-8"))
        else:
            self.data = {"salt": secrets.token_hex(16), "maps": {}, "files": {}}
        self._fakers: dict = {}
        self.corpus_tokens: set[str] = set()  # filled by main() from all raw inputs
        self.cap_words: dict[str, set[str]] = {}  # folded -> capitalized spellings seen in inputs

    def rng(self, cat: str, value: str) -> random.Random:
        return random.Random(hashlib.sha256(f"{self.data['salt']}|{cat}|{value}".encode()).hexdigest())

    def get(self, cat: str, original: str, factory) -> str:
        m = self.data["maps"].setdefault(cat, {})
        if original in m:
            return m[original]
        used = set(m.values())
        real = self.real_tokens() | name_tokens(original)
        rng = self.rng(cat, original)
        for _ in range(200):
            fake = factory(original, rng)
            if fake not in used and not (name_tokens(fake) & real):  # a fake must never echo a real name
                break
        m[original] = fake
        return fake

    def real_tokens(self) -> set[str]:
        """Name-like tokens from all real inputs + everything already mapped."""
        cats = ("first_name", "last_name", "company", "domain", "street", "person", "other", "email_local")
        return self.corpus_tokens | {t for c in cats for k in self.data["maps"].get(c, {}) for t in name_tokens(k)}

    def lookup(self, cat: str, original: str) -> str | None:
        m = self.data["maps"].get(cat, {})
        if original in m:
            return m[original]
        low = ascii_fold(original).casefold()
        return next((v for k, v in m.items() if ascii_fold(k).casefold() == low), None)

    def all_fakes(self) -> set[str]:
        return {v for m in self.data["maps"].values() for v in m.values()}

    def file_id(self, content: bytes, source: str) -> str:
        h = hashlib.sha256(content).hexdigest()
        files = self.data["files"]
        if h not in files:
            files[h] = {"id": f"email_{len(files) + 1:03d}", "source": source}
        return files[h]["id"]

    def faker(self, locale: str):
        if locale not in self._fakers:
            try:
                from faker import Faker
                self._fakers[locale] = Faker(FAKER_LOCALE.get(locale, "en_GB"))
            except Exception:
                self._fakers[locale] = None
        return self._fakers[locale]

    def save(self):
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=2, ensure_ascii=False), "utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(self.path)


# --------------------------------------------------------------------------- #
# Loading messages
# --------------------------------------------------------------------------- #
class _HTMLText(HTMLParser):
    BLOCK = {"br", "p", "div", "tr", "li", "table", "h1", "h2", "h3", "h4", "blockquote"}

    def __init__(self):
        super().__init__()
        self.parts, self._skip = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in ("style", "script", "head"):
            self._skip += 1
        elif tag in self.BLOCK:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("style", "script", "head"):
            self._skip = max(0, self._skip - 1)
        elif tag in ("p", "div", "tr", "table"):
            self.parts.append("\n")
        elif tag in ("td", "th"):
            self.parts.append("\t")

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def html_to_text(html: str) -> str:
    p = _HTMLText()
    p.feed(html)
    text = "".join(p.parts)
    text = re.sub(r"[ \t\xa0]+\n", "\n", text)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


HEADER_KEYS = ["From", "To", "Cc", "Reply-To", "Date", "Subject"]


def load_message(path: Path) -> tuple[dict, str, list[str]]:
    suffix = path.suffix.lower()
    if suffix == ".eml":
        msg = email.message_from_bytes(path.read_bytes(), policy=policy.default)
        headers = {k: str(msg[k]) for k in HEADER_KEYS if msg[k]}
        part = msg.get_body(preferencelist=("plain", "html"))
        body = ""
        if part is not None:
            body = part.get_content()
            if part.get_content_type() == "text/html":
                body = html_to_text(body)
        attachments = [a.get_filename() for a in msg.iter_attachments() if a.get_filename()]
        return headers, body, attachments
    if suffix == ".msg":
        import extract_msg  # pip install extract-msg
        m = extract_msg.Message(str(path))
        headers = {k: v for k, v in {"From": m.sender, "To": m.to, "Cc": m.cc, "Date": str(m.date or ""),
                                     "Subject": m.subject}.items() if v}
        body = m.body or (html_to_text(m.htmlBody.decode("utf-8", "replace")) if m.htmlBody else "")
        attachments = [a.longFilename or a.shortFilename for a in m.attachments if (a.longFilename or a.shortFilename)]
        return headers, body, attachments
    return {}, path.read_text("utf-8", errors="replace"), []


def assemble(headers: dict, body: str, attachments: list[str]) -> str:
    lines = [f"{k}: {' '.join(v.split())}" for k, v in headers.items()]
    if attachments:
        lines.append("Attachments: " + ", ".join(attachments))
    return ("\n".join(lines) + "\n\n" if lines else "") + body.replace("\r\n", "\n").strip() + "\n"


# --------------------------------------------------------------------------- #
# The redactor
# --------------------------------------------------------------------------- #
ADDR_LINE_RE = re.compile(r"^[ \t>]*(?:\*\*)?(?:From|To|Cc|Reply-To|Van|Aan|Von|An|De|Para|À|Od|Do|Kimden|Kime|"
                          r"Gönderen|Alıcı|Bilgi|Envoyé par)(?:\*\*)?\s*:\s*(.+)$", re.M | re.I)
EMAIL_RE = re.compile(r"[\w.%+\-]+@[\w\-]+(?:\.[\w\-]+)*\.[^\W\d_]{2,}")
TRACKING_PARAMS = re.compile(r"^(utm_\w+|fbclid|gclid|msclkid|mc_[ce]id|_hs\w+|mkt_tok|trk\w*|ref|source)$", re.I)
DATE_LIKE = re.compile(r"\d{1,4}[-./]\d{1,2}[-./]\d{1,4}")

ID_KEYWORDS = (r"kvk|k\.v\.k\.|coc|btw(?:-?nr|\s*nummer)?|vat(?:\s*(?:no|number|id))?|ust-?id(?:nr)?|steuer-?nr|"
               r"steuernummer|hrb|handelsregister|bsn|nit|rut|rfc|c\.\s?c\.|cc|c[ée]dula|nif|cif|dni|nie|vergi\s*no|"
               r"vergi\s*numarası|vkn|tc\s*kimlik(?:\s*no)?|t\.c\.\s*kimlik(?:\s*no)?|tckn|kimlik\s*no|mersis(?:\s*no)?|"
               r"ticaret\s*sicil(?:\s*no)?|nip|regon|krs|siret|siren|passport(?:\s*no)?|pasaporte|pasaport|paspoort|"
               r"reisepass|customer\s*(?:no|number|id)|klantnummer|debiteurnummer|kundennummer|"
               r"n[úu]mero\s*de\s*cliente|m[üu]şteri\s*no|account\s*(?:no|number)|rekeningnummer|kontonummer|"
               r"cuenta(?:\s*(?:de\s*ahorros|corriente))?|hesap\s*no|posta\s*kodu|c[óo]digo\s*postal|postal\s*code|"
               r"postcode|zip|plz")
PHONE_KEYWORDS = r"tel|tél|telefon[oe]?|teléfono|telf|phone|mobile?|mob|mobiel|móvil|movil|celular|cel|cep|gsm|whatsapp|fax"


class Redactor:
    def __init__(self, mapper: Mapper, config: dict, ner=None):
        self.m = mapper
        self.keep_domains = [d.lower() for d in config.get("keep_domains", [])]
        self.keep_terms = config.get("keep_terms", [])
        self.default_locale = config.get("default_locale", "en")
        self.ner = ner
        self.locale = self.default_locale
        self.entities: dict[str, tuple[str, str]] = {}  # original -> (fake, source)
        self.csv_pending: list[tuple[str, str]] = []
        self.rules = self._build_rules(config.get("custom_patterns", []))

    # ---------- locale ---------------------------------------------------- #
    def detect_locale(self, text: str) -> str:
        country: dict[str, int] = {}
        for m in EMAIL_RE.finditer(text):
            dom = m.group(0).rsplit("@", 1)[1].lower()
            if not self._keep_domain(dom) and dom.rsplit(".", 1)[-1] in TLD_LOCALE:
                c = TLD_LOCALE[dom.rsplit(".", 1)[-1]]
                country[c] = country.get(c, 0) + 3
        for m in re.finditer(r"(?:\+|\b00)(\d{1,3})", text):
            for n in (3, 2, 1):
                cc = m.group(1)[:n]
                if cc in CC_LOCALE:
                    country[CC_LOCALE[cc]] = country.get(CC_LOCALE[cc], 0) + 3
                    break
        words = re.findall(r"[^\W\d_]+", text.casefold())
        lang = {k: sum(words.count(w) for w in ws) for k, ws in STOPWORDS.items()}
        if re.search(r"[ğış]|İ", text):
            lang["tr"] += 5
        if re.search(r"[ñ¿¡]", text):
            lang["es"] += 3
        pools: dict[str, int] = dict(lang)
        for c, s in country.items():
            pools[LOCALE_POOL[c]] = pools.get(LOCALE_POOL[c], 0) + s
        if not pools or max(pools.values()) == 0:
            return self.default_locale
        pool = max(pools, key=pools.get)
        in_pool = {c: s for c, s in country.items() if LOCALE_POOL[c] == pool}
        return max(in_pool, key=in_pool.get) if in_pool else pool

    def _pool(self) -> dict:
        return POOLS[LOCALE_POOL.get(self.locale, "en")]

    def _fake_first(self, _o, rng):
        f = self.m.faker(self.locale)
        if f:
            f.seed_instance(rng.random())
            return f.first_name()
        return rng.choice(self._pool()["first"])

    def _fake_last(self, _o, rng):
        f = self.m.faker(self.locale)
        if f:
            f.seed_instance(rng.random())
            return f.last_name()
        return rng.choice(self._pool()["last"])

    def _fake_company(self, _o, rng):
        p = self._pool()
        return f"{rng.choice(p['last'])} {rng.choice(p['words'])}"

    def _fake_street(self, _o, rng):
        return rng.choice(self._pool()["streets"])

    # ---------- entity registration ------------------------------------- #
    def _is_kept(self, value: str) -> bool:
        # whole words only: keep term "MAN" must not match "Hermann" or "Germany"
        return any(re.search(LETTER_BOUNDARY_L + re.escape(t) + LETTER_BOUNDARY_R, value, re.I) for t in self.keep_terms)

    def _add_entity(self, original: str, fake: str, source: str):
        original = original.strip()
        if len(original) < 2 or self._is_kept(original) or original.casefold() in SALUTATION_NOUNS:
            return
        self.entities.setdefault(original, (fake, source))

    def add_person(self, name: str, source: str):
        name = re.sub(rf"^\s*{TITLES}\s+", "", name.strip().strip("\"'"), flags=re.I)
        if "," in name:  # "Jansen, Jan" -> "Jan Jansen"
            last, _, first = name.partition(",")
            name = f"{first.strip()} {last.strip()}"
        tokens = [t for t in name.split() if t.casefold() not in HONORIFICS]
        name = " ".join(tokens)
        if not tokens or len(tokens) > 6 or any(ch.isdigit() or ch in "@<>()[]/" for ch in name):
            return
        if self._is_kept(name) or tokens[0].casefold() in SALUTATION_NOUNS:
            return
        name_tokens = [t for t in tokens if t.casefold() not in PARTICLES]
        if not name_tokens or not all(t[0].isupper() for t in name_tokens):
            return
        if all(is_upper_word(t) for t in name_tokens) and len(name_tokens) == 1:
            return  # "SALES", "BAS" ...
        fakes = []
        for i, t in enumerate(tokens):
            if t.casefold() in PARTICLES and i > 0:
                fakes.append(t)
            elif i == 0:
                fakes.append(self.m.get("first_name", t, self._fake_first))
            else:
                fakes.append(self.m.get("last_name", t, self._fake_last))
        self._add_entity(name, " ".join(fakes), source)
        for t, f in zip(tokens, fakes):
            if t.casefold() not in PARTICLES and len(t) >= 3:
                self._add_entity(t, f, source)
        if len(tokens) >= 2:
            self._add_entity(f"{tokens[-1]}, {tokens[0]}", f"{fakes[-1]}, {fakes[0]}", source)

    def add_company(self, name: str, source: str):
        name = " ".join(name.split()).strip(" ,-")
        m = LEGAL_SUFFIX_END.search(name)
        core, suffix = (name[:m.start()].strip(" ,"), m.group(1)) if m else (name, "")
        core = re.sub(rf"^(?:{GREETINGS}|{TITLES})\s+", "", core, flags=re.I).strip()
        if not core or self._is_kept(core) or len(core) < 2:
            return
        fake_core = self.m.get("company", core, self._fake_company)
        if suffix:
            self._add_entity(f"{core} {suffix}", f"{fake_core} {suffix}", source)
        self._add_entity(core, fake_core, source)

    def load_entities_csv(self, path: Path):
        with path.open(encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                typ, value, fake = row.get("type", "").strip(), row.get("value", "").strip(), row.get("fake", "").strip()
                if not value:
                    continue
                if fake:
                    self.m.data["maps"].setdefault(typ, {})[value] = fake
                    self._add_entity(value, fake, "csv")
                elif typ in ("person", "company"):
                    self.csv_pending.append((typ, value))  # registered in the locale of the email it appears in
                else:
                    self._add_entity(value, self.m.get(typ or "other", value,
                                                       lambda o, r: scramble(o, r, letters=True)), "csv")

    # ---------- harvesting names from the email itself ------------------ #
    def harvest(self, text: str):
        # 0. known entities from the CSV (always, even when the heuristics below would miss them)
        folded = ascii_fold(text).casefold()
        for typ, value in self.csv_pending:
            core = LEGAL_SUFFIX_END.sub("", value) if typ == "company" else value
            probes = {value, core} | (set(core.split()[-1:]) if typ == "person" else set())
            if any(re.search(LETTER_BOUNDARY_L + re.escape(ascii_fold(v).casefold()) + LETTER_BOUNDARY_R, folded)
                   for v in probes):
                (self.add_person if typ == "person" else self.add_company)(value, "csv")
        # 1. address lines (headers + quoted "Van:/From:/Kimden:/De:" lines)
        for m in ADDR_LINE_RE.finditer(text):
            value = re.sub(r"\[mailto:([^\]]+)\]", r"<\1>", m.group(1)).replace(";", ",")
            if "@" not in value and not self._is_kept(value):
                self._classify_name(value, "address-line")
                continue
            for disp, addr in getaddresses([value]):
                if disp and "@" not in disp:
                    self._classify_name(disp, "address-line")
                elif addr:
                    self._name_from_local(addr, text)
        # 2. bare email addresses anywhere -> names like jan.jansen if they appear capitalized in text
        for m in EMAIL_RE.finditer(text):
            self._name_from_local(m.group(0), text)
        # 3. titles / greetings
        for m in re.finditer(rf"\b{TITLES}\s+({CAP_WORD}(?:\s+(?:(?:{'|'.join(PARTICLES)})\s+)*{CAP_WORD}){{0,3}})", text):
            self.add_person(m.group(1), "title")
        for m in re.finditer(rf"(?:^|\n)\s*{GREETINGS}\s+({CAP_WORD}(?:\s+{CAP_WORD}){{0,2}})\s*[,!\n]", text, re.I):
            if m.group(1).casefold() not in SALUTATION_NOUNS:
                self.add_person(m.group(1), "greeting")
        for m in re.finditer(rf"({CAP_WORD})\s+(?:Bey|Hanım|Hanim)\b", text):  # Turkish "Ahmet Bey"
            self.add_person(m.group(1), "tr-honorific")
        # 4. signature: first line(s) after a closing phrase
        for m in CLOSINGS.finditer(text):
            after = [l.strip() for l in text[m.end():].splitlines() if l.strip()][:2]
            for line in after:
                if re.fullmatch(rf"{CAP_WORD}(?:\s+(?:(?:{'|'.join(PARTICLES)})\s+)*{CAP_WORD}){{1,4}}", line):
                    self.add_person(line, "signature")
                    break
        # 5. anything ending in a legal form: "Yılmaz Otomotiv San. ve Tic. Ltd. Şti.", "Rojas S.A.S."
        for m in COMPANY_INLINE.finditer(text):
            self.add_company(f"{m.group(1)} {m.group(2)}", "legal-suffix")
        # 6. street names (so the same street in another address format is replaced too)
        for rule, regex, _h in self.rules:
            if rule.startswith("addr_") and "name" in regex.groupindex:
                for m in regex.finditer(text):
                    street = m.group("name").strip()
                    if len(street) >= 5 and not self._is_kept(street):
                        self._add_entity(street, self.m.get("street", street, self._fake_street), "street")
        # 7. customer domains, so bare mentions ("see firma.de") are replaced too
        for m in EMAIL_RE.finditer(text):
            dom = m.group(0).rsplit("@", 1)[1]
            if not self._keep_domain(dom):
                self._add_entity(dom.lower(), self._domain(dom), "domain")
        # 8. name parts of email addresses
        for m in EMAIL_RE.finditer(text):
            if not self._keep_domain(m.group(0).rsplit("@", 1)[1]) or m.group(0).split("@")[0].lower() not in GENERIC_LOCALS:
                self._local_parts(m.group(0))
        # 9. optional NER
        if self.ner:
            for label, value in self.ner(text):
                if "\n" in value or "@" in value or any(c.isdigit() for c in value) or len(value) > 60:
                    continue
                if not value[:1].isupper():
                    continue
                (self.add_person if label == "person" else self.add_company)(value, "NER")

    def _classify_name(self, disp: str, source: str):
        disp = " ".join(disp.strip().strip("\"'").split())
        if not re.search(r"[^\W\d_]", disp) or self._is_kept(disp):
            return
        role = {t.casefold() for t in re.findall(r"[^\W\d_]+", disp)} & (GENERIC_LOCALS | ROLE_WORDS)
        if LEGAL_SUFFIX_END.search(disp) or role:  # "BAS World Sales", "Ventas Rojas" -> organisation
            self.add_company(re.sub(rf"(?i)\s*\b(?:{'|'.join(map(re.escape, role))})\b", "", disp) if role else disp, source)
        else:
            self.add_person(disp, source)

    def _name_from_local(self, addr: str, text: str):
        local = addr.split("@")[0]
        parts = [p for p in re.split(r"[._\-]", local) if p]
        if len(parts) < 2 or not all(p.isalpha() and len(p) >= 2 for p in parts):
            return
        candidate = " ".join(p.capitalize() for p in parts)
        hit = re.search(re.escape(ascii_fold(candidate)), ascii_fold(text), re.I)
        if hit:  # take the real spelling from the text: "yilmaz" -> "Yılmaz"
            self.add_person(text[hit.start():hit.end()], "email-local-part")

    def _local_parts(self, addr: str):
        """'j.surname@' -> 'Surname' written anywhere in any email. Runs last, so real first names
        (found via titles/greetings) already have a first-name fake."""
        local = addr.split("@")[0]
        parts = [p for p in re.split(r"[._\-]", local) if p]
        if local.lower() in GENERIC_LOCALS or len(parts) > 3 or not all(p.isalpha() for p in parts):
            return
        for p in parts:  # "j.surname@" -> "Surname" written anywhere else in any email
            if len(p) < 3 or p.lower() in GENERIC_LOCALS | ROLE_WORDS:
                continue
            key = ascii_fold(p).casefold()
            for word in self.m.cap_words.get(key, ()):
                fake = self.m.lookup("first_name", word) or self.m.get("last_name", word, self._fake_last)
                self._add_entity(word, fake, "email-local-part")

    # ---------- replacement rules ---------------------------------------- #
    def _keep_domain(self, domain: str) -> bool:
        domain = domain.lower()
        if any(domain == k or domain.endswith("." + k) for k in self.keep_domains):
            return True
        terms = {re.sub(r"[\s\-]", "", t.casefold()) for t in self.keep_terms}
        return any(label.replace("-", "") in terms for label in domain.split(".")[:-1])

    def _fake_domain(self, orig: str, rng) -> str:
        labels = orig.split(".")
        tld = ".".join(labels[-2:]) if len(labels) >= 3 and labels[-2] in ("co", "com", "org", "net", "gov", "edu", "ac") else labels[-1]
        name = self._fake_company(orig, rng).lower()
        name = re.sub(r"[^a-z0-9]+", "-", name.translate(str.maketrans("çğıöşüáéíóúñäßøåłś", "cgiosuaeiounasoals")))
        return f"{name.strip('-')}.{tld}"

    def _domain(self, domain: str) -> str:
        return domain if self._keep_domain(domain) else self.m.get("domain", domain.lower(), self._fake_domain)

    def _email(self, m):
        addr = m.group(0)
        local, domain = addr.rsplit("@", 1)
        new_domain = self._domain(domain)
        if local.lower() in GENERIC_LOCALS:
            return f"{local}@{new_domain}"

        def fake_local(o, rng):
            sep = next((c for c in "._-" if c in local), "")
            parts = [p for p in re.split(r"[._\-]", local) if p]
            fakes = []
            for p in parts:  # reuse the person's fake name when known -> coherent thread
                f = self.m.lookup("first_name", p) or self.m.lookup("last_name", p)
                if f is None and len(p) == 1:
                    f = rng.choice(string.ascii_lowercase)
                if f is None and p.isalpha() and 2 <= len(p) <= 15 and len(parts) > 1:
                    f = self.m.get("last_name", p.capitalize(), self._fake_last)
                if f is None:
                    break
                fakes.append(f)
            if len(fakes) == len(parts) and fakes:
                return sep.join(fakes).lower()
            first = self._fake_first(o, rng).lower()
            last = self._fake_last(o, rng).lower()
            if sep:
                return f"{first}{sep}{last}"
            return first[0] + last[0] if len(local) <= 3 else first[0] + last

        new_local = self.m.get("email_local", f"{local.lower()}@{domain.lower()}", fake_local)
        return f"{re.sub(r'[^\x00-\x7f]', '', ascii_fold(new_local))}@{new_domain}"

    def _url(self, m):
        url = m.group(0)
        has_scheme = "://" in url
        p = urlsplit(url if has_scheme else "http://" + url)
        host = p.hostname or ""
        www = host.startswith("www.")
        bare = host[4:] if www else host
        if self._keep_domain(bare):
            query = urlencode([(k, v) for k, v in parse_qsl(p.query) if not TRACKING_PARAMS.match(k)])
            new = urlunsplit((p.scheme, host, p.path, query, ""))
        else:
            new = urlunsplit((p.scheme, ("www." if www else "") + self._domain(bare), "", "", ""))
        return new if has_scheme else new.split("://", 1)[1]

    def _phone(self, m):
        s = m.group(0)
        digits = re.sub(r"\D", "", s)
        if len(digits) < 8 or DATE_LIKE.fullmatch(s.strip()):
            return None
        return self.m.get("phone", digits, lambda o, rng: self._fake_phone(s, rng))

    @staticmethod
    def _fake_phone(s: str, rng) -> str:
        t = s.replace("(0)", "\x00")
        digits = re.sub(r"\D", "", t)
        if t.lstrip().startswith(("+", "00")):
            offset = 2 if t.lstrip().startswith("00") else 0
            cc = next((digits[offset:offset + n] for n in (3, 2, 1) if digits[offset:offset + n] in COUNTRY_CODES), digits[offset:offset + 2])
            keep = offset + len(cc) + 1  # + first subscriber digit (mobile/area indicator)
        elif digits.startswith("0"):
            keep = 2
        else:
            keep = 1
        out, seen = [], 0
        for ch in t:
            if ch.isdigit():
                seen += 1
                out.append(ch if seen <= keep else rng.choice(string.digits))
            else:
                out.append(ch)
        return "".join(out).replace("\x00", "(0)")

    def _labeled_phone(self, m):
        value = m.group("val")
        if len(re.sub(r"\D", "", value)) < 6:
            return None
        fake = self.m.get("phone", re.sub(r"\D", "", value), lambda o, rng: self._fake_phone(value, rng))
        return m.group(0)[: m.start("val") - m.start()] + fake

    def _labeled_id(self, m):
        value = m.group("val")
        fake = self.m.get("id", value, lambda o, rng: scramble(o, rng))
        return m.group(0)[: m.start("val") - m.start()] + fake

    def _groups(self, m, name_cat="street"):
        """Replace named groups: `name` -> fake street name, `num` -> scrambled digits."""
        s, base, out, pos = m.group(0), m.start(), [], 0
        spans = sorted((m.start(g), m.end(g), g) for g in ("name", "num") if g in m.re.groupindex and m.group(g))
        for start, end, g in spans:
            out.append(s[pos:start - base])
            val = m.group(g)
            if g == "name":
                trail = val[len(val.rstrip()):]
                out.append(self.m.get(name_cat, val.strip(), self._fake_street) + trail)
            else:
                out.append(self.m.get("number", f"{m.group(0)}", lambda o, rng: re.sub(
                    r"(?<!\d)0(?=\d)", lambda z: str(rng.randint(1, 9)), scramble(val, rng))))
            pos = end - base
        out.append(s[pos:])
        return "".join(out)

    def _nl_postcode(self, m):
        pc = m.group(0)
        def fake(o, rng):
            letters = rng.choice([a + b for a in string.ascii_uppercase for b in string.ascii_uppercase if a + b not in ("SA", "SD", "SS")])
            return f"{rng.randint(1000, 9999)}{pc[4:-2]}{letters}"
        return self.m.get("postcode", pc.replace(" ", ""), fake)

    def _build_rules(self, custom):
        P = rf"(?:{'|'.join(PARTICLES)})"
        rules = [
            ("iban", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b"),
             lambda m: self.m.get("iban", m.group(0).replace(" ", ""), lambda o, r: fake_iban(m.group(0), r)) if iban_valid(m.group(0)) else None),
            ("vat", re.compile(r"\b(?:NL\d{9}B\d{2}|DE\d{9}|BE0?\d{9}|ATU\d{8}|ES[A-Z0-9]\d{7}[A-Z0-9]|FR[A-Z0-9]{2}\d{9}|PL\d{10}|IT\d{11}|GB\d{9})\b"),
             lambda m: self.m.get("vat", m.group(0), lambda o, r: scramble(o, r, keep=2))),
            ("url", re.compile(r"(?:https?://|www\.)[^\s<>\"'()\[\]]*[^\s<>\"'()\[\].,;:!?]"), self._url),
            ("email", EMAIL_RE, self._email),
            ("tr_tckn", re.compile(r"(?<!\d)[1-9]\d{10}(?!\d)"),
             lambda m: self.m.get("tckn", m.group(0), fake_tckn) if tckn_valid(m.group(0)) else None),
            ("co_nit", re.compile(r"(?<![\d.])\d{3}\.?\d{3}\.?\d{3}\s?-\s?\d(?![\d])"),
             lambda m: self.m.get("nit", m.group(0), fake_nit)
             if nit_dv(re.sub(r"\D", "", m.group(0))[:-1]) == int(m.group(0)[-1]) else None),
        ]
        for c in custom:  # before generic numbers, so e.g. order numbers aren't taken as phones
            strategy, keep, name = c.get("strategy", "digits"), int(c.get("keep", 0)), c["name"]
            rules.append((f"custom:{name}", re.compile(c["regex"]),
                          lambda m, n=name, s=strategy, k=keep: m.group(0) if s == "keep" else
                          self.m.get(f"custom:{n}", m.group(0), lambda o, r: scramble(o, r, keep=k, letters=(s == "alnum")))))
        rules += [
            ("labeled_phone", re.compile(rf"(?i)\b(?:{PHONE_KEYWORDS})(?!\w)\.?\s*(?:\([^)]*\))?\s*[:.]?\s*(?P<val>[+(]?\d[\d ()./\-]{{5,}}\d)"), self._labeled_phone),
            ("labeled_id", re.compile(rf"(?i)\b(?:{ID_KEYWORDS})(?!\w)\.?\s*(?:nr\.?|no\.?|n[º°]\.?|number|numarası)?\s*[:#.]?\s*(?P<val>[A-Z]{{0,3}}\d[\d .\-/]{{2,}}[\dA-Z]|[A-Z]{{0,3}}\d{{3,}})"), self._labeled_id),
            # addresses
            ("addr_co", re.compile(r"(?i)\b(?:Calle|Cl|Cll|Carrera|Cra|Kr|Kra|Cr|Avenida|Av|Ak|Ac|Transversal|Tv|Diagonal|Dg)\.?\s*"
                                   r"(?P<num>\d{1,3}\s?[A-Z]?(?:\s?Bis)?(?:\s?[A-Z])?\s*(?:#|No\.?|N[°º]\.?|Nro\.?)\s*\d{1,3}\s?[A-Z]?\s*-\s*\d{1,3})"), self._groups),
            ("addr_tr", re.compile(rf"(?P<name>(?:{CAP_WORD}\s+){{1,2}})(?:Mahallesi|Mah\.|Mh\.|Caddesi|Cad\.|Cd\.|Sokak|Sokağı|Sok\.|Sk\.|Bulvarı|Blv\.)"), self._groups),
            ("addr_tr_no", re.compile(r"\b(?:No|Kat|Daire|D)\s*[:.]\s*(?P<num>\d{1,5}(?:\s*/\s*[\dA-Z]{1,4})?)"), self._groups),
            ("addr_es", re.compile(rf"\b(?:Calle|C/|Avda\.|Avenida|Paseo|Plaza|Camino|Carretera|Ronda)\s+(?:de(?:l| la| los| las)?\s+)?"
                                   rf"(?P<name>{CAP_WORD}(?:\s+{CAP_WORD})?),?\s*(?:n[º°o]\.?\s*)?(?P<num>\d{{1,4}})"), self._groups),
            ("addr_nl_de", re.compile(rf"(?P<name>[{UP}][{LO}]+(?:straat|weg|laan|plein|gracht|dijk|kade|singel|dreef|steeg|straße|strasse|str\.|allee|gasse))\s+"
                                      rf"(?P<num>\d{{1,4}}(?:\s?[a-z]\b|-\d+)?)(?!\d)"), self._groups),
            ("addr_en", re.compile(rf"\b(?P<num>\d{{1,5}})\s+(?P<name>{CAP_WORD}(?:\s+{CAP_WORD})?\s+)(?:Street|St\.|Road|Rd\.|Avenue|Ave\.|Lane|Ln\.|Drive|Dr\.|Boulevard|Blvd\.|Way|Close|Court)\b"), self._groups),
            ("postcode_nl", re.compile(r"\b\d{4} ?(?!SA|SD|SS)[A-Z]{2}\b"), self._nl_postcode),
            ("postcode", re.compile(rf"\b(?P<num>\d{{5,6}}|\d{{2}}-\d{{3}})(?=[ \t]+[{UP}][{LO}]{{2,}})(?![ \t]+(?:Euro|EUR|USD|TL|TRY|COP|MXN|Pesos?|Km|KM|Kg|Stuks?|Units?|Adet|Liras?)\b)"), self._groups),
            # phones (unlabeled)
            ("phone", re.compile(r"(?<![\w+])(?:\+|00)[1-9](?:[ .\-]?\(?\d\)?){7,14}(?!\w)"), self._phone),
            ("phone", re.compile(r"(?<![\w+/.\-])\(?0\d{1,4}\)?(?:[ .\-]?\d){6,10}(?![\w/])"), self._phone),
            ("phone", re.compile(r"(?<![\w+/.\-])3\d{2}[ .\-]?\d{3}[ .\-]?\d{4}(?![\w/])"), self._phone),  # CO mobile
        ]
        return rules

    # ---------- main -------------------------------------------------------- #
    def redact(self, text: str) -> tuple[str, list[tuple[str, str, str]]]:
        store: list[str] = []
        log: list[tuple[str, str, str]] = []

        def protect(value: str) -> str:
            store.append(value)
            return ph_encode(len(store) - 1)

        def protect_keep_terms(text):
            for term in sorted(self.keep_terms, key=len, reverse=True):
                text = re.sub(LETTER_BOUNDARY_L + re.escape(term) + LETTER_BOUNDARY_R,
                              lambda m: protect(m.group(0)), text, flags=re.I)
            return text

        kept = False
        for name, regex, handler in self.rules:
            if not kept and name not in ("iban", "vat", "url", "email"):
                text, kept = protect_keep_terms(text), True
            def sub(m, name=name, handler=handler):
                fake = handler(m)
                if fake is None:
                    return m.group(0)
                if fake != m.group(0):
                    log.append((name, m.group(0), fake))
                return protect(fake)
            text = regex.sub(sub, text)
        if not kept:
            text = protect_keep_terms(text)

        # a number replaced once (postcode, ID, phone...) must also be replaced where no rule caught it
        repeats: dict[str, str] = {}
        for _rule, orig, fake in log:
            if len(orig) == len(fake):
                for d in re.finditer(r"\d{5,}", orig):
                    if fake[d.start():d.end()].isdigit():
                        repeats.setdefault(d.group(0), fake[d.start():d.end()])
        if repeats:
            rep_re = re.compile(r"(?<!\d)(?:" + "|".join(sorted(map(re.escape, repeats), key=len, reverse=True)) + r")(?!\d)")

            def rep_sub(m):
                log.append(("repeat-number", m.group(0), repeats[m.group(0)]))
                return protect(repeats[m.group(0)])
            text = rep_re.sub(rep_sub, text)

        if self.entities:
            variants: dict[str, str] = {}
            for orig, (fake, _src) in self.entities.items():
                variants[orig] = fake
                variants.setdefault(orig.upper(), fake.upper())
                variants.setdefault(tr_upper(orig), tr_upper(fake))
            lower = {k.casefold(): v for k, v in variants.items()}
            alts = "|".join(re.escape(k) for k in sorted(variants, key=len, reverse=True))
            ent_re = re.compile(f"{LETTER_BOUNDARY_L}(?:{alts}){LETTER_BOUNDARY_R}", re.I)

            def ent_sub(m):
                hit = m.group(0)
                if " " not in hit and "." not in hit and len(hit) < 6 and hit not in variants:
                    return hit  # short single words: exact case only ("Bos" the name, not "bos" the word)
                fake = variants.get(hit) or lower.get(hit.casefold())
                if is_upper_word(hit):
                    fake = fake.upper()
                log.append(("entity", hit, fake))
                return protect(fake)
            text = ent_re.sub(ent_sub, text)

        for _ in range(3):  # placeholders can nest (entity inside a rule's output is impossible, but be safe)
            text = PH_RE.sub(lambda m: store[ph_decode(m.group(1))], text)
        return text, log


NON_NAME_TOKENS = {"com", "org", "net", "www", "gov", "edu", "info", "mail", "http", "https"}


def name_tokens(s: str) -> set[str]:
    return set(re.findall(r"[^\W\d_]{3,}", ascii_fold(s).casefold())) - NON_NAME_TOKENS


_FOLD = str.maketrans("çğıöşüáéíóúñäßøåłśźżćńàèìòùâêîôûëÇĞİÖŞÜÁÉÍÓÚÑÄØÅŁŚŹŻĆŃ",
                      "cgiosuaeiounasoalszzcnaeiouaeioueCGIOSUAEIOUNAOALSZZCN")


def ascii_fold(s: str) -> str:
    """1:1 character folding (keeps string length, so spans stay valid)."""
    return s.translate(_FOLD)


COMMON_WORDS = """no nr kimlik vergi tc sr sra srta estimado estimada sayın mahallesi mah sokak sok caddesi cad
san tic ltd şti doña don bey hanım calle carrera cra avenida beste geachte dear hi hello hola merhaba met vriendelijke
groet groeten kind best regards saludos cordialmente saygılarımla adres firma empresa dirección subject from to cc
date attachments btw kvk iban tel cel cep fax nit""".split()


# --------------------------------------------------------------------------- #
# Review: leak check + suspicious leftovers
# --------------------------------------------------------------------------- #
def review(out: str, log, redactor: Redactor, mapper: Mapper) -> tuple[list[str], list[str]]:
    fakes = mapper.all_fakes()
    fake_tokens = {t.casefold() for f in fakes for t in re.findall(r"[^\W\d_]+", f)}
    keep = [k.casefold() for k in redactor.keep_terms]

    originals = {o for _c, o, _f in log}
    for cat in ("first_name", "last_name", "company", "domain", "street", "person", "other"):
        originals |= set(mapper.data["maps"].get(cat, {}))
    originals |= set(redactor.entities)
    leaks = []
    for o in sorted(originals, key=len, reverse=True):
        if len(o) < 3 or o in fakes or o.casefold() in keep or o.casefold() in fake_tokens:
            continue
        if re.search(LETTER_BOUNDARY_L + re.escape(o) + LETTER_BOUNDARY_R, out, re.I):
            leaks.append(o)

    inserted = {f for _c, _o, f in log}
    ignore = fake_tokens | {w.casefold() for w in COMMON_WORDS}
    suspects: list[str] = []
    P = "|".join(PARTICLES)
    for m in re.finditer(rf"{CAP_WORD}(?:\s+(?:(?:{P})\s+)*{CAP_WORD})+", out):
        words = [w.casefold() for w in re.findall(r"[^\W\d_]+", m.group(0)) if w.casefold() not in PARTICLES]
        if words and not all(w in ignore for w in words) and not redactor._is_kept(m.group(0)):
            suspects.append(f"capitalized phrase: {m.group(0)!r}")
    for m in re.finditer(r"(?<![\w.])\d{6,}(?![\w.])", out):
        if any(m.group(0) in f for f in inserted):
            continue
        suspects.append(f"long number: {m.group(0)!r}")
    for m in re.finditer(r"\b(?=[A-Z0-9\-]*\d)(?=[A-Z0-9\-]*[A-Z])[A-Z0-9\-]{6,}\b", out):
        suspects.append(f"code / ID / plate?: {m.group(0)!r}")
    for m in CLOSINGS.finditer(out):
        block = [l for l in out[m.end():].splitlines() if l.strip()][:6]
        suspects.append("signature block (check by eye):\n        " + "\n        ".join(block))
    return leaks, list(dict.fromkeys(suspects))


def write_review(path: Path, fid: str, locale: str, log, leaks, suspects, entities):
    L = [f"# Review {fid}  (detected locale: {locale})",
         "", "> LOCAL ONLY - this file contains REAL data. Never share or commit it.", ""]
    L.append("## Leak check: " + ("PASS" if not leaks else f"FAIL ({len(leaks)})"))
    L += [f"- still present: {x!r}" for x in leaks] or ["- no known original value found in output"]
    L += ["", "## Suspicious leftovers (verify by hand)"]
    L += [f"- {s}" for s in suspects] or ["- none"]
    L += ["", "## Entities used (source = how they were found; verify NER/greeting ones)", "",
          "| original | fake | source |", "|---|---|---|"]
    L += [f"| {o} | {f} | {s} |" for o, (f, s) in sorted(entities.items())]
    L += ["", "## Replacements", "", "| rule | original | fake |", "|---|---|---|"]
    L += [f"| {r} | {o!s} | {f!s} |".replace("\n", " ") for r, o, f in log]
    path.write_text("\n".join(L) + "\n", "utf-8")


# --------------------------------------------------------------------------- #
# Optional NER backends
# --------------------------------------------------------------------------- #
def load_ner(spec: str | None):
    if not spec:
        return None
    if spec.startswith("spacy:"):
        import spacy
        nlp = spacy.load(spec.split(":", 1)[1])

        def run(text):
            return [("person" if e.label_ in ("PER", "PERSON") else "company", e.text)
                    for e in nlp(text).ents if e.label_ in ("PER", "PERSON", "ORG")]
        return run
    if spec == "gliner":
        from gliner import GLiNER  # pip install gliner  (multilingual, runs locally)
        model = GLiNER.from_pretrained("urchade/gliner_multi_pii-v1")

        def run(text):
            out = []
            for chunk in [text[i:i + 1500] for i in range(0, len(text), 1500)]:
                for e in model.predict_entities(chunk, ["person", "organization", "company"], threshold=0.5):
                    out.append(("person" if e["label"] == "person" else "company", e["text"]))
            return out
        return run
    raise SystemExit(f"unknown --ner backend: {spec}")


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input_dir", type=Path)
    ap.add_argument("output_dir", type=Path)
    ap.add_argument("--config", type=Path)
    ap.add_argument("--entities", type=Path, help="CSV with type,value[,fake] of known customers/persons")
    ap.add_argument("--mapping", type=Path, default=Path("mapping.json"))
    ap.add_argument("--ner", help="spacy:<model> (e.g. spacy:xx_ent_wiki_sm) or gliner")
    args = ap.parse_args()

    config = json.loads(args.config.read_text("utf-8")) if args.config else {}
    mapper = Mapper(args.mapping)
    redactor = Redactor(mapper, config, load_ner(args.ner))
    if args.entities:
        redactor.load_entities_csv(args.entities)
    base_entities = dict(redactor.entities)

    files = sorted(p for p in args.input_dir.iterdir() if p.suffix.lower() in (".eml", ".txt", ".msg"))
    if not files:
        sys.exit(f"no .eml/.txt/.msg files in {args.input_dir}")
    red_dir, rev_dir = args.output_dir / "redacted", args.output_dir / "review_LOCAL_ONLY"
    red_dir.mkdir(parents=True, exist_ok=True)
    rev_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / ".gitignore").write_text("review_LOCAL_ONLY/\n", "utf-8")

    loaded = {p: load_message(p) for p in files}
    for headers, body, attachments in loaded.values():  # pre-scan: fakes may never reuse a real name
        raw = assemble(headers, body, attachments)
        mapper.corpus_tokens |= {t for w in re.findall(rf"[{UP}][^\W\d_]+", raw) for t in name_tokens(w)}
        mapper.corpus_tokens |= {t for e in EMAIL_RE.findall(raw) for t in name_tokens(e)}
        for w in re.findall(rf"{LETTER_BOUNDARY_L}[{UP}][{LO}]{{2,}}{LETTER_BOUNDARY_R}", raw):
            mapper.cap_words.setdefault(ascii_fold(w).casefold(), set()).add(w)

    # pass 1: harvest names from ALL emails, each in its own locale, so a customer found in
    # email A is also replaced in email B
    texts, locales, found = {}, {}, {}
    for path in files:
        texts[path] = assemble(*loaded[path])
        redactor.entities = {}
        redactor.locale = locales[path] = redactor.detect_locale(texts[path])
        redactor.harvest(texts[path])
        found[path] = redactor.entities
    all_entities = dict(base_entities)
    for ents in found.values():
        for k, v in ents.items():
            all_entities.setdefault(k, v)

    # pass 2: redact
    total_leaks = 0
    for path in files:
        fid = mapper.file_id(path.read_bytes(), path.name)
        text = texts[path]
        redactor.entities = all_entities
        redactor.locale = locales[path]
        out, log = redactor.redact(text)
        leaks, suspects = review(out, log, redactor, mapper)
        total_leaks += len(leaks)

        (red_dir / f"{fid}.txt").write_text(out, "utf-8")
        expected = red_dir / f"{fid}.expected.json"
        if not expected.exists():
            expected.write_text("{}\n", "utf-8")
        hit = {o for r, o, _f in log if r == "entity"}
        shown = {k: v for k, v in all_entities.items() if k in found[path] or k in hit}
        write_review(rev_dir / f"{fid}.review.md", fid, redactor.locale, log, leaks, suspects, shown)
        status = "LEAK" if leaks else "ok  "
        print(f"[{status}] {fid}  locale={redactor.locale:<3} replacements={len(log):<3} suspects={len(suspects)}")

    mapper.save()
    print(f"\nRedacted: {red_dir}\nReview (LOCAL ONLY, contains real data): {rev_dir}\nMapping: {args.mapping}")
    if total_leaks:
        print(f"WARNING: {total_leaks} possible leak(s). Fix them (add to --entities) and re-run.")
    print("Read every review file before sharing anything from the redacted folder.")


if __name__ == "__main__":
    main()
