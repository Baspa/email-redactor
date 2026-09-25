# email-redactor

Turns real customer emails into safe, realistic example/eval data for the email-parsing agent.
Runs **fully offline**: raw emails never leave your machine.

## Workflow

1. Export 20–30 varied emails (`.eml`, `.msg`, or `.txt`) into `raw/` (git-ignored).
   Pick for variety: clean, messy forwards, multi-truck requests, missing fields, NL/EN/DE/TR/ES mixes.
2. `cp config.example.json config.json`. Put your own brand, truck makes and domains in `keep_terms` / `keep_domains`,
   otherwise "BAS World" gets pseudonymized as a person.
3. Optionally list known customers/staff in `known_entities.csv` (see `known_entities.example.csv`).
   Rows with a `fake` column pin that exact replacement (useful for staff names).
4. Run:
   ```bash
   python3 redact_emails.py raw/ out/ --config config.json --entities known_entities.csv
   ```
5. For **every** email, read `out/review_LOCAL_ONLY/email_XXX.review.md`:
   - leak check must be PASS
   - check "suspicious leftovers" and the signature block
   - anything missed → add it to `known_entities.csv` and re-run (mapping stays consistent)
6. Read `out/redacted/email_XXX.txt` yourself one final time, then fill in `email_XXX.expected.json`
   with the output you want from the agent. Hold back ~5 as a test set.
7. Only `out/redacted/` may be shared (with Claude, or committed). Never share `mapping.json` or `review_LOCAL_ONLY/`.

## What gets replaced

| Kind | How |
|---|---|
| Person names | Harvested from headers, quoted `Van:/From:/Kimden:/De:` lines, greetings/titles (`Beste`, `Sayın`, `Ahmet Bey`, `Estimado Sr.`, `Herr`), the line after a sign-off, email local parts, CSV, optional NER. Fakes match the email's locale (Turkish → Turkish, Colombian → Spanish two surnames). |
| Companies | Anything ending in a legal form (`B.V.`, `GmbH`, `A.Ş.`, `San. ve Tic. Ltd. Şti.`, `S.A.S.`, `Ltda.`, `Sp. z o.o.`, …). Legal form is kept. |
| Emails / domains | Domain → fake company domain with the same TLD (`.com.tr`, `.com.co`). Local part reuses the person's fake name. Generic boxes (`info@`, `ventas@`) kept. |
| URLs | Customer URLs → bare fake domain. Kept domains keep their path, minus tracking parameters. |
| IBAN | New account number, same bank code, **valid checksum** (incl. TR). |
| TR TCKN / CO NIT | Regenerated with **valid checksums**. |
| Labelled IDs | Digits after `KvK`, `BTW`, `VAT`, `USt-IdNr`, `Vergi No`, `TC Kimlik`, `NIT`, `C.C.`, `RFC`, `NIP`, `customer no`, `hesap no`, `cuenta`, … are scrambled, keeping the format. |
| Phones | Country code + first digit kept, rest scrambled (`+90 532 …`, `+57 3…`, `06-…`, `(0)`). |
| Addresses | NL/DE streets, TR `Mah./Cad./Sok./No:`, CO `Calle 45 # 12-34`, ES `Calle Mayor 12`, EN `12 High Street`, postcodes. Cities are kept. |
| Custom | Regexes in `config.json` → `custom_patterns` (`digits`, `alnum`, `keep` + `keep` prefix length), e.g. VINs, plates, order numbers. |

Everything is consistent across emails and re-runs (`mapping.json`). A fake never reuses a token that
appears as a real name anywhere in your inputs.

## Optional extras

- `pip install faker` → much larger locale-aware name pools.
- `pip install extract-msg` → Outlook `.msg` support.
- NER for names in free text that the heuristics miss (it also produces false positives, so check the review):
  - `pip install gliner` then `--ner gliner` (multilingual PII model, good for TR/ES/NL)
  - `pip install spacy && python -m spacy download xx_ent_wiki_sm` then `--ner spacy:xx_ent_wiki_sm`

## Known limits

- Fake first names don't follow gender (`Doña` + male name can happen). Pin important ones in the CSV.
- A name that only appears mid-sentence, with no title/greeting/header/signature, is missed without NER.
  The "capitalized phrase" check in the review is your safety net.
- VAT numbers get scrambled digits, but their checksums are not recalculated.
- Non-Latin scripts (Cyrillic, Arabic) are only partially handled. Review those by hand.
