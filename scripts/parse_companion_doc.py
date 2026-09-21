"""
Parse the FBI CJIS Requirements Companion Document PDF into structured JSON rows.

The document is a 9-column table (Ver 6.0 Location, Ver 6.1 Location, Title,
Shall Statement / Requirement, Audit/Sanction Date, Priority, IaaS, PaaS, SaaS)
repeated across many pages. Section/Title cells are frequently blank or a ditto
mark (") to indicate "same as the row above" - this script forward-fills those
from the nearest preceding row that had an explicit value, carrying state across
page boundaries.

Two extraction defects in the source PDF's text layer are detected (not fixed)
and surfaced via an "extraction_warning" field for manual review:

- "garbled_text": the PDF's text layer has interleaved/scrambled characters
  (or missing spaces between words) in a way that can't be reconstructed
  automatically. The raw garbled text is kept as-is in shall_text.
- "ambiguous_continuation": a row with no explicit new section number does not
  clearly look like either a sentence continuation of the row above (lowercase
  start, no bullet/number) or a distinct sub-requirement (bullet/number start).
  Rather than guess, the row is left unmerged and flagged.
"""
import argparse
import json
import re
import sys
from pathlib import Path

import pdfplumber

AUDIT_DATE_RE = re.compile(r"^\d{1,2}/\d{1,2}/\d{4}$")
KNOWN_AUDIT_STATUSES = {"Existing", "Zero-cycle"}
KNOWN_PRIORITIES = {"Existing", "P1", "P2", "P3", "P4"}
KNOWN_RESPONSIBILITIES = {"CJIS/CSO", "Agency", "Service Provider", "Both", "TBD"}

# --- Garbled-text detection -------------------------------------------------
# Two independent signals: (1) a low fraction of "real English word" tokens
# across the whole row (catches rows garbled end-to-end), and (2) a letter
# glued directly to punctuation glued to another letter with no space, e.g.
# "Cb.J I ;Set" (catches garbling confined to a couple of short tokens, which
# the whole-row ratio alone is too coarse to notice).
DICT_PATH = Path("/usr/share/dict/words")
EXTRA_WORDS = {
    "telecommunications", "cybersecurity", "online", "internet", "website",
    "email", "login", "logon", "username", "multifactor", "biometric",
    "firewall", "router", "database", "metadata", "workflow", "software",
    "hardware", "firmware", "malware", "encryption", "authenticator",
    "authenticators",
}
SUFFIXES = ("'s", "ing", "edly", "ed", "es", "s")
ABBREV_EXCLUDE = {"e.g.", "i.e.", "etc.", "vs.", "u.s.", "u.k.", "a.m.", "p.m.", "no.", "fig."}
DOMAIN_MARKERS = (".gov", ".com", ".org", ".mil", ".edu", ".net")
GLUED_PUNCTUATION_RE = re.compile(r"[A-Za-z][.;,][A-Za-z]")
GARBLED_RATIO_THRESHOLD = 0.4
MIN_TOKENS_FOR_RATIO_CHECK = 4

if DICT_PATH.exists():
    with DICT_PATH.open(encoding="latin-1") as f:
        DICT_WORDS = set(w.strip().lower() for w in f if w.strip())
else:
    print(f"WARNING: {DICT_PATH} not found; garbled-text ratio check will be less reliable", file=sys.stderr)
    DICT_WORDS = set()


def _in_dict(token):
    lowered = token.lower()
    if lowered in DICT_WORDS or lowered in EXTRA_WORDS:
        return True
    for suffix in SUFFIXES:
        if lowered.endswith(suffix) and len(lowered) - len(suffix) >= 3:
            stem = lowered[: -len(suffix)]
            if stem in DICT_WORDS or stem in EXTRA_WORDS:
                return True
    return False


def _word_ratio(text):
    """Fraction of real-word tokens, or None if too few tokens to judge."""
    tokens = re.findall(r"[A-Za-z']+", text)
    considered = [t for t in tokens if len(t) >= 3 and not t.isupper()]
    if len(considered) < MIN_TOKENS_FOR_RATIO_CHECK:
        return None
    recognized = sum(1 for t in considered if _in_dict(t))
    return recognized / len(considered)


def _has_glued_punctuation(text):
    for token in text.split():
        normalized = token.strip("()[]{}\"',;:").lower()
        if normalized in ABBREV_EXCLUDE or any(marker in normalized for marker in DOMAIN_MARKERS):
            continue
        if GLUED_PUNCTUATION_RE.search(token):
            return True
    return False


def is_garbled(text):
    ratio = _word_ratio(text)
    if ratio is not None and ratio < GARBLED_RATIO_THRESHOLD:
        return True
    return _has_glued_punctuation(text)


# --- Continuation classification ---------------------------------------
BULLET_RE = re.compile(r'^\(?[A-Za-z0-9]{1,3}[.\)]\s')
ELLIPSIS_MARKS = ("…", "...")


def classify_continuation(prev_shall_text, shall_text):
    """
    Returns "continuation" (merge into prev), "distinct" (own row), or
    "ambiguous" (own row, flagged for manual review).
    """
    if prev_shall_text.rstrip().endswith(ELLIPSIS_MARKS) and shall_text.lstrip('"“” ').startswith(ELLIPSIS_MARKS):
        return "continuation"

    stripped = shall_text.lstrip('"“” ')
    if not stripped:
        return "distinct"
    if BULLET_RE.match(stripped):
        return "distinct"
    if stripped[0].islower():
        return "continuation"
    return "ambiguous"


def clean_text(value):
    """Collapse embedded newlines/whitespace into clean single-line prose."""
    if value is None:
        return ""
    text = str(value).replace("\n", " ")
    text = re.sub(r"\s+", " ", text).strip()
    return text


def is_skippable_row(row):
    """True for header rows, section-banner rows, and empty rows."""
    cells = [clean_text(c) for c in row]
    if cells[0].startswith("Ver 6.0 Location"):
        return True
    if len(cells) > 4 and cells[4] == "Sanction Date":
        return True
    non_empty = [c for c in cells if c]
    if len(non_empty) <= 1:
        return True
    return False


def parse_audit_sanction(raw_value):
    value = clean_text(raw_value)
    if not value:
        return None, None
    if AUDIT_DATE_RE.match(value):
        return "dated", value
    if value in KNOWN_AUDIT_STATUSES:
        return value, None
    print(f"WARNING: unexpected Audit/Sanction Date value: {value!r}", file=sys.stderr)
    return value, None


def parse_priority(raw_value):
    value = clean_text(raw_value)
    if not value:
        return None
    if value in KNOWN_PRIORITIES:
        return value
    print(f"WARNING: unexpected Priority value: {value!r}", file=sys.stderr)
    return value


def parse_responsibility(raw_value):
    value = clean_text(raw_value)
    if not value:
        return None
    if value in KNOWN_RESPONSIBILITIES:
        return value
    print(f"WARNING: unexpected responsibility value: {value!r}", file=sys.stderr)
    return value


def add_warning(record, warning):
    existing = record.get("extraction_warning")
    if existing is None:
        record["extraction_warning"] = warning
    elif warning not in existing.split("+"):
        record["extraction_warning"] = existing + "+" + warning


def extract_raw_rows(pdf_path, start_page, end_page):
    """Walk the table cells and forward-fill section/title, one dict per table row."""
    raw_rows = []

    # Forward-fill state, carried across pages since a section's rows can
    # span a page break (e.g. section 3.2.9 continues from page 5 onto page 6).
    current_section_v6_0 = None
    current_section_v6_1 = None
    current_title = None

    with pdfplumber.open(pdf_path) as pdf:
        last_page = len(pdf.pages) if end_page is None else min(end_page, len(pdf.pages))
        for page_number in range(start_page, last_page + 1):
            page = pdf.pages[page_number - 1]
            for table in page.extract_tables():
                for row in table:
                    if is_skippable_row(row):
                        continue

                    cells = list(row) + [None] * (9 - len(row))
                    v6_0, v6_1, title, shall, audit, priority, iaas, paas, saas = cells[:9]

                    v6_0 = clean_text(v6_0)
                    v6_1 = clean_text(v6_1)
                    title = clean_text(title)
                    shall_text = clean_text(shall)

                    if not shall_text:
                        continue

                    # A row only counts as introducing a genuinely new
                    # requirement identifier if its own Location cell was
                    # non-blank (not inherited via forward-fill).
                    had_explicit_id = bool(v6_0)

                    if v6_0:
                        current_section_v6_0 = v6_0
                    if v6_1:
                        current_section_v6_1 = v6_1
                    if title and title != '"':
                        current_title = title

                    audit_status, audit_date = parse_audit_sanction(audit)

                    record = {
                        "section_v6_0": current_section_v6_0,
                        "section_v6_1": current_section_v6_1,
                        "title": current_title,
                        "shall_text": shall_text,
                        "audit_sanction_status": audit_status,
                        "audit_sanction_date": audit_date,
                        "priority": parse_priority(priority),
                        "responsibility_iaas": parse_responsibility(iaas),
                        "responsibility_paas": parse_responsibility(paas),
                        "responsibility_saas": parse_responsibility(saas),
                    }
                    if is_garbled(shall_text):
                        add_warning(record, "garbled_text")

                    raw_rows.append((had_explicit_id, record))

    return raw_rows


def merge_continuations(raw_rows):
    """Stitch clear sentence-continuation rows into their parent row."""
    records = []

    for had_explicit_id, record in raw_rows:
        if had_explicit_id or not records:
            records.append(record)
            continue

        prev = records[-1]
        # Garbling can corrupt the very markers (bullets, capitalization) the
        # classifier relies on - e.g. "b. Set..." interleaved into "ma. a S...",
        # which spuriously looks like a distinct "ma." bullet. Don't trust
        # pattern-matching on text we already know is unreliable.
        if record.get("extraction_warning") and "garbled_text" in record["extraction_warning"].split("+"):
            classification = "ambiguous"
        else:
            classification = classify_continuation(prev["shall_text"], record["shall_text"])

        if classification == "continuation":
            prev["shall_text"] = prev["shall_text"] + " " + record["shall_text"]
            if record.get("extraction_warning"):
                add_warning(prev, record["extraction_warning"])
            continue

        if classification == "ambiguous":
            add_warning(record, "ambiguous_continuation")

        records.append(record)

    return records


def parse_pages(pdf_path, start_page, end_page):
    raw_rows = extract_raw_rows(pdf_path, start_page, end_page)
    return merge_continuations(raw_rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        default="data/sources/RequirementCompanionDoc_v6-1.pdf",
        help="Path to the Requirements Companion Document PDF",
    )
    parser.add_argument(
        "--output",
        default="data/corpus/sample_output.json",
        help="Path to write the extracted JSON rows",
    )
    parser.add_argument(
        "--start-page",
        type=int,
        default=4,
        help="First PDF page (1-indexed) to parse; page 4 is where the table begins",
    )
    parser.add_argument(
        "--end-page",
        type=int,
        default=None,
        help="Last PDF page (1-indexed, inclusive) to parse; omit for end of document",
    )
    args = parser.parse_args()

    records = parse_pages(Path(args.input), args.start_page, args.end_page)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)

    warned = sum(1 for r in records if r.get("extraction_warning"))
    print(f"Wrote {len(records)} rows to {output_path} ({warned} flagged with extraction_warning)", file=sys.stderr)


if __name__ == "__main__":
    main()
