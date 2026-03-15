# Travel Advisory Report — CLAUDE.md

## Development Rules (Read First)

**Never write code or modify files without explicit build approval.**
When asked "how should I implement X," produce a plan only and wait for
confirmation before writing any code. This project generates compliance
documents used by a university system. Incorrect output has real consequences.

---

## Project Overview

Single-script Python tool that:
1. Fetches the current US State Department travel advisory feed
2. Filters destinations into four priority tiers (prohibited / suspended / restricted / high-risk)
3. Generates a PDF report formatted for UT System ITOC review

**Audience:** UT System ITOC (Institutional Travel Oversight Committee) and professors planning international travel. Prioritize legibility and font size over density.

**Cadence:** Scheduled weekly (Friday 7 AM CST) via Windows Task Scheduler + `scripts/run_travel_advisory.bat`.

### Entry Points

```bash
# Install
pip install -e .

# Run (generates PDF)
python src/travel_advisory/main.py --output travel_advisory_2026-03-14.pdf

# Diagnose without generating PDF
python src/travel_advisory/main.py --list-only

# Scheduled (via bat script — sets datestamped paths, copies to OneDrive)
scripts/run_travel_advisory.bat
```

**Output directory (scheduled):** `C:\Users\theal\OneDrive\AI_Projects\Travel Advisory\`

Files produced per run:
- `travel_advisory_YYYY-MM-DD.pdf` — the report
- `travel_advisory_YYYY-MM-DD.verification.txt` — audit log
- `travel_advisory_report.pdf` / `.verification.txt` — "latest" copies
- `run_log.txt` — appended each run
- `travel_advisory_counts.json` — last 5 raw entry counts (gitignored)

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Network / fetch error |
| 2 | Verification assertion failed — PDF not generated |

---

## Architecture

Single file: `src/travel_advisory/main.py` (~2,493 lines). No modules, no subpackages.

### Data Flow (linear pipeline)

```
fetch_advisories()              ← 3-attempt HTTP fetch, pick response with most entries
    │
extract_worldwide_caution()     ← separate HTTP fetch from dedicated State Dept HTML page
    │
parse_advisory() × N            ← raw dict → TravelAdvisory; triggers page scraping fallback
    │
deduplicate_advisories()        ← dedup by country code; keep most recently updated
    │
filter_high_risk()              ← waterfall into 4 buckets (see Country Tiers section)
    │
VerificationReport.populate_*() ← populate audit fields
VerificationReport.run_assertions() ← 6 hard checks; failures → exit code 2
    │
create_report()                 ← builds PDF via TravelAdvisoryPDF(FPDF)
    │
VerificationReport.write()      ← writes .verification.txt alongside PDF
```

### Key Constants

| Constant | Purpose |
|----------|---------|
| `API_URL` | State Dept advisory JSON feed |
| `WORLDWIDE_CAUTION_URL` | Dedicated worldwide caution HTML page (not in JSON feed) |
| `LEVEL_NAMES` | Maps int level → description string |
| `PROHIBITED_COUNTRIES` | Manual dict — foreign adversaries per 15 CFR 791.4(a) |
| `PROHIBITED_COUNTRY_NAMES` | Flat set of lowercase name variants for fast substring matching |
| `UT_SUSPENDED_TRAVEL` | Manual dict — UT System suspended travel countries |
| `RESTRICTED_TRAVEL_REQUIRING_SPECIAL_APPROVAL` | Manual dict — elevated approval required |
| `RISK_FACTORS` | Ordered canonical risk keywords for `extract_risk_factors()` |

### Key Functions

| Function | What it does |
|----------|-------------|
| `fetch_advisories(max_retries=3)` | Makes 3 HTTP attempts; selects response with most entries (primary), most summary text (tiebreaker). API is load-balanced and can return 213 or 214 entries. |
| `parse_level_from_title(title)` | Regex extracts country name and level N from "Country — Level N: Description" |
| `clean_html(text)` | Strips HTML, decodes entities, normalizes whitespace/NBSP |
| `extract_regional_warnings(summary, level)` | Path 1: regex on API Summary field. Handles vague references ("this area") via `_resolve_region_from_context()` and bullet lists via `_expand_bullet_warnings()` |
| `extract_regional_warnings_from_page(html, level)` | Path 2: full HTML page scraping. More reliable. Used as fallback when API Summary hints at regional data but extraction fails. |
| `_has_regional_signals(summary)` | Sentinel that triggers the page-scraping fallback when True |
| `parse_advisory(raw)` | Orchestrates parsing of one raw dict → TravelAdvisory; invokes page scraping fallback if needed |
| `is_prohibited_country(name)` | Uses `PROHIBITED_COUNTRY_NAMES` set — simple substring/exact match |
| `_match_country_dict(name, dict)` | 3-tier match: (1) word-boundary regex on key, (2) official_name substring, (3) word-boundary regex on includes. Used for UT Suspended and Restricted. |
| `is_ut_suspended_country(name)` | Delegates to `_match_country_dict` against `UT_SUSPENDED_TRAVEL` |
| `is_restricted_special_country(name)` | Delegates to `_match_country_dict` against `RESTRICTED_TRAVEL_REQUIRING_SPECIAL_APPROVAL` |
| `deduplicate_advisories(advisories)` | Dedup by country code; keep most recently updated |
| `filter_high_risk(advisories)` | Waterfall filter into 4 buckets (see Country Tiers) |
| `extract_worldwide_caution()` | HTTP GET of `WORLDWIDE_CAUTION_URL`; parses `<div class="pageContent">` blocks; Block 0 = date, Block 1+ = body; infers level from keywords |
| `generate_country_summary(advisory)` | Algorithmic 3–5 sentence summary. No AI API calls. Uses guidance sentence, regional clause, risk factors, country context. |
| `extract_risk_factors(advisory)` | Extracts canonical risk keywords from regional warnings + summary; returns severity-ordered list |
| `_extract_guidance_sentence(advisory)` | Extracts State Dept's core guidance sentence from summary |
| `_extract_country_context(advisory)` | Extracts substantive situational context from "Country Summary:" section or fallback scan |

### Key Classes

**`TravelAdvisory` (dataclass)**
Fields: `country_name`, `country_code`, `overall_level`, `summary`, `last_updated`, `link`, `regional_warnings: list[RegionalWarning]`
Properties: `has_regional_elevation`, `max_regional_level`, `flag_emoji`

**`RegionalWarning` (dataclass)**
Fields: `region_name`, `level`, `reasons`

**`TravelAdvisoryPDF(FPDF)`**
Custom fpdf2 subclass. Methods:
- `header()` / `footer()` — page header (pages 2+) and page number
- `add_title_page(stats)` — page 1; title block, PURPOSE + SUMMARY sections with category list
- `add_worldwide_caution_page(caution)` — page 2 (when present); Level-2 yellow-orange band header
- `add_summary_section(prohibited, ut_suspended, restricted_special, advisories)` — unified quick-reference table, all tiers; column widths `(50, 68, 72)` mm
- `add_prohibited_section(prohibited_advisories)` — detailed prohibited page; **defined but not called from `create_report()`** (gap to close when building out UT Suspended and Restricted section pages)
- `add_advisory_entry(advisory)` — single country detail card with regions + generated summary
- `_clean_text(text)` — replaces Unicode (smart quotes, em dashes, NBSP) with latin-1-safe ASCII; must be called on all text passed to fpdf2 built-in fonts
- `_summary_table_header()` — renders NAVY header row for quick-reference table
- `_regional_notes(adv)` — builds "N DNT regions, M RT regions" notes string

Color palette (RGB tuples):
- `PROHIBITED_COLOR` = (80, 0, 80) dark purple
- `UT_SUSPENDED_COLOR` = (242, 101, 49) #F26531 orange
- `RESTRICTED_SPECIAL_COLOR` = (99, 100, 102) #636466 gray
- `LEVEL_4_COLOR` = (180, 30, 30), `LEVEL_3_COLOR` = (200, 120, 0), `LEVEL_2_COLOR` = (180, 150, 0), `LEVEL_1_COLOR` = (60, 140, 60)
- `NAVY` = (30, 60, 100), `DARK_GRAY` = (40, 40, 40), `MEDIUM_GRAY` = (100, 100, 100), `LIGHT_GRAY` = (220, 220, 220)

**`VerificationReport`**
Accumulates all pipeline data. See Verification System section.

---

## Country Tiers

### Dict Shape (all three policy tiers use this structure)

```python
"Key Name": {
    "code": "XX",           # ISO 3166-1 alpha-2
    "includes": ["A", "B"], # Sub-regions that fold under this entry; [] if none
    "official_name": "...", # Full official country name
}
```

Sub-regions in `includes` are displayed as "Key Name (incl. A, B)" in the PDF and are matched via `_match_country_dict()` using word-boundary regex on each alias. West Bank and Gaza fold under Israel exactly as Hong Kong and Macau fold under China.

---

### Tier 1 — PROHIBITED (Texas EO GA-48) — **IMPLEMENTED**

**Definition:** Countries designated as US foreign adversaries per 15 CFR 791.4(a). Texas Executive Order GA-48 (November 19, 2024) prohibits UT System employees from work-related travel to these countries.

**Source authority:** 15 CFR 791.4(a) (Commerce Dept foreign adversary list)
**Maintenance:** MANUAL — must be verified against eCFR after each regulatory update.
Verification URL: `https://www.ecfr.gov/current/title-15/subtitle-B/chapter-VII/subchapter-E/part-791/subpart-A/section-791.4`

**Current entries (6):** China (incl. Hong Kong, Macau), Cuba, Iran, North Korea, Russia, Venezuela

**Filter function:** `is_prohibited_country()` — uses `PROHIBITED_COUNTRY_NAMES` flat set with exact + substring match (note: this is less rigorous than `_match_country_dict`; sufficient because the prohibited list is small and well-known)

**Consolidation in `filter_high_risk()`:** After the loop, a second pass collapses multiple API entries (e.g., "China", "Hong Kong", "Macau" each appear in the API) into one advisory per canonical dict key, preferring the parent-name match over includes matches.

**What's implemented:**
- Dict + flat name set
- `is_prohibited_country()` + waterfall placement
- Quick-reference table rows (with includes in display name)
- Title page stats
- Detailed section page: `add_prohibited_section()` — **defined but not wired into `create_report()`**
- Verification audit: `populate_prohibited_audit()` + assertion checks

---

### Tier 2 — UT SUSPENDED — **DATA PIPELINE COMPLETE; PDF SECTION PAGE NOT YET BUILT**

**Definition:** Countries for which the UT System has issued an active travel suspension. All travel to or through these countries — including layovers and connections, regardless of ultimate destination — requires exception approval from both the ITOC and the University President.

**Source authority:** UT System Chancellor memo (specific memo TBD — must be documented when adding the PDF section header).

**Current entries (16):** Bahrain, Belarus, Iran\*, Iraq, Israel (incl. West Bank, Gaza), Jordan, Kuwait, Lebanon, Oman, Qatar, Russia\*, Saudi Arabia, Syria, UAE, Ukraine, Yemen
(\* Iran and Russia also appear in PROHIBITED_COUNTRIES. The waterfall places them in the prohibited bucket first; they never reach the ut_suspended bucket at runtime.)

**Filter function:** `is_ut_suspended_country()` → `_match_country_dict(name, UT_SUSPENDED_TRAVEL)` — 3-tier word-boundary matching, more rigorous than prohibited's substring approach.

**What's implemented:**
- `UT_SUSPENDED_TRAVEL` dict (same shape as PROHIBITED_COUNTRIES)
- `is_ut_suspended_country()` + waterfall placement in `filter_high_risk()`
- Quick-reference table rows in `add_summary_section()` (with includes; shows "UT SUSPENDED" label in orange; notes column: "ITOC + President req. (incl. layovers)")
- Title page stats (`ut_suspended` count)
- Verification audit: `populate_ut_suspended_audit()`, unmatched [WARN], leak assertions

**NOT YET BUILT — design spec for PDF section page:**
When building the UT Suspended section page, follow the pattern of `add_prohibited_section()` with these requirements:
- Section heading (orange band matching `UT_SUSPENDED_COLOR`): "UT SUSPENDED — Travel Not Authorized Without Exception"
- One-sentence definition immediately below the heading: "Travel to or through these countries is suspended by the UT System; all travel, including layovers and connections, requires prior approval from the Institutional Travel Oversight Committee (ITOC) and the University President."
- Per-country blocks: country name (with includes), official name, State Dept advisory level (if matched from API), last updated date
- Footnote (at bottom of section, not inline): "This suspension applies to travel through these countries as a layover or connection point, regardless of the traveler's ultimate destination."
- Source authority line citing UT System Chancellor memo (specific memo TBD)
- Wire into `create_report()` after `add_prohibited_section()` call (once that is also wired in)
- Extend `add_summary_section()` notes column if section-level display changes are needed (currently already populated)
- No new verification fields required; audit already implemented

---

### Tier 3 — RESTRICTED (Elevated Approval Required) — **DATA PIPELINE COMPLETE; PDF SECTION PAGE NOT YET BUILT**

**Definition:** Countries not under active suspension but for which the UT System requires elevated approval before travel may be booked. All travel to or through these countries — including layovers and connections — requires prior approval from both the ITOC and the University President.

**Source authority:** UT System Chancellor memo (specific memo TBD — same document as UT Suspended, likely).

**Current entries (4):** Cyprus, Egypt, Moldova, Turkey

**Filter function:** `is_restricted_special_country()` → `_match_country_dict(name, RESTRICTED_TRAVEL_REQUIRING_SPECIAL_APPROVAL)`

**What's implemented:**
- `RESTRICTED_TRAVEL_REQUIRING_SPECIAL_APPROVAL` dict (same shape as PROHIBITED_COUNTRIES)
- `is_restricted_special_country()` + waterfall placement in `filter_high_risk()`
- Quick-reference table rows in `add_summary_section()` (label: "RESTRICTED" in gray; notes: "ITOC + President req. (incl. layovers)")
- Title page stats (`restricted` count)
- Verification audit: `populate_restricted_special_audit()`, unmatched [WARN], leak assertions

**NOT YET BUILT — design spec for PDF section page:**
When building the Restricted section page:
- Section heading (gray band matching `RESTRICTED_SPECIAL_COLOR`): "RESTRICTED — Elevated Approval Required Prior to Booking"
- One-sentence definition immediately below the heading: "Travel to or through these countries is not suspended, but requires prior approval from the Institutional Travel Oversight Committee (ITOC) and the University President before any travel may be booked."
- Per-country blocks: same structure as UT Suspended section page
- Footnote (at bottom of section, not inline): "This approval requirement applies to travel through these countries as a layover or connection point, regardless of the traveler's ultimate destination."
- Source authority line citing UT System Chancellor memo (specific memo TBD)
- Wire into `create_report()` after UT Suspended section page

---

### Tier 4 — HIGH-RISK (General State Dept Advisories)

Computed dynamically from API data. No manual dict. Includes:
- Level 4 (Do Not Travel) countries — any not already in tiers 1–3
- Level 3 (Reconsider Travel) countries — any not already in tiers 1–3
- Level 1/2 countries with at least one regional warning elevated to Level 3 or 4 and `has_regional_elevation = True`

Sorted within `filter_high_risk()` by `(-overall_level, -max_regional_level, country_name)`.

---

### Waterfall Priority

```
is_prohibited_country()       → bucket: prohibited
    ↓ else
is_ut_suspended_country()     → bucket: ut_suspended
    ↓ else
is_restricted_special_country() → bucket: restricted_special
    ↓ else
overall_level >= 3            → bucket: high_risk
    ↓ else
has_regional_elevation        → bucket: high_risk
    ↓ else
(dropped — not in report)
```

No country appears in more than one bucket. Assertions in `VerificationReport.run_assertions()` verify this after every run.

---

## Current PDF Structure

```
Page 1    add_title_page()
          Title block (NAVY rules), PURPOSE section, SUMMARY section
          Category list: PROHIBITED / UT SUSPENDED / RESTRICTED / L4 / L3 / REGIONAL WARNINGS / TOTAL
          Counts come from stats dict built in create_report()

Page 2    add_worldwide_caution_page()   [only if worldwide caution was fetched]
          LEVEL_2_COLOR header band; level + date; body text

Page 3+   add_summary_section()
          Unified quick-reference table (NAVY header row)
          Row order: PROHIBITED → UT SUSPENDED → RESTRICTED → L4 → L3 → L2/1 regional
          Columns: Country (50mm) | Level (68mm) | Notes (72mm)
          Multi-page with "Quick Reference (continued)" header
          Footnote: layover/connection rule; EO GA-48 abbreviation key

Page N+   add_advisory_entry() × each high_risk entry
          Level-colored header bar; advisory level description; last updated;
          Do Not Travel regions; Reconsider Travel regions; generated summary; link
```

**Not currently rendered** (defined but not wired into `create_report()`):
- `add_prohibited_section()` — detailed prohibited country cards with official names and advisory levels

**When UT Suspended and Restricted section pages are added**, the PDF structure will expand to:

```
Page 1      Title page
Page 2      Worldwide Caution (if present)
Page 3+     Quick Reference table (unchanged)
Page N+     Prohibited section page (add_prohibited_section — to be wired in)
Page N+     UT Suspended section page (to be built)
Page N+     Restricted section page (to be built)
Page N+     Detailed Advisories (high-risk entries, unchanged)
```

---

## Regional Warning Extraction

Regional warnings are sub-national designations within a country advisory — e.g., "Do Not Travel to State of Colima" within a Mexico Level 2 advisory.

### Path 1 — API Summary field (primary)

`extract_regional_warnings(summary, overall_level)` — called inside `parse_advisory()` for every entry.

Pre-processing:
- `clean_html()` — strips tags, decodes entities, normalizes whitespace
- `_expand_bullet_warnings()` — converts "Do Not Travel to:\n- Region A\n- Region B" into standalone sentences

Patterns (both case-insensitive):
- `"Do not travel to X due to Y"` → Level 4 (only for countries below Level 4)
- `"Reconsider travel to X due to Y"` → Level 3 (only for countries below Level 3)

Vague reference resolution: When the matched region is "this area", "these areas", etc., `_resolve_region_from_context()` walks backward through preceding lines to find the header (e.g., "Union territory of Jammu and Kashmir:") that names the actual region.

**Known fragility:** The API Summary field is frequently truncated or uses non-standard formatting. Pattern 1 misses regions described without explicit "due to" clauses. This is why Path 2 exists.

### Path 2 — Full HTML page scraping (fallback)

Triggered automatically inside `parse_advisory()` when:
- `overall_level <= 2` (higher-level countries don't need regional elevation to be in the report)
- AND `regional_warnings` is empty after Path 1
- AND `_has_regional_signals(summary)` returns True (signals: "do not travel", "level 3", "level 4", "some areas have increased risk", etc.)

`fetch_advisory_page(link)` — HTTP GET of the advisory's `Link` URL; non-fatal on failure.

`extract_regional_warnings_from_page(html, level)` — two structured patterns:
1. "Region Name - Level N: Do Not Travel" — inline format common in Europe/structured advisories
2. Level header sections: "Level: 4 - Do not travel" followed by region-name lines; region identified by being capitalized, non-directive, and followed by a directive on the next line

Falls back to Path 1 regex applied to the full page HTML if neither structured pattern fires.

**Known fragility:** Some countries have regional signal phrases in their summaries but genuinely have no sub-national warnings (false positives from `_has_regional_signals`). These show up in `regional_signal_gaps` in the verification log as `[WARN]` — they do not halt the report.

Page scraping usage is tracked in `verification.page_fallback_used` and reported in the verification log under "PAGE SCRAPING FALLBACK."

---

## Verification System

### Hard Assertions (halt at exit code 2, PDF not generated)

Implemented in `VerificationReport.run_assertions()`:

1. **Waterfall leak check**: No prohibited country in ut_suspended, restricted_special, or high_risk
2. **Waterfall leak check**: No UT suspended country in restricted_special or high_risk
3. **Waterfall leak check**: No restricted country in high_risk
4. **Parse failure rate**: `parse_failures / raw_count < 5%`
5. **Sanity check**: `len(high_risk) > 0` (zero high-risk countries is impossible — signals a pipeline failure)
6. **Dedup check**: No duplicate country codes across all four buckets after deduplication

### Soft Warnings (logged, do not halt)

- **Entry count instability**: `check_entry_stability()` warns if raw count differs from previous run by more than 1. Written to `travel_advisory_counts.json` (gitignored). The API is load-balanced and can serve 213 or 214 entries; `fetch_advisories()` mitigates this by preferring the response with the most entries.
- **Worldwide caution not found**: Logged if `extract_worldwide_caution()` returns None.
- **Unmatched UT suspended country**: Printed as `[WARN] No API entry found for: {country}` during console output (e.g., Israel currently has no State Dept API entry). The PDF entry is still included using `overall_level=0`.
- **Regional signal gaps**: Countries where `_has_regional_signals()` is True but no warnings were extracted. Listed in verification log under "REGIONAL SIGNAL GAPS."

### Verification Log

Written to `{output}.verification.txt` alongside the PDF. Sections:
- PIPELINE STATS: raw / parsed / dedup counts, stability flag, worldwide caution status
- PROHIBITED COUNTRY AUDIT: expected vs matched counts with `[OK]` / `[MISS]` per country
- UT SUSPENDED TRAVEL AUDIT: same format
- RESTRICTED / ELEVATED APPROVAL AUDIT: same format
- HIGH-RISK BREAKDOWN: Level 4 / Level 3 / regional lists
- PAGE SCRAPING FALLBACK: countries where path 2 was used
- REGIONAL SIGNAL GAPS: `[WARN]` entries
- DATA HASH: SHA-256 fingerprint of all processed advisories (for change detection)
- ASSERTIONS: ALL PASSED or FAILED with per-error `[FAIL]` lines

The bat script appends the full verification log to `run_log.txt` on every run.

---

## Manual Maintenance Checklist

These dicts are NOT auto-populated and must be maintained by a human:

| Dict | Verify against | When |
|------|---------------|------|
| `PROHIBITED_COUNTRIES` | 15 CFR 791.4(a) at eCFR | When Commerce Dept amends the foreign adversary list |
| `UT_SUSPENDED_TRAVEL` | UT System Chancellor memo (TBD) | When UT System issues or lifts a travel suspension |
| `RESTRICTED_TRAVEL_REQUIRING_SPECIAL_APPROVAL` | UT System Chancellor memo (TBD) | When UT System updates the elevated-approval list |

When updating any dict: add or remove entries using the standard shape (`code`, `includes`, `official_name`), then commit with a reference to the source document and amendment date.

---

## Dependency Notes

- **fpdf2**: Only dependency. Uses built-in Helvetica font (latin-1 encoding). All text passed to fpdf2 must go through `_clean_text()` first to replace Unicode characters. `multi_cell` defaults to `align='J'` (justified) — pass `align='L'` explicitly when a consistent left indent is required across wrapped lines.
- **stdlib only**: `urllib.request`, `urllib.error`, `json`, `re`, `html`, `hashlib`, `logging`, `argparse`, `dataclasses`, `datetime`, `pathlib`
- No AI API calls. All summarization is algorithmic (`generate_country_summary()`).
