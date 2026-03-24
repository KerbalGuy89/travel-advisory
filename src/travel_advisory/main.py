"""
Travel Advisory Report Generator.

Fetches US State Department travel advisories and generates a PDF report
of high-risk destinations (Level 3/4 countries and countries with regional warnings).

Data source: https://cadataapi.state.gov/api/TravelAdvisories
"""

import argparse
import hashlib
import html
import json
import logging
import re
import sys
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from fpdf import FPDF

logger = logging.getLogger(__name__)


# State Department API endpoint
API_URL = "https://cadataapi.state.gov/api/TravelAdvisories"

# Dedicated worldwide caution page (not in the JSON feed)
WORLDWIDE_CAUTION_URL = (
    "https://travel.state.gov/en/international-travel/"
    "travel-advisories/global-events/worldwide-caution.html"
)

# Advisory level definitions
LEVEL_NAMES = {
    1: "Exercise Normal Precautions",
    2: "Exercise Increased Caution",
    3: "Reconsider Travel",
    4: "Do Not Travel",
}

# Hard minimum entry count — the API serves ~214 countries when fully loaded.
# Anything below this threshold indicates a backend failure and the report
# should NOT be generated (better no report than a dangerously incomplete one).
MIN_EXPECTED_ENTRIES = 200

# Cache filename for the last known good API response (written alongside
# travel_advisory_counts.json in the output directory; gitignored).
API_CACHE_FILENAME = "travel_advisory_cache.json"

# Listing page URL for cross-validation of entry count
LISTING_PAGE_URL = (
    "https://travel.state.gov/content/travel/en/traveladvisories/"
    "traveladvisories.html"
)

# Maximum number of regional signal gaps before the report halts.
# The baseline is ~20 false positives from _has_regional_signals (countries
# whose summaries contain signal phrases like "some areas have increased risk"
# but don't have actual sub-national Level 3/4 designations).  A jump well
# above baseline suggests truncated API summaries or broadly failing extraction.
MAX_REGIONAL_SIGNAL_GAPS = 30

# NOTE: The State Dept API Category field uses FIPS 10-4 codes, not ISO
# 3166-1 alpha-2.  A partial FIPS-to-ISO mapping was considered but rejected
# because FIPS codes for one country can equal ISO codes for a different
# country (e.g. FIPS "SG" = Senegal, ISO "SG" = Singapore), causing dedup
# collisions.  The codebase uses the raw FIPS codes as-is.  Country matching
# is primarily name-based (_match_country_dict, is_prohibited_country), so
# the code mismatch between FIPS and the ISO codes in the policy dicts does
# not cause functional issues.  If a complete FIPS-to-ISO mapping is ever
# needed, it must cover ALL ~250 codes, not just the divergent ones.

# Countries that are known to always have Level 4 regional warnings.
# Used as a canary in verification — if any of these has zero extracted
# regions, something is broken in the extraction pipeline.
MUST_HAVE_REGIONS = {"Mexico", "Colombia", "Pakistan", "India"}

# =============================================================================
# PROHIBITED COUNTRIES - Texas Executive Order GA-48
# =============================================================================
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# MANUAL MAINTENANCE REQUIRED
# This list must be kept in sync with 15 CFR 791.4(a) — the official list of
# US Department of Commerce "foreign adversary" designations.  It is NOT
# auto-populated from any API.
#
# To verify/update:
#   1. Visit: https://www.ecfr.gov/current/title-15/subtitle-B/chapter-VII/
#             subchapter-E/part-791/subpart-A/section-791.4
#   2. Compare § 791.4(a) with the keys below.
#   3. Add or remove countries (with code, includes, official_name) as needed.
#   4. Commit the change with a reference to the eCFR amendment date.
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#
# Per 15 CFR 791.4, the following are designated as "foreign adversaries" by
# the US Department of Commerce. Texas EO GA-48 prohibits state employees from
# work-related travel to these countries.
#
# Reference:
# - Texas EO GA-48: https://gov.texas.gov/uploads/files/press/EO-GA-48_Hardening_State_Government_FINAL_11-19-2024.pdf
# - 15 CFR 791.4: https://www.ecfr.gov/current/title-15/subtitle-B/chapter-VII/subchapter-E/part-791/subpart-A/section-791.4
# =============================================================================

PROHIBITED_COUNTRIES = {
    "China": {
        "code": "CN",
        "includes": ["Hong Kong", "Macau"],
        "official_name": "People's Republic of China",
    },
    "Cuba": {
        "code": "CU",
        "includes": [],
        "official_name": "Republic of Cuba",
    },
    "Iran": {
        "code": "IR",
        "includes": [],
        "official_name": "Islamic Republic of Iran",
    },
    "North Korea": {
        "code": "KP",
        "includes": [],
        "official_name": "Democratic People's Republic of Korea",
    },
    "Russia": {
        "code": "RU",
        "includes": [],
        "official_name": "Russian Federation",
    },
    "Venezuela": {
        "code": "VE",
        "includes": [],
        "official_name": "Bolivarian Republic of Venezuela (Maduro Regime)",
    },
}

# Country names to filter out of regular advisory list (includes variations)
PROHIBITED_COUNTRY_NAMES = {
    "china", "hong kong", "macau", "macao",
    "cuba",
    "iran",
    "north korea", "korea, north", "democratic people's republic of korea",
    "russia", "russian federation",
    "venezuela",
}

# =============================================================================
# UT SUSPENDED TRAVEL - UT System Travel Suspension
# =============================================================================
# Travel to these countries is suspended by the UT System. This applies to
# travel to or through these countries, including layovers and connections.
# Exceptions require approval from both the Institutional Travel Oversight Committee
# (ITOC) and the University President.
#
# Note: Iran and Russia also appear in PROHIBITED_COUNTRIES. The filter
# waterfall places them in the prohibited bucket first; they will never reach
# the ut_suspended bucket.
# =============================================================================

UT_SUSPENDED_TRAVEL = {
    "Lebanon": {
        "code": "LB",
        "includes": [],
        "official_name": "Lebanese Republic",
    },
    "Iraq": {
        "code": "IQ",
        "includes": [],
        "official_name": "Republic of Iraq",
    },
    "Yemen": {
        "code": "YE",
        "includes": [],
        "official_name": "Republic of Yemen",
    },
    "Syria": {
        "code": "SY",
        "includes": [],
        "official_name": "Syrian Arab Republic",
    },
    "Iran": {
        "code": "IR",
        "includes": [],
        "official_name": "Islamic Republic of Iran",
    },
    "Israel": {
        "code": "IL",
        "includes": ["West Bank", "Gaza"],
        "official_name": "State of Israel",
    },
    "Russia": {
        "code": "RU",
        "includes": [],
        "official_name": "Russian Federation",
    },
    "Ukraine": {
        "code": "UA",
        "includes": [],
        "official_name": "Ukraine",
    },
    "Belarus": {
        "code": "BY",
        "includes": [],
        "official_name": "Republic of Belarus",
    },
    "Jordan": {
        "code": "JO",
        "includes": [],
        "official_name": "Hashemite Kingdom of Jordan",
    },
    "UAE": {
        "code": "AE",
        "includes": [],
        "official_name": "United Arab Emirates",
    },
    "Qatar": {
        "code": "QA",
        "includes": [],
        "official_name": "State of Qatar",
    },
    "Oman": {
        "code": "OM",
        "includes": [],
        "official_name": "Sultanate of Oman",
    },
    "Bahrain": {
        "code": "BH",
        "includes": [],
        "official_name": "Kingdom of Bahrain",
    },
    "Kuwait": {
        "code": "KW",
        "includes": [],
        "official_name": "State of Kuwait",
    },
    "Saudi Arabia": {
        "code": "SA",
        "includes": [],
        "official_name": "Kingdom of Saudi Arabia",
    },
}

# =============================================================================
# RESTRICTED TRAVEL REQUIRING SPECIAL APPROVAL - UT System Elevated Approval
# =============================================================================
# Travel to these countries is not suspended but requires elevated approval
# from both the Institutional Travel Oversight Committee (ITOC) and the University
# President before booking. Applies to travel to or through these countries,
# including layovers and connections.
# =============================================================================

RESTRICTED_TRAVEL_REQUIRING_SPECIAL_APPROVAL = {
    "Moldova": {
        "code": "MD",
        "includes": [],
        "official_name": "Republic of Moldova",
    },
    "Egypt": {
        "code": "EG",
        "includes": [],
        "official_name": "Arab Republic of Egypt",
    },
    "Cyprus": {
        "code": "CY",
        "includes": [],
        "official_name": "Republic of Cyprus",
    },
    "Turkey": {
        "code": "TR",
        "includes": [],
        "official_name": "Republic of Turkey",
    },
}

# Country code to flag emoji mapping (uses regional indicator symbols)
# This converts 2-letter ISO codes to flag emojis
def country_code_to_flag(code: str) -> str:
    """Convert a 2-letter country code to a flag emoji.

    Uses Unicode regional indicator symbols. For example:
    'US' -> regional indicator U + regional indicator S -> US flag emoji
    """
    if not code or len(code) != 2:
        return ""
    # Regional indicator symbols start at 0x1F1E6 for 'A'
    return "".join(chr(0x1F1E6 + ord(c.upper()) - ord('A')) for c in code)


@dataclass
class RegionalWarning:
    """A specific region within a country with elevated risk."""
    region_name: str
    level: int
    reasons: str = ""


@dataclass
class TravelAdvisory:
    """Represents a country's travel advisory."""
    country_name: str
    country_code: str
    overall_level: int
    summary: str
    last_updated: datetime
    link: str
    regional_warnings: list[RegionalWarning] = field(default_factory=list)
    cdc_notices: list['CDCHealthNotice'] = field(default_factory=list)

    @property
    def has_regional_elevation(self) -> bool:
        """True if country has regions with higher risk than overall level."""
        return any(w.level > self.overall_level for w in self.regional_warnings)

    @property
    def max_regional_level(self) -> int:
        """Highest risk level among regional warnings."""
        if not self.regional_warnings:
            return self.overall_level
        return max(w.level for w in self.regional_warnings)

    @property
    def flag_emoji(self) -> str:
        """Get the flag emoji for this country."""
        return country_code_to_flag(self.country_code)


@dataclass
class CDCHealthNotice:
    """A CDC Level 3/4 travel health notice for a single country."""
    country_name: str
    level: int               # 3 or 4 only
    level_name: str          # CDC's label, e.g. "Avoid Nonessential Travel"
    disease: str             # e.g. "Yellow Fever", "Mpox"
    last_updated: datetime
    link: str


@dataclass
class CDCGlobalOutbreak:
    """A CDC Level 1/2 global or multi-country health notice."""
    title: str               # e.g. "Global Measles"
    level: int               # 1 or 2
    level_name: str          # CDC's label
    disease: str             # normalized disease name
    affected_summary: str    # e.g. "Multiple regions worldwide"
    last_updated: datetime
    link: str                # full URL to the CDC notice page


# =============================================================================
# CDC TRAVEL HEALTH NOTICES
# =============================================================================
CDC_NOTICES_URL = "https://wwwnc.cdc.gov/travel/notices"

CDC_LEVEL_NAMES = {
    1: "Practice Usual Precautions",
    2: "Practice Enhanced Precautions",
    3: "Reconsider Nonessential Travel",
    4: "Avoid All Travel",
}

# CDC country names that diverge from State Dept naming conventions.
# Keys are lowercase CDC names; values are State Dept-style names.
CDC_NAME_MAP: dict[str, str] = {
    "democratic republic of the congo": "Congo, Democratic Republic of the",
    "republic of the congo": "Congo, Republic of the",
    "cote d'ivoire": "Cote d'Ivoire",
    "côte d'ivoire": "Cote d'Ivoire",
    "south sudan": "South Sudan",
    "republic of south sudan": "South Sudan",
    "timor-leste": "Timor-Leste",
    "new caledonia": "New Caledonia",
    "cook islands": "Cook Islands",
}


def _total_summary_length(entries: list[dict]) -> int:
    """Return the combined length of all Summary fields."""
    return sum(len(e.get('Summary', '')) for e in entries)


def _load_api_cache(cache_path: Path) -> list[dict]:
    """Load cached API response from disk.  Returns [] on any failure."""
    try:
        if cache_path.exists():
            data = json.loads(cache_path.read_text(encoding='utf-8'))
            entries = data.get('entries', [])
            ts = data.get('timestamp', 'unknown')
            if entries:
                logger.info("Loaded %d cached entries (from %s)", len(entries), ts)
            return entries
    except (json.JSONDecodeError, OSError, KeyError) as exc:
        logger.warning("Could not read API cache: %s", exc)
    return []


def _save_api_cache(cache_path: Path, entries: list[dict]) -> None:
    """Persist a full API response to disk for future fallback."""
    try:
        cache_path.write_text(json.dumps({
            'timestamp': datetime.now().isoformat(timespec='seconds'),
            'entries': entries,
        }), encoding='utf-8')
        logger.debug("Saved %d entries to API cache", len(entries))
    except OSError as exc:
        logger.warning("Could not write API cache: %s", exc)


def fetch_advisories(max_retries: int = 3,
                     cache_path: Path | None = None) -> list[dict]:
    """Fetch travel advisory data from the State Department API.

    The API is load-balanced across backends that can disagree on both entry
    count and summary content.  All attempts are made and the response is
    selected by:
      1. Most entries (primary) — a higher count means fewer missing advisories.
      2. Total summary length (tiebreaker) — richer text when counts are equal.

    If the best live response has fewer than MIN_EXPECTED_ENTRIES entries and
    a cache_path is provided, falls back to the last known good cached response.

    Returns:
        List of advisory dictionaries from the API.

    Raises:
        ConnectionError: If all attempts fail.
    """
    best: list[dict] = []
    best_size = -1
    last_error: Exception | None = None

    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(
                API_URL,
                headers={"User-Agent": "TravelAdvisoryReport/1.0"}
            )
            with urllib.request.urlopen(req, timeout=30) as response:
                data = json.loads(response.read().decode('utf-8'))
                entries = data if isinstance(data, list) else data.get('data', [])
                size = _total_summary_length(entries)
                logger.debug("Fetch attempt %d: %d entries, %d total summary chars",
                             attempt + 1, len(entries), size)
                # Prefer more entries; use summary length as tiebreaker only.
                if len(entries) > len(best) or (
                    len(entries) == len(best) and size > best_size
                ):
                    best, best_size = entries, size
        except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
            last_error = e
            logger.debug("Fetch attempt %d failed: %s", attempt + 1, e)

    if not best:
        raise ConnectionError(f"Failed to fetch advisories after {max_retries} attempts: {last_error}")

    # Cache management: save good responses, fall back to cache on bad ones
    if cache_path:
        if len(best) >= MIN_EXPECTED_ENTRIES:
            _save_api_cache(cache_path, best)
        else:
            cached = _load_api_cache(cache_path)
            if len(cached) > len(best):
                logger.warning(
                    "[WARN] Live API returned only %d entries (below %d minimum). "
                    "Falling back to cached response with %d entries.",
                    len(best), MIN_EXPECTED_ENTRIES, len(cached),
                )
                best = cached

    return best


def parse_level_from_title(title: str) -> tuple[str, int]:
    """Extract country name and advisory level from title.

    Args:
        title: Advisory title like "Mexico - Level 2: Exercise Increased Caution"

    Returns:
        Tuple of (country_name, level_number)
    """
    # Pattern: "Country Name - Level N: Description"
    match = re.match(r'^(.+?)\s*-\s*Level\s*(\d)', title, re.IGNORECASE)
    if match:
        return match.group(1).strip(), int(match.group(2))
    return title, 0


def clean_html(text: str) -> str:
    """Remove HTML tags and decode entities from text."""
    # Decode HTML entities
    text = html.unescape(text)
    # Remove HTML tags but preserve some structure
    text = re.sub(r'<br\s*/?>', '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'<p[^>]*>', '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'</p>', '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'<li[^>]*>', '\n- ', text, flags=re.IGNORECASE)
    text = re.sub(r'<[^>]+>', '', text)
    # Normalize non-breaking and narrow no-break spaces to regular spaces
    text = re.sub(r'[\xa0\u202f]', ' ', text)
    # Clean up whitespace
    text = re.sub(r'\n{3,}', '\n\n', text)
    text = re.sub(r' +', ' ', text)
    return text.strip()


def _resolve_region_from_context(clean_text: str, match_start: int) -> str | None:
    """When the regex captures 'this area', look backwards for a header line.

    State Dept advisories use a consistent pattern where the region name
    appears as a header on the line(s) preceding the warning directive:

        Union territory of Jammu and Kashmir:
        Do not travel to this area ...

        India-Pakistan Border
        Do not travel to this area ...

    This function walks backwards from the match position to find that header.
    """
    # Get all text before the match
    preceding = clean_text[:match_start]
    # Split into lines and walk backwards past blank lines
    lines = preceding.split('\n')
    for line in reversed(lines):
        line = line.strip()
        if not line or line.startswith('-'):
            continue
        # Strip trailing colons and punctuation used in headers
        header = re.sub(r'[:\s]+$', '', line).strip()
        # Reject if it looks like boilerplate or a section label
        boilerplate = [
            'country summary', 'if you decide', 'travel advisory',
            'read the', 'visit our', 'review', 'enroll', 'prepare',
            'we highly', 'check with', 'permission is not',
            'do not travel', 'reconsider travel', 'exercise increased',
            'exercise normal', 'check the', 'consult', 'safety and security',
            'website for', 'see the',
        ]
        if any(bp in header.lower() for bp in boilerplate):
            return None
        # Reject "Level N" section labels (e.g. "Level 4: Do Not Travel")
        if re.match(r'^Level\s+\d', header, re.IGNORECASE):
            return None
        if len(header) < 3 or len(header) > 200:
            return None
        # Remove leading articles
        header = re.sub(r'^(the|a|an)\s+', '', header, flags=re.IGNORECASE).strip()
        return header
    return None


def _expand_bullet_warnings(text: str) -> str:
    """Expand bullet-list warning formats into standalone sentences.

    Converts patterns like:
        Do Not Travel to:
        - Region A due to X.
        - Region B due to Y.

    Into:
        Do not travel to Region A due to X.
        Do not travel to Region B due to Y.

    This normalizes all formats before the main regex runs.
    """
    lines = text.split('\n')
    result = []
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        # Check for directive ending with colon and no region after it
        directive_match = re.match(
            r'(Do\s+Not\s+Travel\s+to|Reconsider\s+Travel\s+to)\s*:\s*$',
            line, re.IGNORECASE
        )
        if directive_match:
            directive = directive_match.group(1)
            i += 1
            # Collect subsequent bullet lines
            while i < len(lines):
                bullet_line = lines[i].strip()
                if bullet_line.startswith('- ') or bullet_line.startswith('* '):
                    content = bullet_line[2:].strip()
                    # Synthesize a standalone sentence
                    sentence = f"{directive} {content}"
                    if not sentence.endswith('.'):
                        sentence += '.'
                    result.append(sentence)
                    i += 1
                elif not bullet_line:
                    # Skip empty lines — clean_html() inserts blank lines
                    # between <p>/<ul> blocks that separate the directive
                    # header from its bullets.
                    i += 1
                else:
                    break
        else:
            result.append(lines[i])
            i += 1
    return '\n'.join(result)


def extract_regional_warnings(summary: str, overall_level: int) -> list[RegionalWarning]:
    """Extract regional warnings from advisory summary.

    Looks for patterns like:
    - "Level 4: region names due to reasons"
    - "Do not travel to X due to Y"
    - "Reconsider travel to X"

    When the matched region is a vague reference like "this area", falls back
    to the preceding header line to resolve the actual region name.

    Args:
        summary: The advisory summary HTML/text.
        overall_level: The country's overall advisory level.

    Returns:
        List of RegionalWarning objects for elevated regions.
    """
    warnings = []
    clean_text = clean_html(summary)
    clean_text = _expand_bullet_warnings(clean_text)

    vague_terms = [
        'these areas', 'this area', 'the area', 'certain areas',
        'following areas', 'following locations', 'following regions',
        'the following', 'areas below', 'locations below',
    ]
    skip_phrases = ['country', 'nation', 'all of', 'anywhere', 'entire']

    # Pattern 1: "Do not travel to X due to Y" (implies Level 4)
    # This is the most reliable pattern in State Dept advisories
    if overall_level < 4:
        do_not_travel = re.finditer(
            r'Do\s+not\s+travel\s+to[:\s]+(.+?)\s+(?:due\s+to|for\s+any\s+reason[,.]?\s*(?:due\s+to)?)\s*([^.]*?)\.',
            clean_text,
            re.IGNORECASE
        )
        for match in do_not_travel:
            region = match.group(1).strip()
            reasons = match.group(2).strip()
            if not reasons:
                reasons = "unspecified"

            # Skip country-wide statements
            if any(skip in region.lower() for skip in skip_phrases):
                continue

            # Clean up region name - remove leading articles, dashes, colons
            region = re.sub(r'^(the|a|an)\s+', '', region, flags=re.IGNORECASE)
            region = re.sub(r'^[-:*]\s*', '', region)  # Remove leading punctuation
            region = region.strip()

            # When the match is a vague reference like "this area", resolve the
            # actual region name from the preceding header line
            if any(vague in region.lower() for vague in vague_terms):
                resolved = _resolve_region_from_context(clean_text, match.start())
                if resolved:
                    region = resolved
                else:
                    continue

            if len(region) < 3 or len(region) > 200:
                continue

            # Avoid duplicates
            if not any(region.lower() in w.region_name.lower() or
                       w.region_name.lower() in region.lower() for w in warnings):
                warnings.append(RegionalWarning(
                    region_name=region,
                    level=4,
                    reasons=reasons
                ))

    # Pattern 2: "Reconsider travel to X due to Y" (implies Level 3)
    if overall_level < 3:
        reconsider = re.finditer(
            r'Reconsider\s+travel\s+to[:\s]+(.+?)\s+(?:due\s+to|for\s+any\s+reason[,.]?\s*(?:due\s+to)?)\s*([^.]*?)\.',
            clean_text,
            re.IGNORECASE
        )
        for match in reconsider:
            region = match.group(1).strip()
            reasons = match.group(2).strip()
            if not reasons:
                reasons = "unspecified"

            # Skip country-wide statements
            if any(skip in region.lower() for skip in skip_phrases):
                continue

            region = re.sub(r'^(the|a|an)\s+', '', region, flags=re.IGNORECASE)
            region = re.sub(r'^[-:*]\s*', '', region)
            region = region.strip()

            # Resolve vague references from preceding header line
            if any(vague in region.lower() for vague in vague_terms):
                resolved = _resolve_region_from_context(clean_text, match.start())
                if resolved:
                    region = resolved
                else:
                    continue

            if len(region) < 3 or len(region) > 200:
                continue

            if not any(region.lower() in w.region_name.lower() or
                       w.region_name.lower() in region.lower() for w in warnings):
                warnings.append(RegionalWarning(
                    region_name=region,
                    level=3,
                    reasons=reasons
                ))

    return warnings


def _has_regional_signals(summary: str) -> bool:
    """Detect whether a summary likely contains regional warning data.

    Returns True if the summary text has phrases that typically indicate
    sub-national risk levels, even when the regex extraction fails to
    capture them (e.g. because the data is in a non-standard format).
    """
    signals = [
        r'some\s+areas\s+have\s+increased\s+risk',
        r'level\s+[34]',
        r'do\s+not\s+travel',
        r'reconsider\s+travel',
        r'high-risk\s+areas',
        r'restricted\s+areas',
        r'not\s+allowed\s+to\s+travel',
    ]
    text = summary.lower()
    return any(re.search(s, text) for s in signals)


def fetch_advisory_page(url: str) -> str:
    """Fetch the full advisory HTML page from travel.state.gov.

    Returns the raw HTML string, or empty string on failure.
    Non-fatal: logs a warning on failure so the pipeline continues.
    """
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "TravelAdvisoryReport/1.0"}
        )
        with urllib.request.urlopen(req, timeout=15) as response:
            return response.read().decode('utf-8', errors='replace')
    except (urllib.error.URLError, OSError, ValueError) as e:
        logger.warning("Failed to fetch advisory page %s: %s", url, e)
        return ""


def extract_regional_warnings_from_page(
    page_html: str, overall_level: int
) -> list[RegionalWarning]:
    """Extract regional warnings from a full advisory HTML page.

    Advisory pages use several formats:
    1. "Region - Level N: Do Not Travel" (inline)
    2. Level header followed by region names on subsequent lines:
         Level: 4 - Do not travel
         State of Colima
         Do not travel due to terrorism, crime...

    This is far more reliable than the API Summary field for countries
    like Mexico where the summary omits regional detail.
    """
    warnings = []
    clean_text = clean_html(page_html)

    # Pattern 1: "Region Name - Level N: Do Not Travel" (inline format)
    structured = re.finditer(
        r'([A-Z][A-Za-z\s\'-]+?)\s*[-\u2013\u2014]\s*Level\s+(\d)\s*:\s*(Do\s+Not\s+Travel|Reconsider\s+Travel)',
        clean_text
    )
    for match in structured:
        region = match.group(1).strip()
        level = int(match.group(2))

        if level <= overall_level:
            continue
        if region.lower() in ('country summary', 'last update', 'advisory'):
            continue
        if len(region) < 3 or len(region) > 200:
            continue

        after_match = clean_text[match.end():]
        reasons = ""
        paren = re.match(r'\s*\(([^)]+)\)', after_match)
        if paren:
            reasons = paren.group(1).strip()

        if not any(region.lower() == w.region_name.lower() for w in warnings):
            warnings.append(RegionalWarning(
                region_name=region,
                level=level,
                reasons=reasons
            ))

    # Pattern 2: Level header sections with region names on following lines
    # e.g. "Level: 4 - Do not travel" followed by region-name lines
    if not warnings:
        # Split into sections by level headers
        level_sections = re.split(
            r'Level\s*:\s*(\d)\s*-\s*(Do\s+Not\s+Travel|Reconsider\s+Travel)',
            clean_text, flags=re.IGNORECASE
        )
        # level_sections: [preamble, level_num, directive, section_text, level_num, ...]
        i = 1
        while i + 2 < len(level_sections):
            level = int(level_sections[i])
            section_text = level_sections[i + 2]
            i += 3

            if level <= overall_level:
                continue

            # Find region names: lines that look like headers (capitalized,
            # no directive keywords) followed by a directive or crime description.
            #
            # Two confirmed formats:
            #   Format A (Colombia, Pakistan old-style):
            #     Region Name
            #     Do not travel to this area due to...
            #   Format B (Madagascar, Pakistan tsg_aem):
            #     Region Name
            #     Violent crime, such as armed carjacking...
            #
            # For tsg_aem pages the section text extends to end of page,
            # so we must distinguish real regions from boilerplate sections
            # (embassy info, travel tips, country list).  Real region
            # descriptions always contain crime/safety keywords; boilerplate
            # does not.
            _safety_keywords = re.compile(
                r'crime|violen|terroris|kidnap|armed|carjack|bandit|'
                r'robbery|murder|conflict|extremis|disappearance|'
                r'civil\s+unrest|landmine|unexploded',
                re.IGNORECASE,
            )
            lines = section_text.split('\n')
            for j, line in enumerate(lines):
                line = line.strip()
                if not line:
                    continue
                # Terminate scan at boilerplate boundary markers
                if re.match(r'^(If you decide to travel|Scroll to review|'
                            r'Travel advisory levels|Learn more about)',
                            line, re.IGNORECASE):
                    break
                # A region name line is typically a short capitalized phrase
                # that is NOT a directive or boilerplate
                if re.match(r'^(Do\s+not\s+travel|Reconsider\s+travel|Exercise|Read\s+the|Visit|If\s+you|There\s+|Most\s+|Shooting|U\.S\.|Check|Expand|Collapse)', line, re.IGNORECASE):
                    continue
                if line.startswith('- ') or line.startswith('* '):
                    continue
                # Must start with uppercase and be reasonably short (region name)
                if not line[0].isupper() or len(line) > 100:
                    continue
                # Look ahead for a directive line or crime/safety description.
                next_line = ""
                for k in range(j + 1, min(j + 4, len(lines))):
                    nl = lines[k].strip()
                    if nl:
                        next_line = nl
                        break
                reasons = ""
                if re.match(r'(Do\s+not\s+travel|Reconsider\s+travel)', next_line, re.IGNORECASE):
                    # Next line is a directive — extract reasons from it
                    reasons_match = re.search(r'due\s+to\s+([^.]+)', next_line, re.IGNORECASE)
                    reasons = reasons_match.group(1).strip() if reasons_match else ""
                elif not _safety_keywords.search(next_line):
                    # Next line has no crime/safety content — this is
                    # boilerplate, not a region description.
                    continue
                region = line.strip()
                if len(region) >= 3 and not any(region.lower() == w.region_name.lower() for w in warnings):
                    warnings.append(RegionalWarning(
                        region_name=region,
                        level=level,
                        reasons=reasons
                    ))

    # Fallback: try the same regex patterns used for summary text
    if not warnings:
        warnings = extract_regional_warnings(page_html, overall_level)

    return warnings


def parse_advisory(raw: dict) -> tuple[TravelAdvisory | None, bool]:
    """Parse a raw API response into a TravelAdvisory object.

    Args:
        raw: Dictionary from the API response.

    Returns:
        Tuple of (TravelAdvisory or None, page_fallback_used).
    """
    try:
        title = raw.get('Title', '')
        country_name, overall_level = parse_level_from_title(title)

        if overall_level == 0:
            # Compound entries (e.g. "Mainland China, Hong Kong & Macau - See Summaries")
            # have no level in the title. Keep them if they match a prohibited country
            # so they route correctly to the prohibited list.
            if is_prohibited_country(country_name):
                logger.info("Keeping level-0 prohibited entry: %s", title)
            else:
                logger.warning("Skipping unparseable advisory (no level): %s", title)
                return None, False

        # Get country code from Category field (usually a list like ["MX"])
        # The API returns FIPS 10-4 codes in the Category field, not ISO 3166-1.
        # We use the raw FIPS codes as-is — see comment near top of file.
        category = raw.get('Category', [])
        country_code = category[0].upper() if category else ""

        summary = raw.get('Summary', '')
        link = raw.get('Link', raw.get('id', ''))

        # Parse the update timestamp
        updated_str = raw.get('Updated', raw.get('Published', ''))
        try:
            # Handle ISO format with timezone
            last_updated = datetime.fromisoformat(updated_str.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            last_updated = datetime.now()

        # Extract regional warnings
        regional_warnings = extract_regional_warnings(summary, overall_level)

        # Page scraping fallback: for countries where the API Summary hints
        # at regional warnings but the regex failed to extract any, fetch
        # the full advisory page for more reliable structured data.
        # Level 3 countries are included because they can have Level 4
        # sub-regions (e.g. Colombia, Pakistan) that only appear on the page.
        page_fallback_used = False
        if overall_level <= 3 and not regional_warnings and _has_regional_signals(summary):
            page_html = fetch_advisory_page(link)
            if page_html:
                regional_warnings = extract_regional_warnings_from_page(page_html, overall_level)
                if regional_warnings:
                    page_fallback_used = True
                    logger.info("Recovered %d regional warnings from page for %s",
                                len(regional_warnings), country_name)

        return TravelAdvisory(
            country_name=country_name,
            country_code=country_code,
            overall_level=overall_level,
            summary=clean_html(summary),
            last_updated=last_updated,
            link=link,
            regional_warnings=regional_warnings
        ), page_fallback_used
    except Exception as e:
        logger.error("Failed to parse advisory '%s': %s", raw.get('Title', '<no title>'), e)
        return None, False


def is_prohibited_country(country_name: str) -> bool:
    """Check if a country is on the prohibited list (Texas EO GA-48).

    Uses exact match first, then word-boundary regex to catch compound entries
    like 'Mainland China, Hong Kong & Macau - See Summaries' without falsely
    matching country names that contain a prohibited name as a substring
    (e.g. a hypothetical 'Iranistan').
    """
    name_lower = country_name.lower().strip()
    # Exact match
    if name_lower in PROHIBITED_COUNTRY_NAMES:
        return True
    # Word-boundary match: check if any prohibited name appears at a word
    # boundary within the country name
    return any(re.search(r'\b' + re.escape(p) + r'\b', name_lower)
               for p in PROHIBITED_COUNTRY_NAMES)


def _match_country_dict(country_name: str, country_dict: dict) -> bool:
    """Check if a country name matches any entry in a country dictionary.

    Matching strategy (all case-insensitive):
    1. Word-boundary regex on the dict key — prevents short names like "Oman"
       from falsely matching longer names like "Romania".
    2. Substring match on official_name — catches cases where the API uses the
       full official name (e.g. "United Arab Emirates" for key "UAE").
    3. Word-boundary regex on each entry in the 'includes' list.
    """
    name_lower = country_name.lower().strip()
    for key, info in country_dict.items():
        # 1. Word-boundary match on canonical key name
        if re.search(r'\b' + re.escape(key.lower()) + r'\b', name_lower):
            return True
        # 2. Official name substring match (handles abbreviations like UAE)
        official = info.get('official_name', '').lower()
        if official and official in name_lower:
            return True
        # 3. Word-boundary match on includes aliases
        for alias in info.get('includes', []):
            if re.search(r'\b' + re.escape(alias.lower()) + r'\b', name_lower):
                return True
    return False


def is_ut_suspended_country(country_name: str) -> bool:
    """Check if a country is on the UT System suspended travel list."""
    return _match_country_dict(country_name, UT_SUSPENDED_TRAVEL)


def is_restricted_special_country(country_name: str) -> bool:
    """Check if a country requires Institutional Travel Oversight Committee (ITOC) + President elevated approval."""
    return _match_country_dict(country_name, RESTRICTED_TRAVEL_REQUIRING_SPECIAL_APPROVAL)


def deduplicate_advisories(
    advisories: list[TravelAdvisory],
) -> tuple[list[TravelAdvisory], list[str]]:
    """Remove duplicate advisories, keeping the most recently updated entry.

    Deduplicates by country code first; falls back to normalized country name
    for entries without a code.

    Returns:
        Tuple of (deduplicated_list, list_of_duplicate_descriptions).
    """
    seen: dict[str, TravelAdvisory] = {}
    duplicates: list[str] = []

    for adv in advisories:
        key = adv.country_code.upper() if adv.country_code else adv.country_name.lower().strip()
        if key in seen:
            existing = seen[key]
            # Keep the more recently updated entry
            if adv.last_updated > existing.last_updated:
                duplicates.append(
                    f"Dropped '{existing.country_name}' (code={existing.country_code}, "
                    f"updated={existing.last_updated:%Y-%m-%d}) in favor of "
                    f"'{adv.country_name}' (updated={adv.last_updated:%Y-%m-%d})"
                )
                seen[key] = adv
            else:
                duplicates.append(
                    f"Dropped '{adv.country_name}' (code={adv.country_code}, "
                    f"updated={adv.last_updated:%Y-%m-%d}) in favor of "
                    f"'{existing.country_name}' (updated={existing.last_updated:%Y-%m-%d})"
                )
        else:
            seen[key] = adv

    return list(seen.values()), duplicates


def filter_high_risk(
    advisories: list[TravelAdvisory],
) -> tuple[list[TravelAdvisory], list[TravelAdvisory], list[TravelAdvisory], list[TravelAdvisory]]:
    """Filter advisories into four priority buckets using a waterfall.

    Waterfall priority (first match wins):
      1. Prohibited       — Texas EO GA-48 foreign adversaries
      2. UT Suspended     — UT System suspended travel (ITOC + President exception required; incl. layovers)
      3. Restricted       — UT System elevated approval required (ITOC + President; incl. layovers)
      4. High-risk        — Level 3/4 or Level 1/2 with regional Level 3/4 warnings

    Args:
        advisories: List of all parsed advisories.

    Returns:
        Tuple of (prohibited, ut_suspended, restricted_special, high_risk).
    """
    prohibited = []
    ut_suspended = []
    restricted_special = []
    high_risk = []

    for advisory in advisories:
        if is_prohibited_country(advisory.country_name):
            prohibited.append(advisory)
            continue

        if is_ut_suspended_country(advisory.country_name):
            ut_suspended.append(advisory)
            continue

        if is_restricted_special_country(advisory.country_name):
            restricted_special.append(advisory)
            continue

        # Include if overall level is 3 or 4
        if advisory.overall_level >= 3:
            high_risk.append(advisory)
            continue

        # Include if there are elevated regional warnings
        if advisory.has_regional_elevation and advisory.max_regional_level >= 3:
            high_risk.append(advisory)

    # Consolidate: at most one advisory per canonical PROHIBITED_COUNTRIES key.
    # Prefer the advisory whose name matches the parent key (e.g. "China") over
    # an include match (e.g. "Hong Kong"). Discards duplicate includes.
    _by_key: dict[str, tuple[bool, TravelAdvisory]] = {}
    for adv in prohibited:
        name_lower = adv.country_name.lower()
        for key, info in PROHIBITED_COUNTRIES.items():
            is_parent = key.lower() in name_lower
            is_include = any(inc.lower() in name_lower for inc in info.get('includes', []))
            if not (is_parent or is_include):
                continue
            existing = _by_key.get(key)
            if existing is None or (is_parent and not existing[0]):
                _by_key[key] = (is_parent, adv)
            break
    prohibited = [adv for _, adv in _by_key.values()]

    prohibited.sort(key=lambda a: a.country_name)
    ut_suspended.sort(key=lambda a: a.country_name)
    restricted_special.sort(key=lambda a: a.country_name)
    high_risk.sort(key=lambda a: (-a.overall_level, -a.max_regional_level, a.country_name))

    return prohibited, ut_suspended, restricted_special, high_risk


def fetch_listing_page_count() -> int | None:
    """Scrape the travel.state.gov listing page for the total advisory count.

    Returns the number of table rows (destinations) found on the listing page,
    or None if the page is unreachable or unparseable.  This is informational
    only — used to cross-validate the API entry count in the verification log.
    """
    try:
        req = urllib.request.Request(
            LISTING_PAGE_URL,
            headers={"User-Agent": "TravelAdvisoryReport/1.0"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            page_html = resp.read().decode('utf-8', errors='replace')
    except (urllib.error.URLError, OSError) as exc:
        logger.warning("Could not fetch listing page for cross-validation: %s", exc)
        return None

    # The listing page has a table with one row per destination.
    # Count <tr> tags inside the advisory table (skip the header row).
    rows = re.findall(r'<tr[^>]*>', page_html)
    if len(rows) > 1:
        count = len(rows) - 1  # subtract header row
        logger.info("Listing page cross-validation: %d destinations found", count)
        return count

    logger.warning("Listing page fetched but no table rows found.")
    return None


def extract_worldwide_caution() -> 'TravelAdvisory | None':
    """Fetch the worldwide caution advisory from the dedicated State Dept page.

    Parses the HTML at WORLDWIDE_CAUTION_URL, extracting the date and body text
    from <div class="pageContent"> blocks.  Returns None (with a logged warning)
    if the page is unreachable or contains no usable text.
    """
    try:
        req = urllib.request.Request(
            WORLDWIDE_CAUTION_URL,
            headers={"User-Agent": "Mozilla/5.0 (travel-advisory-report/1.0)"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw_html = resp.read().decode("utf-8", errors="replace")
    except Exception as exc:
        logger.warning("Could not fetch worldwide caution page: %s", exc)
        return None

    # Extract all pageContent div bodies
    blocks = re.findall(
        r'<div[^>]+class="pageContent"[^>]*>(.*?)</div>',
        raw_html,
        re.DOTALL,
    )
    if not blocks:
        logger.warning("Worldwide caution page fetched but no pageContent divs found.")
        return None

    def _strip_html(fragment: str) -> str:
        """Remove HTML tags and decode entities; collapse whitespace."""
        text = re.sub(r'<[^>]+>', ' ', fragment)
        text = html.unescape(text)
        return re.sub(r'\s+', ' ', text).strip()

    # Block 0 contains the date line; remaining blocks are body text.
    date_text = _strip_html(blocks[0])
    body_text = "\n\n".join(_strip_html(b) for b in blocks[1:] if _strip_html(b))

    if not body_text:
        logger.warning("Worldwide caution page contained no body text.")
        return None

    # Extract issue date from the date block (e.g. "February 28, 2026 - ...")
    date_match = re.search(r'(\w+ \d{1,2}, \d{4})', date_text)
    last_updated: datetime | None = None
    if date_match:
        try:
            last_updated = datetime.strptime(date_match.group(1), "%B %d, %Y")
        except ValueError:
            pass
    if last_updated is None:
        last_updated = datetime.now()

    # Infer advisory level from body text keywords (worldwide caution is typically L2)
    body_lower = body_text.lower()
    if "do not travel" in body_lower:
        level = 4
    elif "reconsider travel" in body_lower:
        level = 3
    else:
        level = 2  # "exercise increased caution" or unspecified

    return TravelAdvisory(
        country_name="Worldwide Caution",
        country_code="WW",
        overall_level=level,
        summary=body_text,
        last_updated=last_updated,
        link=WORLDWIDE_CAUTION_URL,
    )


def fetch_cdc_notices() -> tuple[list[CDCHealthNotice], list[CDCGlobalOutbreak]]:
    """Fetch and parse CDC travel health notices.

    Scrapes https://wwwnc.cdc.gov/travel/notices.

    Returns:
        Tuple of (health_notices, global_outbreaks) where:
        - health_notices: Level 3/4 notices for single resolvable countries
        - global_outbreaks: Level 1/2 global or multi-country notices

    Non-fatal: returns ([], []) on any fetch or parse failure.
    Logs a warning on failure so the pipeline continues without CDC data.
    """
    try:
        req = urllib.request.Request(
            CDC_NOTICES_URL,
            headers={"User-Agent": "TravelAdvisoryReport/1.0"},
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            page_html = resp.read().decode('utf-8', errors='replace')
    except (urllib.error.URLError, OSError) as exc:
        logger.warning("Could not fetch CDC travel notices page: %s", exc)
        return [], []

    health_notices: list[CDCHealthNotice] = []
    global_outbreaks: list[CDCGlobalOutbreak] = []

    # The page groups notices under level headings.  Each notice is an <a> tag
    # inside a list item.  We parse the HTML structure to extract level, title,
    # date, and link for each notice.
    #
    # Structure on the page:
    #   <div ...> or <h3>  containing "Level N"
    #   followed by <li> blocks with <a href="/travel/notices/levelN/slug">Title</a>
    #   and a date string nearby.

    # Extract all notice entries with their level from the HTML.
    # Pattern: link href contains /travel/notices/level{N}/ and link text is title
    notice_pattern = re.compile(
        r'<a[^>]+href="(/travel/notices/level(\d)/([^"]+))"[^>]*>\s*(.+?)\s*</a>',
        re.IGNORECASE | re.DOTALL,
    )
    # Date pattern near notices (e.g., "March 16, 2026")
    date_pattern = re.compile(r'(\w+ \d{1,2}, \d{4})')

    # Split page into chunks around each notice link for date extraction
    raw_notices: list[dict] = []
    for match in notice_pattern.finditer(page_html):
        href = match.group(1)
        level = int(match.group(2))
        slug = match.group(3)
        title = clean_html(match.group(4)).strip()

        # Skip the overview/portal page links
        if not title or 'travel health notices' in title.lower():
            continue

        # Build full URL
        link = f"https://wwwnc.cdc.gov{href}"

        # Find the nearest date after this match
        after_text = page_html[match.end():match.end() + 300]
        date_match = date_pattern.search(after_text)
        last_updated = datetime.now()
        if date_match:
            try:
                last_updated = datetime.strptime(date_match.group(1), "%B %d, %Y")
            except ValueError:
                pass

        raw_notices.append({
            'title': title,
            'level': level,
            'slug': slug,
            'link': link,
            'last_updated': last_updated,
        })

    for notice in raw_notices:
        title = notice['title']
        level = notice['level']
        link = notice['link']
        last_updated = notice['last_updated']
        level_name = CDC_LEVEL_NAMES.get(level, f"Level {level}")

        # Extract disease and country from title.
        # Common formats:
        #   "Yellow Fever in Venezuela"
        #   "Chikungunya in Mayotte"
        #   "Global Measles"
        #   "Global Polio"
        #   "Clade II Monkeypox in Ghana and Liberia"
        #   "Rocky Mountain Spotted Fever in Mexico"

        is_global = 'global' in title.lower()

        # Try to split on " in " to get disease and location
        in_match = re.match(r'^(.+?)\s+in\s+(.+)$', title, re.IGNORECASE)
        if in_match:
            disease = in_match.group(1).strip()
            location = in_match.group(2).strip()
        else:
            disease = title
            location = ""

        # Determine if this is a multi-country notice
        # Multi-country: title has "Global", or location lists multiple countries
        # with "and" or commas
        country_names: list[str] = []
        if location and not is_global:
            # Strip parenthetical region details, e.g. "Bolivia (Santa Cruz ...)"
            location_clean = re.sub(r'\s*\([^)]*\)', '', location)
            # Split on " and " and commas
            parts = re.split(r'\s+and\s+|,\s*', location_clean)
            country_names = [p.strip() for p in parts if p.strip()]

        is_multi_country = is_global or len(country_names) >= 3

        if level >= 3:
            # Level 3/4: create CDCHealthNotice entries
            if not is_multi_country and len(country_names) >= 1:
                # Single or dual country — create one notice per country
                for cname in country_names:
                    normalized = CDC_NAME_MAP.get(cname.lower(), cname)
                    health_notices.append(CDCHealthNotice(
                        country_name=normalized,
                        level=level,
                        level_name=level_name,
                        disease=disease,
                        last_updated=last_updated,
                        link=link,
                    ))
            elif is_multi_country or not country_names:
                # Global or multi-country Level 3/4: try to expand by
                # fetching the individual notice page
                expanded = _expand_cdc_notice_countries(link, level, level_name,
                                                        disease, last_updated)
                health_notices.extend(expanded)
        else:
            # Level 1/2
            if is_multi_country:
                # Global or multi-country → CDCGlobalOutbreak
                affected = location if location else "Multiple regions worldwide"
                if is_global:
                    affected = "Multiple regions worldwide"
                global_outbreaks.append(CDCGlobalOutbreak(
                    title=title,
                    level=level,
                    level_name=level_name,
                    disease=disease,
                    affected_summary=affected,
                    last_updated=last_updated,
                    link=link,
                ))
            # Single-country Level 1/2: discard silently (out of scope)

    logger.info("CDC notices parsed: %d Level 3/4 notices, %d global outbreaks",
                len(health_notices), len(global_outbreaks))
    return health_notices, global_outbreaks


def _expand_cdc_notice_countries(
    link: str, level: int, level_name: str, disease: str, last_updated: datetime
) -> list[CDCHealthNotice]:
    """Fetch an individual CDC notice page and extract listed countries.

    Used for global/multi-country Level 3/4 notices that need to be expanded
    into per-country CDCHealthNotice records.

    Returns a list of CDCHealthNotice; empty list on any failure.
    """
    try:
        req = urllib.request.Request(
            link,
            headers={"User-Agent": "TravelAdvisoryReport/1.0"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            page_html = resp.read().decode('utf-8', errors='replace')
    except (urllib.error.URLError, OSError) as exc:
        logger.warning("Could not fetch CDC notice page %s: %s", link, exc)
        return []

    notices: list[CDCHealthNotice] = []
    clean_text = clean_html(page_html)

    # Look for bulleted country lists — common in CDC global notices.
    # Countries appear as lines in a list, typically after a "current situation"
    # header.  We look for lines that are short (likely country names) and
    # appear in sequence.
    lines = clean_text.split('\n')
    for line in lines:
        line = line.strip()
        # Strip leading bullet markers
        if line.startswith('- ') or line.startswith('* '):
            line = line[2:].strip()
        # Skip long lines (descriptions, not country names)
        if not line or len(line) > 60 or len(line) < 3:
            continue
        # Skip lines that are clearly not country names
        if any(kw in line.lower() for kw in [
            'http', 'click', 'learn more', 'see', 'visit', 'page',
            'what is', 'what should', 'recommendation', 'before you',
            'after you', 'clinician', 'key points', 'current situation',
        ]):
            continue
        # Must start with uppercase and contain mostly letters
        if not line[0].isupper():
            continue
        # Simple heuristic: a country name is a short line of mostly
        # alphabetic + space + punctuation characters
        alpha_ratio = sum(c.isalpha() or c == ' ' for c in line) / len(line)
        if alpha_ratio < 0.8:
            continue
        # Normalize via CDC_NAME_MAP
        normalized = CDC_NAME_MAP.get(line.lower(), line)
        # Avoid duplicates
        if not any(n.country_name.lower() == normalized.lower() for n in notices):
            notices.append(CDCHealthNotice(
                country_name=normalized,
                level=level,
                level_name=level_name,
                disease=disease,
                last_updated=last_updated,
                link=link,
            ))

    if notices:
        logger.info("Expanded CDC notice '%s' into %d country entries", disease, len(notices))
    else:
        logger.debug("Could not expand CDC notice at %s into individual countries", link)
    return notices


def match_cdc_notices(
    notices: list[CDCHealthNotice],
    prohibited: list[TravelAdvisory],
    ut_suspended: list[TravelAdvisory],
    restricted_special: list[TravelAdvisory],
    high_risk: list[TravelAdvisory],
) -> tuple[list[TravelAdvisory], list[str]]:
    """Attach CDC notices to existing advisories or create new entries.

    For each CDCHealthNotice:
    - Normalize the CDC country name via CDC_NAME_MAP
    - Search all advisory buckets for a matching country (case-insensitive,
      substring match consistent with is_prohibited_country() pattern)
    - If matched: append the CDCHealthNotice to advisory.cdc_notices
    - If not matched: create a new TravelAdvisory with overall_level=0
      (sentinel for CDC-only origin) and cdc_notices=[notice].
      Add to a returned cdc_only list.

    Returns:
        Tuple of (cdc_only_advisories, unmatched_names) where unmatched_names
        are CDC country names that could not be resolved at all.
    """
    all_advisories = prohibited + ut_suspended + restricted_special + high_risk
    cdc_only: list[TravelAdvisory] = []
    unmatched_names: list[str] = []
    # Track CDC-only countries already created to avoid duplicates
    cdc_only_seen: dict[str, TravelAdvisory] = {}

    for notice in notices:
        normalized = CDC_NAME_MAP.get(notice.country_name.lower(), notice.country_name)
        name_lower = normalized.lower().strip()

        # Search existing advisories for a match
        matched_adv = None
        for adv in all_advisories:
            adv_lower = adv.country_name.lower()
            if name_lower == adv_lower:
                matched_adv = adv
                break
            if re.search(r'\b' + re.escape(name_lower) + r'\b', adv_lower):
                matched_adv = adv
                break
            if re.search(r'\b' + re.escape(adv_lower) + r'\b', name_lower):
                matched_adv = adv
                break

        if matched_adv is not None:
            matched_adv.cdc_notices.append(notice)
        else:
            # Check if we already created a CDC-only entry for this country
            if name_lower in cdc_only_seen:
                cdc_only_seen[name_lower].cdc_notices.append(notice)
            else:
                new_adv = TravelAdvisory(
                    country_name=normalized,
                    country_code="",
                    overall_level=0,
                    summary="",
                    last_updated=notice.last_updated,
                    link="",
                    regional_warnings=[],
                    cdc_notices=[notice],
                )
                cdc_only.append(new_adv)
                cdc_only_seen[name_lower] = new_adv

    return cdc_only, unmatched_names


# Canonical risk factor keywords, ordered by severity (most severe first).
# Used by extract_risk_factors() to normalize and prioritize risk descriptions.
RISK_FACTORS = [
    "terrorism",
    "armed conflict",
    "war",
    "civil unrest",
    "kidnapping",
    "crime",
    "violent crime",
    "wrongful detention",
    "political tension",
    "piracy",
    "natural disaster",
    "health",
    "maritime",
    "landmines",
]


def extract_risk_factors(advisory: TravelAdvisory) -> list[str]:
    """Extract and normalize risk factors from an advisory's regional warnings and summary.

    Parses each RegionalWarning.reasons string and scans advisory.summary for
    canonical risk factor keywords. Returns a deduplicated list ordered by severity.
    """
    found: set[str] = set()

    # Collect raw reason fragments from regional warnings
    raw_fragments: list[str] = []
    for warning in advisory.regional_warnings:
        if warning.reasons:
            # Split on commas and "and" to get individual reason phrases
            parts = re.split(r',\s*|\s+and\s+', warning.reasons)
            raw_fragments.extend(p.strip().lower() for p in parts if p.strip())

    # Match fragments against canonical vocabulary (bidirectional:
    # "civil unrest" in "widespread civil unrest" AND "unrest" matches "civil unrest")
    for fragment in raw_fragments:
        for factor in RISK_FACTORS:
            if factor in fragment or (len(fragment) > 4 and fragment in factor):
                found.add(factor)

    # Scan advisory summary for additional canonical keywords
    summary_lower = (advisory.summary or "").lower()
    for factor in RISK_FACTORS:
        if re.search(r'\b' + re.escape(factor) + r'\b', summary_lower):
            found.add(factor)

    # Also match common short forms to their canonical multi-word factors
    aliases = {"unrest": "civil unrest", "conflict": "armed conflict",
               "detention": "wrongful detention"}
    for alias, factor in aliases.items():
        if re.search(r'\b' + re.escape(alias) + r'\b', summary_lower):
            found.add(factor)

    # Return in canonical severity order
    return [f for f in RISK_FACTORS if f in found]


def _extract_guidance_sentence(advisory: TravelAdvisory) -> str | None:
    """Extract the State Department's core guidance sentence from the summary.

    Looks for "Do not travel to ... due to ...", "Reconsider travel to ... due to ...",
    or "Exercise increased caution in ... due to ..." patterns.
    """
    summary = advisory.summary or ""
    # Normalize whitespace (summaries contain \n, \xa0, \u202f between words)
    normalized = re.sub(r'[\s\xa0\u202f]+', ' ', summary)
    # Protect "U.S." from being treated as a sentence boundary
    normalized = normalized.replace('U.S.', 'U_S_')
    # Match the directive + "due to {reasons}" within a single sentence
    # (use [^.]+ to prevent crossing sentence boundaries)
    patterns = [
        r'(Do not travel to [^.]+? due to [^.]+\.)',
        r'(Reconsider travel to [^.]+? due to [^.]+\.)',
        r'(Exercise increased caution (?:in|when traveling to) [^.]+? due to [^.]+\.)',
    ]
    for pattern in patterns:
        match = re.search(pattern, normalized, re.IGNORECASE)
        if match:
            return match.group(1).replace('U_S_', 'U.S.').strip()
    return None


def _extract_country_context(advisory: TravelAdvisory) -> str | None:
    """Extract a substantive context sentence from the advisory summary.

    Tries the 'Country Summary:' section first, then falls back to the first
    sentence in the body that describes on-the-ground conditions.
    """
    summary = advisory.summary or ""
    normalized = re.sub(r'[\s\xa0\u202f]+', ' ', summary)
    # Protect abbreviations from period-splitting
    normalized = normalized.replace('U.S.', 'U_S_')

    # Try explicit "Country Summary:" header first
    match = re.search(r'Country Summary:\s*(.+?)\.', normalized)
    if match:
        sentence = match.group(1).replace('U_S_', 'U.S.').strip()
        # Strip any sub-heading prefix (e.g., "Terrorism: There is risk...")
        sub_heading = re.match(r'^[A-Z][\w\s]{2,20}:\s+', sentence)
        if sub_heading:
            sentence = sentence[sub_heading.end():]
        if len(sentence) > 20:
            return sentence + "."

    # Fall back: scan sentences for substantive situational context
    # Use word stems (leading \b only) so "terrorist", "kidnapping", etc. all match
    context_keywords = re.compile(
        r'\b(crime|violen|attack|terror|threat|secur|kidnap|unrest|conflict'
        r'|gang|cartel|extremis|militia|armed|instab)', re.IGNORECASE
    )
    # Protect common abbreviations from period-splitting
    protected = normalized.replace('U.S.', 'U_S_')
    # Split on period followed by space+uppercase (sentence boundary)
    sentences = re.split(r'\.\s+(?=[A-Z])', protected)
    for sent in sentences:
        sent = sent.replace('U_S_', 'U.S.').strip()
        # Must start with uppercase (not a fragment) and be a reasonable length
        if not sent or not sent[0].isupper():
            continue
        if len(sent) < 30 or len(sent) > 200:
            continue
        # Skip directives, boilerplate, pronouns, and vague sentences
        if re.match(r'(Do not travel|Reconsider travel|Exercise increased|Read the'
                     r'|Some areas|Updated|Visit |There was|If you|They |It |This |These |Those '
                     r'|Security forces|In some |We |You |The U_S_|Advisory summary)',
                     sent, re.IGNORECASE):
            continue
        # Skip sentences with embedded bullet points or vague area references
        if ' - ' in sent or 'these areas' in sent.lower():
            continue
        # Skip changelog boilerplate (e.g., 'The "unrest" risk indicator was added')
        if 'risk indicator' in sent.lower() or 'was added' in sent.lower():
            continue
        # Strip heading prefixes (e.g., "Terrorism: ...", "Armed conflict ...")
        # These are section headers followed by body text
        heading_match = re.match(r'^([A-Z][\w\s]{2,20}):\s+', sent)
        if heading_match:
            sent = sent[heading_match.end():]
            if not sent or len(sent) < 30:
                continue
        # Strip known heading phrases that appear without colons
        # (e.g., "Terrorism Violent extremist...", "Armed conflict Syria has...")
        heading_phrases = ['Terrorism ', 'Crime ', 'Armed conflict ',
                           'Civil unrest ', 'Kidnapping ', 'Health ',
                           'Piracy ', 'Violent crime ']
        for phrase in heading_phrases:
            if sent.startswith(phrase) and len(sent) > len(phrase) + 5:
                rest = sent[len(phrase):]
                if rest[0].isupper():
                    sent = rest
                    break
        if len(sent) < 30:
            continue
        if context_keywords.search(sent):
            return sent if sent.endswith('.') else sent + "."
    return None


def _format_list(items: list[str]) -> str:
    """Format a list of strings with commas and 'and'."""
    if len(items) == 1:
        return items[0]
    if len(items) == 2:
        return f"{items[0]} and {items[1]}"
    return ", ".join(items[:-1]) + f", and {items[-1]}"


def generate_country_summary(advisory: TravelAdvisory) -> str:
    """Generate a 3-5 sentence summary for a country advisory.

    Combines the advisory level, State Department guidance, regional details
    with named regions, risk factors, and country context into a readable
    paragraph. No AI API calls; purely algorithmic.
    """
    level_name = LEVEL_NAMES.get(advisory.overall_level, "Unknown")
    sentences = [
        f"{advisory.country_name} is rated Level {advisory.overall_level} "
        f"({level_name}) by the US State Department."
    ]

    # Guidance sentence extracted from State Dept summary
    guidance = _extract_guidance_sentence(advisory)
    if guidance:
        sentences.append(guidance)

    # Regional clause with named regions (only for countries below Level 4
    # and only when there are 2+ elevated regions — single-region cases are
    # already covered by the guidance sentence above)
    if advisory.overall_level < 4 and advisory.regional_warnings:
        dnt_regions = [w for w in advisory.regional_warnings if w.level == 4]
        rt_regions = [w for w in advisory.regional_warnings if w.level == 3]
        total_elevated = len(dnt_regions) + len(rt_regions)
        if total_elevated >= 2:
            if dnt_regions:
                names = [w.region_name for w in dnt_regions[:4]]
                text = f"There {'is' if len(dnt_regions) == 1 else 'are'} "
                text += f"{len(dnt_regions)} Do Not Travel region{'s' if len(dnt_regions) != 1 else ''}"
                text += f", including {_format_list(names)}"
                if len(dnt_regions) > 4:
                    text += f" and {len(dnt_regions) - 4} more"
                if rt_regions:
                    text += f", along with {len(rt_regions)} Reconsider Travel region{'s' if len(rt_regions) != 1 else ''}"
                text += "."
                sentences.append(text)
            elif rt_regions:
                names = [w.region_name for w in rt_regions[:4]]
                text = f"There {'is' if len(rt_regions) == 1 else 'are'} "
                text += f"{len(rt_regions)} Reconsider Travel region{'s' if len(rt_regions) != 1 else ''}"
                text += f", including {_format_list(names)}"
                if len(rt_regions) > 4:
                    text += f" and {len(rt_regions) - 4} more"
                text += "."
                sentences.append(text)

    # Risk factors clause (cap at 5 to keep the sentence readable)
    risk_factors = extract_risk_factors(advisory)
    if risk_factors:
        sentences.append(f"Key risk factors include {_format_list(risk_factors[:5])}.")

    # Country context from "Country Summary:" section
    context = _extract_country_context(advisory)
    if context and len(sentences) < 5:
        sentences.append(context)

    return " ".join(sentences)


class TravelAdvisoryPDF(FPDF):
    """Custom PDF class for travel advisory reports."""

    # Color scheme — brand palette
    PROHIBITED_COLOR = (80, 0, 80)        # Dark purple - prohibited countries
    UT_SUSPENDED_COLOR = (242, 101, 49)   # #F26531 Orange - UT suspended travel
    RESTRICTED_SPECIAL_COLOR = (99, 100, 102)  # #636466 Gray - restricted/elevated approval
    LEVEL_4_COLOR = (180, 30, 30)         # Dark red
    LEVEL_3_COLOR = (200, 120, 0)         # Orange
    LEVEL_2_COLOR = (180, 150, 0)         # Yellow-orange
    LEVEL_1_COLOR = (60, 140, 60)         # Green

    NAVY = (30, 60, 100)
    DARK_GRAY = (40, 40, 40)
    MEDIUM_GRAY = (100, 100, 100)
    LIGHT_GRAY = (220, 220, 220)

    # CDC notice colors — intentionally quieter than level colors (informational)
    CDC_LEVEL_3_COLOR = (0, 100, 120)    # Deep teal — Level 3/4 CDC notices
    CDC_GLOBAL_COLOR = (80, 80, 100)     # Muted slate — global outbreak section

    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=20)

    def _clean_text(self, text: str) -> str:
        """Handle unicode by replacing problematic characters for PDF."""
        # Replace common unicode characters with ASCII equivalents
        replacements = {
            '\u2018': "'", '\u2019': "'",  # Smart quotes
            '\u201c': '"', '\u201d': '"',
            '\u2013': '-', '\u2014': '-',  # Dashes
            '\u2026': '...',  # Ellipsis
            '\u00a0': ' ',    # Non-breaking space
        }
        for old, new in replacements.items():
            text = text.replace(old, new)
        return text.encode('latin-1', 'replace').decode('latin-1')

    def get_level_color(self, level: int) -> tuple:
        """Get the color associated with an advisory level."""
        colors = {
            4: self.LEVEL_4_COLOR,
            3: self.LEVEL_3_COLOR,
            2: self.LEVEL_2_COLOR,
            1: self.LEVEL_1_COLOR,
        }
        return colors.get(level, self.DARK_GRAY)

    def header(self):
        if self.page_no() > 1:
            self.set_font('Helvetica', 'B', 10)
            self.set_text_color(*self.MEDIUM_GRAY)
            self.cell(0, 8, self._clean_text('Travel Advisory Report \u2014 High Risk Destinations & Compliance Guidelines'), align='C')
            self.ln(8)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 10)
        self.set_text_color(*self.MEDIUM_GRAY)
        self.cell(0, 10, f'Page {self.page_no()}', align='C')

    def add_title_page(self, stats: dict):
        """Create the report title page with summary statistics."""
        self.add_page()

        # --- Title block ---
        # Top NAVY rule
        self.set_draw_color(*self.NAVY)
        self.set_line_width(0.8)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(6)

        # Report title
        self.set_x(self.l_margin)
        self.set_font('Helvetica', 'B', 22)
        self.set_text_color(*self.NAVY)
        self.cell(self.epw, 10, 'TRAVEL ADVISORY REPORT', align='C')
        self.ln(10 + 3)

        # Subtitle
        self.set_x(self.l_margin)
        self.set_font('Helvetica', '', 12)
        self.set_text_color(*self.MEDIUM_GRAY)
        self.cell(self.epw, 6, 'High-Risk Destinations Subject to ITOC Review', align='C')
        self.ln(6 + 3)

        # Generated date
        self.set_x(self.l_margin)
        self.set_font('Helvetica', 'I', 9)
        self.set_text_color(*self.MEDIUM_GRAY)
        self.cell(self.epw, 5, f'Generated: {datetime.now().strftime("%B %d, %Y at %H:%M")}', align='C')
        self.ln(5 + 6)

        # Bottom NAVY rule
        self.set_draw_color(*self.NAVY)
        self.set_line_width(0.8)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(10)

        # --- PURPOSE section ---
        self.set_x(self.l_margin)
        self.set_font('Helvetica', 'B', 14)
        self.set_text_color(*self.NAVY)
        self.cell(self.epw, 5, 'PURPOSE', align='C')
        self.ln(5 + 3)

        intro_margin = 20
        intro_w = self.w - 2 * intro_margin
        intro = (
            'This report identifies international destinations requiring Institutional Travel '
            'Oversight Committee (ITOC) review under UT System travel policy and Texas Executive '
            'Order GA-48. Destinations are categorized by risk level based on US State Department '
            'travel advisories, UT System travel suspensions, and federal foreign adversary '
            'designations. All travel to listed destinations, including layovers and connections, '
            'must follow the approval requirements outlined herein.'
        )
        self.set_x(intro_margin)
        self.set_font('Helvetica', '', 10)
        self.set_text_color(*self.DARK_GRAY)
        self.multi_cell(intro_w, 6, self._clean_text(intro), align='J',
                        new_x='LMARGIN', new_y='NEXT')
        self.ln(10)

        # --- SUMMARY section ---
        self.set_x(self.l_margin)
        self.set_font('Helvetica', 'B', 14)
        self.set_text_color(*self.NAVY)
        self.cell(self.epw, 5, 'SUMMARY', align='C')
        self.ln(5)
        self.set_draw_color(*self.LIGHT_GRAY)
        self.set_line_width(0.3)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(4)

        # --- Category list (20mm side margins) ---
        cat_left = 20           # mm left margin
        cat_right = 20          # mm right margin
        cat_w = self.w - cat_left - cat_right
        sq_size = 3             # mm color legend square
        sq_gap = 2              # mm gap after square
        sq_offset = sq_size + sq_gap
        name_h = 6              # line height for category name row
        desc_h = 4.5            # line height for description row
        cat_gap = 3             # mm between categories

        # (cat_name, count, description, color)
        categories = [
            ('PROHIBITED (EO GA-48)', stats.get('prohibited', 0),
             'Designated foreign adversaries per 15 CFR 791.4; work-related travel not '
             'authorized for state employees under Texas Executive Order GA-48.',
             self.PROHIBITED_COLOR),
            ('UT SUSPENDED', stats.get('ut_suspended', 0),
             'Active UT System travel suspension; requires ITOC and University President '
             'approval. Restrictions apply to layovers and connections through these '
             'countries, not just final destinations.',
             self.UT_SUSPENDED_COLOR),
            ('RESTRICTED \u2014 ELEVATED APPROVAL', stats.get('restricted', 0),
             'Requires ITOC and University President approval prior to booking. '
             'Restrictions apply to layovers and connections through these countries, '
             'not just final destinations.',
             self.RESTRICTED_SPECIAL_COLOR),
            ('LEVEL 4 \u2014 DO NOT TRAVEL', stats.get('level_4', 0),
             'US State Department advises against all travel; designated Area of High '
             'Risk requiring ITOC review.',
             self.LEVEL_4_COLOR),
            ('LEVEL 3 \u2014 RECONSIDER TRAVEL', stats.get('level_3', 0),
             'US State Department advises reconsidering travel; designated Area of High '
             'Risk requiring ITOC review.',
             self.LEVEL_3_COLOR),
            ('REGIONAL WARNINGS', stats.get('regional', 0),
             'Countries rated Level 1 or 2 overall but containing specific regions '
             'designated Level 3 or 4. Travelers should consult the Detailed Advisories '
             'section to verify their itinerary does not include activities in '
             'elevated-risk regions.',
             self.LEVEL_2_COLOR),
            ('TOTAL UNIQUE ENTRIES', stats.get('total', 0), None, self.NAVY),
        ]

        for i, (cat_name, count, description, color) in enumerate(categories):
            if i > 0:
                self.ln(cat_gap)

            # Color legend square
            sq_y = self.get_y() + (name_h - sq_size) / 2
            self.set_fill_color(*color)
            self.rect(cat_left, sq_y, sq_size, sq_size, style='F')

            # Category name (bold 11pt DARK_GRAY, left) + count (bold 11pt NAVY, right)
            self.set_x(cat_left + sq_offset)
            self.set_font('Helvetica', 'B', 11)
            self.set_text_color(*self.DARK_GRAY)
            self.cell(cat_w - 15 - sq_offset, name_h, self._clean_text(cat_name), align='L')
            self.set_text_color(*self.NAVY)
            self.cell(15, name_h, str(count), align='R')
            self.ln(name_h)

            # Description (italic 9pt MEDIUM_GRAY, indented past square)
            if description:
                self.set_x(cat_left + sq_offset)
                self.set_font('Helvetica', 'I', 9)
                self.set_text_color(*self.MEDIUM_GRAY)
                self.multi_cell(cat_w - sq_offset, desc_h,
                                self._clean_text(description), align='L',
                                new_x='LMARGIN', new_y='NEXT')

            # Subtle rule between categories (not after last)
            if description is not None:  # skip rule after TOTAL UNIQUE ENTRIES
                self.ln(1)
                self.set_draw_color(*self.LIGHT_GRAY)
                self.set_line_width(0.1)
                self.line(cat_left, self.get_y(), self.w - cat_right, self.get_y())

        # --- CDC informational stat lines (secondary, MEDIUM_GRAY) ---
        cdc_global = stats.get('cdc_global_outbreaks', 0)
        cdc_only_count = stats.get('cdc_only', 0)
        if cdc_global > 0 or cdc_only_count > 0:
            self.ln(cat_gap + 2)
            self.set_font('Helvetica', 'I', 9)
            self.set_text_color(*self.MEDIUM_GRAY)
            if cdc_global > 0:
                self.set_x(cat_left + sq_offset)
                self.cell(cat_w - sq_offset, desc_h,
                          self._clean_text(
                              f'Global Health Alerts (Informational): '
                              f'{cdc_global} active CDC notices'),
                          align='L')
                self.ln(desc_h)
            if cdc_only_count > 0:
                self.set_x(cat_left + sq_offset)
                self.cell(cat_w - sq_offset, desc_h,
                          self._clean_text(
                              f'CDC-Only Health Notices (Level 3/4): '
                              f'{cdc_only_count} countries'),
                          align='L')
                self.ln(desc_h)

    def add_worldwide_caution_page(self, caution: TravelAdvisory) -> None:
        """Render the worldwide caution advisory on a dedicated page.

        Appears as page 2, immediately before the quick reference table.
        Uses a prominent LEVEL_2_COLOR header band so it is immediately visible.
        """
        self.add_page()

        # Full-width header band
        band_h = 16
        self.set_fill_color(*self.LEVEL_2_COLOR)
        self.rect(0, self.t_margin, self.w, band_h, style='F')
        self.set_xy(0, self.t_margin)
        self.set_font('Helvetica', 'B', 14)
        self.set_text_color(255, 255, 255)
        self.cell(self.w, band_h, 'WORLDWIDE CAUTION - US State Department', align='C')
        self.ln(band_h + 5)

        # Level and date
        level_name = LEVEL_NAMES.get(caution.overall_level, '')
        level_str = f'Level {caution.overall_level}: {level_name}' if level_name else f'Level {caution.overall_level}'
        date_str = caution.last_updated.strftime('%B %d, %Y')
        self.set_x(self.l_margin)
        self.set_font('Helvetica', 'B', 10)
        self.set_text_color(*self.DARK_GRAY)
        self.cell(self.epw * 0.5, 6, level_str, align='L')
        self.set_font('Helvetica', 'I', 10)
        self.set_text_color(*self.MEDIUM_GRAY)
        self.cell(self.epw * 0.5, 6, f'Updated: {date_str}', align='R')
        self.ln(10)

        # Thin rule
        self.set_draw_color(*self.LIGHT_GRAY)
        self.set_line_width(0.3)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(6)

        # Summary body
        self.set_x(self.l_margin)
        self.set_font('Helvetica', '', 10)
        self.set_text_color(*self.DARK_GRAY)
        self.multi_cell(self.epw, 6, self._clean_text(caution.summary), align='J',
                        new_x='LMARGIN', new_y='NEXT')

    def add_global_awareness_page(
        self,
        worldwide_caution: 'TravelAdvisory | None',
        global_outbreaks: list[CDCGlobalOutbreak],
    ) -> None:
        """Render worldwide caution and CDC global alerts on one combined page.

        Only called when at least one of the two sources has data.
        Worldwide caution renders first (if present), followed by CDC global
        outbreak table (if any).  If only one source has data the other is
        simply omitted — no empty section appears.
        """
        self.add_page()

        # --- Worldwide Caution block ---
        if worldwide_caution is not None:
            # Full-width header band
            band_h = 16
            self.set_fill_color(*self.LEVEL_2_COLOR)
            self.rect(0, self.t_margin, self.w, band_h, style='F')
            self.set_xy(0, self.t_margin)
            self.set_font('Helvetica', 'B', 14)
            self.set_text_color(255, 255, 255)
            self.cell(self.w, band_h, 'WORLDWIDE CAUTION - US State Department', align='C')
            self.ln(band_h + 5)

            # Level and date
            level_name = LEVEL_NAMES.get(worldwide_caution.overall_level, '')
            level_str = (f'Level {worldwide_caution.overall_level}: {level_name}'
                         if level_name else f'Level {worldwide_caution.overall_level}')
            date_str = worldwide_caution.last_updated.strftime('%B %d, %Y')
            self.set_x(self.l_margin)
            self.set_font('Helvetica', 'B', 10)
            self.set_text_color(*self.DARK_GRAY)
            self.cell(self.epw * 0.5, 6, level_str, align='L')
            self.set_font('Helvetica', 'I', 10)
            self.set_text_color(*self.MEDIUM_GRAY)
            self.cell(self.epw * 0.5, 6, f'Updated: {date_str}', align='R')
            self.ln(10)

            # Thin rule
            self.set_draw_color(*self.LIGHT_GRAY)
            self.set_line_width(0.3)
            self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
            self.ln(6)

            # Summary body
            self.set_x(self.l_margin)
            self.set_font('Helvetica', '', 10)
            self.set_text_color(*self.DARK_GRAY)
            self.multi_cell(self.epw, 6, self._clean_text(worldwide_caution.summary),
                            align='J', new_x='LMARGIN', new_y='NEXT')
            self.ln(8)

        # --- CDC Global Health Alerts block ---
        if global_outbreaks:
            # If worldwide caution already rendered above, add a separator;
            # otherwise this is the first content on the page.
            if worldwide_caution is not None:
                self.set_draw_color(*self.LIGHT_GRAY)
                self.set_line_width(0.3)
                self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
                self.ln(6)

            # Render CDC global outbreak content inline (no new page)
            self._render_global_outbreaks(global_outbreaks)

    def add_prohibited_section(self, prohibited_advisories: list[TravelAdvisory]):
        """Add the prohibited countries section (Texas EO GA-48)."""
        self.add_page()

        # Section header
        self.set_fill_color(*self.PROHIBITED_COLOR)
        self.set_text_color(255, 255, 255)
        self.set_font('Helvetica', 'B', 16)
        self.multi_cell(0, 12, '  PROHIBITED - Travel Not Authorized', fill=True,
                        new_x='LMARGIN', new_y='NEXT')
        self.ln(3)

        # Legal reference
        self.set_text_color(*self.DARK_GRAY)
        self.set_font('Helvetica', 'B', 11)
        self.cell(0, 6, 'Texas Executive Order GA-48 - Foreign Adversaries')
        self.ln(6)

        self.set_font('Helvetica', '', 11)
        self.set_x(10)
        legal_text = (
            "Per 15 CFR 791.4, the US Department of Commerce has designated the following "
            "countries as foreign adversaries. Texas Executive Order GA-48 (November 19, 2024) "
            "prohibits state employees from work-related travel to these countries."
        )
        self.multi_cell(0, 5, self._clean_text(legal_text))
        self.ln(8)

        # List each prohibited country
        for name, info in PROHIBITED_COUNTRIES.items():
            # Find matching advisory if exists (substring match for compound entries)
            matching = next(
                (a for a in prohibited_advisories if name.lower() in a.country_name.lower()),
                None
            )

            # Country header
            self.set_fill_color(*self.PROHIBITED_COLOR)
            self.set_text_color(255, 255, 255)
            self.set_font('Helvetica', 'B', 11)
            header = f"  {name}"
            if info['includes']:
                header += f" (including {', '.join(info['includes'])})"
            self.multi_cell(0, 8, self._clean_text(header), fill=True,
                            new_x='LMARGIN', new_y='NEXT')

            # Official name and advisory level
            self.set_text_color(*self.DARK_GRAY)
            self.set_font('Helvetica', 'I', 11)
            self.multi_cell(0, 5, f"Official: {info['official_name']}",
                            new_x='LMARGIN', new_y='NEXT')

            if matching:
                self.set_font('Helvetica', '', 11)
                level_text = f"State Dept Advisory: Level {matching.overall_level} - {LEVEL_NAMES.get(matching.overall_level, '')}"
                self.set_text_color(*self.get_level_color(matching.overall_level))
                self.multi_cell(0, 5, level_text,
                                new_x='LMARGIN', new_y='NEXT')

                self.set_text_color(*self.MEDIUM_GRAY)
                self.set_font('Helvetica', '', 10)
                self.multi_cell(0, 5, f"Last Updated: {matching.last_updated.strftime('%B %d, %Y')}",
                                new_x='LMARGIN', new_y='NEXT')
                self.ln(2)
            else:
                self.ln(4)

        # Reference links
        self.ln(5)
        self.set_draw_color(*self.LIGHT_GRAY)
        self.line(10, self.get_y(), self.epw + 10, self.get_y())
        self.ln(5)

        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(*self.MEDIUM_GRAY)
        self.set_x(10)
        self.multi_cell(0, 4, self._clean_text(
            "References:\n"
            "- Texas EO GA-48: gov.texas.gov/uploads/files/press/EO-GA-48_Hardening_State_Government_FINAL_11-19-2024.pdf\n"
            "- 15 CFR 791.4: ecfr.gov/current/title-15/subtitle-B/chapter-VII/subchapter-E/part-791/subpart-A/section-791.4"
        ), align='L')

    def add_advisory_entry(self, advisory: TravelAdvisory):
        """Add a single country advisory entry to the report."""
        # Check if we need a new page (need at least ~70mm for an entry)
        if self.get_y() > 220:
            self.add_page()

        # Country header bar
        level_color = self.get_level_color(advisory.overall_level)
        self.set_fill_color(*level_color)
        self.set_text_color(255, 255, 255)
        self.set_font('Helvetica', 'B', 14)

        # Header with country name and level
        header_text = f"  {advisory.country_name} - Level {advisory.overall_level}"
        self.multi_cell(0, 10, self._clean_text(header_text), fill=True,
                        new_x='LMARGIN', new_y='NEXT')

        # Advisory level description
        self.set_text_color(*self.DARK_GRAY)
        self.set_font('Helvetica', 'I', 11)
        level_desc = LEVEL_NAMES.get(advisory.overall_level, "")
        self.multi_cell(0, 6, level_desc,
                        new_x='LMARGIN', new_y='NEXT')
        self.ln(1)

        # Last updated
        self.set_font('Helvetica', '', 10)
        self.set_text_color(*self.MEDIUM_GRAY)
        self.multi_cell(0, 5, f'Last Updated: {advisory.last_updated.strftime("%B %d, %Y")}',
                        new_x='LMARGIN', new_y='NEXT')
        self.ln(2)

        # Regional warnings - show all Level 3 (Reconsider Travel) and Level 4 (Do Not Travel) regions
        if advisory.regional_warnings:
            high_risk_regions = [w for w in advisory.regional_warnings if w.level >= 3]
            if high_risk_regions:
                # Sort by level descending so Level 4 appears first
                high_risk_regions.sort(key=lambda w: w.level, reverse=True)

                # Do Not Travel regions
                level_4_regions = [w for w in high_risk_regions if w.level == 4]
                if level_4_regions:
                    self.set_font('Helvetica', 'B', 11)
                    self.set_text_color(*self.LEVEL_4_COLOR)
                    self.cell(0, 6, 'Do Not Travel Regions:')
                    self.ln(6)

                    self.set_font('Helvetica', '', 11)
                    for warning in level_4_regions:
                        self.set_x(15)
                        self.set_text_color(*self.LEVEL_4_COLOR)
                        region_text = f'- {warning.region_name}'
                        if warning.reasons:
                            region_text += f' (due to {warning.reasons})'
                        self.multi_cell(0, 5, self._clean_text(region_text),
                                        new_x='LMARGIN', new_y='NEXT')
                    self.ln(2)

                # Reconsider Travel regions
                level_3_regions = [w for w in high_risk_regions if w.level == 3]
                if level_3_regions:
                    self.set_font('Helvetica', 'B', 11)
                    self.set_text_color(*self.LEVEL_3_COLOR)
                    self.cell(0, 6, 'Reconsider Travel Regions:')
                    self.ln(6)

                    self.set_font('Helvetica', '', 11)
                    for warning in level_3_regions:
                        self.set_x(15)
                        self.set_text_color(*self.LEVEL_3_COLOR)
                        region_text = f'- {warning.region_name}'
                        if warning.reasons:
                            region_text += f' (due to {warning.reasons})'
                        self.multi_cell(0, 5, self._clean_text(region_text),
                                        new_x='LMARGIN', new_y='NEXT')
                    self.ln(2)

        # CDC health notice callout (if any notices are attached)
        if advisory.cdc_notices:
            self.set_font('Helvetica', 'B', 10)
            self.set_text_color(*self.CDC_LEVEL_3_COLOR)
            self.cell(0, 6, 'CDC Health Notice:')
            self.ln(6)
            self.set_font('Helvetica', '', 10)
            for cdc_n in advisory.cdc_notices:
                self.set_x(15)
                self.set_text_color(*self.CDC_LEVEL_3_COLOR)
                notice_line = (f"Level {cdc_n.level} ({cdc_n.level_name}) "
                               f"- {cdc_n.disease}")
                self.multi_cell(0, 5, self._clean_text(notice_line),
                                new_x='LMARGIN', new_y='NEXT')
                self.set_x(20)
                self.set_font('Helvetica', 'I', 9)
                self.set_text_color(*self.MEDIUM_GRAY)
                self.multi_cell(0, 4, self._clean_text(cdc_n.link),
                                new_x='LMARGIN', new_y='NEXT')
                self.set_font('Helvetica', '', 10)
            self.ln(2)

        # Country summary paragraph
        summary_text = generate_country_summary(advisory)
        self.set_font('Helvetica', '', 10)
        self.set_text_color(*self.DARK_GRAY)
        self.multi_cell(0, 5, self._clean_text(summary_text),
                        new_x='LMARGIN', new_y='NEXT')
        self.ln(2)

        # Link to full advisory
        if advisory.link:
            self.set_font('Helvetica', 'I', 10)
            self.set_text_color(0, 76, 151)  # #004c97 Deep Blue
            self.set_x(10)
            self.multi_cell(0, 5, f'Full Advisory: {advisory.link}', align='L',
                            new_x='LMARGIN', new_y='NEXT')

        # Divider
        self.ln(5)
        self.set_draw_color(*self.LIGHT_GRAY)
        self.set_line_width(0.3)
        self.line(10, self.get_y(), self.epw + 10, self.get_y())
        self.ln(8)

    # Column widths for the quick-reference table (total = 190mm effective)
    _TABLE_COL_W = (50, 68, 72)

    def _summary_table_header(self):
        """Render the column header row for the quick-reference table."""
        col_w = self._TABLE_COL_W
        self.set_font('Helvetica', 'B', 10)
        self.set_fill_color(*self.NAVY)
        self.set_draw_color(*self.NAVY)
        self.set_text_color(255, 255, 255)
        x0 = self.get_x()
        for label, w in zip(('Country', 'Level', 'Notes'), col_w):
            self.cell(w, 8, f'  {label}', border=1, fill=True)
        self.ln(8)
        self.set_x(x0)

    def add_summary_section(
        self,
        prohibited: list[TravelAdvisory],
        ut_suspended: list[TravelAdvisory],
        restricted_special: list[TravelAdvisory],
        advisories: list[TravelAdvisory],
    ):
        """Add a unified quick-reference table of all countries in the report.

        Order: Prohibited → UT Suspended → Restricted/Special Approval →
        Level 4 → Level 3 → Level 2/1 with regional warnings.
        Each group is sorted alphabetically within the group.
        """
        self.add_page()

        # Section title
        self.set_font('Helvetica', 'B', 16)
        self.set_text_color(*self.NAVY)
        self.cell(0, 10, 'Quick Reference - Countries by Risk Level', align='C')
        self.ln(12)

        # Build sorted row list: (advisory, label, color, notes)
        rows: list[tuple[TravelAdvisory, str, tuple, str]] = []

        # Prohibited countries — iterate canonical dict so includes are shown
        for key, info in sorted(PROHIBITED_COUNTRIES.items()):
            matched = next(
                (a for a in prohibited
                 if key.lower() in a.country_name.lower()
                 or (info.get('code') and info['code'].upper() == a.country_code.upper())),
                None,
            )
            if matched is None:
                continue
            display_name = key
            if info.get('includes'):
                display_name += f" (incl. {', '.join(info['includes'])})"
            stub = TravelAdvisory(
                country_name=display_name,
                country_code=info.get('code', matched.country_code),
                overall_level=matched.overall_level,
                summary='',
                last_updated=matched.last_updated,
                link=matched.link,
            )
            rows.append((stub, 'PROHIBITED', self.PROHIBITED_COLOR, 'EO GA-48'))

        # UT Suspended countries — iterate the policy dict so all entries always appear,
        # regardless of whether the State Dept API returned a matching advisory.
        # Skip entries already covered by the prohibited bucket (waterfall).
        for name, info in sorted(UT_SUSPENDED_TRAVEL.items()):
            if is_prohibited_country(name):
                continue
            display_name = name
            if info.get('includes'):
                display_name += f" (incl. {', '.join(info['includes'])})"
            matched = next(
                (a for a in ut_suspended
                 if name.lower() in a.country_name.lower()
                 or (info.get('code') and info['code'].upper() == a.country_code.upper())),
                None,
            )
            stub = TravelAdvisory(
                country_name=display_name,
                country_code=info.get('code', matched.country_code if matched else ''),
                overall_level=matched.overall_level if matched else 0,
                summary='',
                last_updated=matched.last_updated if matched else datetime.now(),
                link=matched.link if matched else '',
            )
            rows.append((stub, 'UT SUSPENDED', self.UT_SUSPENDED_COLOR, 'ITOC + President req. (incl. layovers)'))

        # Restricted / elevated approval — same pattern as UT Suspended above.
        for name, info in sorted(RESTRICTED_TRAVEL_REQUIRING_SPECIAL_APPROVAL.items()):
            display_name = name
            if info.get('includes'):
                display_name += f" (incl. {', '.join(info['includes'])})"
            matched = next(
                (a for a in restricted_special if name.lower() in a.country_name.lower()), None
            )
            stub = TravelAdvisory(
                country_name=display_name,
                country_code=info.get('code', matched.country_code if matched else ''),
                overall_level=matched.overall_level if matched else 0,
                summary='',
                last_updated=matched.last_updated if matched else datetime.now(),
                link=matched.link if matched else '',
            )
            rows.append((stub, 'RESTRICTED', self.RESTRICTED_SPECIAL_COLOR, 'ITOC + President req. (incl. layovers)'))

        # Level 4 countries
        l4 = sorted(
            [a for a in advisories if a.overall_level == 4],
            key=lambda a: a.country_name,
        )
        for adv in l4:
            rows.append((adv, '4 - Do Not Travel', self.LEVEL_4_COLOR, 'ITOC exemption req.'))

        # Level 3 countries
        l3 = sorted(
            [a for a in advisories if a.overall_level == 3],
            key=lambda a: a.country_name,
        )
        for adv in l3:
            rows.append((adv, '3 - Reconsider Travel', self.LEVEL_3_COLOR, 'ITOC exemption req.'))

        # Level 2 with regional warnings
        l2_regional = sorted(
            [a for a in advisories if a.overall_level == 2 and a.has_regional_elevation],
            key=lambda a: a.country_name,
        )
        for adv in l2_regional:
            notes = self._regional_notes(adv)
            rows.append((adv, '2 - Increased Caution', self.LEVEL_2_COLOR, notes))

        # Level 1 with regional warnings
        l1_regional = sorted(
            [a for a in advisories if a.overall_level == 1 and a.has_regional_elevation],
            key=lambda a: a.country_name,
        )
        for adv in l1_regional:
            notes = self._regional_notes(adv)
            rows.append((adv, '1 - Normal Precautions', self.LEVEL_1_COLOR, notes))

        col_w = self._TABLE_COL_W
        row_h = 7

        # Preamble above table (compact italic notes + abbreviation key)
        preamble_x = self.l_margin
        preamble_w = self.epw
        self.set_draw_color(*self.LIGHT_GRAY)
        self.set_line_width(0.3)
        self.line(preamble_x, self.get_y(), preamble_x + preamble_w, self.get_y())
        self.ln(2)
        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(*self.MEDIUM_GRAY)
        self.set_x(preamble_x)
        self.multi_cell(preamble_w, 3.5, self._clean_text(
            'Note: Prohibited, UT Suspended, and Restricted designations apply to travel '
            'through these countries as a layover or connection point, regardless of '
            'ultimate destination.'
        ), align='L', new_x='LMARGIN', new_y='NEXT')
        self.ln(1)
        self.set_x(preamble_x)
        self.multi_cell(preamble_w, 3.5, self._clean_text(
            'EO GA-48 = Texas Executive Order GA-48 (foreign adversaries)  |  '
            'DNT = Do Not Travel (Level 4 regions)  |  '
            'RT = Reconsider Travel (Level 3 regions)'
        ), align='L', new_x='LMARGIN', new_y='NEXT')
        self.ln(2)
        self.line(preamble_x, self.get_y(), preamble_x + preamble_w, self.get_y())
        self.ln(3)

        # Draw table header
        self._summary_table_header()

        # Draw rows
        for idx, (adv, label, color, notes) in enumerate(rows):
            # Page break check
            if self.get_y() + row_h > self.h - self.b_margin - 2:
                self.add_page()
                self.set_font('Helvetica', 'B', 14)
                self.set_text_color(*self.NAVY)
                self.cell(0, 10, 'Quick Reference (continued)', align='C')
                self.ln(10)
                self._summary_table_header()

            # Alternating row background
            if idx % 2 == 1:
                self.set_fill_color(*self.LIGHT_GRAY)
                fill = True
            else:
                fill = False

            x0 = self.get_x()
            y0 = self.get_y()
            self.set_draw_color(*self.LIGHT_GRAY)

            # Country name — strip API suffixes like " - See Summaries"
            display_name = re.sub(r'\s*-\s*See\s+Summaries?\s*$', '', adv.country_name)
            name_text = f'  {self._clean_text(display_name)}'

            # Measure how many lines the country name needs (dry run)
            self.set_font('Helvetica', '', 10)
            lines = self.multi_cell(col_w[0], row_h, name_text,
                                    dry_run=True, output='LINES')
            n_lines = max(len(lines), 1)
            text_h = n_lines * row_h
            # For multi-line rows, actual_h = (2*n_lines-1)*row_h adds equal
            # top/bottom padding of (n_lines-1)*row_h/2.  This places line 1's
            # text at y0 + actual_h/2, matching the vertical center that
            # cell() uses for the Level and Notes columns.
            actual_h = (2 * n_lines - 1) * row_h if n_lines > 1 else row_h
            v_pad = (actual_h - text_h) / 2  # 0 for single-line rows

            # Draw country cell fill and side borders spanning the full
            # actual_h, then render text inset by v_pad to center it.
            if fill:
                self.set_fill_color(*self.LIGHT_GRAY)
                self.rect(x0, y0, col_w[0], actual_h, style='F')
            self.line(x0, y0, x0, y0 + actual_h)
            self.line(x0 + col_w[0], y0, x0 + col_w[0], y0 + actual_h)
            self.set_xy(x0, y0 + v_pad)
            self.set_text_color(*self.DARK_GRAY)
            self.multi_cell(col_w[0], row_h, name_text, align='L',
                            border=0, fill=False, new_x='RIGHT', new_y='TOP')
            self.set_xy(x0 + col_w[0], y0)

            # Level label (color-coded) — height matches country cell
            self.set_font('Helvetica', 'B', 9)
            self.set_text_color(*color)
            self.cell(col_w[1], actual_h, f'  {label}', border='LR', fill=fill)

            # Notes
            self.set_font('Helvetica', '', 9)
            self.set_text_color(*self.DARK_GRAY)
            self.cell(col_w[2], actual_h, f'  {self._clean_text(notes)}',
                      border='LR', fill=fill)

            # Bottom border across all columns
            self.set_xy(x0, y0 + actual_h)
            self.line(x0, y0 + actual_h, x0 + sum(col_w), y0 + actual_h)


    @staticmethod
    def _regional_notes(adv: TravelAdvisory) -> str:
        """Build a short notes string describing regional warning counts."""
        dnt = sum(1 for w in adv.regional_warnings if w.level == 4)
        rt = sum(1 for w in adv.regional_warnings if w.level == 3)
        parts = []
        if dnt:
            parts.append(f'{dnt} DNT region{"s" if dnt != 1 else ""}')
        if rt:
            parts.append(f'{rt} RT region{"s" if rt != 1 else ""}')
        return ', '.join(parts)

    def add_global_outbreak_section(self, outbreaks: list[CDCGlobalOutbreak]):
        """Add the CDC Global Health Alerts as a standalone page.

        Only called when len(outbreaks) > 0.
        """
        self.add_page()
        self._render_global_outbreaks(outbreaks)

    def _render_global_outbreaks(self, outbreaks: list[CDCGlobalOutbreak]):
        """Render the CDC Global Health Alerts content at the current position.

        Does not start a new page — caller is responsible for page management.
        Used by both add_global_outbreak_section() (standalone) and
        add_global_awareness_page() (combined with worldwide caution).
        """
        # Section header bar
        band_h = 12
        self.set_fill_color(*self.CDC_GLOBAL_COLOR)
        self.set_text_color(255, 255, 255)
        self.set_font('Helvetica', 'B', 13)
        self.multi_cell(0, band_h,
                        '  Global Health Alerts - For Informational Purposes Only',
                        fill=True, new_x='LMARGIN', new_y='NEXT')
        self.ln(3)

        # Preamble
        self.set_font('Helvetica', 'I', 9)
        self.set_text_color(*self.MEDIUM_GRAY)
        preamble = (
            'The notices below are issued by the CDC and indicate disease activity '
            'affecting multiple regions worldwide. These are NOT high-risk travel '
            'designations - they do not constitute a travel restriction and are '
            'provided for traveler awareness only.'
        )
        self.multi_cell(0, 4.5, self._clean_text(preamble),
                        new_x='LMARGIN', new_y='NEXT')
        self.ln(4)

        # Sort by level descending, then alphabetically by disease
        sorted_outbreaks = sorted(outbreaks, key=lambda o: (-o.level, o.disease))

        # Table header (no Link column — full URLs listed below the table)
        col_w = (50, 25, 90, 25)  # Disease, Level, Scope, Updated
        self.set_font('Helvetica', 'B', 9)
        self.set_fill_color(*self.CDC_GLOBAL_COLOR)
        self.set_draw_color(*self.CDC_GLOBAL_COLOR)
        self.set_text_color(255, 255, 255)
        for label, w in zip(('Disease', 'CDC Level', 'Scope', 'Updated'), col_w):
            self.cell(w, 7, f'  {label}', border=1, fill=True)
        self.ln(7)

        # Table rows
        row_h = 6
        for idx, ob in enumerate(sorted_outbreaks):
            # Page break check
            if self.get_y() + row_h > self.h - self.b_margin - 2:
                self.add_page()
                self.set_font('Helvetica', 'B', 9)
                self.set_fill_color(*self.CDC_GLOBAL_COLOR)
                self.set_draw_color(*self.CDC_GLOBAL_COLOR)
                self.set_text_color(255, 255, 255)
                for label, w in zip(('Disease', 'CDC Level', 'Scope', 'Updated'), col_w):
                    self.cell(w, 7, f'  {label}', border=1, fill=True)
                self.ln(7)

            fill = idx % 2 == 1
            if fill:
                self.set_fill_color(*self.LIGHT_GRAY)

            self.set_draw_color(*self.LIGHT_GRAY)
            self.set_font('Helvetica', '', 9)
            self.set_text_color(*self.DARK_GRAY)
            self.cell(col_w[0], row_h, f'  {self._clean_text(ob.disease)}',
                      border='LR', fill=fill)
            self.cell(col_w[1], row_h, f'  {ob.level}',
                      border='LR', fill=fill)

            scope = ob.affected_summary[:45] if len(ob.affected_summary) > 45 else ob.affected_summary
            self.cell(col_w[2], row_h, f'  {self._clean_text(scope)}',
                      border='LR', fill=fill)

            date_str = ob.last_updated.strftime('%Y-%m-%d')
            self.cell(col_w[3], row_h, f'  {date_str}',
                      border='LR', fill=fill)
            self.ln(row_h)

        # Full URLs below table — each on its own line for print readability
        self.ln(4)
        self.set_font('Helvetica', 'B', 10)
        self.set_text_color(0, 0, 0)
        self.cell(0, 5, 'CDC Notice Links:')
        self.ln(6)
        for ob in sorted_outbreaks:
            self.set_font('Helvetica', '', 10)
            self.set_text_color(0, 0, 0)
            self.set_x(15)
            self.multi_cell(0, 5,
                            self._clean_text(f"{ob.disease}: {ob.link}"),
                            new_x='LMARGIN', new_y='NEXT')

    def add_cdc_only_section(self, cdc_only: list[TravelAdvisory]):
        """Add section for countries appearing solely due to a CDC Level 3/4 notice.

        Only called when len(cdc_only) > 0.
        Placed after all State Dept detailed advisory entries.
        """
        self.add_page()

        # Section header
        band_h = 12
        self.set_fill_color(*self.CDC_LEVEL_3_COLOR)
        self.set_text_color(255, 255, 255)
        self.set_font('Helvetica', 'B', 13)
        self.multi_cell(0, band_h,
                        '  CDC-Only Health Notices - No State Dept Advisory Issued',
                        fill=True, new_x='LMARGIN', new_y='NEXT')
        self.ln(3)

        # Preamble
        self.set_font('Helvetica', 'I', 9)
        self.set_text_color(*self.MEDIUM_GRAY)
        preamble = (
            'The following countries carry a CDC Level 3 or Level 4 health notice '
            'but have not been issued a high-risk travel advisory by the US State '
            'Department. Review the linked CDC notices for full details.'
        )
        self.multi_cell(0, 4.5, self._clean_text(preamble),
                        new_x='LMARGIN', new_y='NEXT')
        self.ln(5)

        for adv in cdc_only:
            # Page break check
            if self.get_y() > 240:
                self.add_page()

            # Country name header
            self.set_fill_color(*self.CDC_LEVEL_3_COLOR)
            self.set_text_color(255, 255, 255)
            self.set_font('Helvetica', 'B', 11)
            self.multi_cell(0, 8,
                            f'  {self._clean_text(adv.country_name)}',
                            fill=True, new_x='LMARGIN', new_y='NEXT')

            self.set_font('Helvetica', 'I', 9)
            self.set_text_color(*self.MEDIUM_GRAY)
            self.multi_cell(0, 5, 'Source: CDC travel health notice only (no State Dept advisory)',
                            new_x='LMARGIN', new_y='NEXT')
            self.ln(1)

            # List each CDC notice
            for cdc_n in adv.cdc_notices:
                self.set_x(15)
                self.set_font('Helvetica', '', 10)
                self.set_text_color(*self.CDC_LEVEL_3_COLOR)
                notice_line = (f"Level {cdc_n.level} ({cdc_n.level_name}) "
                               f"- {cdc_n.disease}")
                self.multi_cell(0, 5, self._clean_text(notice_line),
                                new_x='LMARGIN', new_y='NEXT')
                self.set_x(20)
                self.set_font('Helvetica', 'I', 9)
                self.set_text_color(*self.MEDIUM_GRAY)
                self.multi_cell(0, 4, self._clean_text(cdc_n.link),
                                new_x='LMARGIN', new_y='NEXT')

            self.ln(3)
            self.set_draw_color(*self.LIGHT_GRAY)
            self.set_line_width(0.3)
            self.line(10, self.get_y(), self.epw + 10, self.get_y())
            self.ln(5)


def create_report(
    prohibited: list[TravelAdvisory],
    ut_suspended: list[TravelAdvisory],
    restricted_special: list[TravelAdvisory],
    advisories: list[TravelAdvisory],
    output_path: Path,
    worldwide_caution: 'TravelAdvisory | None' = None,
    global_outbreaks: list[CDCGlobalOutbreak] | None = None,
    cdc_only: list[TravelAdvisory] | None = None,
) -> Path:
    """Generate the PDF report.

    Args:
        prohibited: List of prohibited country advisories (Texas EO GA-48).
        ut_suspended: List of UT System suspended travel advisories.
        restricted_special: List of advisories requiring Institutional Travel Oversight Committee (ITOC) + President approval.
        advisories: List of general high-risk advisories to include.
        output_path: Where to save the PDF.
        worldwide_caution: Optional worldwide caution advisory to render on page 2.
        global_outbreaks: Optional list of CDC global outbreak notices.
        cdc_only: Optional list of CDC-only advisories (no State Dept advisory).

    Returns:
        Path to the generated PDF.
    """
    if global_outbreaks is None:
        global_outbreaks = []
    if cdc_only is None:
        cdc_only = []

    pdf = TravelAdvisoryPDF()

    # Calculate statistics
    stats = {
        'prohibited': len(prohibited),
        'ut_suspended': len(ut_suspended),
        'restricted': len(restricted_special),
        'restricted_special': len(restricted_special),
        'total': len(prohibited) + len(ut_suspended) + len(restricted_special) + len(advisories),
        'level_4': sum(1 for a in advisories if a.overall_level == 4),
        'level_3': sum(1 for a in advisories if a.overall_level == 3),
        'regional': sum(1 for a in advisories if a.overall_level < 3 and a.has_regional_elevation),
        'cdc_global_outbreaks': len(global_outbreaks),
        'cdc_only': len(cdc_only),
    }

    # Title page with statistics
    pdf.add_title_page(stats)

    # Combined worldwide caution + CDC global alerts page
    # Renders only if at least one source has data; omitted entirely otherwise.
    if worldwide_caution is not None or global_outbreaks:
        pdf.add_global_awareness_page(worldwide_caution, global_outbreaks)

    # Unified quick-reference table (prohibited + ut_suspended + restricted + high-risk)
    pdf.add_summary_section(prohibited, ut_suspended, restricted_special, advisories)

    # Detailed entries - Level 4 first
    pdf.add_page()
    pdf.set_font('Helvetica', 'B', 16)
    pdf.set_text_color(*pdf.NAVY)
    pdf.cell(0, 10, 'Detailed Advisories', align='C')
    pdf.ln(15)

    for advisory in advisories:
        pdf.add_advisory_entry(advisory)

    # CDC-only countries — after all State Dept detailed entries
    if cdc_only:
        pdf.add_cdc_only_section(cdc_only)

    # Save
    pdf.output(str(output_path))
    return output_path


class VerificationReport:
    """Accumulates pipeline data and writes a verification log alongside the PDF.

    Tracks raw counts, parse failures, duplicates, prohibited matching, and
    high-risk breakdown. Runs assertions that halt report generation on failure.
    """

    def __init__(self):
        self.raw_count: int = 0
        self.parsed_count: int = 0
        self.parse_failures: int = 0
        self.failed_titles: list[str] = []
        self.duplicates_removed: int = 0
        self.duplicate_descriptions: list[str] = []
        self.after_dedup_count: int = 0
        self.prohibited_matched: dict[str, str] = {}   # name -> matched API entry
        self.prohibited_unmatched: list[str] = []
        self.ut_suspended_matched: dict[str, str] = {}
        self.ut_suspended_unmatched: list[str] = []
        self.restricted_special_matched: dict[str, str] = {}
        self.restricted_special_unmatched: list[str] = []
        self.level_4_countries: list[str] = []
        self.level_3_countries: list[str] = []
        self.regional_countries: list[str] = []
        self.high_risk_names: list[str] = []
        self.data_hash: str = ""
        self.assertion_errors: list[str] = []
        self.regional_signal_gaps: list[str] = []    # countries with signals but no warnings
        self.missing_expected_regions: list[str] = []  # ground-truth canary failures
        self.page_fallback_used: list[str] = []      # countries where page scraping was used
        self.worldwide_caution_found: bool = False
        self.worldwide_caution_title: str = ""
        self.entry_count_stable: bool = True
        self.listing_page_count: int | None = None   # cross-validation from HTML listing
        self.used_cache: bool = False                 # True if API cache was used as fallback
        # CDC health notices
        self.cdc_fetch_success: bool = True
        self.cdc_notices_found: int = 0
        self.cdc_global_outbreaks_found: int = 0
        self.cdc_global_outbreaks: list[str] = []
        self.cdc_annotated: list[str] = []
        self.cdc_only_countries: list[str] = []
        self.cdc_unmatched: list[str] = []

    def check_entry_stability(self, current_count: int, history_path: 'Path') -> None:
        """Compare current raw entry count against recent history and warn on variance.

        Reads/updates a JSON history file (last 5 runs) in the output directory.
        Sets entry_count_stable = False and logs a warning if the count differs
        from the previous run by more than 1.  Never raises — instability is
        warn-only.
        """
        _HISTORY_MAX = 5
        history: list[dict] = []

        if history_path.exists():
            try:
                history = json.loads(history_path.read_text(encoding='utf-8'))
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Could not read entry count history: %s", exc)

        if history:
            prev_count = history[-1].get('count', current_count)
            delta = abs(current_count - prev_count)
            if delta > 1:
                self.entry_count_stable = False
                logger.warning(
                    "[WARN] Entry count changed by %d (prev=%d, now=%d) — "
                    "API backend variance detected.",
                    delta, prev_count, current_count,
                )

        history.append({
            'timestamp': datetime.now().isoformat(timespec='seconds'),
            'count': current_count,
        })
        history = history[-_HISTORY_MAX:]

        try:
            history_path.write_text(
                json.dumps(history, indent=2), encoding='utf-8'
            )
        except OSError as exc:
            logger.warning("Could not write entry count history: %s", exc)

    def record_worldwide_caution(self, adv: 'TravelAdvisory | None') -> None:
        """Record whether a worldwide caution advisory was found in the API data."""
        if adv is not None:
            self.worldwide_caution_found = True
            self.worldwide_caution_title = adv.country_name

    def compute_data_hash(self, advisories: list[TravelAdvisory]) -> str:
        """Compute a SHA-256 fingerprint of the processed advisory data."""
        hasher = hashlib.sha256()
        for adv in sorted(advisories, key=lambda a: a.country_code or a.country_name):
            record = f"{adv.country_code}|{adv.country_name}|{adv.overall_level}|{adv.last_updated.isoformat()}"
            hasher.update(record.encode())
        self.data_hash = hasher.hexdigest()
        return self.data_hash

    def populate_prohibited_audit(self, prohibited_advisories: list[TravelAdvisory]):
        """Check which expected prohibited countries were matched in API data.

        Uses is_prohibited_country() — the same function the waterfall uses —
        so the audit never disagrees with the pipeline about what matched.
        """
        for name in PROHIBITED_COUNTRIES:
            match = next(
                (a for a in prohibited_advisories if is_prohibited_country(a.country_name)
                 and (name.lower() in a.country_name.lower()
                      or any(inc.lower() in a.country_name.lower()
                             for inc in PROHIBITED_COUNTRIES[name].get('includes', [])))),
                None
            )
            if match:
                self.prohibited_matched[name] = match.country_name
            else:
                self.prohibited_unmatched.append(name)

    def populate_ut_suspended_audit(self, ut_suspended_advisories: list[TravelAdvisory]):
        """Check which expected UT suspended countries were matched in API data.

        Uses _match_country_dict() — the same function the waterfall uses —
        so the audit agrees with the pipeline (fixes UAE-style false misses).
        """
        for name, info in UT_SUSPENDED_TRAVEL.items():
            single = {name: info}
            match = next(
                (a for a in ut_suspended_advisories if _match_country_dict(a.country_name, single)),
                None
            )
            if match:
                self.ut_suspended_matched[name] = match.country_name
            else:
                self.ut_suspended_unmatched.append(name)

    def populate_restricted_special_audit(self, restricted_advisories: list[TravelAdvisory]):
        """Check which expected restricted/special-approval countries were matched in API data.

        Uses _match_country_dict() — the same function the waterfall uses.
        """
        for name, info in RESTRICTED_TRAVEL_REQUIRING_SPECIAL_APPROVAL.items():
            single = {name: info}
            match = next(
                (a for a in restricted_advisories if _match_country_dict(a.country_name, single)),
                None
            )
            if match:
                self.restricted_special_matched[name] = match.country_name
            else:
                self.restricted_special_unmatched.append(name)

    def populate_high_risk_breakdown(self, high_risk: list[TravelAdvisory]):
        """Record the high-risk breakdown by level."""
        for adv in high_risk:
            self.high_risk_names.append(adv.country_name)
            if adv.overall_level == 4:
                self.level_4_countries.append(adv.country_name)
            elif adv.overall_level == 3:
                self.level_3_countries.append(adv.country_name)
            else:
                self.regional_countries.append(adv.country_name)

    def run_assertions(
        self,
        prohibited: list[TravelAdvisory],
        ut_suspended: list[TravelAdvisory],
        restricted_special: list[TravelAdvisory],
        high_risk: list[TravelAdvisory],
        all_advisories: list[TravelAdvisory] | None = None,
    ) -> bool:
        """Run verification assertions. Returns True if all pass."""
        self.assertion_errors = []

        # 1. No prohibited country leaked into any lower-priority bucket
        for adv in ut_suspended + restricted_special + high_risk:
            if is_prohibited_country(adv.country_name):
                self.assertion_errors.append(
                    f"LEAK: Prohibited country '{adv.country_name}' found outside prohibited bucket"
                )

        # 2. No UT suspended country leaked into restricted or high-risk
        for adv in restricted_special + high_risk:
            if is_ut_suspended_country(adv.country_name):
                self.assertion_errors.append(
                    f"LEAK: UT suspended country '{adv.country_name}' found outside ut_suspended bucket"
                )

        # 3. No restricted country leaked into high-risk
        for adv in high_risk:
            if is_restricted_special_country(adv.country_name):
                self.assertion_errors.append(
                    f"LEAK: Restricted country '{adv.country_name}' found in high-risk list"
                )

        # 4. Parse failure rate < 5%
        if self.raw_count > 0:
            failure_rate = self.parse_failures / self.raw_count
            if failure_rate >= 0.05:
                self.assertion_errors.append(
                    f"PARSE FAILURES: {self.parse_failures}/{self.raw_count} "
                    f"({failure_rate:.1%}) exceeds 5% threshold"
                )

        # 5. At least 1 high-risk country found (sanity check)
        if len(high_risk) == 0:
            self.assertion_errors.append("SANITY: Zero high-risk countries found")

        # 6. No duplicate country codes remain after dedup
        codes = [
            a.country_code
            for a in list(prohibited) + list(ut_suspended) + list(restricted_special) + list(high_risk)
            if a.country_code
        ]
        seen_codes: set[str] = set()
        for code in codes:
            if code in seen_codes:
                self.assertion_errors.append(f"DUPLICATE: Country code '{code}' appears more than once")
            seen_codes.add(code)

        # 7. Hard minimum entry count — refuse to generate a report from a
        #    partial API response (the API is load-balanced and can serve as
        #    few as 17 entries from a bad backend).
        if self.raw_count < MIN_EXPECTED_ENTRIES:
            self.assertion_errors.append(
                f"ENTRY COUNT: Only {self.raw_count} entries received "
                f"(minimum {MIN_EXPECTED_ENTRIES}). API may have served a partial response."
            )

        # 8. Flag unresolved regional signal gaps
        if all_advisories:
            for adv in all_advisories:
                if adv.overall_level <= 2 and not adv.regional_warnings:
                    if _has_regional_signals(adv.summary):
                        self.regional_signal_gaps.append(adv.country_name)
            if self.regional_signal_gaps:
                logger.warning(
                    "Regional signal gaps (%d countries have signals but no extracted warnings): %s",
                    len(self.regional_signal_gaps),
                    ", ".join(self.regional_signal_gaps)
                )
            # Too many gaps suggests truncated API summaries or failing extraction
            if len(self.regional_signal_gaps) > MAX_REGIONAL_SIGNAL_GAPS:
                self.assertion_errors.append(
                    f"REGIONAL GAPS: {len(self.regional_signal_gaps)} countries have regional "
                    f"signals but no extracted warnings (threshold: {MAX_REGIONAL_SIGNAL_GAPS})"
                )

        # 9. Ground-truth canary — countries known to always have L4 regions
        if all_advisories:
            for expected_name in MUST_HAVE_REGIONS:
                adv = next(
                    (a for a in all_advisories
                     if expected_name.lower() in a.country_name.lower()),
                    None,
                )
                if adv and not adv.regional_warnings:
                    self.missing_expected_regions.append(expected_name)
                    logger.warning(
                        "[WARN] Expected regional warnings for %s but found none",
                        expected_name,
                    )

        return len(self.assertion_errors) == 0

    def write(self, path: Path):
        """Write the verification log to a file."""
        lines = []
        lines.append("=" * 70)
        lines.append("TRAVEL ADVISORY REPORT — VERIFICATION LOG")
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 70)

        # Pipeline stats
        lines.append("")
        lines.append("--- PIPELINE STATS ---")
        lines.append(f"Raw API entries:        {self.raw_count}")
        lines.append(f"Parsed successfully:    {self.parsed_count}")
        lines.append(f"Parse failures:         {self.parse_failures}")
        if self.failed_titles:
            for title in self.failed_titles:
                lines.append(f"  - {title}")
        lines.append(f"Duplicates removed:     {self.duplicates_removed}")
        if self.duplicate_descriptions:
            for desc in self.duplicate_descriptions:
                lines.append(f"  - {desc}")
        lines.append(f"After dedup:            {self.after_dedup_count}")
        stability = "stable" if self.entry_count_stable else "[WARN] UNSTABLE — count differed from previous run by >1"
        lines.append(f"Entry count stability:  {stability}")
        if self.used_cache:
            lines.append(f"API cache fallback:     [WARN] USED — live API returned fewer than {MIN_EXPECTED_ENTRIES} entries")
        if self.listing_page_count is not None:
            delta = abs(self.raw_count - self.listing_page_count)
            lines.append(f"Listing page count:     {self.listing_page_count} (delta from API: {delta})")
        if self.worldwide_caution_found:
            lines.append(f"Worldwide caution:      FOUND — '{self.worldwide_caution_title}'")
        else:
            lines.append("Worldwide caution:      not found at worldwide caution URL")

        # Prohibited audit
        lines.append("")
        lines.append("--- PROHIBITED COUNTRY AUDIT (Texas EO GA-48) ---")
        lines.append(f"Expected: {len(PROHIBITED_COUNTRIES)} countries")
        lines.append(f"Matched:  {len(self.prohibited_matched)}")
        for name, api_entry in self.prohibited_matched.items():
            lines.append(f"  [OK]   {name} -> '{api_entry}'")
        if self.prohibited_unmatched:
            lines.append(f"Unmatched: {len(self.prohibited_unmatched)}")
            for name in self.prohibited_unmatched:
                lines.append(f"  [MISS] {name} — no API entry found")

        # UT Suspended audit
        lines.append("")
        lines.append("--- UT SUSPENDED TRAVEL AUDIT ---")
        lines.append(f"Expected: {len(UT_SUSPENDED_TRAVEL)} countries")
        lines.append(f"Matched:  {len(self.ut_suspended_matched)}")
        for name, api_entry in self.ut_suspended_matched.items():
            lines.append(f"  [OK]   {name} -> '{api_entry}'")
        if self.ut_suspended_unmatched:
            lines.append(f"Unmatched: {len(self.ut_suspended_unmatched)}")
            for name in self.ut_suspended_unmatched:
                lines.append(f"  [MISS] {name} — no API entry found (may be prohibited-only)")

        # Restricted special approval audit
        lines.append("")
        lines.append("--- RESTRICTED / ELEVATED APPROVAL AUDIT ---")
        lines.append(f"Expected: {len(RESTRICTED_TRAVEL_REQUIRING_SPECIAL_APPROVAL)} countries")
        lines.append(f"Matched:  {len(self.restricted_special_matched)}")
        for name, api_entry in self.restricted_special_matched.items():
            lines.append(f"  [OK]   {name} -> '{api_entry}'")
        if self.restricted_special_unmatched:
            lines.append(f"Unmatched: {len(self.restricted_special_unmatched)}")
            for name in self.restricted_special_unmatched:
                lines.append(f"  [MISS] {name} — no API entry found")

        # High-risk breakdown
        lines.append("")
        lines.append("--- HIGH-RISK BREAKDOWN ---")
        lines.append(f"Level 4 (Do Not Travel):       {len(self.level_4_countries)}")
        for name in sorted(self.level_4_countries):
            lines.append(f"  - {name}")
        lines.append(f"Level 3 (Reconsider Travel):   {len(self.level_3_countries)}")
        for name in sorted(self.level_3_countries):
            lines.append(f"  - {name}")
        lines.append(f"Regional warnings (L1/L2):     {len(self.regional_countries)}")
        for name in sorted(self.regional_countries):
            lines.append(f"  - {name}")

        # Page fallback usage
        if self.page_fallback_used:
            lines.append("")
            lines.append("--- PAGE SCRAPING FALLBACK ---")
            lines.append(f"Countries using page fallback: {len(self.page_fallback_used)}")
            for name in sorted(self.page_fallback_used):
                lines.append(f"  - {name}")

        # Unresolved regional signal gaps
        if self.regional_signal_gaps:
            lines.append("")
            lines.append("--- REGIONAL SIGNAL GAPS (warnings) ---")
            lines.append(f"Countries with regional signals but no extracted warnings: {len(self.regional_signal_gaps)}")
            for name in sorted(self.regional_signal_gaps):
                lines.append(f"  [WARN] {name}")

        # Ground-truth canary: countries expected to have regions
        if self.missing_expected_regions:
            lines.append("")
            lines.append("--- MISSING EXPECTED REGIONS (canary) ---")
            for name in sorted(self.missing_expected_regions):
                lines.append(f"  [WARN] {name} — expected regional warnings but found none")

        # CDC health notices
        lines.append("")
        lines.append("--- CDC HEALTH NOTICES ---")
        lines.append(f"Fetch success:                  {'Yes' if self.cdc_fetch_success else 'No'}")
        lines.append(f"Level 3/4 notices found:        {self.cdc_notices_found}")
        lines.append(f"Global outbreak notices (L1/2): {self.cdc_global_outbreaks_found}")
        if self.cdc_global_outbreaks:
            for title in self.cdc_global_outbreaks:
                lines.append(f"  - {title}")
        lines.append(f"Annotated existing entries:      {len(self.cdc_annotated)}")
        if self.cdc_annotated:
            for name in sorted(self.cdc_annotated):
                lines.append(f"  - {name}")
        lines.append(f"CDC-only countries (net-new):    {len(self.cdc_only_countries)}")
        if self.cdc_only_countries:
            for name in sorted(self.cdc_only_countries):
                lines.append(f"  - {name}")
        lines.append(f"Unmatched CDC names:            {len(self.cdc_unmatched)}")
        if self.cdc_unmatched:
            for name in self.cdc_unmatched:
                lines.append(f"  [WARN] {name}")

        # Data hash
        lines.append("")
        lines.append("--- DATA HASH ---")
        lines.append(f"SHA-256: {self.data_hash}")

        # Assertions
        lines.append("")
        lines.append("--- ASSERTIONS ---")
        if self.assertion_errors:
            lines.append(f"FAILED ({len(self.assertion_errors)} errors):")
            for err in self.assertion_errors:
                lines.append(f"  [FAIL] {err}")
        else:
            lines.append("ALL PASSED")
            lines.append("  [OK] No prohibited countries leaked into lower-priority buckets")
            lines.append("  [OK] No UT suspended countries leaked into restricted or high-risk")
            lines.append("  [OK] No restricted countries leaked into high-risk list")
            lines.append(f"  [OK] Parse failure rate within threshold ({self.parse_failures}/{self.raw_count})")
            lines.append(f"  [OK] High-risk countries found ({len(self.high_risk_names)})")
            lines.append("  [OK] No duplicate country codes after dedup")
            lines.append(f"  [OK] Entry count meets minimum ({self.raw_count} >= {MIN_EXPECTED_ENTRIES})")
            lines.append(f"  [OK] Regional signal gaps within threshold ({len(self.regional_signal_gaps)} <= {MAX_REGIONAL_SIGNAL_GAPS})")

        lines.append("")
        lines.append("=" * 70)

        path.write_text("\n".join(lines), encoding="utf-8")


def main():
    """Main entry point for the travel advisory report generator."""
    parser = argparse.ArgumentParser(
        description="Generate a PDF report of high-risk travel destinations from US State Department data"
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default="travel_advisory_report.pdf",
        help="Output PDF filename (default: travel_advisory_report.pdf)"
    )
    parser.add_argument(
        "--list-only",
        action="store_true",
        help="Print country list to console without generating PDF"
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Set logging verbosity (default: WARNING)"
    )

    args = parser.parse_args()

    # Configure logging from CLI arg
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(levelname)s: %(message)s",
    )

    # Initialize verification
    verification = VerificationReport()

    print("Fetching travel advisories from US State Department...")

    # Resolve output directory for cache and counts files
    _output_dir = Path(args.output).resolve().parent
    _cache_path = _output_dir / API_CACHE_FILENAME

    try:
        raw_data = fetch_advisories(cache_path=_cache_path)
    except ConnectionError as e:
        print(f"\nError: {e}")
        print("Please check your internet connection and try again.")
        return 1

    verification.raw_count = len(raw_data)
    # Detect if cache was used (live API returned fewer than minimum)
    if _cache_path.exists():
        try:
            cached_ts = json.loads(_cache_path.read_text(encoding='utf-8')).get('timestamp', '')
            # If the cache timestamp matches a recent save, live data was good.
            # If not, we may have used the cache. Check by re-reading the cache.
        except (json.JSONDecodeError, OSError):
            pass
    print(f"Retrieved {len(raw_data)} advisories.")

    # Stability check — compare raw count against recent run history
    _counts_file = _output_dir / "travel_advisory_counts.json"
    verification.check_entry_stability(len(raw_data), _counts_file)

    # Cross-validate entry count against the HTML listing page
    listing_count = fetch_listing_page_count()
    verification.listing_page_count = listing_count

    # Fetch worldwide caution from its dedicated page (not in the JSON feed)
    worldwide_caution = extract_worldwide_caution()
    verification.record_worldwide_caution(worldwide_caution)

    # Parse all advisories, tracking failures
    print("Parsing advisory data...")
    advisories = []
    for raw in raw_data:
        parsed, used_fallback = parse_advisory(raw)
        if parsed:
            advisories.append(parsed)
            if used_fallback:
                verification.page_fallback_used.append(parsed.country_name)
        else:
            verification.parse_failures += 1
            verification.failed_titles.append(raw.get('Title', '<no title>'))

    verification.parsed_count = len(advisories)
    print(f"Parsed {len(advisories)} valid advisories ({verification.parse_failures} failures).")

    # Deduplicate
    advisories, dup_descriptions = deduplicate_advisories(advisories)
    verification.duplicates_removed = len(dup_descriptions)
    verification.duplicate_descriptions = dup_descriptions
    verification.after_dedup_count = len(advisories)
    if dup_descriptions:
        print(f"Removed {len(dup_descriptions)} duplicate(s).")

    # Filter into four priority buckets
    prohibited, ut_suspended, restricted_special, high_risk = filter_high_risk(advisories)

    # Populate verification details
    verification.populate_prohibited_audit(prohibited)
    verification.populate_ut_suspended_audit(ut_suspended)
    verification.populate_restricted_special_audit(restricted_special)
    verification.populate_high_risk_breakdown(high_risk)
    verification.compute_data_hash(prohibited + ut_suspended + restricted_special + high_risk)

    # Fetch CDC travel health notices (non-fatal)
    print("Fetching CDC travel health notices...")
    try:
        cdc_notices, global_outbreaks = fetch_cdc_notices()
    except Exception as e:
        logger.warning("CDC fetch failed: %s", e)
        cdc_notices, global_outbreaks = [], []
        verification.cdc_fetch_success = False

    cdc_only, cdc_unmatched = match_cdc_notices(
        cdc_notices, prohibited, ut_suspended, restricted_special, high_risk
    )

    verification.cdc_notices_found = len(cdc_notices)
    verification.cdc_global_outbreaks_found = len(global_outbreaks)
    verification.cdc_global_outbreaks = [o.title for o in global_outbreaks]
    verification.cdc_annotated = [
        a.country_name for a in (prohibited + ut_suspended + restricted_special + high_risk)
        if a.cdc_notices
    ]
    verification.cdc_only_countries = [a.country_name for a in cdc_only]
    verification.cdc_unmatched = cdc_unmatched

    print(f"CDC: {len(cdc_notices)} Level 3/4 notices, "
          f"{len(global_outbreaks)} global health alerts.")

    print(f"\nProhibited countries (Texas EO GA-48): {len(prohibited)}")
    for adv in prohibited:
        print(f"  - {adv.country_name}")

    print(f"\nUT System suspended travel: {len(ut_suspended)}")
    for adv in ut_suspended:
        print(f"  - {adv.country_name}")
    _ut_unmatched = [
        n for n in UT_SUSPENDED_TRAVEL
        if not is_prohibited_country(n)
        and not any(
            n.lower() in a.country_name.lower()
            or (UT_SUSPENDED_TRAVEL[n].get('code') and
                UT_SUSPENDED_TRAVEL[n]['code'].upper() == a.country_code.upper())
            for a in ut_suspended
        )
    ]
    if _ut_unmatched:
        print(f"  [WARN] No API entry found for: {', '.join(_ut_unmatched)}")

    print(f"\nRestricted / elevated approval required: {len(restricted_special)}")
    for adv in restricted_special:
        print(f"  - {adv.country_name}")
    _re_unmatched = [
        n for n in RESTRICTED_TRAVEL_REQUIRING_SPECIAL_APPROVAL
        if not any(n.lower() in a.country_name.lower() for a in restricted_special)
    ]
    if _re_unmatched:
        print(f"  [WARN] No API entry found for: {', '.join(_re_unmatched)}")

    print(f"\nFound {len(high_risk)} additional high-risk destinations:")
    level_4 = [a for a in high_risk if a.overall_level == 4]
    level_3 = [a for a in high_risk if a.overall_level == 3]
    regional = [a for a in high_risk if a.overall_level < 3]

    print(f"  - Level 4 (Do Not Travel): {len(level_4)}")
    print(f"  - Level 3 (Reconsider Travel): {len(level_3)}")
    print(f"  - Level 1/2 with regional warnings: {len(regional)}")

    # Run verification assertions
    assertions_passed = verification.run_assertions(
        prohibited, ut_suspended, restricted_special, high_risk, all_advisories=advisories
    )

    if args.list_only:
        print("\n" + "=" * 60)
        print("PROHIBITED COUNTRIES (Texas EO GA-48)")
        print("=" * 60)
        for name, info in PROHIBITED_COUNTRIES.items():
            includes = f" (incl. {', '.join(info['includes'])})" if info['includes'] else ""
            print(f"[PROHIBITED] {name}{includes}")

        print("\n" + "=" * 60)
        print("UT SUSPENDED TRAVEL")
        print("=" * 60)
        for name, info in UT_SUSPENDED_TRAVEL.items():
            includes = f" (incl. {', '.join(info['includes'])})" if info['includes'] else ""
            print(f"[UT SUSPENDED] {name}{includes}")

        print("\n" + "=" * 60)
        print("RESTRICTED / ELEVATED APPROVAL REQUIRED")
        print("=" * 60)
        for name, info in RESTRICTED_TRAVEL_REQUIRING_SPECIAL_APPROVAL.items():
            includes = f" (incl. {', '.join(info['includes'])})" if info['includes'] else ""
            print(f"[RESTRICTED] {name}{includes}")

        print("\n" + "=" * 60)
        print("HIGH-RISK COUNTRIES")
        print("=" * 60)

        for advisory in high_risk:
            marker = "*" if advisory.has_regional_elevation else " "
            print(f"[L{advisory.overall_level}]{marker} {advisory.country_name}")
            if advisory.has_regional_elevation:
                for w in advisory.regional_warnings[:3]:
                    if w.level > advisory.overall_level:
                        print(f"       -> L{w.level}: {w.region_name[:50]}")

        print("\n* = Has elevated regional warnings")
        print(f"\nData hash: {verification.data_hash}")
        return 0

    # Halt on verification failure before generating PDF
    output_path = Path(args.output)
    verification_path = output_path.with_suffix('.verification.txt')

    if not assertions_passed:
        verification.write(verification_path)
        print(f"\n*** VERIFICATION FAILED ***")
        for err in verification.assertion_errors:
            print(f"  [FAIL] {err}")
        print(f"\nVerification log: {verification_path.absolute()}")
        return 2

    # Generate PDF
    print(f"\nGenerating PDF report...")
    create_report(prohibited, ut_suspended, restricted_special, high_risk, output_path,
                  worldwide_caution=worldwide_caution,
                  global_outbreaks=global_outbreaks,
                  cdc_only=cdc_only)

    # Write verification log alongside PDF
    verification.write(verification_path)

    print(f"\nReport saved to: {output_path.absolute()}")
    print(f"Verification log: {verification_path.absolute()}")
    print(f"Data hash: {verification.data_hash}")
    print("Stay safe out there!")

    return 0


if __name__ == "__main__":
    sys.exit(main())
