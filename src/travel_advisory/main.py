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

# Advisory level definitions
LEVEL_NAMES = {
    1: "Exercise Normal Precautions",
    2: "Exercise Increased Caution",
    3: "Reconsider Travel",
    4: "Do Not Travel",
}

# =============================================================================
# PROHIBITED COUNTRIES - Texas Executive Order GA-48
# =============================================================================
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
# Exceptions require approval from both the Institutional Oversight Committee
# (IOC) and the University President.
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
# from both the Institutional Oversight Committee (IOC) and the University
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


def _total_summary_length(entries: list[dict]) -> int:
    """Return the combined length of all Summary fields."""
    return sum(len(e.get('Summary', '')) for e in entries)


def fetch_advisories(max_retries: int = 3) -> list[dict]:
    """Fetch travel advisory data from the State Department API.

    The API occasionally returns truncated Summary fields that omit regional
    warning details.  To mitigate this, the fetch is retried up to
    *max_retries* times and the response with the most total summary data is
    kept.

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
                if size > best_size:
                    best, best_size = entries, size
                    logger.debug("Fetch attempt %d: %d entries, %d total summary chars",
                                 attempt + 1, len(entries), size)
        except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
            last_error = e
            logger.debug("Fetch attempt %d failed: %s", attempt + 1, e)

    if not best:
        raise ConnectionError(f"Failed to fetch advisories after {max_retries} attempts: {last_error}")

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
                    i += 1
                    break
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
            # no directive keywords) followed by a directive line
            lines = section_text.split('\n')
            for j, line in enumerate(lines):
                line = line.strip()
                if not line:
                    continue
                # A region name line is typically a short capitalized phrase
                # that is NOT a directive or boilerplate
                if re.match(r'^(Do\s+not\s+travel|Reconsider\s+travel|Exercise|Read\s+the|Visit|If\s+you|There\s+|Most\s+|Shooting|U\.S\.|Check|Expand|Collapse)', line, re.IGNORECASE):
                    continue
                if line.startswith('- ') or line.startswith('* '):
                    continue
                # Must start with uppercase and be reasonably short (region name)
                if not line[0].isupper() or len(line) > 100:
                    continue
                # Check that the next non-empty line is a directive
                next_line = ""
                for k in range(j + 1, min(j + 4, len(lines))):
                    nl = lines[k].strip()
                    if nl:
                        next_line = nl
                        break
                if re.match(r'(Do\s+not\s+travel|Reconsider\s+travel)', next_line, re.IGNORECASE):
                    # Extract reasons from the directive line
                    reasons_match = re.search(r'due\s+to\s+([^.]+)', next_line, re.IGNORECASE)
                    reasons = reasons_match.group(1).strip() if reasons_match else ""
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
        category = raw.get('Category', [])
        country_code = category[0] if category else ""

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
        page_fallback_used = False
        if overall_level <= 2 and not regional_warnings and _has_regional_signals(summary):
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

    Uses exact match first, then substring matching to catch compound entries
    like 'Mainland China, Hong Kong & Macau - See Summaries'.
    """
    name_lower = country_name.lower().strip()
    # Exact match
    if name_lower in PROHIBITED_COUNTRY_NAMES:
        return True
    # Substring match: check if any prohibited name appears within the country name
    return any(prohibited in name_lower for prohibited in PROHIBITED_COUNTRY_NAMES)


def _match_country_dict(country_name: str, country_dict: dict) -> bool:
    """Check if a country name matches any entry in a country dictionary.

    Matches against canonical key names and all entries in 'includes' lists,
    using case-insensitive substring matching in both directions.
    """
    name_lower = country_name.lower().strip()
    for key, info in country_dict.items():
        if key.lower() in name_lower or name_lower in key.lower():
            return True
        for alias in info.get("includes", []):
            if alias.lower() in name_lower or name_lower in alias.lower():
                return True
    return False


def is_ut_suspended_country(country_name: str) -> bool:
    """Check if a country is on the UT System suspended travel list."""
    return _match_country_dict(country_name, UT_SUSPENDED_TRAVEL)


def is_restricted_special_country(country_name: str) -> bool:
    """Check if a country requires Institutional Oversight Committee (IOC) + President elevated approval."""
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
      2. UT Suspended     — UT System suspended travel (IOC + President exception required; incl. layovers)
      3. Restricted       — UT System elevated approval required (IOC + President; incl. layovers)
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

    prohibited.sort(key=lambda a: a.country_name)
    ut_suspended.sort(key=lambda a: a.country_name)
    restricted_special.sort(key=lambda a: a.country_name)
    high_risk.sort(key=lambda a: (-a.overall_level, -a.max_regional_level, a.country_name))

    return prohibited, ut_suspended, restricted_special, high_risk


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

    # Color scheme
    PROHIBITED_COLOR = (80, 0, 80)        # Dark purple - prohibited countries
    UT_SUSPENDED_COLOR = (180, 60, 0)     # Deep orange - UT suspended travel
    RESTRICTED_SPECIAL_COLOR = (160, 110, 0)  # Amber - restricted/elevated approval
    LEVEL_4_COLOR = (180, 30, 30)         # Dark red
    LEVEL_3_COLOR = (200, 120, 0)         # Orange
    LEVEL_2_COLOR = (180, 150, 0)         # Yellow-orange
    LEVEL_1_COLOR = (60, 140, 60)         # Green

    NAVY = (30, 60, 100)
    DARK_GRAY = (40, 40, 40)
    MEDIUM_GRAY = (100, 100, 100)
    LIGHT_GRAY = (220, 220, 220)

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
            self.cell(0, 8, 'US State Department Travel Advisories - High Risk Report', align='C')
            self.ln(8)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 10)
        self.set_text_color(*self.MEDIUM_GRAY)
        self.cell(0, 10, f'Page {self.page_no()}', align='C')

    def add_title_page(self, stats: dict):
        """Create the report title page with summary statistics."""
        self.add_page()

        # Title
        self.ln(30)
        self.set_font('Helvetica', 'B', 28)
        self.set_text_color(*self.NAVY)
        self.cell(0, 15, 'Travel Advisory Report', align='C')
        self.ln(12)

        # Subtitle
        self.set_font('Helvetica', '', 14)
        self.set_text_color(*self.MEDIUM_GRAY)
        self.cell(0, 8, 'Areas of High Risk', align='C')
        self.ln(8)

        # Source
        self.set_font('Helvetica', 'I', 10)
        self.cell(0, 6, 'US Department of State', align='C')
        self.ln(20)

        # Generation date
        self.set_font('Helvetica', '', 11)
        self.set_text_color(*self.DARK_GRAY)
        self.cell(0, 6, f'Generated: {datetime.now().strftime("%B %d, %Y at %H:%M")}', align='C')
        self.ln(25)

        # Statistics box
        self.set_fill_color(*self.LIGHT_GRAY)
        box_x = 40
        box_width = self.epw - 40
        self.set_x(box_x)
        self.set_font('Helvetica', 'B', 12)
        self.set_text_color(*self.NAVY)
        self.cell(box_width, 10, 'Summary', fill=True, align='C')
        self.ln(12)

        # Stats
        self.set_font('Helvetica', '', 11)
        self.set_text_color(*self.DARK_GRAY)

        stat_items = [
            (f"PROHIBITED (Texas EO GA-48): {stats.get('prohibited', 0)} countries", self.PROHIBITED_COLOR),
            (f"Level 4 (Do Not Travel): {stats.get('level_4', 0)} countries", self.LEVEL_4_COLOR),
            (f"Level 3 (Reconsider Travel): {stats.get('level_3', 0)} countries", self.LEVEL_3_COLOR),
            (f"Countries with Regional Warnings: {stats.get('regional', 0)}", self.LEVEL_2_COLOR),
            (f"Total Entries: {stats.get('total', 0)}", self.NAVY),
        ]

        for text, color in stat_items:
            self.set_x(50)
            self.set_fill_color(*color)
            self.cell(5, 6, '', fill=True)
            self.set_x(58)
            self.set_text_color(*self.DARK_GRAY)
            self.multi_cell(0, 6, text,
                            new_x='LMARGIN', new_y='NEXT')
            self.ln(2)

        # Legend
        self.ln(15)
        self.set_font('Helvetica', 'B', 12)
        self.set_text_color(*self.NAVY)
        self.cell(0, 6, 'Advisory Level Definitions:', align='C')
        self.ln(8)

        self.set_font('Helvetica', 'B', 11)
        for level, name in LEVEL_NAMES.items():
            self.set_x(50)
            self.set_text_color(*self.get_level_color(level))
            self.cell(0, 6, f'Level {level}: {name}')
            self.ln(6)

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
            self.set_text_color(0, 80, 180)
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

        # Tier definitions printed above the table
        tier_defs = [
            (self.PROHIBITED_COLOR,
             'PROHIBITED (Texas EO GA-48):',
             'Travel is prohibited for UT employees per Texas Executive Order GA-48 '
             'designating these countries as foreign adversaries.'),
            (self.UT_SUSPENDED_COLOR,
             'UT SUSPENDED:',
             'UT System travel is suspended to or through these countries, including layovers '
             'and connections. Exceptions require approval from both the Institutional Oversight '
             'Committee (IOC) and the University President.'),
            (self.RESTRICTED_SPECIAL_COLOR,
             'RESTRICTED - ELEVATED APPROVAL:',
             'Travel to or through these countries, including layovers and connections, requires '
             'Institutional Oversight Committee (IOC) and University President approval before booking.'),
        ]
        for color, heading, definition in tier_defs:
            self.set_font('Helvetica', 'B', 9)
            self.set_text_color(*color)
            self.cell(0, 5, heading)
            self.ln(5)
            self.set_font('Helvetica', 'I', 8)
            self.set_text_color(*self.DARK_GRAY)
            self.multi_cell(0, 4, self._clean_text(definition),
                            new_x='LMARGIN', new_y='NEXT')
            self.ln(2)
        self.ln(3)

        # Build sorted row list: (advisory, label, color, notes)
        rows: list[tuple[TravelAdvisory, str, tuple, str]] = []

        # Prohibited countries first (alphabetical)
        for adv in sorted(prohibited, key=lambda a: a.country_name):
            rows.append((adv, 'PROHIBITED', self.PROHIBITED_COLOR, 'EO GA-48'))

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
                (a for a in ut_suspended if name.lower() in a.country_name.lower()), None
            )
            stub = TravelAdvisory(
                country_name=display_name,
                country_code=info.get('code', matched.country_code if matched else ''),
                overall_level=matched.overall_level if matched else 0,
                summary='',
                last_updated=matched.last_updated if matched else datetime.now(),
                link=matched.link if matched else '',
            )
            rows.append((stub, 'UT SUSPENDED', self.UT_SUSPENDED_COLOR, 'IOC + President req. (incl. layovers)'))

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
            rows.append((stub, 'RESTRICTED', self.RESTRICTED_SPECIAL_COLOR, 'IOC + President req. (incl. layovers)'))

        # Level 4 countries
        l4 = sorted(
            [a for a in advisories if a.overall_level == 4],
            key=lambda a: a.country_name,
        )
        for adv in l4:
            rows.append((adv, '4 - Do Not Travel', self.LEVEL_4_COLOR, ''))

        # Level 3 countries
        l3 = sorted(
            [a for a in advisories if a.overall_level == 3],
            key=lambda a: a.country_name,
        )
        for adv in l3:
            rows.append((adv, '3 - Reconsider Travel', self.LEVEL_3_COLOR, ''))

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

        # Draw table header
        self._summary_table_header()

        # Draw rows
        for idx, (adv, label, color, notes) in enumerate(rows):
            # Page break check — leave room for row + footnote
            if self.get_y() + row_h > self.h - self.b_margin - 20:
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
            actual_h = max(len(lines), 1) * row_h

            # Draw country cell (wraps long names)
            self.set_xy(x0, y0)
            self.set_text_color(*self.DARK_GRAY)
            self.multi_cell(col_w[0], row_h, name_text,
                            border='LR', fill=fill, new_x='RIGHT', new_y='TOP')

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

        # Footnote
        self.ln(6)
        self.set_draw_color(*self.LIGHT_GRAY)
        self.line(10, self.get_y(), self.epw + 10, self.get_y())
        self.ln(4)
        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(*self.MEDIUM_GRAY)
        self.multi_cell(0, 4, self._clean_text(
            'EO GA-48: Texas Executive Order GA-48 (Nov 2024) prohibits state employee '
            'work-related travel to countries designated as foreign adversaries per 15 CFR 791.4.\n'
            'DNT = Do Not Travel (Level 4 regions)  |  RT = Reconsider Travel (Level 3 regions)\n'
            'Note: Prohibited, UT Suspended, and Restricted designations apply to travel '
            'through these countries as a layover or connection point, regardless of ultimate destination.'
        ), align='L')

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


def create_report(
    prohibited: list[TravelAdvisory],
    ut_suspended: list[TravelAdvisory],
    restricted_special: list[TravelAdvisory],
    advisories: list[TravelAdvisory],
    output_path: Path,
) -> Path:
    """Generate the PDF report.

    Args:
        prohibited: List of prohibited country advisories (Texas EO GA-48).
        ut_suspended: List of UT System suspended travel advisories.
        restricted_special: List of advisories requiring Institutional Oversight Committee (IOC) + President approval.
        advisories: List of general high-risk advisories to include.
        output_path: Where to save the PDF.

    Returns:
        Path to the generated PDF.
    """
    pdf = TravelAdvisoryPDF()

    # Calculate statistics
    stats = {
        'prohibited': len(prohibited),
        'ut_suspended': len(ut_suspended),
        'restricted_special': len(restricted_special),
        'total': len(prohibited) + len(ut_suspended) + len(restricted_special) + len(advisories),
        'level_4': sum(1 for a in advisories if a.overall_level == 4),
        'level_3': sum(1 for a in advisories if a.overall_level == 3),
        'regional': sum(1 for a in advisories if a.overall_level < 3 and a.has_regional_elevation),
    }

    # Title page with statistics
    pdf.add_title_page(stats)

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
        self.page_fallback_used: list[str] = []      # countries where page scraping was used

    def compute_data_hash(self, advisories: list[TravelAdvisory]) -> str:
        """Compute a SHA-256 fingerprint of the processed advisory data."""
        hasher = hashlib.sha256()
        for adv in sorted(advisories, key=lambda a: a.country_code or a.country_name):
            record = f"{adv.country_code}|{adv.country_name}|{adv.overall_level}|{adv.last_updated.isoformat()}"
            hasher.update(record.encode())
        self.data_hash = hasher.hexdigest()
        return self.data_hash

    def populate_prohibited_audit(self, prohibited_advisories: list[TravelAdvisory]):
        """Check which expected prohibited countries were matched in API data."""
        for name in PROHIBITED_COUNTRIES:
            match = next(
                (a for a in prohibited_advisories if name.lower() in a.country_name.lower()),
                None
            )
            if match:
                self.prohibited_matched[name] = match.country_name
            else:
                self.prohibited_unmatched.append(name)

    def populate_ut_suspended_audit(self, ut_suspended_advisories: list[TravelAdvisory]):
        """Check which expected UT suspended countries were matched in API data."""
        for name in UT_SUSPENDED_TRAVEL:
            match = next(
                (a for a in ut_suspended_advisories if name.lower() in a.country_name.lower()),
                None
            )
            if match:
                self.ut_suspended_matched[name] = match.country_name
            else:
                self.ut_suspended_unmatched.append(name)

    def populate_restricted_special_audit(self, restricted_advisories: list[TravelAdvisory]):
        """Check which expected restricted/special-approval countries were matched in API data."""
        for name in RESTRICTED_TRAVEL_REQUIRING_SPECIAL_APPROVAL:
            match = next(
                (a for a in restricted_advisories if name.lower() in a.country_name.lower()),
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

        # 5. Flag unresolved regional signal gaps (warning, not a hard failure)
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

    args = parser.parse_args()

    # Initialize verification
    verification = VerificationReport()

    print("Fetching travel advisories from US State Department...")

    try:
        raw_data = fetch_advisories()
    except ConnectionError as e:
        print(f"\nError: {e}")
        print("Please check your internet connection and try again.")
        return 1

    verification.raw_count = len(raw_data)
    print(f"Retrieved {len(raw_data)} advisories.")

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

    print(f"\nProhibited countries (Texas EO GA-48): {len(prohibited)}")
    for adv in prohibited:
        print(f"  - {adv.country_name}")

    print(f"\nUT System suspended travel: {len(ut_suspended)}")
    for adv in ut_suspended:
        print(f"  - {adv.country_name}")

    print(f"\nRestricted / elevated approval required: {len(restricted_special)}")
    for adv in restricted_special:
        print(f"  - {adv.country_name}")

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
    create_report(prohibited, ut_suspended, restricted_special, high_risk, output_path)

    # Write verification log alongside PDF
    verification.write(verification_path)

    print(f"\nReport saved to: {output_path.absolute()}")
    print(f"Verification log: {verification_path.absolute()}")
    print(f"Data hash: {verification.data_hash}")
    print("Stay safe out there!")

    return 0


if __name__ == "__main__":
    sys.exit(main())
