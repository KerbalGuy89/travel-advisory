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


def fetch_advisories() -> list[dict]:
    """Fetch travel advisory data from the State Department API.

    Returns:
        List of advisory dictionaries from the API.

    Raises:
        ConnectionError: If the API is unavailable.
    """
    try:
        req = urllib.request.Request(
            API_URL,
            headers={"User-Agent": "TravelAdvisoryReport/1.0"}
        )
        with urllib.request.urlopen(req, timeout=30) as response:
            data = json.loads(response.read().decode('utf-8'))
            return data if isinstance(data, list) else data.get('data', [])
    except urllib.error.URLError as e:
        raise ConnectionError(f"Failed to fetch advisories: {e}")
    except json.JSONDecodeError as e:
        raise ConnectionError(f"Invalid API response: {e}")


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
    # Clean up whitespace
    text = re.sub(r'\n{3,}', '\n\n', text)
    text = re.sub(r' +', ' ', text)
    return text.strip()


def extract_regional_warnings(summary: str, overall_level: int) -> list[RegionalWarning]:
    """Extract regional warnings from advisory summary.

    Looks for patterns like:
    - "Level 4: region names due to reasons"
    - "Do not travel to X due to Y"
    - "Reconsider travel to X"

    Args:
        summary: The advisory summary HTML/text.
        overall_level: The country's overall advisory level.

    Returns:
        List of RegionalWarning objects for elevated regions.
    """
    warnings = []
    clean_text = clean_html(summary)

    # Pattern 1: "Do not travel to X due to Y" (implies Level 4)
    # This is the most reliable pattern in State Dept advisories
    if overall_level < 4:
        do_not_travel = re.finditer(
            r'[Dd]o\s+not\s+travel\s+to[:\s]+(.+?)\s+due\s+to\s+([^.]+)',
            clean_text
        )
        for match in do_not_travel:
            region = match.group(1).strip()
            reasons = match.group(2).strip()

            # Skip country-wide statements
            skip_phrases = ['country', 'nation', 'all of', 'anywhere', 'entire']
            if any(skip in region.lower() for skip in skip_phrases):
                continue

            # Clean up region name - remove leading articles, dashes, colons
            region = re.sub(r'^(the|a|an)\s+', '', region, flags=re.IGNORECASE)
            region = re.sub(r'^[-:*]\s*', '', region)  # Remove leading punctuation
            region = region.strip()

            # Skip vague references
            vague_terms = ['these areas', 'this area', 'the area', 'certain areas']
            if any(vague in region.lower() for vague in vague_terms):
                continue

            if len(region) < 3 or len(region) > 200:
                continue

            # Avoid duplicates
            if not any(region.lower() in w.region_name.lower() for w in warnings):
                warnings.append(RegionalWarning(
                    region_name=region,
                    level=4,
                    reasons=reasons
                ))

    # Pattern 2: "Reconsider travel to X due to Y" (implies Level 3)
    if overall_level < 3:
        reconsider = re.finditer(
            r'[Rr]econsider\s+travel\s+to[:\s]+(.+?)\s+due\s+to\s+([^.]+)',
            clean_text
        )
        for match in reconsider:
            region = match.group(1).strip()
            reasons = match.group(2).strip()

            # Skip country-wide statements
            skip_phrases = ['country', 'nation', 'all of', 'anywhere', 'entire']
            if any(skip in region.lower() for skip in skip_phrases):
                continue

            region = re.sub(r'^(the|a|an)\s+', '', region, flags=re.IGNORECASE)
            region = re.sub(r'^[-:*]\s*', '', region)
            region = region.strip()

            # Skip vague references
            vague_terms = ['these areas', 'this area', 'the area', 'certain areas']
            if any(vague in region.lower() for vague in vague_terms):
                continue

            if len(region) < 3 or len(region) > 200:
                continue

            if not any(region.lower() in w.region_name.lower() for w in warnings):
                warnings.append(RegionalWarning(
                    region_name=region,
                    level=3,
                    reasons=reasons
                ))

    return warnings


def parse_advisory(raw: dict) -> TravelAdvisory | None:
    """Parse a raw API response into a TravelAdvisory object.

    Args:
        raw: Dictionary from the API response.

    Returns:
        TravelAdvisory object or None if parsing fails.
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
                return None

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

        return TravelAdvisory(
            country_name=country_name,
            country_code=country_code,
            overall_level=overall_level,
            summary=clean_html(summary),
            last_updated=last_updated,
            link=link,
            regional_warnings=regional_warnings
        )
    except Exception as e:
        logger.error("Failed to parse advisory '%s': %s", raw.get('Title', '<no title>'), e)
        return None


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


def filter_high_risk(advisories: list[TravelAdvisory]) -> tuple[list[TravelAdvisory], list[TravelAdvisory]]:
    """Filter to only high-risk advisories, separating prohibited countries.

    Includes:
    - All Level 3 and Level 4 countries
    - Level 1/2 countries with Level 3/4 regional warnings

    Excludes from high-risk list:
    - Countries designated as foreign adversaries (Texas EO GA-48)

    Args:
        advisories: List of all parsed advisories.

    Returns:
        Tuple of (prohibited_advisories, high_risk_advisories).
        Prohibited countries are separated and excluded from high-risk list.
    """
    prohibited = []
    high_risk = []

    for advisory in advisories:
        # Check if this is a prohibited country first
        if is_prohibited_country(advisory.country_name):
            prohibited.append(advisory)
            continue

        # Include if overall level is 3 or 4
        if advisory.overall_level >= 3:
            high_risk.append(advisory)
            continue

        # Include if there are elevated regional warnings
        if advisory.has_regional_elevation and advisory.max_regional_level >= 3:
            high_risk.append(advisory)

    # Sort prohibited alphabetically
    prohibited.sort(key=lambda a: a.country_name)

    # Sort high-risk by overall level (descending), then by max regional level, then by name
    high_risk.sort(key=lambda a: (-a.overall_level, -a.max_regional_level, a.country_name))

    return prohibited, high_risk


class TravelAdvisoryPDF(FPDF):
    """Custom PDF class for travel advisory reports."""

    # Color scheme
    PROHIBITED_COLOR = (80, 0, 80)   # Dark purple - prohibited countries
    LEVEL_4_COLOR = (180, 30, 30)    # Dark red
    LEVEL_3_COLOR = (200, 120, 0)    # Orange
    LEVEL_2_COLOR = (180, 150, 0)    # Yellow-orange
    LEVEL_1_COLOR = (60, 140, 60)    # Green

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
        # Check if we need a new page (need at least 60mm for an entry)
        if self.get_y() > 230:
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

    def add_summary_section(self, advisories: list[TravelAdvisory]):
        """Add a summary section listing all countries by level."""
        self.add_page()

        self.set_font('Helvetica', 'B', 16)
        self.set_text_color(*self.NAVY)
        self.cell(0, 10, 'Quick Reference - Countries by Risk Level', align='C')
        self.ln(15)

        # Group by overall level
        by_level = {4: [], 3: [], 2: [], 1: []}
        for adv in advisories:
            by_level[adv.overall_level].append(adv)

        for level in [4, 3, 2, 1]:
            countries = by_level[level]
            if not countries:
                continue

            # Level header
            self.set_font('Helvetica', 'B', 13)
            self.set_text_color(*self.get_level_color(level))
            self.multi_cell(0, 7, f'Level {level}: {LEVEL_NAMES[level]} ({len(countries)} countries)',
                            new_x='LMARGIN', new_y='NEXT')

            # Country list
            self.set_x(10)  # Reset to left margin
            self.set_font('Helvetica', '', 11)
            self.set_text_color(*self.DARK_GRAY)

            # Format as comma-separated list
            names = [c.country_name for c in sorted(countries, key=lambda x: x.country_name)]
            text = ', '.join(names)
            self.multi_cell(0, 5, self._clean_text(text))
            self.ln(6)


def create_report(
    prohibited: list[TravelAdvisory],
    advisories: list[TravelAdvisory],
    output_path: Path
) -> Path:
    """Generate the PDF report.

    Args:
        prohibited: List of prohibited country advisories (Texas EO GA-48).
        advisories: List of high-risk advisories to include.
        output_path: Where to save the PDF.

    Returns:
        Path to the generated PDF.
    """
    pdf = TravelAdvisoryPDF()

    # Calculate statistics
    stats = {
        'prohibited': len(prohibited),
        'total': len(prohibited) + len(advisories),
        'level_4': sum(1 for a in advisories if a.overall_level == 4),
        'level_3': sum(1 for a in advisories if a.overall_level == 3),
        'regional': sum(1 for a in advisories if a.overall_level < 3 and a.has_regional_elevation),
    }

    # Title page with statistics
    pdf.add_title_page(stats)

    # PROHIBITED COUNTRIES SECTION - Must appear first
    pdf.add_prohibited_section(prohibited)

    # Quick reference summary (high-risk only, excludes prohibited)
    pdf.add_summary_section(advisories)

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
        self.level_4_countries: list[str] = []
        self.level_3_countries: list[str] = []
        self.regional_countries: list[str] = []
        self.high_risk_names: list[str] = []
        self.data_hash: str = ""
        self.assertion_errors: list[str] = []

    def compute_data_hash(self, advisories: list[TravelAdvisory]) -> str:
        """Compute a SHA-256 fingerprint of the processed advisory data."""
        hasher = hashlib.sha256()
        for adv in sorted(advisories, key=lambda a: a.country_code or a.country_name):
            record = f"{adv.country_code}|{adv.country_name}|{adv.overall_level}|{adv.last_updated.isoformat()}"
            hasher.update(record.encode())
        self.data_hash = hasher.hexdigest()
        return self.data_hash

    def populate_prohibited_audit(self, prohibited_advisories: list[TravelAdvisory]):
        """Check which of the 6 expected prohibited countries were matched in API data."""
        for name in PROHIBITED_COUNTRIES:
            match = next(
                (a for a in prohibited_advisories if name.lower() in a.country_name.lower()),
                None
            )
            if match:
                self.prohibited_matched[name] = match.country_name
            else:
                self.prohibited_unmatched.append(name)

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

    def run_assertions(self, prohibited: list[TravelAdvisory], high_risk: list[TravelAdvisory]) -> bool:
        """Run verification assertions. Returns True if all pass."""
        self.assertion_errors = []

        # 1. No prohibited country leaked into high-risk list
        for adv in high_risk:
            if is_prohibited_country(adv.country_name):
                self.assertion_errors.append(
                    f"LEAK: Prohibited country '{adv.country_name}' found in high-risk list"
                )

        # 2. Parse failure rate < 5%
        if self.raw_count > 0:
            failure_rate = self.parse_failures / self.raw_count
            if failure_rate >= 0.05:
                self.assertion_errors.append(
                    f"PARSE FAILURES: {self.parse_failures}/{self.raw_count} "
                    f"({failure_rate:.1%}) exceeds 5% threshold"
                )

        # 3. At least 1 high-risk country found (sanity check)
        if len(high_risk) == 0:
            self.assertion_errors.append("SANITY: Zero high-risk countries found")

        # 4. No duplicate country codes remain after dedup
        codes = [a.country_code for a in (list(prohibited) + list(high_risk)) if a.country_code]
        seen_codes: set[str] = set()
        for code in codes:
            if code in seen_codes:
                self.assertion_errors.append(f"DUPLICATE: Country code '{code}' appears more than once")
            seen_codes.add(code)

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
            lines.append("  [OK] No prohibited countries leaked into high-risk list")
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
        parsed = parse_advisory(raw)
        if parsed:
            advisories.append(parsed)
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

    # Filter to high-risk only, separating prohibited countries
    prohibited, high_risk = filter_high_risk(advisories)

    # Populate verification details
    verification.populate_prohibited_audit(prohibited)
    verification.populate_high_risk_breakdown(high_risk)
    verification.compute_data_hash(prohibited + high_risk)

    print(f"\nProhibited countries (Texas EO GA-48): {len(prohibited)}")
    for adv in prohibited:
        print(f"  - {adv.country_name}")

    print(f"\nFound {len(high_risk)} additional high-risk destinations:")
    level_4 = [a for a in high_risk if a.overall_level == 4]
    level_3 = [a for a in high_risk if a.overall_level == 3]
    regional = [a for a in high_risk if a.overall_level < 3]

    print(f"  - Level 4 (Do Not Travel): {len(level_4)}")
    print(f"  - Level 3 (Reconsider Travel): {len(level_3)}")
    print(f"  - Level 1/2 with regional warnings: {len(regional)}")

    # Run verification assertions
    assertions_passed = verification.run_assertions(prohibited, high_risk)

    if args.list_only:
        print("\n" + "=" * 60)
        print("PROHIBITED COUNTRIES (Texas EO GA-48)")
        print("=" * 60)
        for name, info in PROHIBITED_COUNTRIES.items():
            includes = f" (incl. {', '.join(info['includes'])})" if info['includes'] else ""
            print(f"[PROHIBITED] {name}{includes}")

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
    create_report(prohibited, high_risk, output_path)

    # Write verification log alongside PDF
    verification.write(verification_path)

    print(f"\nReport saved to: {output_path.absolute()}")
    print(f"Verification log: {verification_path.absolute()}")
    print(f"Data hash: {verification.data_hash}")
    print("Stay safe out there!")

    return 0


if __name__ == "__main__":
    sys.exit(main())
