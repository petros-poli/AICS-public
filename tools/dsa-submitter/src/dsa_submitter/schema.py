"""The Commission's DSA Transparency Database submission schema, verbatim.

Single source of truth for every field name, allowed value and constraint the
submission endpoint documents. Nothing in this module is invented: each list is
copied from the official API documentation page
(https://transparency.dsa.ec.europa.eu/page/api-documentation, API path version
``v1``; the same rules are enforced server-side by StatementStoreRequest.php).
``validate_statement`` mirrors the documented rules so a payload is checked
locally before it is ever POSTed.

Endpoint (both environments serve the same paths):

* sandbox:    https://sandbox.sor.dsa.ec.europa.eu/api/v1/statement
* production: https://transparency.dsa.ec.europa.eu/api/v1/statement

Authentication is ``Authorization: Bearer <token>`` with ``Accept`` and
``Content-Type`` ``application/json``. Success is ``201 Created``; the response
body echoes the statement plus ``uuid``, ``id``, ``created_at``, ``permalink``,
``self`` and ``puid``. Validation failures are ``422`` with
``{"message": ..., "errors": {field: [messages]}}``; resubmitting an existing
``puid`` is a 422 that carries ``existing`` (the previously created statement).
"""

from __future__ import annotations

import re
from datetime import date

API_VERSION = "v1"
SANDBOX_STATEMENT_URL = "https://sandbox.sor.dsa.ec.europa.eu/api/v1/statement"
PRODUCTION_STATEMENT_URL = "https://transparency.dsa.ec.europa.eu/api/v1/statement"
DOCUMENTATION_URL = "https://transparency.dsa.ec.europa.eu/page/api-documentation"

DECISION_VISIBILITY = (
    "DECISION_VISIBILITY_CONTENT_REMOVED",
    "DECISION_VISIBILITY_CONTENT_DISABLED",
    "DECISION_VISIBILITY_CONTENT_DEMOTED",
    "DECISION_VISIBILITY_CONTENT_AGE_RESTRICTED",
    "DECISION_VISIBILITY_CONTENT_INTERACTION_RESTRICTED",
    "DECISION_VISIBILITY_CONTENT_LABELLED",
    "DECISION_VISIBILITY_CONTENT_OTHER",
)

DECISION_MONETARY = (
    "DECISION_MONETARY_SUSPENSION",
    "DECISION_MONETARY_TERMINATION",
    "DECISION_MONETARY_OTHER",
)

DECISION_PROVISION = (
    "DECISION_PROVISION_PARTIAL_SUSPENSION",
    "DECISION_PROVISION_TOTAL_SUSPENSION",
    "DECISION_PROVISION_PARTIAL_TERMINATION",
    "DECISION_PROVISION_TOTAL_TERMINATION",
)

DECISION_ACCOUNT = (
    "DECISION_ACCOUNT_SUSPENDED",
    "DECISION_ACCOUNT_TERMINATED",
)

ACCOUNT_TYPES = (
    "ACCOUNT_TYPE_BUSINESS",
    "ACCOUNT_TYPE_PRIVATE",
)

DECISION_GROUNDS = (
    "DECISION_GROUND_ILLEGAL_CONTENT",
    "DECISION_GROUND_INCOMPATIBLE_CONTENT",
)

CONTENT_TYPES = (
    "CONTENT_TYPE_APP",
    "CONTENT_TYPE_AUDIO",
    "CONTENT_TYPE_IMAGE",
    "CONTENT_TYPE_PRODUCT",
    "CONTENT_TYPE_SYNTHETIC_MEDIA",
    "CONTENT_TYPE_TEXT",
    "CONTENT_TYPE_VIDEO",
    "CONTENT_TYPE_OTHER",
)

STATEMENT_CATEGORIES = (
    "STATEMENT_CATEGORY_ANIMAL_WELFARE",
    "STATEMENT_CATEGORY_CONSUMER_INFORMATION",
    "STATEMENT_CATEGORY_CYBER_VIOLENCE",
    "STATEMENT_CATEGORY_CYBER_VIOLENCE_AGAINST_WOMEN",
    "STATEMENT_CATEGORY_DATA_PROTECTION_AND_PRIVACY_VIOLATIONS",
    "STATEMENT_CATEGORY_ILLEGAL_OR_HARMFUL_SPEECH",
    "STATEMENT_CATEGORY_INTELLECTUAL_PROPERTY_INFRINGEMENTS",
    "STATEMENT_CATEGORY_NEGATIVE_EFFECTS_ON_CIVIC_DISCOURSE_OR_ELECTIONS",
    "STATEMENT_CATEGORY_NOT_SPECIFIED_NOTICE",
    "STATEMENT_CATEGORY_OTHER_VIOLATION_TC",
    "STATEMENT_CATEGORY_PROTECTION_OF_MINORS",
    "STATEMENT_CATEGORY_RISK_FOR_PUBLIC_SECURITY",
    "STATEMENT_CATEGORY_SCAMS_AND_FRAUD",
    "STATEMENT_CATEGORY_SELF_HARM",
    "STATEMENT_CATEGORY_UNSAFE_AND_PROHIBITED_PRODUCTS",
    "STATEMENT_CATEGORY_VIOLENCE",
)

# The optional category_specification keywords (same membership as the
# documentation's list; order is irrelevant to validation).
CATEGORY_SPECIFICATIONS = (
    "KEYWORD_ADULT_SEXUAL_MATERIAL",
    "KEYWORD_AGE_SPECIFIC_RESTRICTIONS",
    "KEYWORD_AGE_SPECIFIC_RESTRICTIONS_MINORS",
    "KEYWORD_ANIMAL_HARM",
    "KEYWORD_BIOMETRIC_DATA_BREACH",
    "KEYWORD_BULLYING_AGAINST_GIRLS",
    "KEYWORD_CHILD_SEXUAL_ABUSE_MATERIAL",
    "KEYWORD_CHILD_SEXUAL_ABUSE_MATERIAL_DEEPFAKE",
    "KEYWORD_CONTENT_PROMOTING_EATING_DISORDERS",
    "KEYWORD_COORDINATED_HARM",
    "KEYWORD_COPYRIGHT_INFRINGEMENT",
    "KEYWORD_CYBER_BULLYING_INTIMIDATION",
    "KEYWORD_CYBER_HARASSMENT",
    "KEYWORD_CYBER_HARASSMENT_AGAINST_WOMEN",
    "KEYWORD_CYBER_INCITEMENT",
    "KEYWORD_CYBER_STALKING",
    "KEYWORD_CYBER_STALKING_AGAINST_WOMEN",
    "KEYWORD_DATA_FALSIFICATION",
    "KEYWORD_DEFAMATION",
    "KEYWORD_DESIGN_INFRINGEMENT",
    "KEYWORD_DISCRIMINATION",
    "KEYWORD_FEMALE_GENDERED_DISINFORMATION",
    "KEYWORD_GEOGRAPHIC_INDICATIONS_INFRINGEMENT",
    "KEYWORD_GEOGRAPHICAL_REQUIREMENTS",
    "KEYWORD_GOODS_SERVICES_NOT_PERMITTED",
    "KEYWORD_GROOMING_SEXUAL_ENTICEMENT_MINORS",
    "KEYWORD_HATE_SPEECH",
    "KEYWORD_HIDDEN_ADVERTISEMENT",
    "KEYWORD_HUMAN_EXPLOITATION",
    "KEYWORD_HUMAN_TRAFFICKING",
    "KEYWORD_ILLEGAL_ORGANIZATIONS",
    "KEYWORD_IMPERSONATION_ACCOUNT_HIJACKING",
    "KEYWORD_INAUTHENTIC_ACCOUNTS",
    "KEYWORD_INAUTHENTIC_LISTINGS",
    "KEYWORD_INAUTHENTIC_USER_REVIEWS",
    "KEYWORD_INCITEMENT_AGAINST_WOMEN",
    "KEYWORD_INCITEMENT_VIOLENCE_HATRED",
    "KEYWORD_INSUFFICIENT_INFORMATION_ON_TRADERS",
    "KEYWORD_LANGUAGE_REQUIREMENTS",
    "KEYWORD_MISINFORMATION_DISINFORMATION",
    "KEYWORD_MISLEADING_INFO_CONSUMER_RIGHTS",
    "KEYWORD_MISLEADING_INFO_GOODS_SERVICES",
    "KEYWORD_MISSING_PROCESSING_GROUND",
    "KEYWORD_NON_CONSENSUAL_IMAGE_SHARING",
    "KEYWORD_NON_CONSENSUAL_IMAGE_SHARING_AGAINST_WOMEN",
    "KEYWORD_NON_CONSENSUAL_MATERIAL_DEEPFAKE",
    "KEYWORD_NON_CONSENSUAL_MATERIAL_DEEPFAKE_AGAINST_WOMEN",
    "KEYWORD_NONCOMPLIANCE_PRICING",
    "KEYWORD_NUDITY",
    "KEYWORD_PATENT_INFRINGEMENT",
    "KEYWORD_PHISHING",
    "KEYWORD_PROHIBITED_PRODUCTS",
    "KEYWORD_PYRAMID_SCHEMES",
    "KEYWORD_RIGHT_TO_BE_FORGOTTEN",
    "KEYWORD_RISK_ENVIRONMENTAL_DAMAGE",
    "KEYWORD_RISK_PUBLIC_HEALTH",
    "KEYWORD_SELF_MUTILATION",
    "KEYWORD_STALKING",
    "KEYWORD_SUICIDE",
    "KEYWORD_TERRORIST_CONTENT",
    "KEYWORD_TRADE_SECRET_INFRINGEMENT",
    "KEYWORD_TRADEMARK_INFRINGEMENT",
    "KEYWORD_TRAFFICKING_WOMEN_GIRLS",
    "KEYWORD_UNLAWFUL_SALE_ANIMALS",
    "KEYWORD_UNSAFE_CHALLENGES",
    "KEYWORD_UNSAFE_PRODUCTS",
    "KEYWORD_VIOLATION_EU_LAW",
    "KEYWORD_VIOLATION_NATIONAL_LAW",
    "KEYWORD_OTHER",
)

# EU/EEA 2-letter codes exactly as the documentation lists them (GR, not EL).
TERRITORIAL_SCOPES = (
    "AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "ES", "FI",
    "FR", "GR", "HR", "HU", "IE", "IS", "IT", "LI", "LT", "LU",
    "LV", "MT", "NL", "NO", "PL", "PT", "RO", "SE", "SI", "SK",
)

SOURCE_TYPES = (
    "SOURCE_ARTICLE_16",
    "SOURCE_TRUSTED_FLAGGER",
    "SOURCE_TYPE_OTHER_NOTIFICATION",
    "SOURCE_VOLUNTARY",
)

AUTOMATED_DECISIONS = (
    "AUTOMATED_DECISION_FULLY",
    "AUTOMATED_DECISION_PARTIALLY",
    "AUTOMATED_DECISION_NOT_AUTOMATED",
)

YES_NO = ("Yes", "No")

PUID_PATTERN = re.compile(r"^[a-zA-Z0-9-_]+$")
DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")
LANGUAGE_PATTERN = re.compile(r"^[A-Z]{2}$")
EAN13_PATTERN = re.compile(r"^[0-9]{13}$")

CONTENT_DATE_MIN = date(2000, 1, 1)
APPLICATION_DATE_MIN = date(2020, 1, 1)
DATE_MAX = date(2038, 1, 1)

# Documented character limits.
LIMIT_500 = ("decision_visibility_other", "decision_monetary_other", "content_type_other",
             "category_specification_other", "illegal_content_legal_ground",
             "incompatible_content_ground", "source_identity", "decision_ground_reference_url",
             "puid")
LIMIT_2000 = ("illegal_content_explanation", "incompatible_content_explanation")
DECISION_FACTS_LIMIT = 5000


def _parse_date(value, field, errors):
    if not isinstance(value, str) or not DATE_PATTERN.match(value):
        errors.append(f"{field}: must be a YYYY-MM-DD date")
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        errors.append(f"{field}: not a real calendar date")
        return None


def _check_str(value, field, allowed, errors):
    if value not in allowed:
        errors.append(f"{field}: must be one of {', '.join(allowed)}")


def _check_str_list(value, field, allowed, errors):
    if not isinstance(value, list) or not value:
        errors.append(f"{field}: must be a non-empty array")
        return
    if len(set(value)) != len(value):
        errors.append(f"{field}: duplicate values")
    for item in value:
        if item not in allowed:
            errors.append(f"{field}: {item!r} is not an allowed value")


def validate_statement(statement):
    """Return the list of documented-rule violations in a statement payload.

    An empty list means the payload passes every rule the documentation states
    for the single-statement endpoint. Mirrors StatementStoreRequest.php: the
    four decision fields are required-without-all of each other, the
    illegal/incompatible text fields are required with their ground and
    excluded otherwise, dates are YYYY-MM-DD with documented bounds, and every
    closed list is checked against the constants above.
    """
    errors = []
    if not isinstance(statement, dict):
        return ["statement: must be a JSON object"]

    # --- the four decision types: at least one must be present ---
    has_visibility = "decision_visibility" in statement
    has_monetary = "decision_monetary" in statement
    has_provision = "decision_provision" in statement
    has_account = "decision_account" in statement
    if not (has_visibility or has_monetary or has_provision or has_account):
        errors.append("decision_visibility: required when decision_monetary, "
                      "decision_provision and decision_account are all absent")

    if has_visibility:
        _check_str_list(statement["decision_visibility"], "decision_visibility",
                        DECISION_VISIBILITY, errors)
        other = "DECISION_VISIBILITY_CONTENT_OTHER" in statement["decision_visibility"]
        text = statement.get("decision_visibility_other")
        if other and not text:
            errors.append("decision_visibility_other: required with "
                          "DECISION_VISIBILITY_CONTENT_OTHER")
        if not other and text is not None:
            errors.append("decision_visibility_other: only allowed with "
                          "DECISION_VISIBILITY_CONTENT_OTHER")

    if has_monetary:
        _check_str(statement["decision_monetary"], "decision_monetary",
                   DECISION_MONETARY, errors)
        other = statement["decision_monetary"] == "DECISION_MONETARY_OTHER"
        text = statement.get("decision_monetary_other")
        if other and not text:
            errors.append("decision_monetary_other: required with DECISION_MONETARY_OTHER")
        if not other and text is not None:
            errors.append("decision_monetary_other: only allowed with DECISION_MONETARY_OTHER")

    if has_provision:
        _check_str(statement["decision_provision"], "decision_provision",
                   DECISION_PROVISION, errors)

    if has_account:
        _check_str(statement["decision_account"], "decision_account",
                   DECISION_ACCOUNT, errors)

    if "account_type" in statement:
        _check_str(statement["account_type"], "account_type", ACCOUNT_TYPES, errors)

    # --- ground and its conditional text fields ---
    ground = statement.get("decision_ground")
    _check_str(ground, "decision_ground", DECISION_GROUNDS, errors)
    illegal = ground == "DECISION_GROUND_ILLEGAL_CONTENT"
    incompatible = ground == "DECISION_GROUND_INCOMPATIBLE_CONTENT"
    if illegal:
        if not statement.get("illegal_content_legal_ground"):
            errors.append("illegal_content_legal_ground: required with "
                          "DECISION_GROUND_ILLEGAL_CONTENT")
        if not statement.get("illegal_content_explanation"):
            errors.append("illegal_content_explanation: required with "
                          "DECISION_GROUND_ILLEGAL_CONTENT")
        for field in ("incompatible_content_ground", "incompatible_content_explanation",
                      "incompatible_content_illegal"):
            if field in statement:
                errors.append(f"{field}: only allowed with DECISION_GROUND_INCOMPATIBLE_CONTENT")
    if incompatible:
        if not statement.get("incompatible_content_ground"):
            errors.append("incompatible_content_ground: required with "
                          "DECISION_GROUND_INCOMPATIBLE_CONTENT")
        if not statement.get("incompatible_content_explanation"):
            errors.append("incompatible_content_explanation: required with "
                          "DECISION_GROUND_INCOMPATIBLE_CONTENT")
        for field in ("illegal_content_legal_ground", "illegal_content_explanation"):
            if field in statement:
                errors.append(f"{field}: only allowed with DECISION_GROUND_ILLEGAL_CONTENT")
        if "incompatible_content_illegal" in statement:
            _check_str(statement["incompatible_content_illegal"],
                       "incompatible_content_illegal", YES_NO, errors)

    if "decision_ground_reference_url" in statement:
        url = statement["decision_ground_reference_url"]
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            errors.append("decision_ground_reference_url: must be a URL")

    # --- content type ---
    if "content_type" not in statement:
        errors.append("content_type: required")
    else:
        _check_str_list(statement["content_type"], "content_type", CONTENT_TYPES, errors)
        other = "CONTENT_TYPE_OTHER" in statement["content_type"]
        text = statement.get("content_type_other")
        if other and not text:
            errors.append("content_type_other: required with CONTENT_TYPE_OTHER")
        if not other and text is not None:
            errors.append("content_type_other: only allowed with CONTENT_TYPE_OTHER")

    # --- category ---
    _check_str(statement.get("category"), "category", STATEMENT_CATEGORIES, errors)
    if "category_addition" in statement:
        _check_str_list(statement["category_addition"], "category_addition",
                        STATEMENT_CATEGORIES, errors)
    if "category_specification" in statement:
        _check_str_list(statement["category_specification"], "category_specification",
                        CATEGORY_SPECIFICATIONS, errors)
        other = "KEYWORD_OTHER" in statement["category_specification"]
        text = statement.get("category_specification_other")
        if other and not text:
            errors.append("category_specification_other: required with KEYWORD_OTHER")
        if not other and text is not None:
            errors.append("category_specification_other: only allowed with KEYWORD_OTHER")

    # --- product identifier ---
    if "content_id" in statement:
        content_id = statement["content_id"]
        if not isinstance(content_id, dict) or set(content_id) - {"EAN-13"}:
            errors.append("content_id: only the EAN-13 key is accepted")
        elif "EAN-13" in content_id and not EAN13_PATTERN.match(str(content_id["EAN-13"])):
            errors.append("content_id.EAN-13: must be 13 digits")

    # --- territorial scope ---
    if "territorial_scope" not in statement:
        errors.append("territorial_scope: required")
    else:
        _check_str_list(statement["territorial_scope"], "territorial_scope",
                        TERRITORIAL_SCOPES, errors)

    if "content_language" in statement:
        language = statement["content_language"]
        if not isinstance(language, str) or not LANGUAGE_PATTERN.match(language):
            errors.append("content_language: must be an uppercase two-letter ISO 639-1 code")

    # --- dates ---
    content_date = _parse_date(statement.get("content_date"), "content_date", errors)
    if content_date and content_date < CONTENT_DATE_MIN:
        errors.append("content_date: must be after or equal to 2000-01-01")
    application_date = _parse_date(statement.get("application_date"), "application_date", errors)
    if application_date and application_date < APPLICATION_DATE_MIN:
        errors.append("application_date: must be after or equal to 2020-01-01")
    if content_date and content_date > DATE_MAX:
        errors.append("content_date: must be before or equal to 2038-01-01")
    if application_date and application_date > DATE_MAX:
        errors.append("application_date: must be before or equal to 2038-01-01")
    for field in ("end_date_account_restriction", "end_date_monetary_restriction",
                  "end_date_service_restriction", "end_date_visibility_restriction"):
        if field in statement and statement[field] is not None:
            end_date = _parse_date(statement[field], field, errors)
            if end_date and application_date and end_date < application_date:
                errors.append(f"{field}: must be after or equal to the application date")
            if end_date and end_date > DATE_MAX:
                errors.append(f"{field}: must be before or equal to 2038-01-01")

    # --- facts, source, automation, puid ---
    facts = statement.get("decision_facts")
    if not facts or not isinstance(facts, str):
        errors.append("decision_facts: required")
    elif len(facts) > DECISION_FACTS_LIMIT:
        errors.append(f"decision_facts: limited to {DECISION_FACTS_LIMIT} characters")

    _check_str(statement.get("source_type"), "source_type", SOURCE_TYPES, errors)
    if "source_identity" in statement and statement["source_type"] == "SOURCE_VOLUNTARY":
        errors.append("source_identity: not taken into account with SOURCE_VOLUNTARY")

    _check_str(statement.get("automated_detection"), "automated_detection", YES_NO, errors)
    _check_str(statement.get("automated_decision"), "automated_decision",
               AUTOMATED_DECISIONS, errors)

    puid = statement.get("puid")
    if not puid or not isinstance(puid, str):
        errors.append("puid: required")
    elif len(puid) > 500 or not PUID_PATTERN.match(puid):
        errors.append("puid: alphanumeric characters, hyphens and underscores only, "
                      "max 500 characters")

    # --- documented character limits ---
    for field in LIMIT_500:
        value = statement.get(field)
        if isinstance(value, str) and len(value) > 500:
            errors.append(f"{field}: limited to 500 characters")
    for field in LIMIT_2000:
        value = statement.get(field)
        if isinstance(value, str) and len(value) > 2000:
            errors.append(f"{field}: limited to 2000 characters")

    return errors
