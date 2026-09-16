"""
Message Stylometric Feature Extractor.
Extracts 24 deterministic stylometric and linguistic features from message text using spaCy and Python.
CRITICAL: Operates entirely locally and statically — no network calls at inference time.
"""
import re
import string
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Optional
from feature_extraction.feature_contract import MessageFeatureContract

# Pre-compiled regex patterns
URL_REGEX = re.compile(
    r"(?:https?://|www\.)[^\s/$.?#].[^\s]*|https?://[^\s]+|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s]*)?",
    re.IGNORECASE
)

# Lexicons for domain heuristics
URGENCY_PHRASES = [
    "immediately", "urgent", "urgently", "expire", "expires", "expiring",
    "expiration", "suspend", "suspended", "suspension", "verify now",
    "within 24 hours", "within 48 hours", "within 12 hours", "act now",
    "final notice", "action required", "immediate action", "limited time",
    "terminate", "terminated", "locked", "compromised", "unauthorized access"
]

CREDENTIAL_PHRASES = [
    "password", "otp", "pin", "cvv", "cvv2", "kyc", "account number",
    "login", "log in", "verify identity", "passcode", "security code",
    "credentials", "bank account", "debit card", "credit card", "ssn",
    "social security", "card number", "routing number"
]

GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear sir", "dear madam", "dear sir/madam",
    "dear client", "dear member", "dear account holder", "valued customer",
    "valuable customer", "dear email user", "dear cardholder", "attention customer",
    "dear friend", "dear subscriber"
]

MODAL_WORDS = {
    "must", "should", "need", "needs", "needed", "ought", "shall",
    "would", "could", "can", "may", "might"
}

FIRST_PERSON_PRONOUNS = {"i", "me", "my", "mine", "myself", "we", "us", "our", "ours", "ourselves"}
SECOND_PERSON_PRONOUNS = {"you", "your", "yours", "yourself", "yourselves"}
THIRD_PERSON_PRONOUNS = {
    "he", "him", "his", "himself", "she", "her", "hers", "herself",
    "it", "its", "itself", "they", "them", "their", "theirs", "themselves"
}

_nlp = None

def get_spacy_nlp():
    """Lazy loader for spaCy English pipeline with fallback for environments lacking downloads."""
    global _nlp
    if _nlp is None:
        try:
            import spacy
            try:
                _nlp = spacy.load("en_core_web_sm", disable=["ner"])
            except Exception:
                # If en_core_web_sm is not installed, fallback to blank English model with sentencizer
                _nlp = spacy.blank("en")
                if "sentencizer" not in _nlp.pipe_names:
                    _nlp.add_pipe("sentencizer")
        except Exception:
            _nlp = None
    return _nlp

def _empty_features() -> Dict[str, float]:
    """Returns a valid, zero-safe feature dictionary aligned with MessageFeatureContract."""
    return {name: 0.0 for name in MessageFeatureContract.FEATURE_NAMES}

def extract_message_features(text: str) -> Dict[str, float]:
    """
    Extracts all 24 deterministic stylometric features from a message or email string.
    Zero-safe for empty/whitespace strings — never raises and never produces NaNs.
    """
    if not isinstance(text, str):
        text = str(text) if text is not None else ""
        
    text_clean = text.strip()
    if not text_clean or len(text_clean) == 0:
        return _empty_features()

    char_count = float(len(text_clean))
    nlp = get_spacy_nlp()
    
    # Process text with spaCy
    if nlp is not None:
        try:
            doc = nlp(text_clean)
        except Exception:
            doc = None
    else:
        doc = None

    # Sentence and Token level analysis
    if doc is not None:
        sentences = list(doc.sents) if doc.has_annotation("SENTENCE") or hasattr(doc, "sents") else [doc]
        if not sentences:
            sentences = [doc]
        tokens = [token for token in doc if not token.is_space]
    else:
        # Fallback basic tokenization
        raw_sents = [s.strip() for s in re.split(r"[.!?]+", text_clean) if s.strip()]
        sentences = raw_sents if raw_sents else [text_clean]
        tokens = [t for t in re.findall(r"\b\w+\b|[^\w\s]", text_clean) if t.strip()]

    word_count = float(len(tokens))
    sentence_count = float(max(1, len(sentences)))

    # Handle single or zero-token edge case safely
    if word_count == 0:
        res = _empty_features()
        res["CharCount"] = char_count
        return res

    # 1. Length & Diversity metrics
    sentence_lengths = []
    for s in sentences:
        if hasattr(s, "__iter__"):
            s_len = len([t for t in s if (hasattr(t, "is_space") and not t.is_space) or (isinstance(t, str) and t.strip())])
        else:
            s_len = len(str(s).split())
        sentence_lengths.append(max(1, s_len))

    avg_sentence_length = float(np.mean(sentence_lengths)) if sentence_lengths else 0.0
    sentence_length_variance = float(np.var(sentence_lengths)) if len(sentence_lengths) > 1 else 0.0

    token_texts_lower = [t.text.lower() if hasattr(t, "text") else str(t).lower() for t in tokens]
    unique_tokens = set(token_texts_lower)
    lexical_diversity = float(len(unique_tokens) / word_count) if word_count > 0 else 0.0

    word_token_lengths = [len(t) for t in token_texts_lower if t.isalnum()]
    avg_word_length = float(np.mean(word_token_lengths)) if word_token_lengths else 0.0

    # 2. Syntactic & Linguistic POS Features
    imperative_verb_count = 0
    subordinate_clause_count = 0
    passive_voice_count = 0
    modal_verb_count = 0
    stopword_count = 0
    function_word_count = 0
    first_person_count = 0
    second_person_count = 0
    third_person_count = 0

    if doc is not None and doc.has_annotation("TAG"):
        for sent in doc.sents:
            # Check clause start for imperative verbs (Base form VB at sentence/clause start)
            first_non_punct = None
            for token in sent:
                if not token.is_punct and not token.is_space:
                    first_non_punct = token
                    break
            if first_non_punct and first_non_punct.tag_ == "VB":
                imperative_verb_count += 1

        for token in doc:
            tag = token.tag_
            dep = token.dep_
            pos = token.pos_
            t_lower = token.text.lower()

            # Clauses: subordinate conjunctions, adverbial clauses, complement clauses
            if dep in {"mark", "advcl", "ccomp", "xcomp", "acl", "relcl"}:
                subordinate_clause_count += 1

            # Passive voice constructions (auxpass / nsubjpass)
            if dep in {"auxpass", "nsubjpass"} or (token.dep_ == "aux" and token.head.dep_ == "pass"):
                passive_voice_count += 1

            # Modals
            if tag == "MD" or t_lower in MODAL_WORDS:
                modal_verb_count += 1

            # Stopwords & Function words
            if token.is_stop:
                stopword_count += 1
            if pos in {"DET", "ADP", "CCONJ", "SCONJ", "PRON", "AUX"}:
                function_word_count += 1

            # Pronoun ratios
            if t_lower in FIRST_PERSON_PRONOUNS:
                first_person_count += 1
            elif t_lower in SECOND_PERSON_PRONOUNS:
                second_person_count += 1
            elif t_lower in THIRD_PERSON_PRONOUNS:
                third_person_count += 1
    else:
        # Fallback heuristics
        for t_lower in token_texts_lower:
            if t_lower in FIRST_PERSON_PRONOUNS:
                first_person_count += 1
            elif t_lower in SECOND_PERSON_PRONOUNS:
                second_person_count += 1
            elif t_lower in THIRD_PERSON_PRONOUNS:
                third_person_count += 1
            if t_lower in MODAL_WORDS:
                modal_verb_count += 1

    clause_density = float(subordinate_clause_count / sentence_count)
    first_person_ratio = float(first_person_count / word_count)
    second_person_ratio = float(second_person_count / word_count)
    third_person_ratio = float(third_person_count / word_count)
    stopword_ratio = float(stopword_count / word_count)
    function_word_ratio = float(function_word_count / word_count)

    # 3. Lexical and Domain Lexicons
    text_lower = text_clean.lower()
    
    urgency_count = sum(text_lower.count(phrase) for phrase in URGENCY_PHRASES)
    credential_count = sum(text_lower.count(phrase) for phrase in CREDENTIAL_PHRASES)

    # Generic Greeting Detection
    greeting_generic_flag = 0.0
    for greeting in GENERIC_GREETINGS:
        if greeting in text_lower[:120]:
            greeting_generic_flag = 1.0
            break

    # 4. Punctuation, Digits, URLs, Case
    exclamation_count = float(text_clean.count("!"))
    exclamation_ratio = float(exclamation_count / sentence_count)

    uppercase_words = sum(1 for t in tokens if (t.text if hasattr(t, "text") else str(t)).isupper() and len(t) > 1)
    uppercase_word_ratio = float(uppercase_words / word_count)

    punct_count = sum(1 for c in text_clean if c in string.punctuation)
    punctuation_ratio = float(punct_count / char_count)

    digit_count = sum(1 for c in text_clean if c.isdigit())
    digit_ratio = float(digit_count / char_count)

    url_matches = URL_REGEX.findall(text_clean)
    url_count = float(len(url_matches))

    features = {
        "CharCount": float(round(char_count, 4)),
        "WordCount": float(round(word_count, 4)),
        "SentenceCount": float(round(sentence_count, 4)),
        "AvgSentenceLength": float(round(avg_sentence_length, 4)),
        "SentenceLengthVariance": float(round(sentence_length_variance, 4)),
        "LexicalDiversity": float(round(lexical_diversity, 4)),
        "AvgWordLength": float(round(avg_word_length, 4)),
        "ImperativeVerbCount": float(round(imperative_verb_count, 4)),
        "ClauseDensity": float(round(clause_density, 4)),
        "FirstPersonPronounRatio": float(round(first_person_ratio, 4)),
        "SecondPersonPronounRatio": float(round(second_person_ratio, 4)),
        "ThirdPersonPronounRatio": float(round(third_person_ratio, 4)),
        "UrgencyWordCount": float(round(urgency_count, 4)),
        "CredentialRequestCount": float(round(credential_count, 4)),
        "ExclamationRatio": float(round(exclamation_ratio, 4)),
        "UppercaseWordRatio": float(round(uppercase_word_ratio, 4)),
        "PunctuationRatio": float(round(punctuation_ratio, 4)),
        "DigitRatio": float(round(digit_ratio, 4)),
        "URLCount": float(round(url_count, 4)),
        "StopwordRatio": float(round(stopword_ratio, 4)),
        "FunctionWordRatio": float(round(function_word_ratio, 4)),
        "PassiveVoiceCount": float(round(passive_voice_count, 4)),
        "ModalVerbCount": float(round(modal_verb_count, 4)),
        "GreetingGenericFlag": float(round(greeting_generic_flag, 4))
    }
    return features

def extract_message_features_df(texts: List[str]) -> pd.DataFrame:
    """
    Extracts stylometric features for a batch of messages and validates against MessageFeatureContract.
    """
    rows = [extract_message_features(t) for t in texts]
    df = pd.DataFrame(rows)
    return MessageFeatureContract.validate_and_align(df)
