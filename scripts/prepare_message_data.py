"""
Data Ingestion, Cleaning, and Stratified Splitting for GenAI and Human Phishing Messages.
Processes raw corpora into standardized text and stylometric feature datasets.
Fails loudly if raw datasets are missing. Zero synthetic data generation.
"""
import sys
import os
import re
import html
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

from feature_extraction.message_features import extract_message_features_df
from feature_extraction.feature_contract import MessageFeatureContract

BASE_DIR = Path(__file__).resolve().parent.parent
RAW_DIR = BASE_DIR / "data" / "raw" / "messages"
PROCESSED_DIR = BASE_DIR / "data" / "processed" / "messages"

LABEL_MAPPING = {
    "legitimate": 0,
    "human_phishing": 1,
    "ai_phishing": 2
}

REVERSE_LABEL_MAPPING = {v: k for k, v in LABEL_MAPPING.items()}

def clean_email_text(text: str) -> str:
    """
    Cleans raw email / message content:
    - Strips email RFC headers (From, To, Subject, Received, etc.)
    - Removes HTML tags and unescapes HTML entities
    - Removes email reply chains (> quotes, 'On ... wrote:')
    - Removes standard email signature sign-offs
    - Normalizes excessive whitespace
    """
    if not isinstance(text, str):
        return ""

    s = text

    # Unescape HTML entities
    s = html.unescape(s)

    # Strip HTML tags
    s = re.sub(r"<[^>]+>", " ", s)

    # Strip common email header lines if present at the start of text
    lines = s.splitlines()
    body_lines = []
    in_header = True
    header_pattern = re.compile(
        r"^(?:from|to|subject|date|received|return-path|delivered-to|message-id|mime-version|content-type|content-transfer-encoding|x-[\w-]+):",
        re.IGNORECASE
    )
    reply_pattern = re.compile(r"^\s*>|^\s*On\s+.*wrote:\s*$", re.IGNORECASE)

    for line in lines:
        stripped = line.strip()
        if in_header:
            if header_pattern.match(stripped):
                continue
            elif stripped == "":
                in_header = False
                continue
            else:
                in_header = False

        # Filter quoted replies
        if reply_pattern.match(stripped):
            continue

        # Stop at email signature delimiters
        if stripped in {"--", "---", "-- ", "___"}:
            break

        body_lines.append(line)

    cleaned = "\n".join(body_lines)
    # Normalize whitespaces
    cleaned = re.sub(r"[ \t]+", " ", cleaned)
    cleaned = re.sub(r"\n\s*\n+", "\n", cleaned).strip()
    return cleaned

def load_raw_sources() -> pd.DataFrame:
    """
    Loads raw datasets from data/raw/messages/
    Expected structure:
    - data/raw/messages/ai_phishing.csv (or .json/.txt)
    - data/raw/messages/human_phishing.csv (or .json/.txt)
    - data/raw/messages/legitimate.csv (or .json/.txt)
    """
    if not RAW_DIR.exists():
        raise FileNotFoundError(
            f"Raw messages directory not found: {RAW_DIR}\n"
            f"Please create the directory and place the required raw corpus files:\n"
            f"  - {RAW_DIR / 'ai_phishing.csv'} (GPT-4o phishing corpus)\n"
            f"  - {RAW_DIR / 'human_phishing.csv'} (Nazario / Nigerian Fraud email corpus)\n"
            f"  - {RAW_DIR / 'legitimate.csv'} (Legitimate banking / formal email corpus)"
        )

    expected_files = {
        "ai_phishing": [RAW_DIR / "ai_phishing.csv", RAW_DIR / "opara_gpt4o.csv", RAW_DIR / "ai_phishing.json"],
        "human_phishing": [RAW_DIR / "human_phishing.csv", RAW_DIR / "nazario.csv", RAW_DIR / "human_phishing.json"],
        "legitimate": [RAW_DIR / "legitimate.csv", RAW_DIR / "enron_sample.csv", RAW_DIR / "legitimate.json"]
    }

    records = []

    for label, candidate_paths in expected_files.items():
        found_file = None
        for path in candidate_paths:
            if path.exists():
                found_file = path
                break

        if not found_file:
            raise FileNotFoundError(
                f"Missing required raw dataset for class '{label}'.\n"
                f"Expected one of: {[str(p) for p in candidate_paths]}\n"
                f"Please ensure authentic data files are present in {RAW_DIR} before running."
            )

        print(f"Loading '{label}' from: {found_file.name}")
        if found_file.suffix == ".csv":
            df = pd.read_csv(found_file)
            # Find candidate text column
            text_col = None
            for candidate in ["text", "body", "content", "email_text", "message", "Email Text"]:
                if candidate in df.columns:
                    text_col = candidate
                    break
            if not text_col:
                text_col = df.columns[0]
            for val in df[text_col].dropna():
                records.append({
                    "text": str(val),
                    "label": label,
                    "source": found_file.name
                })
        elif found_file.suffix == ".json":
            df = pd.read_json(found_file)
            text_col = "text" if "text" in df.columns else df.columns[0]
            for val in df[text_col].dropna():
                records.append({
                    "text": str(val),
                    "label": label,
                    "source": found_file.name
                })

    all_df = pd.DataFrame(records)
    print(f"Loaded {len(all_df)} raw records from all sources.")
    return all_df

def prepare_message_dataset():
    print("=" * 60)
    print("GENAI & HUMAN PHISHING MESSAGE DATA PREPARATION PIPELINE")
    print("=" * 60)

    raw_df = load_raw_sources()

    # 1. Clean text
    print("\nCleaning message texts (stripping headers, HTML tags, replies, signatures)...")
    raw_df["text_clean"] = raw_df["text"].apply(clean_email_text)

    # 2. Filter short rows (< 20 chars)
    initial_count = len(raw_df)
    df_filtered = raw_df[raw_df["text_clean"].str.len() >= 20].copy()
    dropped_short = initial_count - len(df_filtered)
    print(f"Dropped {dropped_short} records with text length < 20 characters.")

    # 3. Deduplicate on normalized text
    before_dedup = len(df_filtered)
    df_dedup = df_filtered.drop_duplicates(subset=["text_clean"]).copy()
    dropped_dupes = before_dedup - len(df_dedup)
    print(f"Deduplicated: removed {dropped_dupes} duplicate messages. Remaining: {len(df_dedup)}")

    # 4. Map integer labels
    df_dedup["numeric_label"] = df_dedup["label"].map(LABEL_MAPPING)

    # 5. Extract 24 stylometric features
    print(f"\nExtracting 24 stylometric features for {len(df_dedup)} messages...")
    texts = df_dedup["text_clean"].tolist()
    features_df = extract_message_features_df(texts)
    MessageFeatureContract.validate_and_align(features_df)

    # Combine metadata with features
    df_full = df_dedup.reset_index(drop=True)
    features_df = features_df.reset_index(drop=True)

    # 6. Stratified Split 70% Train / 15% Val / 15% Test
    print("\nPerforming Stratified 70/15/15 train/val/test split (random_state=42)...")
    
    indices = np.arange(len(df_full))
    train_idx, temp_idx = train_test_split(
        indices,
        test_size=0.30,
        random_state=42,
        stratify=df_full["numeric_label"]
    )
    val_idx, test_idx = train_test_split(
        temp_idx,
        test_size=0.50,
        random_state=42,
        stratify=df_full.iloc[temp_idx]["numeric_label"]
    )

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    # Save feature splits
    X_train = features_df.iloc[train_idx]
    X_val = features_df.iloc[val_idx]
    X_test = features_df.iloc[test_idx]

    y_train = df_full.iloc[train_idx][["numeric_label"]].rename(columns={"numeric_label": "threat_label"})
    y_val = df_full.iloc[val_idx][["numeric_label"]].rename(columns={"numeric_label": "threat_label"})
    y_test = df_full.iloc[test_idx][["numeric_label"]].rename(columns={"numeric_label": "threat_label"})

    # Save text splits for transformer fine-tuning
    text_train = df_full.iloc[train_idx][["text_clean", "label", "source"]].rename(columns={"text_clean": "text"})
    text_val = df_full.iloc[val_idx][["text_clean", "label", "source"]].rename(columns={"text_clean": "text"})
    text_test = df_full.iloc[test_idx][["text_clean", "label", "source"]].rename(columns={"text_clean": "text"})

    X_train.to_csv(PROCESSED_DIR / "X_train.csv", index=False)
    y_train.to_csv(PROCESSED_DIR / "y_train.csv", index=False)
    X_val.to_csv(PROCESSED_DIR / "X_val.csv", index=False)
    y_val.to_csv(PROCESSED_DIR / "y_val.csv", index=False)
    X_test.to_csv(PROCESSED_DIR / "X_test.csv", index=False)
    y_test.to_csv(PROCESSED_DIR / "y_test.csv", index=False)

    text_train.to_csv(PROCESSED_DIR / "text_train.csv", index=False)
    text_val.to_csv(PROCESSED_DIR / "text_val.csv", index=False)
    text_test.to_csv(PROCESSED_DIR / "text_test.csv", index=False)

    print(f"\nSuccessfully wrote processed datasets to: {PROCESSED_DIR}")
    print("\nClass Distribution per Split:")
    for split_name, split_y in [("Train", y_train), ("Validation", y_val), ("Test", y_test)]:
        counts = split_y["threat_label"].value_counts().to_dict()
        readable_counts = {REVERSE_LABEL_MAPPING.get(k, k): v for k, v in counts.items()}
        print(f"  {split_name} ({len(split_y)} total): {readable_counts}")

    print("=" * 60)

if __name__ == "__main__":
    prepare_message_dataset()
