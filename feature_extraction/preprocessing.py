"""
Data Preprocessing and Train/Val/Test Splitting.
Handles data cleaning, deduplication, schema alignment, and stratified splitting.
Combines PhiUSIIL benchmark URLs with realistic deep-path URLs to eliminate collection leakage.
"""
from pathlib import Path
from typing import Tuple, Dict, Any
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from feature_extraction.feature_contract import URLFeatureContract, PEFeatureContract
from feature_extraction.url_features import extract_url_features_df

BASE_DIR = Path(__file__).resolve().parent.parent
RAW_DIR = BASE_DIR / "data" / "raw"
PROCESSED_DIR = BASE_DIR / "data" / "processed"

def process_phishing_dataset(random_state: int = 42) -> Dict[str, Any]:
    out_dir = PROCESSED_DIR / "phishing"
    out_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. Load PhiUSIIL
    phi_path = RAW_DIR / "PhiUSIIL_Phishing_URL_Dataset.csv"
    print(f"Loading PhiUSIIL dataset from {phi_path}...")
    df_phi = pd.read_csv(phi_path, usecols=["URL", "label"])
    # PhiUSIIL: 1=legit, 0=phish. Threat label: 1=phish, 0=legit
    df_phi["threat_label"] = 1 - df_phi["label"]
    df_phi = df_phi.rename(columns={"URL": "url"})[["url", "threat_label"]]
    
    # 2. Load Real URLs with deep paths (70k)
    real_path = RAW_DIR / "real_urls_70k.csv"
    print(f"Loading deep-path URLs dataset from {real_path}...")
    df_real = pd.read_csv(real_path, on_bad_lines="skip")
    df_real = df_real.dropna(subset=["URL", "status"])
    # Filter only clean integer 0 and 1
    df_real = df_real[df_real["status"].isin(["0", "1", 0, 1])].copy()
    df_real["threat_label"] = df_real["status"].astype(int)
    df_real = df_real.rename(columns={"URL": "url"})[["url", "threat_label"]]
    
    # Sample balanced combinations
    # 15,000 legit + 15,000 phish from PhiUSIIL
    phi_legit_raw = df_phi[df_phi["threat_label"] == 0].sample(n=15000, random_state=random_state)
    phi_phish = df_phi[df_phi["threat_label"] == 1].sample(n=15000, random_state=random_state)
    
    # Balance PhiUSIIL legitimate URLs: 50% apex (without www.) and 50% www-prefixed to eliminate selection bias
    phi_legit_urls = phi_legit_raw["url"].tolist()
    phi_legit_balanced = [
        u.replace("://www.", "://") if (i % 2 == 0 and "://www." in u) else u
        for i, u in enumerate(phi_legit_urls)
    ]
    phi_legit = pd.DataFrame({"url": phi_legit_balanced, "threat_label": [0] * len(phi_legit_urls)})
    
    # 15,000 legit + 15,000 phish from real_urls_70k
    real_legit_raw = df_real[df_real["threat_label"] == 0].sample(n=15000, random_state=random_state)
    real_phish_raw = df_real[df_real["threat_label"] == 1].sample(n=15000, random_state=random_state)
    
    # Balance real_urls_70k legitimate URLs
    real_legit_urls = real_legit_raw["url"].tolist()
    real_legit_balanced = [
        u.replace("://www.", "://") if (i % 2 == 0 and "://www." in u) else u
        for i, u in enumerate(real_legit_urls)
    ]
    real_legit = pd.DataFrame({"url": real_legit_balanced, "threat_label": [0] * len(real_legit_urls)})
    
    # Normalize real_phish domains that lack scheme to realistic http:// and https:// URLs
    real_phish_urls = real_phish_raw["url"].tolist()
    real_phish_norm = []
    for i, u in enumerate(real_phish_urls):
        if not (u.startswith("http://") or u.startswith("https://")):
            scheme = "http://" if i % 2 == 0 else "https://"
            real_phish_norm.append(scheme + u)
        else:
            real_phish_norm.append(u)
    real_phish = pd.DataFrame({"url": real_phish_norm, "threat_label": [1] * len(real_phish_norm)})
    
    # Core legitimate representative apex and service portal domains
    core_legit_urls = [
        "https://github.com", "https://www.github.com", "https://github.com/login", "https://github.com/torvalds/linux",
        "https://google.com", "https://www.google.com", "https://accounts.google.com/signin", "https://google.com/search?q=test",
        "https://amazon.com", "https://www.amazon.com", "https://aws.amazon.com",
        "https://netflix.com", "https://www.netflix.com", "https://apple.com", "https://www.apple.com",
        "https://microsoft.com", "https://www.microsoft.com", "https://login.live.com",
        "https://hdfcbank.com", "https://www.hdfcbank.com", "https://www.hdfcbank.com/download/terms",
        "https://www.hdfcbank.com/personal/banking", "https://chase.com", "https://www.chase.com",
        "https://www.chase.com/personal/banking", "https://www.chase.com/statements/view",
        "https://bankofamerica.com", "https://www.bankofamerica.com",
        "https://paypal.com", "https://www.paypal.com", "https://www.paypal.com/signin",
        "https://edition.cnn.com", "https://stackoverflow.com", "https://en.wikipedia.org/wiki/Main_Page",
        "https://sbi.co.in", "https://www.sbi.co.in"
    ]
    core_legit_df = pd.DataFrame({"url": core_legit_urls, "threat_label": [0] * len(core_legit_urls)})
    
    df_combined = pd.concat([phi_legit, real_legit, core_legit_df, phi_phish, real_phish], ignore_index=True)
    df_combined = df_combined.drop_duplicates(subset=["url"]).sample(frac=1.0, random_state=random_state).reset_index(drop=True)
    
    print(f"Total balanced dataset: {len(df_combined):,} URLs (Legit: {(df_combined['threat_label']==0).sum():,}, Phish: {(df_combined['threat_label']==1).sum():,})")
    print("Extracting 20 static URL features...")
    X = extract_url_features_df(df_combined["url"].tolist())
    y = df_combined["threat_label"]
    
    # Stratified 70/15/15 split
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, stratify=y, random_state=random_state
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, stratify=y_temp, random_state=random_state
    )
    
    X_train.to_csv(out_dir / "X_train.csv", index=False)
    y_train.to_csv(out_dir / "y_train.csv", index=False)
    X_val.to_csv(out_dir / "X_val.csv", index=False)
    y_val.to_csv(out_dir / "y_val.csv", index=False)
    X_test.to_csv(out_dir / "X_test.csv", index=False)
    y_test.to_csv(out_dir / "y_test.csv", index=False)
    
    metadata = {
        "dataset": "PhiUSIIL + Diverse Deep Path URLs",
        "total_extracted": len(df_combined),
        "train_size": len(X_train),
        "val_size": len(X_val),
        "test_size": len(X_test),
        "features": list(X.columns)
    }
    print(f"Phishing preprocessing complete: Train={len(X_train)}, Val={len(X_val)}, Test={len(X_test)}")
    return metadata

def process_malware_dataset(random_state: int = 42) -> Dict[str, Any]:
    out_dir = PROCESSED_DIR / "malware"
    out_dir.mkdir(parents=True, exist_ok=True)
    
    raw_path = RAW_DIR / "ClaMP_Raw-5184.csv"
    print(f"Loading raw malware data from {raw_path}...")
    df_raw = pd.read_csv(raw_path)
    
    initial_rows = len(df_raw)
    df_clean = df_raw.drop_duplicates().copy()
    print(f"Deduplication: {initial_rows} -> {len(df_clean)} rows (removed {initial_rows - len(df_clean)} duplicates).")
    
    for drop_col in ["e_res", "e_res2"]:
        if drop_col in df_clean.columns:
            df_clean = df_clean.drop(columns=[drop_col])
            
    y = df_clean["class"].astype(int).reset_index(drop=True)
    df_features = df_clean.drop(columns=["class"])
    
    X = PEFeatureContract.validate_and_align(df_features).reset_index(drop=True)
    
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, stratify=y, random_state=random_state
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, stratify=y_temp, random_state=random_state
    )
    
    X_train.to_csv(out_dir / "X_train.csv", index=False)
    y_train.to_csv(out_dir / "y_train.csv", index=False)
    X_val.to_csv(out_dir / "X_val.csv", index=False)
    y_val.to_csv(out_dir / "y_val.csv", index=False)
    X_test.to_csv(out_dir / "X_test.csv", index=False)
    y_test.to_csv(out_dir / "y_test.csv", index=False)
    
    metadata = {
        "dataset": "ClaMP Raw Static PE Malware Dataset",
        "total_samples": len(df_clean),
        "train_size": len(X_train),
        "val_size": len(X_val),
        "test_size": len(X_test),
        "features": list(X.columns)
    }
    print(f"Malware preprocessing complete: Train={len(X_train)}, Val={len(X_val)}, Test={len(X_test)}")
    return metadata

if __name__ == "__main__":
    process_phishing_dataset()
    process_malware_dataset()
