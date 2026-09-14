import pandas as pd
import numpy as np
from pathlib import Path
import json

BASE_DIR = Path(__file__).resolve().parent.parent
RAW_DIR = BASE_DIR / "data" / "raw"
DOCS_DIR = BASE_DIR / "docs"

def verify_phiusiil():
    print("=" * 60)
    print("VERIFYING PHIUSIIL DATASET (PHISHING)")
    print("=" * 60)
    csv_path = RAW_DIR / "PhiUSIIL_Phishing_URL_Dataset.csv"
    assert csv_path.exists(), f"File not found: {csv_path}"
    
    df = pd.read_csv(csv_path)
    total_rows, total_cols = df.shape
    print(f"Total Rows: {total_rows:,}")
    print(f"Total Columns: {total_cols}")
    
    # Class distribution
    # In PhiUSIIL: label is typically in 'label' column: 1=legitimate, 0=phishing
    target_col = 'label'
    print(f"\nTarget Column: '{target_col}'")
    val_counts = df[target_col].value_counts().to_dict()
    print("Class Distribution:")
    for k, v in val_counts.items():
        print(f"  Class {k}: {v:,} ({v/total_rows*100:.2f}%)")
    
    # Missing values
    missing = df.isnull().sum()
    missing_cols = missing[missing > 0]
    print(f"\nMissing values in columns: {len(missing_cols)}")
    if len(missing_cols) > 0:
        for col, count in missing_cols.items():
            print(f"  {col}: {count}")
    else:
        print("  No missing values found across any columns.")
        
    # Duplicates
    dup_count = df.duplicated().sum()
    print(f"\nExact Duplicate Rows: {dup_count:,}")
    
    # Identify URL-extractable vs HTML/content features
    # Columns in PhiUSIIL:
    cols = list(df.columns)
    print(f"\nAll {len(cols)} columns in dataset:")
    print(cols)
    
    # Non-feature identifiers
    metadata_cols = ['FILENAME', 'URL', 'Domain', 'TLD']
    
    # Features requiring HTML/page fetch (cannot be extracted from raw URL string)
    html_page_features = [
        'LineOfCode', 'LargestLineLength', 'HasTitle', 'Title',
        'DomainTitleMatchScore', 'URLTitleMatchScore', 'HasFavicon',
        'Robots', 'IsResponsive', 'NoOfURLRedirect', 'NoOfSelfRedirect',
        'HasDescription', 'NoOfPopup', 'NoOfiFrame', 'HasExternalFormSubmit',
        'HasSocialNet', 'HasSubmitButton', 'HasHiddenFields', 'HasPasswordField',
        'Bank', 'Pay', 'Crypto', 'HasCopyright', 'NoOfImage', 'NoOfCSS',
        'NoOfJS', 'NoOfSelfRef', 'NoOfEmptyRef', 'NoOfExternalRef'
    ]
    
    # Pure URL lexical/structural features (extractable statically from raw URL string without visiting)
    url_static_features = [
        'URLLength', 'DomainLength', 'IsDomainIP', 'TLDLength',
        'NoOfSubDomain', 'NoOfLettersInURL', 'NoOfDegitsInURL',
        'NoOfEqualsInURL', 'NoOfQMarkInURL', 'NoOfAmpersandInURL',
        'NoOfOtherSpecialCharsInURL', 'SpcharRatioInURL', 'IsHTTPS'
    ]
    
    present_static = [c for c in url_static_features if c in cols]
    present_html = [c for c in html_page_features if c in cols]
    print(f"\nPure URL Static Features (extractable without visiting): {len(present_static)}")
    print(present_static)
    print(f"HTML/Page Content Features (require visiting website): {len(present_html)}")
    
    summary = {
        "dataset_name": "PhiUSIIL Phishing URL Dataset",
        "source": "UCI Machine Learning Repository (DOI: 10.24432/C57P5R, 2024)",
        "total_samples": int(total_rows),
        "total_columns": int(total_cols),
        "class_distribution": {str(k): int(v) for k, v in val_counts.items()},
        "duplicate_rows": int(dup_count),
        "url_static_features": present_static,
        "html_features": present_html
    }
    return summary

def verify_clamp():
    print("\n" + "=" * 60)
    print("VERIFYING CLAMP DATASET (STATIC PE MALWARE)")
    print("=" * 60)
    csv_path = RAW_DIR / "ClaMP_Raw-5184.csv"
    assert csv_path.exists(), f"File not found: {csv_path}"
    
    df = pd.read_csv(csv_path)
    total_rows, total_cols = df.shape
    print(f"Total Rows: {total_rows:,}")
    print(f"Total Columns: {total_cols}")
    
    target_col = 'class'
    print(f"\nTarget Column: '{target_col}'")
    val_counts = df[target_col].value_counts().to_dict()
    print("Class Distribution:")
    for k, v in val_counts.items():
        print(f"  Class {k} ({'Malicious' if k==1 else 'Benign'}): {v:,} ({v/total_rows*100:.2f}%)")
        
    # Missing values
    missing = df.isnull().sum()
    missing_cols = missing[missing > 0]
    print(f"\nMissing values in columns: {len(missing_cols)}")
    for col, count in missing_cols.items():
        print(f"  {col}: {count} missing values ({count/total_rows*100:.2f}%)")
        
    dup_count = df.duplicated().sum()
    print(f"\nExact Duplicate Rows: {dup_count:,}")
    
    # Feature columns (all except class)
    feature_cols = [c for c in df.columns if c != 'class']
    print(f"\nTotal Feature Columns: {len(feature_cols)}")
    
    # Check e_res and e_res2
    print(f"Nulls in e_res: {df['e_res'].isnull().sum()} / {total_rows}")
    print(f"Nulls in e_res2: {df['e_res2'].isnull().sum()} / {total_rows}")
    
    # Active 53 PE header features
    active_pe_features = [c for c in feature_cols if c not in ['e_res', 'e_res2']]
    print(f"Active PE Features matching pefile directly: {len(active_pe_features)}")
    
    summary = {
        "dataset_name": "ClaMP Raw PE Malware Dataset",
        "source": "Mendeley Data / GitHub (Kumar et al., 2022)",
        "total_samples": int(total_rows),
        "total_columns": int(total_cols),
        "class_distribution": {str(k): int(v) for k, v in val_counts.items()},
        "duplicate_rows": int(dup_count),
        "missing_columns": list(missing_cols.index),
        "active_pe_features": active_pe_features
    }
    return summary

if __name__ == "__main__":
    phiusiil_meta = verify_phiusiil()
    clamp_meta = verify_clamp()
    
    report = {
        "phiusiil": phiusiil_meta,
        "clamp": clamp_meta
    }
    
    out_file = DOCS_DIR / "dataset_verification_report.json"
    with open(out_file, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nVerification report saved to {out_file}")
