"""
DistilBERT Transformer Fine-Tuning Script for 3-Class GenAI & Human Phishing Detection.
Fine-tunes distilbert-base-uncased using Hugging Face Trainer API.
Logs GPU/CPU availability, computes empirical test metrics, and exports metadata.
"""
import sys
import os
import json
import time
from datetime import datetime, timezone
from pathlib import Path
import numpy as np
import pandas as pd
import torch
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    Trainer,
    TrainingArguments,
    EarlyStoppingCallback,
    EvalPrediction
)
from datasets import Dataset
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

DATA_DIR = BASE_DIR / "data" / "processed" / "messages"
OUTPUT_DIR = BASE_DIR / "models" / "message_content" / "distilbert"
METADATA_DIR = OUTPUT_DIR / "metadata"

CLASS_NAMES = ["legitimate", "human_phishing", "ai_phishing"]
MODEL_CHECKPOINT = "distilbert-base-uncased"

def compute_metrics(eval_pred: EvalPrediction) -> dict:
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=1)
    
    acc = accuracy_score(labels, preds)
    macro_f1 = f1_score(labels, preds, average="macro", zero_division=0)
    weighted_f1 = f1_score(labels, preds, average="weighted", zero_division=0)
    
    precisions = precision_score(labels, preds, average=None, zero_division=0)
    recalls = recall_score(labels, preds, average=None, zero_division=0)
    f1s = f1_score(labels, preds, average=None, zero_division=0)
    
    return {
        "accuracy": float(acc),
        "macro_f1": float(macro_f1),
        "weighted_f1": float(weighted_f1)
    }

def train_transformer_detector():
    print("=" * 60)
    print("DISTILBERT TRANSFORMER FINE-TUNING PIPELINE")
    print("=" * 60)
    
    device = "cuda" if torch.cuda.is_available() else "cpu"
    gpu_name = torch.cuda.get_device_name(0) if torch.cuda.is_available() else "None (CPU Execution)"
    print(f"Hardware Acceleration: {device.upper()} -> {gpu_name}")
    
    if not (DATA_DIR / "text_train.csv").exists() or not (DATA_DIR / "y_train.csv").exists():
        raise FileNotFoundError(
            f"Processed text datasets not found in {DATA_DIR}.\n"
            f"Please run `python scripts/prepare_message_data.py` first with raw corpora in data/raw/messages/."
        )
        
    train_text_df = pd.read_csv(DATA_DIR / "text_train.csv")
    val_text_df = pd.read_csv(DATA_DIR / "text_val.csv")
    test_text_df = pd.read_csv(DATA_DIR / "text_test.csv")
    
    y_train = pd.read_csv(DATA_DIR / "y_train.csv").squeeze("columns")
    y_val = pd.read_csv(DATA_DIR / "y_val.csv").squeeze("columns")
    y_test = pd.read_csv(DATA_DIR / "y_test.csv").squeeze("columns")
    
    train_text_df["label"] = y_train.values
    val_text_df["label"] = y_val.values
    test_text_df["label"] = y_test.values
    
    print(f"Loaded {len(train_text_df)} train, {len(val_text_df)} val, {len(test_text_df)} test samples.")
    
    tokenizer = AutoTokenizer.from_pretrained(MODEL_CHECKPOINT)
    
    def tokenize_fn(examples):
        return tokenizer(
            examples["text"],
            padding="max_length",
            truncation=True,
            max_length=256
        )
        
    train_ds = Dataset.from_pandas(train_text_df[["text", "label"]])
    val_ds = Dataset.from_pandas(val_text_df[["text", "label"]])
    test_ds = Dataset.from_pandas(test_text_df[["text", "label"]])
    
    train_tokenized = train_ds.map(tokenize_fn, batched=True)
    val_tokenized = val_ds.map(tokenize_fn, batched=True)
    test_tokenized = test_ds.map(tokenize_fn, batched=True)
    
    id2label = {i: c for i, c in enumerate(CLASS_NAMES)}
    label2id = {c: i for i, c in enumerate(CLASS_NAMES)}
    
    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_CHECKPOINT,
        num_labels=3,
        id2label=id2label,
        label2id=label2id
    )
    
    training_args = TrainingArguments(
        output_dir=str(OUTPUT_DIR / "checkpoints"),
        learning_rate=2e-5,
        per_device_train_batch_size=16,
        per_device_eval_batch_size=16,
        weight_decay=0.01,
        num_train_epochs=10,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="macro_f1",
        greater_is_better=True,
        seed=42,
        logging_steps=50,
        save_total_limit=2,
        report_to="none"
    )
    
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_tokenized,
        eval_dataset=val_tokenized,
        compute_metrics=compute_metrics,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=2)]
    )
    
    print("\nStarting DistilBERT fine-tuning...")
    t0 = time.time()
    trainer.train()
    training_duration = time.time() - t0
    print(f"Training completed in {training_duration:.2f} seconds ({training_duration/60:.1f} min).")
    
    # Evaluate on held-out test set
    print("\nEvaluating fine-tuned model on held-out test set...")
    t_eval_0 = time.perf_counter()
    test_preds_raw = trainer.predict(test_tokenized)
    t_eval_1 = time.perf_counter()
    
    latency_ms_per_sample = ((t_eval_1 - t_eval_0) * 1000) / len(test_text_df)
    
    logits = test_preds_raw.predictions
    preds = np.argmax(logits, axis=1)
    labels = test_text_df["label"].values
    
    acc = accuracy_score(labels, preds)
    macro_f1 = f1_score(labels, preds, average="macro", zero_division=0)
    weighted_f1 = f1_score(labels, preds, average="weighted", zero_division=0)
    
    precisions = precision_score(labels, preds, average=None, zero_division=0)
    recalls = recall_score(labels, preds, average=None, zero_division=0)
    f1s = f1_score(labels, preds, average=None, zero_division=0)
    
    per_class = {}
    for idx, cname in enumerate(CLASS_NAMES):
        per_class[cname] = {
            "precision": round(float(precisions[idx]), 4),
            "recall": round(float(recalls[idx]), 4),
            "f1_score": round(float(f1s[idx]), 4)
        }
        
    cm = confusion_matrix(labels, preds).tolist()
    
    # Save final model & tokenizer
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    METADATA_DIR.mkdir(parents=True, exist_ok=True)
    
    model.save_pretrained(OUTPUT_DIR)
    tokenizer.save_pretrained(OUTPUT_DIR)
    print(f"Saved fine-tuned DistilBERT and tokenizer to: {OUTPUT_DIR}")
    
    metadata = {
        "model_type": "distilbert-base-uncased-sequence-classification",
        "model_version": "v1.0.0",
        "task": "3_class_message_phishing_detection",
        "classes": CLASS_NAMES,
        "device_used": device,
        "gpu_name": gpu_name,
        "training_date": datetime.now(timezone.utc).isoformat(),
        "training_duration_seconds": round(training_duration, 2),
        "hyperparameters": {
            "learning_rate": 2e-5,
            "per_device_train_batch_size": 16,
            "weight_decay": 0.01,
            "num_train_epochs": 10,
            "max_length": 256,
            "early_stopping_patience": 2,
            "seed": 42
        },
        "test_metrics": {
            "accuracy": round(float(acc), 4),
            "macro_f1": round(float(macro_f1), 4),
            "weighted_f1": round(float(weighted_f1), 4),
            "per_class_metrics": per_class,
            "confusion_matrix": cm,
            "latency_ms_per_sample": round(float(latency_ms_per_sample), 4)
        }
    }
    
    meta_path = METADATA_DIR / "metadata.json"
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"Saved metadata to: {meta_path}")
    print("=" * 60)

if __name__ == "__main__":
    train_transformer_detector()
