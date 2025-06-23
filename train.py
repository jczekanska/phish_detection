import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from feature_extraction import SuspiciousFeatures

os.makedirs('models', exist_ok=True)
metadata = {}

data_dir = 'data'
for fname in os.listdir(data_dir):
    if not fname.lower().endswith('.csv'):
        continue
    dataset_name = os.path.splitext(fname)[0]
    path = os.path.join(data_dir, fname)
    print(f"\n====================")
    print(f"[{dataset_name}] Training model")

    df = pd.read_csv(path)

    if {'body', 'label'}.issubset(df.columns):
        X = df['body']
        y = df['label']
        pipeline = Pipeline([
            ('features', FeatureUnion([
                ('tfidf', TfidfVectorizer(stop_words='english', max_features=5000)),
                ('susp', SuspiciousFeatures()),
            ])),
            ('clf', RandomForestClassifier(n_estimators=100, random_state=42))
        ])
    elif 'CLASS_LABEL' in df.columns:
        feature_cols = [c for c in df.columns if c not in ('id', 'CLASS_LABEL')]
        X = df[feature_cols]
        y = df['CLASS_LABEL']
        pipeline = Pipeline([
            ('clf', RandomForestClassifier(n_estimators=100, random_state=42))
        ])
    else:
        print(f"[{dataset_name }] Skipping the dataset: unrecognized columns {df.columns.tolist()}")
        continue

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"[{dataset_name}] Accuracy: {acc:.4f}")
    print(classification_report(y_test, y_pred, target_names=['legit','phish']))

print("\n====================")
print("Training completed.")