import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib
from feature_extraction import SuspiciousFeatures

datasets = {
    'CEAS_08': 'data/CEAS_08.csv',
    'Phishing_Legitimate_full': 'data/Phishing_Legitimate_full.csv'
}

results = {}

for name, path in datasets.items():
    print(f"\n====================")
    print(f"[{name}] Training model")
    df = pd.read_csv(path)
    if name == 'CEAS_08':
        X = df['body']
        y = df['label']
        pipeline = Pipeline([
            ('features', FeatureUnion([
                ('tfidf', TfidfVectorizer(stop_words='english', max_features=5000)),
                ('susp', SuspiciousFeatures()),
            ])),
            ('clf', RandomForestClassifier(n_estimators=100, random_state=42))
        ])
    else:
        feature_cols = [col for col in df.columns if col not in ('id', 'CLASS_LABEL')]
        X = df[feature_cols]
        y = df['CLASS_LABEL']
        pipeline = Pipeline([
            ('clf', RandomForestClassifier(n_estimators=100, random_state=42))
        ])

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred, target_names=['legit', 'phish'])
    print(f"[{name}] Accuracy: {acc:.4f}")
    print(report)

    results[name] = acc
    os.makedirs('models', exist_ok=True)
    model_file = f"models/model_{name}.pkl"
    joblib.dump(pipeline, model_file)
    print(f"[{name}] Model saved to {model_file}")


print(f"\n====================")
print("Summary:")
for name, acc in results.items():
    print(f" - {name}: {acc:.4f}")