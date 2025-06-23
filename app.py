import os
import joblib
from flask import Flask, request, render_template
from pathlib import Path

app = Flask(__name__)
app.secret_key = os.urandom(24)

def load_models(models_dir='models'):
    models = {}
    for model_file in Path(models_dir).glob('model_*.pkl'):
        name = model_file.stem.replace('model_', '')
        pipeline = joblib.load(str(model_file))
        models[name] = pipeline
    return models

# Load models once at startup
models = load_models()

@app.route('/', methods=['GET', 'POST'])
def index():
    results = []
    average = None
    verdict = None

    if request.method == 'POST':
        text = request.form.get('email_text', '')
        probabilities = []

        for name, pipeline in models.items():
            try:
                proba = pipeline.predict_proba([text])[0][1]
                probabilities.append(proba)
                results.append({'model': name, 'prob': f"{proba*100:.2f}%"})
            except Exception:
                results.append({'model': name, 'prob': 'Error: cannot process input'})

        if probabilities:
            avg = sum(probabilities) / len(probabilities)
            average = f"{avg*100:.2f}%"
            verdict = 'Phishing' if avg >= 0.7 else 'Legitimate'

    return render_template(
        'index.html',
        results=results,
        average=average,
        verdict=verdict
    )

@app.route('/login')
def login():
    # Placeholder for Gmail functionality
    return "<h2>nothing here yet :)</h2>"

if __name__ == '__main__':
    app.run(debug=True)
