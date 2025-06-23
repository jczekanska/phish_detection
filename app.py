import os
import joblib
from pathlib import Path
from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request

app = Flask(__name__)
app.secret_key = 'secret_key_here'

@app.context_processor
def inject_token_flag():
    return {'token_exists': os.path.exists('token.json')}

def load_models(models_dir='models'):
    models = {}
    for model_file in Path(models_dir).glob('model_*.pkl'):
        name = model_file.stem.replace('model_', '')
        pipeline = joblib.load(str(model_file))
        models[name] = pipeline
    return models

models = load_models()

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
CLIENT_SECRETS_FILE = 'credentials.json'

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
            except:
                results.append({'model': name, 'prob': 'Error'})
        if probabilities:
            avg = sum(probabilities) / len(probabilities)
            average = f"{avg*100:.2f}%"
            verdict = 'Phishing' if avg >= 0.5 else 'Legitimate'
    return render_template('index.html', results=results, average=average, verdict=verdict)

@app.route('/login')
def login():
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES, redirect_uri=url_for('oauth2callback', _external=True))
    auth_url, state = flow.authorization_url(access_type='offline', prompt='consent')
    session['state'] = state
    return redirect(auth_url)

@app.route('/oauth2callback')
def oauth2callback():
    if 'error' in request.args:
        flash(request.args['error'])
        return redirect(url_for('index'))
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES, state=session.get('state'), redirect_uri=url_for('oauth2callback', _external=True))
    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials
    with open('token.json', 'w') as token:
        token.write(creds.to_json())
    return redirect(url_for('scan'))

@app.route('/scan')
def scan():
    if not os.path.exists('token.json'):
        return redirect(url_for('login'))
    try:
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    except:
        os.remove('token.json')
        return redirect(url_for('login'))
    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    if not creds.valid:
        return redirect(url_for('login'))
    return render_template('scan.html')

@app.route('/scan_data')
def scan_data():
    creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    service = build('gmail', 'v1', credentials=creds)
    msgs = service.users().messages().list(
        userId='me',
        labelIds=['INBOX'],
        maxResults=10
    ).execute().get('messages', [])
    flagged = []
    for msg in msgs:
        data = service.users().messages().get(userId='me', id=msg['id'], format='full').execute()
        headers = data['payload'].get('headers', [])
        subject = next((h['value'] for h in headers if h['name'].lower()=='subject'), '(no subject)')
        body = ''
        parts = data['payload'].get('parts', [])
        for part in parts:
            if part.get('mimeType')=='text/plain' and part.get('body',{}).get('data'):
                import base64
                raw = part['body']['data']
                body = base64.urlsafe_b64decode(raw).decode('utf-8', errors='ignore')
                break
        if not body:
            body = data.get('snippet','')
        for name, pipeline in models.items():
            try:
                proba = pipeline.predict_proba([body])[0][1]
                if proba >= 0.7:
                    flagged.append({
                        'subject': subject,
                        'body_preview': body[:200] + ('…' if len(body)>200 else ''),
                        'model': name,
                        'prob': f"{proba*100:.2f}%"
                    })
            except:
                continue
    return jsonify({'total_scanned': len(msgs), 'flagged_count': len(flagged), 'flagged': flagged})

if __name__ == '_main_':
    app.run(debug=True)