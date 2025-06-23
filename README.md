# Phish Detect App

## IN PROGRESS

A Flask-based phishing email detection utility that supports manual email checks and automatic Gmail scanning. Train and compare models on two public datasets.

## Features

* **Manual Input**: Paste email text into a web form for instant phishing prediction and simple explanation of flagged indicators (URLs, suspicious keywords).

* **Gmail Auto Scan**: OAuth2-powered integration with Gmail to automatically fetch unread messages and highlight suspicious ones.

## Dataset Providers

  * **[CEAS 2008 Phishing Email Dataset (via Kaggle)](https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset?resource=download)**

## Quick Start (Ubuntu)

1. **Enter the project**

   ```bash
   cd phish_detect_app
   ```
2. **Create virtual environment**

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
3. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```
4. **Obtain Google API credentials**
- Go to `Google Cloud Console -> APIs & Services` and create a project.
- Enable `Gmail API` for that project.
- In `APIs & Services -> OAuth consent screen` select `External` as the user type and configure the screen, then add a test user.
- In `APIs & Services -> Credentials` click `Create Credentials -> OAuth client ID -> Web application`.
- Set `Authorized redirect URI` to `http://localhost:5000/oauth2callback`
- Download the JSON and save it as `credentials.json` in the project root.
4. **Run the app**

   ```bash
   export FLASK_APP=app.py
   flask run
   ```
5. **Access UI** at `http://localhost:5000`

## Additional

Users may input their own CSV datasets into the `data/` directory and create models that can be used by the app as long as the file can be parsed by `train.py`. If so, running that file provides the user with a ready-to-use model in `models/` directory.

## License

MIT
