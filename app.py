from flask import Flask, render_template, request, session
import joblib
import numpy as np
import math
import pandas as pd

app = Flask(__name__)
app.secret_key = "safenet_secret_key"

model = joblib.load("phishing_model_final.pkl")

def extract_features(url):
    url_length = len(url)
    num_digits = sum(c.isdigit() for c in url)
    special_chars = ['@', '?', '-', '=', '_', '&', '%', '.', '/']
    num_special_chars = sum(c in special_chars for c in url)
    has_https = 1 if url.lower().startswith('https') else 0
    num_dots = url.count('.')
    suspicious_keywords = [
        'login', 'secure', 'account', 'update', 'verify',
        'bank', 'free', 'click', 'signin', 'ebayisapi'
    ]
    suspicious_words = sum(word in url.lower() for word in suspicious_keywords)
    entropy = -sum((url.count(c)/len(url)) * math.log2(url.count(c)/len(url)) for c in set(url)) if url else 0
    return [url_length, num_digits, num_special_chars, has_https, num_dots, suspicious_words, entropy]

def add_to_history(entries):
    if 'history' not in session:
        session['history'] = []
    session['history'] = entries + session['history']
    session.modified = True

@app.route('/')
def home():
    history = session.get('history', [])
    return render_template('index.html', prediction=None, batch_results=None, history=history)

@app.route('/predict', methods=['POST'])
def predict():
    url = request.form['url']
    features = np.array(extract_features(url)).reshape(1, -1)
    result = model.predict(features)[0]
    prob = model.predict_proba(features)[0]
    confidence = round(max(prob) * 100, 2)

    if result == 1:
        label_text = f"🔒 Safe Website ({confidence}% confidence)"
        color = "green"
    else:
        label_text = f"⚠️ Malicious Website ({confidence}% confidence)"
        color = "red"

    add_to_history([{'url': url, 'label': 'Safe' if result == 1 else 'Malicious', 'confidence': confidence}])

    label = f"{label_text}<br><small style='color:#9ca3af;'>URL: <a href='{url}' target='_blank' style='color:{color};'>{url}</a></small>"

    return render_template('index.html', prediction=label, color=color, batch_results=None, history=session.get('history', []))

@app.route('/batch', methods=['POST'])
def batch():
    file = request.files['file']
    try:
        if file.filename.endswith('.csv'):
            df = pd.read_csv(file)
        else:
            df = pd.read_csv(file, names=['URL'])
    except Exception as e:
        return render_template('index.html', prediction=f"Error reading file: {e}", batch_results=None, history=session.get('history', []))

    results = []
    for url in df['URL']:
        try:
            url_str = str(url).strip()
            features = np.array(extract_features(url_str)).reshape(1, -1)
            result = model.predict(features)[0]
            prob = model.predict_proba(features)[0]
            confidence = round(max(prob) * 100, 2)
            label = "Safe" if result == 1 else "Malicious"
            results.append({'url': url_str, 'label': label, 'confidence': confidence})
        except:
            results.append({'url': url_str, 'label': "Error", 'confidence': 0})

    add_to_history(results)

    return render_template('index.html', batch_results=results, prediction=None, history=session.get('history', []))

@app.route('/clear-history', methods=['POST'])
def clear_history():
    session.pop('history', None)
    return render_template('index.html', prediction=None, batch_results=None, history=[])

if __name__ == '__main__':
    app.run(debug=True)
