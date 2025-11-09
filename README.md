# SafeNet AI

**SafeNet AI** is an AI-powered phishing and malicious website detection system built using **Flask**, **Machine Learning**, and a modern UI.  
It helps users identify whether a given website URL is safe or malicious, with real-time predictions and batch URL analysis.

---

## Features

- **Single URL Analysis** – Instantly check if a website is safe or malicious.
- **Batch Analysis** – Upload `.csv` or `.txt` files containing multiple URLs for bulk scanning.
- **Confidence Scores** – Displays model prediction confidence for each result.
- **AI-Powered Detection** – Uses a trained ML model (`phishing_model_final.pkl`) for intelligent classification.
- **Modern UI** – Beautiful glassmorphism interface with animations.
- **Scan History** – Keeps track of your recent analyses during the session.

---

## Tech Stack

| Layer | Technology / Libraries |
|-------|----------------------|
| **Frontend** | HTML, CSS, JavaScript |
| **Backend** | Flask (Python) |
| **Machine Learning** | scikit-learn, joblib, pandas, numpy, math |
| **Data Handling** | CSV, TXT batch uploads, Pandas DataFrames |

---
