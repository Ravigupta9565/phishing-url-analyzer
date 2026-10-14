from flask import Flask, render_template, request
import sqlite3
import re
import datetime
import tldextract
import whois

app = Flask(__name__)

# Database Setup for Scan History
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            score INTEGER,
            risk TEXT,
            date TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def check_domain_age(url):
    try:
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"
        if not ext.domain:
            return 0, []
        
        w = whois.whois(domain)
        creation_date = w.creation_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if creation_date:
            if isinstance(creation_date, str):
                creation_date = datetime.datetime.strptime(creation_date.split()[0], '%Y-%m-%d')
            
            age_days = (datetime.datetime.now() - creation_date).days
            if age_days < 30:
                return 25, [f"High Risk: Domain is extremely new ({age_days} days old), frequently used in phishing."]
            elif age_days < 180:
                return 10, [f"Warning: Domain is relatively young ({age_days} days old)."]
    except Exception as e:
        # WHOIS lookup might fail for IPs or local domains
        pass
    return 0, []

def analyze_url(url):
    score = 0
    reasons = []

    # 1. IP Address Check
    if re.search(r'(\d{1,3}\.){3}\d{1,3}', url):
        score += 35
        reasons.append("Critical: URL contains a raw IP address instead of a domain name.")

    # 2. Length Check
    if len(url) > 75:
        score += 20
        reasons.append("Warning: Unusually long URL (> 75 characters) used to conceal true destination.")

    # 3. '@' Symbol Trick
    if '@' in url:
        score += 25
        reasons.append("High Risk: Contains '@' symbol, a common browser redirection trick.")

    # 4. Excessive Subdomains
    if url.count('.') > 3:
        score += 15
        reasons.append("Suspicious: Multiple subdomains detected.")

    # 5. HTTPS Check
    if not url.startswith("https://"):
        score += 15
        reasons.append("Insecure: URL does not use secure HTTPS protocol.")

    # 6. High-Risk Phishing Keywords
    suspicious_words = ['login', 'verify', 'update', 'banking', 'secure', 'signin', 'account', 'password', 'confirm', 'wallet']
    for word in suspicious_words:
        if word in url.lower():
            score += 20
            reasons.append(f"High Risk: Contains sensitive keyword: '{word}'.")
            break

    # 7. WHOIS Domain Age Check
    age_score, age_reasons = check_domain_age(url)
    score += age_score
    reasons.extend(age_reasons)

    score = min(score, 100)

    # Risk Classification
    if score >= 60:
        risk = "High Risk (Malicious / Phishing)"
        status_class = "danger"
    elif score >= 30:
        risk = "Medium Risk (Suspicious)"
        status_class = "warning"
    else:
        risk = "Low Risk (Likely Safe)"
        status_class = "safe"

    # Save to Database
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("INSERT INTO history (url, score, risk, date) VALUES (?, ?, ?, ?)", 
                   (url, score, risk, current_time))
    conn.commit()
    conn.close()

    return {
        "url": url,
        "score": score,
        "risk": risk,
        "status_class": status_class,
        "reasons": reasons if reasons else ["No major security heuristics or anomalies detected."]
    }

@app.route('/', methods=['GET', 'POST'])
def home():
    result = None
    if request.method == 'POST':
        url = request.form.get('url')
        if url:
            result = analyze_url(url)
            
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT url, score, risk, date FROM history ORDER BY id DESC LIMIT 5")
    history = cursor.fetchall()
    conn.close()

    return render_template('index.html', result=result, history=history)

if __name__ == '__main__':
    app.run(debug=True)