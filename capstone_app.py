from flask import Flask, render_template, request, redirect, session, url_for, send_file
from werkzeug.utils import secure_filename
import os

# NEW: database imports
import sqlite3
import json

#Encryption algorithm imports
from custom_cipher import encrypt_xor_file, decrypt_xor_file
from aes_test_fernet import encrypt_aes_file, decrypt_aes_file 

app = Flask(__name__)
app.secret_key = 'test_secret_key'

# NEW: database helper
def get_db():
    return sqlite3.connect('database.db')

# NEW: ensure folders exist
os.makedirs("uploads", exist_ok=True)
os.makedirs("encrypted", exist_ok=True)

#Home
@app.route('/')
def home():
    return render_template('main_page.html')

#Step 1
@app.route('/quiz/step1', methods=['GET', 'POST'])
def step1():
    if request.method == 'POST':
        session['use_case'] = request.form.get('use_case')
        session['sensitivity'] = request.form.get('sensitivity')
        session['environment'] = request.form.get('environment')
        return redirect(url_for('step2'))
    return render_template('step1.html')

#Step 2
@app.route('/quiz/step2', methods=['GET', 'POST'])
def step2():
    if request.method == 'POST':
        session['threat_model'] = request.form.get('threat_model')
        session['adversary'] = request.form.get('adversary')
        session['timeframe'] = request.form.get('timeframe')
        return redirect(url_for('step3'))
    return render_template('step2.html')

#Step 3
@app.route('/quiz/step3', methods=['GET', 'POST'])
def step3():
    if request.method == 'POST':
        session['performance'] = request.form.get('performance')
        session['hardware'] = request.form.get('hardware')
        session['dataVolume'] = request.form.get('dataVolume')
        return redirect(url_for('step4'))
    return render_template('step3.html')

#Step 4
@app.route('/quiz/step4', methods=['GET', 'POST'])
def step4():
    if request.method == 'POST':
        session['compliance'] = request.form.get('compliance')
        session['addsecurity'] = request.form.get('addsecurity')
        return redirect(url_for('result'))
    return render_template('step4.html')

#Results
@app.route('/quiz/result')
def result():
    # Get user inputs
    use_case = session.get('use_case')
    sensitivity = session.get('sensitivity')
    environment = session.get('environment')
    threat_model = session.get('threat_model')
    adversary = session.get('adversary')
    timeframe = session.get('timeframe')
    performance = session.get('performance')
    hardware = session.get('hardware')
    dataVolume = session.get('dataVolume')
    compliance = session.get('compliance')
    addsecurity = session.get('addsecurity')

    # Scoring system (UNCHANGED)
    scores = {
        "Lightweight Encryption": 0,
        "Standard AES Encryption": 0,
        "High-Security AES": 0,
        "Hybrid Encryption (AES + RSA)": 0,
        "Post-Quantum Ready Encryption": 0
    }

    reasons = []

    if sensitivity in ["confidential", "high"]:
        scores["High-Security AES"] += 2
        scores["Hybrid Encryption (AES + RSA)"] += 2
        reasons.append("High data sensitivity detected")

    if performance == "optimized":
        scores["Lightweight Encryption"] += 3
        reasons.append("Performance-focused requirement")

    if adversary in ["advanced", "quantum"]:
        scores["Hybrid Encryption (AES + RSA)"] += 2
        scores["Post-Quantum Ready Encryption"] += 3
        reasons.append("Advanced adversary model detected")

    if compliance in ["federal", "nist", "iso"]:
        scores["Standard AES Encryption"] += 2
        scores["High-Security AES"] += 2
        reasons.append("Compliance requirements favor strong encryption")

    if addsecurity == "postquantum":
        scores["Post-Quantum Ready Encryption"] += 4
        reasons.append("Post-quantum requirement selected")

    # Pick best option
    method = max(scores, key=scores.get)

    # =========================
    # NEW: SAVE QUIZ TO DATABASE
    # =========================
    conn = get_db()
    cursor = conn.cursor()

    answers = {
        "use_case": use_case,
        "sensitivity": sensitivity,
        "environment": environment,
        "threat_model": threat_model,
        "adversary": adversary,
        "timeframe": timeframe,
        "performance": performance,
        "hardware": hardware,
        "dataVolume": dataVolume,
        "compliance": compliance,
        "addsecurity": addsecurity
    }

    cursor.execute('''
        INSERT INTO quiz_results (answers, recommended_method)
        VALUES (?, ?)
    ''', (json.dumps(answers), method))

    conn.commit()
    quiz_id = cursor.lastrowid
    conn.close()

    return render_template('result.html',
        method=method,
        scores=scores,
        reasons=reasons,
        quiz_id=quiz_id  # NEW
    )

# =========================
# FILE PROCESSING
# =========================
@app.route('/process_file', methods=['POST'])
def process_file():
    uploaded_file = request.files['file']
    method = request.form.get('method')
    quiz_id = request.form.get('quiz_id')  # NEW

    if uploaded_file.filename == '':
        return "No file selected"

    filename = secure_filename(uploaded_file.filename)
    filepath = os.path.join("uploads", filename)
    uploaded_file.save(filepath)

    # Apply encryption based on method
    if method == "Lightweight Encryption":
        result_path = encrypt_xor_file(filepath, key="userkey123")

    elif method == "Standard AES Encryption":
        result_path = encrypt_aes_file(filepath, password="userkey123")

    elif method == "Hybrid Encryption (AES + RSA)":
        result_path = encrypt_hybrid(filepath)

    else:
        result_path = filepath

    # =========================
    # NEW: SAVE FILE RECORD
    # =========================
    conn = get_db()
    conn.execute('''
        INSERT INTO files (quiz_id, filename, method, filepath)
        VALUES (?, ?, ?, ?)
    ''', (quiz_id, filename, method, result_path))
    conn.commit()
    conn.close()

    return send_file(result_path, as_attachment=True)

# =========================
# RUN APP
# =========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)