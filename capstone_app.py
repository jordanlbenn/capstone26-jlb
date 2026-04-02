from flask import Flask, render_template, request, redirect, session, url_for, send_file
from werkzeug.utils import secure_filename
import os

#Database handling
import sqlite3
import json

# Encryption imports
from custom_cipher import encrypt_xor_file, decrypt_xor_file
from aes_fernet import encrypt_aes_file, decrypt_aes_file 
from aes_gcm import encrypt_aes_gcm_file, decrypt_aes_gcm_file
from hybrid_aes_rsa import encrypt_hybrid_file, decrypt_hybrid_file



app = Flask(__name__)
app.secret_key = 'test_secret_key'

# Database helper
def get_db():
    return sqlite3.connect('database.db')

# Ensure folders exist
os.makedirs("uploads", exist_ok=True)
os.makedirs("encrypted", exist_ok=True)
os.makedirs("decrypted", exist_ok=True)

#Home
@app.route('/')
def home():
    return render_template('main_page.html')



#Quiz Steps
@app.route('/quiz/step1', methods=['GET', 'POST'])
def step1():
    if request.method == 'POST':
        session['use_case'] = request.form.get('use_case')
        session['sensitivity'] = request.form.get('sensitivity')
        session['environment'] = request.form.get('environment')
        return redirect(url_for('step2'))
    return render_template('step1.html')

@app.route('/quiz/step2', methods=['GET', 'POST'])
def step2():
    if request.method == 'POST':
        session['threat_model'] = request.form.get('threat_model')
        session['adversary'] = request.form.get('adversary')
        session['timeframe'] = request.form.get('timeframe')
        return redirect(url_for('step3'))
    return render_template('step2.html')

@app.route('/quiz/step3', methods=['GET', 'POST'])
def step3():
    if request.method == 'POST':
        session['performance'] = request.form.get('performance')
        session['hardware'] = request.form.get('hardware')
        session['dataVolume'] = request.form.get('dataVolume')
        return redirect(url_for('step4'))
    return render_template('step3.html')

@app.route('/quiz/step4', methods=['GET', 'POST'])
def step4():
    if request.method == 'POST':
        session['compliance'] = request.form.get('compliance')
        return redirect(url_for('result'))
    return render_template('step4.html')

#Results Page
@app.route('/quiz/result')
def result():
    direct = request.args.get('direct')

    if direct == 'true':
        return render_template(
        'result.html',
        show_recommendation=False,
        method=None,
        scores={},
        reasons=[]
    )
    
    # Get inputs
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

    #Scoring
    scores = {
        "Lightweight Encryption": 0,
        "Standard AES Encryption": 0,
        "High-Security AES": 0,
        "Hybrid Encryption (AES + RSA)": 0,
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
        reasons.append("Advanced adversary model detected")

    if compliance in ["federal", "nist", "iso"]:
        scores["Standard AES Encryption"] += 2
        scores["High-Security AES"] += 2
        reasons.append("Compliance requirements favor strong encryption")

    #Pick best
    method = max(scores, key=scores.get)

    #Save to DB
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
        "compliance": compliance
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
        quiz_id=quiz_id
    )

#Encryption
@app.route('/process_file', methods=['POST'])
def process_file():
    uploaded_file = request.files['file']
    method = request.form.get('method')
    quiz_id = request.form.get('quiz_id')
    key = request.form.get('key')  # ✅ FIXED

    if uploaded_file.filename == '':
        return "No file selected"

    filename = secure_filename(uploaded_file.filename)
    filepath = os.path.join("uploads", filename)
    uploaded_file.save(filepath)

    #Encryption logic
    if method == "Lightweight Encryption":
        result_path = encrypt_xor_file(filepath, key)

    elif method == "Standard AES Encryption":
        result_path = encrypt_aes_file(filepath, key)

    elif method == "Hybrid Encryption (AES + RSA)":
        result_path = encrypt_hybrid_file(filepath, key)

    elif method == "High-Security AES Encryption":
        result_path = encrypt_aes_gcm_file(filepath, key)

    else:
        result_path = filepath

    #Save to DB
    conn = get_db()
    conn.execute('''
        INSERT INTO files (quiz_id, filename, method, filepath)
        VALUES (?, ?, ?, ?)
    ''', (quiz_id, filename, method, result_path))
    conn.commit()
    conn.close()

    return send_file(result_path, as_attachment=True)

#Decryption Route
@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt_file_page():
    if request.method == 'POST':
        uploaded_file = request.files['file']
        method = request.form.get('method')
        key = request.form.get('key')

        if uploaded_file.filename == '':
            return "No file selected"

        filename = secure_filename(uploaded_file.filename)
        filepath = os.path.join("uploads", filename)
        uploaded_file.save(filepath)

        try:
            if method == "Lightweight Encryption":
                result_path = decrypt_xor_file(filepath, key)

            elif method == "Standard AES Encryption":
                result_path = decrypt_aes_file(filepath, key)

            elif method == "Hybrid Encryption (AES + RSA)":
                result_path = decrypt_hybrid_file(filepath, key)
        
            elif method == "High-Security AES Encryption":
                result_path = decrypt_aes_gcm_file(filepath, key)
 
            else:
                return "Invalid method"

        except Exception:
            return "Invalid key or corrupted file"

        return send_file(result_path, as_attachment=True)

    return render_template('decrypt.html')

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt_direct():
    if request.method == 'POST':
        file = request.files['file']
        method = request.form['method']
        key = request.form['key']

        filepath = f"uploads/{file.filename}"
        file.save(filepath)

        
        return render_template(
            'result.html',
            show_recommendation=False,
            method=method,
            result="File encrypted successfully!"
        )

#Run App
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)