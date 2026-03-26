from flask import Flask, render_template, request, redirect, session, url_for, send_from_directory
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.secret_key = 'test_secret_key'

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

    # Scoring system
    scores = {
        "Lightweight Encryption": 0,
        "Standard AES Encryption": 0,
        "High-Security AES": 0,
        "Hybrid Encryption (AES + RSA)": 0,
        "Post-Quantum Ready Encryption": 0
    }

    reasons = []

    # Logic
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

    return render_template('result.html',
        method=method,
        scores=scores,
        reasons=reasons
    )

from flask import request, send_file
import os

@app.route('/process_file', methods=['POST'])
def process_file():
    uploaded_file = request.files['file']
    method = request.form.get('method')

    if uploaded_file.filename == '':
        return "No file selected"

    filepath = os.path.join("uploads", uploaded_file.filename)
    uploaded_file.save(filepath)

    # Apply encryption based on method
    if method == "Lightweight Encryption":
        result_path = encrypt_xor(filepath)

    elif method == "Standard AES Encryption":
        result_path = encrypt_aes(filepath)

    elif method == "Hybrid Encryption (AES + RSA)":
        result_path = encrypt_hybrid(filepath)

    else:
        result_path = filepath

    return send_file(result_path, as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)