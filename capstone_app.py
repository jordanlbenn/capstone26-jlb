from flask import Flask, render_template, request, redirect, session, url_for, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import os
import json

# Encryption imports
from custom_cipher import encrypt_xor_file, decrypt_xor_file
from aes_fernet import encrypt_aes_file, decrypt_aes_file 
from hybrid_aes_rsa import encrypt_hybrid_file, decrypt_hybrid_file

app = Flask(__name__)
app.secret_key = 'test_secret_key'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///capstone.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Databse Models
class QuizResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    answers = db.Column(db.Text)
    recommended_method = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())


class FileRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer)
    username = db.Column(db.String(100))
    filename = db.Column(db.String(200))
    method = db.Column(db.String(100))
    filepath = db.Column(db.String(300))
    duration = db.Column(db.Float)  # time in seconds
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())


# Ensure folders exist
os.makedirs("uploads", exist_ok=True)
os.makedirs("encrypted", exist_ok=True)
os.makedirs("decrypted", exist_ok=True)

@app.route('/')
def home():
    return render_template('main_page.html')


# Quiz Steps
@app.route('/quiz/step1', methods=['GET', 'POST'])
def step1():
    if request.method == 'POST':
        username = request.form.get('username')
        session['username'] = request.form.get('username')
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

# Results
@app.route('/quiz/result')
def result():
    direct = request.args.get('direct') == 'true'

    if direct:
        # Remove username from session if user skipped the quiz
        username = session.pop('username', None)

        return render_template(
            'result.html',
            show_recommendation=False,
            method=None,
            scores={},
            reasons=[],
            direct=False,
            username=username,
            quiz_id=session.get('quiz_id')
        )

    # Quiz result flow: get inputs from session
    username = session.get('username')  # must exist
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

    # Scoring logic
    scores = {
        "Lightweight Encryption": 0,
        "Standard AES Encryption": 0,
        "Hybrid Encryption (AES + RSA)": 0,
    }
    reasons = []

    if sensitivity in ["confidential", "high"]:
        scores["Hybrid Encryption (AES + RSA)"] += 3
        scores["Standard AES Encryption"] += 1
        reasons.append("Your data was identified as highly sensitive or confidential. "
        "This means the information likely contains personal records, financial details, "
        "business-critical files, or other content where unauthorized access could cause "
        "serious harm. Hybrid Encryption (AES + RSA) is strongly favored here because it "
        "combines AES for fast, secure file encryption with RSA for secure key exchange, "
        "creating an additional layer of protection for safeguarding sensitive assets. "
        "Standard AES Encryption also earns consideration because it is widely trusted, "
        "cryptographically strong, and highly effective for protecting confidential data."
)

    if performance == "optimized":
        scores["Lightweight Encryption"] += 3
        reasons.append("You prioritized performance and speed in your requirements. "
        "This suggests encryption may need to run efficiently on lower-powered systems, "
        "process large volumes of data quickly, or minimize delays during file operations. "
        "Lightweight Encryption is recommended in this case because it reduces computational "
        "overhead, making it suitable for educational demonstrations, rapid processing, "
        "or environments where efficiency matters more than maximum cryptographic strength.")

    if adversary in ["advanced"]:
        scores["Hybrid Encryption (AES + RSA)"] += 3
        reasons.append("Your threat model assumes an advanced attacker or highly capable adversary. "
        "This includes scenarios where attackers may use sophisticated intrusion methods, "
        "target encryption keys directly, or exploit weak key-sharing mechanisms. "
        "Hybrid Encryption (AES + RSA) is strongly recommended because RSA secures the "
        "exchange of encryption keys while AES protects the actual file contents. "
        "This layered design improves resilience against interception, unauthorized "
        "decryption attempts, and targeted attacks on sensitive communications.")

    if compliance in ["federal", "nist", "iso"]:
        scores["Standard AES Encryption"] += 3
        scores["Hybrid Encryption (AES + RSA)"] += 1
        reasons.append("Your environment includes compliance, regulatory, or industry security standards "
        "such as federal guidelines, NIST recommendations, or ISO frameworks. "
        "These standards typically favor well-established, thoroughly validated encryption "
        "methods with strong security track records. Standard AES Encryption is highly "
        "recommended because AES is widely accepted across professional, enterprise, "
        "and government systems for protecting sensitive information. "
        "Hybrid Encryption also receives some consideration since combining AES with RSA "
        "can further strengthen secure key management in regulated workflows.")

    # Pick best method
    method = max(scores, key=scores.get)

    # Prepare answers dict for storage
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

    # Save result to DB
    new_result = QuizResult(
        username=username,
        answers=json.dumps(answers),
        recommended_method=method
    )
    db.session.add(new_result)
    db.session.commit()

    # Store quiz_id in session for reference (if needed)
    session['quiz_id'] = new_result.id

    return render_template(
        'result.html',
        show_recommendation=True,
        method=method,
        scores=scores,
        reasons=reasons,
        direct=False,
        username=username
    )
# Encryption Route
@app.route('/process_file', methods=['POST'])
def process_file():
    uploaded_file = request.files['file']
    method = request.form.get('method')
    quiz_id = request.form.get('quiz_id')  # may be None if direct encryption
    key = request.form.get('key')
    
    username = session.get('username') or request.form.get('username')
    
    if not username:
        return "Error: username not provided"
    
    if uploaded_file.filename == '':
        return "No file selected"
    
    # Save original uploaded file
    filename = secure_filename(uploaded_file.filename)
    filepath = os.path.join("uploads", filename)
    os.makedirs("uploads", exist_ok=True)
    uploaded_file.save(filepath)
    
    # Encrypt based on selected method
    if method == "Lightweight Encryption":
        result_path = encrypt_xor_file(filepath, key)
    elif method == "Standard AES Encryption":
        result_path = encrypt_aes_file(filepath, key)
    elif method == "Hybrid Encryption (AES + RSA)":
        result_path = encrypt_hybrid_file(filepath, key)
    else:
        # If method not recognized, just keep original
        result_path = filepath
    
    # Save record in DB
    new_file = FileRecord(
        username=username,
        quiz_id=quiz_id,
        filename=filename,
        method=method,
        filepath=result_path
    )
    
    db.session.add(new_file)
    db.session.commit()
    
    # Return encrypted file as download
    return send_file(result_path, as_attachment=True)


# Decryption
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

            else:
                return "Invalid method"

        except Exception:
            return "Invalid key or corrupted file"

        return send_file(result_path, as_attachment=True)

    return render_template('decrypt.html')


# Direct Encryption (For Skipping Quiz)
@app.route('/encrypt_direct', methods=['GET', 'POST'])
def encrypt_direct():
    if request.method == 'POST':
        # Process file like /process_file
        return redirect(url_for('process_file_direct'))
    return render_template('encrypt_direct.html')


# Admin Dashboard
@app.route('/admin')
def admin():
    search_query = request.args.get('search', '')

    # Filter quiz results by username if search query exists
    quiz_results_query = QuizResult.query
    if search_query:
        quiz_results_query = quiz_results_query.filter(QuizResult.username.ilike(f"%{search_query}%"))
    results = quiz_results_query.order_by(QuizResult.created_at.desc()).all()

    # Files (no username column, just show file info)
    files = FileRecord.query.order_by(FileRecord.created_at.desc()).all()

    return render_template(
        'admin.html',
        search_query=search_query,
        results=results,
        files=files
    )

# RUN APP
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)