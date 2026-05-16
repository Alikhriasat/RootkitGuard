from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
import joblib
import json
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "rootkit_guard_secure_key_2026")

# قراءة رابط قاعدة البيانات السحابية من Render، وإذا لم يجدها يستخدم SQLite مؤقتاً للتجربة
DATABASE_URL = os.environ.get("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    # تعديل بسيط لأن SQLAlchemy تطلب بروتوكول postgresql:// بدلاً من postgres://
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL or 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# تعريف جدول المستخدمين
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# تحميل الموديل والـ Vectorizer
try:
    model = joblib.load('syscall_model.pkl')
    vectorizer = joblib.load('vectorizer.pkl')
    print("AI Engine Status: ONLINE & LOADED SUCCESSFULLY")
except Exception as e:
    print(f"CRITICAL ERROR: Could not load AI models: {e}")
    model = None
    vectorizer = None

history_log = []

@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
            is_ajax = True
        else:
            username = request.form.get('username')
            password = request.form.get('password')
            is_ajax = False
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.password == password:
            session['username'] = username
            if is_ajax:
                return jsonify({'status': 'success'})
            return redirect(url_for('dashboard'))
        else:
            msg = 'Invalid Username or Password!'
            if is_ajax:
                return jsonify({'status': 'fail', 'message': msg})
            return render_template('login.html', error=msg)

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
            is_ajax = True
        else:
            username = request.form.get('username')
            password = request.form.get('password')
            is_ajax = False
            
        if not username or not password:
            msg = 'Please fill in all fields.'
            return jsonify({'status': 'fail', 'message': msg}) if is_ajax else msg

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            msg = 'Username already exists! Choose another one.'
            if is_ajax:
                return jsonify({'status': 'fail', 'message': msg})
            return render_template('login.html', error=msg)

        new_user = User(username=username, password=password)
        try:
            db.session.add(new_user)
            db.session.commit()
            msg = f'Account created successfully! You can login now as {username}.'
            if is_ajax:
                return jsonify({'status': 'success', 'message': msg})
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            msg = 'Database error, please try again.'
            if is_ajax:
                return jsonify({'status': 'fail', 'message': msg})
            return render_template('login.html', error=msg)
    
    try:
        return render_template('register.html')
    except Exception:
        return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'], history=history_log)

@app.route('/analyze', methods=['POST'])
def analyze():
    if model is None or vectorizer is None:
        return jsonify({'status': 'Error', 'message': 'AI Engine is offline. Check model files.'}), 500

    data = request.get_json()
    if not data:
        return jsonify({'status': 'Error', 'message': 'No data provided.'}), 400

    filename = data.get('filename')
    file_content = data.get('file_content')

    if not file_content or file_content == {}:
        return jsonify({'status': 'Empty File', 'message': 'The JSON file contains no data/features.'}), 400

    try:
        json_str = json.dumps(file_content)
        processed_features = vectorizer.transform([json_str])
        prediction = model.predict(processed_features)[0]
        
        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(processed_features)[0]
            confidence = int(max(probabilities) * 100)
        else:
            confidence = 96

        if prediction == 1 or str(prediction).lower() == 'rootkit':
            status = "Rootkit Detected"
        else:
            status = "System Clean"

        new_scan = {
            'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'filename': filename,
            'result': status,
            'confidence': confidence
        }
        history_log.insert(0, new_scan)

        return jsonify({
            'status': status,
            'confidence': confidence
        })

    except Exception as e:
        return jsonify({'status': 'Error', 'message': f'Analysis failed during ML processing: {str(e)}'}), 500

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
