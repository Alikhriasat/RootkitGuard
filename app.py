import os
import re
import json
import joblib
from datetime import datetime
import numpy as np
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_super_secret_key_here'
# الاتصال بقاعدة بيانات Render أونلاين
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# =========================================================
# 1. تعريف موديلات قاعدة البيانات (User & ScanHistory)
# =========================================================
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(256), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)

class ScanHistory(db.Model):
    __tablename__ = 'scan_history'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    filename = db.Column(db.String(256), nullable=False)
    result = db.Column(db.String(128), nullable=False)
    confidence = db.Column(db.Integer, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)

# =========================================================
# 2. تحميل موديلات الذكاء الاصطناعي (Model + Vectorizer + Selector)
# =========================================================
model = None
vectorizer = None
selector = None

print("=== STARTING AI MODEL CHECK ===")
try:
    print(f"Current Working Directory: {os.getcwd()}")
    if os.path.exists('rf_syscall_model.pkl'):
        model = joblib.load('rf_syscall_model.pkl')
        print("✔ 'rf_syscall_model.pkl' LOADED SUCCESSFULLY!")
        
    if os.path.exists('rf_vectorizer.pkl'):
        vectorizer = joblib.load('rf_vectorizer.pkl')
        print("✔ 'rf_vectorizer.pkl' LOADED SUCCESSFULLY!")

    if os.path.exists('rf_selector.pkl'):
        selector = joblib.load('rf_selector.pkl')
        print("✔ 'rf_selector.pkl' LOADED SUCCESSFULLY!")
except Exception as e:
    print(f"Error loading ML models: {e}")
print("=== END OF AI MODEL CHECK ===")


# =========================================================
# 3. دالة تنظيف ومعالجة الميزات النصية (مطابقة للمحلي 100%)
# =========================================================
def clean_sequence(text):
    text = str(text).lower()
    text = text.replace("|", " ")
    text = re.sub(r"[^a-z0-9_ ]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


# =========================================================
# 4. الـ Routes الخاصة بنظام الواجهات الرسومية والفحص
# =========================================================

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        # كود احتياطي لجلب اسم مستخدم افتراضي إذا لم يتم تسجيل الدخول لتجنب الأخطاء
        username = "Ali"
        history = ScanHistory.query.order_by(ScanHistory.date.desc()).all()
    else:
        user = User.query.get(session['user_id'])
        username = user.username if user else "Ali"
        history = ScanHistory.query.filter_by(user_id=session['user_id']).order_by(ScanHistory.date.desc()).all()
        
    return render_template('dashboard.html', username=username, history=history)

@app.route('/detect', methods=['POST'])
def detect():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file and file.filename.endswith('.json'):
        try:
            content = file.read().decode('utf-8')
            data = json.loads(content)
            
            if isinstance(data, list) and len(data) > 0:
                sample = data[0]
            elif isinstance(data, dict):
                sample = data
            else:
                return jsonify({'error': 'Invalid JSON structure'}), 400

            sequence = sample.get('sequence', '')
            if not sequence:
                return jsonify({'error': 'No syscall sequence found in JSON.'}), 400

            # معالجة وتنبؤ بالذكاء الاصطناعي بنفس الطريقة المحلية
            cleaned_sequence = clean_sequence(sequence)
            X = vectorizer.transform([cleaned_sequence])
            X_selected = selector.transform(X)
            
            prediction = model.predict(X_selected)[0]
            
            # حساب نسبة الـ Confidence الحقيقية للموديل بدقة
            confidence = 100
            try:
                prob = model.predict_proba(X_selected)
                confidence = int(np.max(prob) * 100)
            except:
                pass

            # حفظ عملية الفحص في قاعدة البيانات لتظهر في الـ History Log فوراً
            current_user_id = session.get('user_id', None)
            new_scan = ScanHistory(
                user_id=current_user_id,
                filename=file.filename,
                result=str(prediction),
                confidence=confidence
            )
            db.session.add(new_scan)
            db.session.commit()

            return jsonify({
                'filename': file.filename,
                'prediction': str(prediction),
                'confidence': confidence,
                'status': 'success'
            })

        except Exception as e:
            return jsonify({'error': f'Backend error during prediction: {str(e)}'}), 500
            
    return jsonify({'error': 'Invalid file type. Please upload a .json file.'}), 400


# =========================================================
# 5. الـ Routes الخاصة بنظام الحماية والـ Authentication
# =========================================================

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username') or (request.get_json().get('username') if request.is_json else None)
        password = request.form.get('password') or (request.get_json().get('password') if request.is_json else None)
            
        if not username or not password:
            if request.is_json: return jsonify({'error': 'Missing credentials'}), 400
            flash('Missing credentials', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(username=username).first():
            if request.is_json: return jsonify({'error': 'Username already exists!'}), 400
            flash('Username already exists!', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        if request.is_json: return jsonify({'status': 'success'})
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username') or (request.get_json().get('username') if request.is_json else None)
        password = request.form.get('password') or (request.get_json().get('password') if request.is_json else None)
            
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            if request.is_json: return jsonify({'status': 'success', 'redirect': url_for('dashboard')})
            return redirect(url_for('dashboard'))
        else:
            if request.is_json: return jsonify({'error': 'Invalid credentials'}), 401
            flash('Invalid credentials', 'danger')
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
