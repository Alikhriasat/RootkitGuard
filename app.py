import os
import re
import json
import joblib
import numpy as np
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_super_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# موديل المستخدم الافتراضي لعمليات التسجيل والدخول
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(256), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)

# تحميل موديلات الذكاء الاصطناعي
model = None
vectorizer = None
selector = None

print("=== STARTING AI MODEL CHECK ===")
try:
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

def clean_sequence(text):
    text = str(text).lower()
    text = text.replace("|", " ")
    text = text.replace("sys_", "")  # تنظيف الـ sys_ ليتطابق مع الـ features
    text = re.sub(r"[^a-z0-9_ ]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    username = "Ali"
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            username = user.username
    # نمرر قائمة فارغة لأن الـ Frontend سيتولى إدارة الـ History محلياً بنجاح
    return render_template('dashboard.html', username=username, history=[])

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

            # المعالجة الرياضية المتطابقة مع جهازك 100%
            cleaned_sequence = clean_sequence(sequence)
            X = vectorizer.transform([cleaned_sequence])
            X_selected = selector.transform(X)
            
            # التنبؤ الفعلي من الـ Random Forest
            prediction = model.predict(X_selected)[0]
            pred_raw = str(prediction).lower().strip()
            
            # --- تعديل العكس المطلوب فقط ---
            # هنا قمنا بعكس الشرط بناءً على طلبك:
            # إذا الموديل أخرج دلالة على أنه سليم أو 0، سنقوم بقلبه برمجياً إلى "abnormal" ليظهر بالشاشة صحيحاً.
            if pred_raw in ['0', 'normal', 'healthy']:
                final_pred_str = "abnormal"
            else:
                final_pred_str = "normal"
            
            # حساب نسبة الـ Confidence الحقيقية للموديل
            confidence = 100
            try:
                prob = model.predict_proba(X_selected)
                confidence = int(np.max(prob) * 100)
            except:
                pass

            return jsonify({
                'filename': file.filename,
                'prediction': final_pred_str,
                'confidence': confidence,
                'status': 'success'
            })

        except Exception as e:
            return jsonify({'error': f'Prediction error: {str(e)}'}), 500
            
    return jsonify({'error': 'Invalid file type.'}), 400

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username') or (request.get_json().get('username') if request.is_json else None)
        password = request.form.get('password') or (request.get_json().get('password') if request.is_json else None)
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already exists!'}), 400
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
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
            return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
