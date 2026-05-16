from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
import joblib
import json
from datetime import datetime, timedelta
import os

app = Flask(__name__)
# مفتاح الأمان للجلسات (Sessions)
app.secret_key = os.environ.get("SECRET_KEY", "rootkit_guard_secure_key_2026")

# الاعتماد على قاعدة البيانات المحلية SQLite كلياً لضمان الاستقرار التام في الوقت الحالي
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# تعريف جدول المستخدمين الأساسي
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    
    # حقول الحماية من الهجمات التكرارية Brute-Force
    failed_attempts = db.Column(db.Integer, default=0)
    lockout_until = db.Column(db.DateTime, nullable=True)

# تحميل موديلات الذكاء الاصطناعي لفحص ملفات الـ Syscall
try:
    model = joblib.load('syscall_model.pkl')
    vectorizer = joblib.load('vectorizer.pkl')
    print("AI Engine Status: ONLINE")
except Exception as e:
    print(f"Error loading ML models: {e}")
    model, vectorizer = None, None

history_log = []

# دالة التحقق المعدلة والبسيطة (تطلب فقط 6 خانات أو أكثر دون شروط الرموز المعقدة)
def is_password_strong(password):
    if len(password) < 6:
        return False, "Password must be at least 6 characters long."
    return True, "Valid password"

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
        if user:
            # التحقق مما إذا كان الحساب مقفلاً مؤقتاً
            if user.lockout_until and datetime.utcnow() < user.lockout_until:
                remaining_time = int((user.lockout_until - datetime.utcnow()).total_seconds())
                msg = f"Account locked. Try again in {remaining_time} seconds."
                return jsonify({'status': 'fail', 'message': msg}) if is_ajax else render_template('login.html', error=msg)
            
            # التحقق من كلمة المرور
            if user.password == password:
                user.failed_attempts = 0
                user.lockout_until = None
                db.session.commit()
                session['username'] = username
                return jsonify({'status': 'success'}) if is_ajax else redirect(url_for('dashboard'))
            else:
                user.failed_attempts += 1
                if user.failed_attempts >= 3:
                    user.lockout_until = datetime.utcnow() + timedelta(minutes=5)
                    msg = "Too many failed attempts. Account locked for 5 minutes."
                else:
                    msg = f"Invalid Password! {3 - user.failed_attempts} attempts remaining."
                db.session.commit()
                return jsonify({'status': 'fail', 'message': msg}) if is_ajax else render_template('login.html', error=msg)
        else:
            msg = "Username does not exist!"
            return jsonify({'status': 'fail', 'message': msg}) if is_ajax else render_template('login.html', error=msg)
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

        # فحص طول كلمة المرور المبسط
        is_valid, validation_msg = is_password_strong(password)
        if not is_valid:
            return jsonify({'status': 'fail', 'message': validation_msg}) if is_ajax else render_template('login.html', error=validation_msg)

        # التحقق من عدم تكرار اسم المستخدم
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            msg = 'Username already exists!'
            return jsonify({'status': 'fail', 'message': msg}) if is_ajax else render_template('login.html', error=msg)

        new_user = User(username=username, password=password)
        try:
            db.session.add(new_user)
            db.session.commit()
            return jsonify({'status': 'success', 'message': 'Account created successfully!'}) if is_ajax else redirect(url_for('login'))
        except Exception:
            db.session.rollback()
            return jsonify({'status': 'fail', 'message': 'Database error, please try again.'}) if is_ajax else render_template('login.html', error='Database error.')
    
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
        return jsonify({'status': 'Error', 'message': 'AI Engine offline.'}), 500
    data = request.get_json()
    if not data:
        return jsonify({'status': 'Error', 'message': 'No data.'}), 400
    filename = data.get('filename')
    file_content = data.get('file_content')
    if not file_content:
        return jsonify({'status': 'Empty File'}), 400

    try:
        json_str = json.dumps(file_content)
        processed_features = vectorizer.transform([json_str])
        prediction = model.predict(processed_features)[0]
        confidence = int(max(model.predict_proba(processed_features)[0]) * 100) if hasattr(model, "predict_proba") else 96
        status = "Rootkit Detected" if (prediction == 1 or str(prediction).lower() == 'rootkit') else "System Clean"
        
        new_scan = {
            'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'filename': filename,
            'result': status,
            'confidence': confidence
        }
        history_log.insert(0, new_scan)
        return jsonify({'status': status, 'confidence': confidence})
    except Exception as e:
        return jsonify({'status': 'Error', 'message': str(e)}), 500

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
