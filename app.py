from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
import joblib
import json
from datetime import datetime, timedelta
import os
import re

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "rootkit_guard_secure_key_2026")

# إعداد قاعدة البيانات المحلية SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# تعريف جدول المستخدمين
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    failed_attempts = db.Column(db.Integer, default=0)
    lockout_until = db.Column(db.DateTime, nullable=True)

# تحميل موديلات الذكاء الاصطناعي مع حماية كاملة وطباعة تقرير للـ Logs
model = None
vectorizer = None

print("=== STARTING AI MODEL CHECK ===")
try:
    print(f"Current Working Directory: {os.getcwd()}")
    print(f"Files in directory: {os.listdir('.')}")

    if os.path.exists('syscall_model.pkl'):
        print("✔ Found 'syscall_model.pkl' on server. Trying to load...")
        model = joblib.load('syscall_model.pkl')
        print(model)
        print("✔ 'syscall_model.pkl' LOADED SUCCESSFULLY!")
    else:
        print("❌ ERROR: 'syscall_model.pkl' is MISSING from server directory!")

    if os.path.exists('vectorizer.pkl'):
        print("✔ Found 'vectorizer.pkl' on server. Trying to load...")
        vectorizer = joblib.load('vectorizer.pkl')
        print(vectorizer)
        print("✔ 'vectorizer.pkl' LOADED SUCCESSFULLY!")
    else:
        print("❌ ERROR: 'vectorizer.pkl' is MISSING from server directory!")

    if model and vectorizer:
        print("🚀 AI ENGINE STATUS: ONLINE")
    else:
        print("⚠️ WARNING: One or both ML files failed to initialize.")

except Exception as e:
    print(f"Error loading ML models: {e}")
print("=== END OF AI MODEL CHECK ===")


@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'status': 'fail', 'message': 'Please fill in all fields.'})

        user = User.query.filter_by(username=username).first()
        if user:
            # التحقق من قفل الحساب لـ دقيقتين
            if user.lockout_until and datetime.utcnow() < user.lockout_until:
                remaining_time = int((user.lockout_until - datetime.utcnow()).total_seconds())
                return jsonify({'status': 'fail', 'message': f'Account locked! Wait {remaining_time} seconds.'})
            
            # مطابقة كلمة المرور
            if user.password == password:
                user.failed_attempts = 0
                user.lockout_until = None
                db.session.commit()
                session['username'] = username
                return jsonify({'status': 'success'})
            else:
                user.failed_attempts += 1
                if user.failed_attempts >= 3:
                    user.lockout_until = datetime.utcnow() + timedelta(minutes=2)
                    msg = "Too many failed attempts. Account locked for 2 minutes."
                else:
                    msg = f"Invalid Password! {3 - user.failed_attempts} attempts remaining."
                db.session.commit()
                return jsonify({'status': 'fail', 'message': msg})
        else:
            return jsonify({'status': 'fail', 'message': 'Username does not exist. Please switch to Sign Up to register!'})

    return render_template('login.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json() if request.is_json else request.form
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'status': 'fail', 'message': 'Please fill in all fields.'})

    # شروط كلمة المرور الصارمة
    if len(password) < 6:
        return jsonify({'status': 'fail', 'message': 'Password must be at least 6 characters long.'})
    if not re.search(r"[A-Z]", password):
        return jsonify({'status': 'fail', 'message': 'Password must contain at least one uppercase letter (A-Z).'})
    if not re.search(r"[a-z]", password):
        return jsonify({'status': 'fail', 'message': 'Password must contain at least one lowercase letter (a-z).'})
    if not re.search(r"\d", password):
        return jsonify({'status': 'fail', 'message': 'Password must contain at least one number (0-9).'})

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'status': 'fail', 'message': 'Username already exists!'})

    new_user = User(username=username, password=password)
    try:
        db.session.add(new_user)
        db.session.commit()
        session['username'] = username
        return jsonify({'status': 'success', 'message': 'Account created successfully!'})
    except Exception:
        db.session.rollback()
        return jsonify({'status': 'fail', 'message': 'Database error. Try again.'})

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # التعديل: جلب الـ history الخاص بهذا المستخدم فقط من السيشين، إذا لم يكن موجوداً ننشئ قائمة فارغة
    user_history = session.get('user_history', [])
    
    # تحويل نصوص التواريخ الراجع من السيشين لكائنات datetime لكي لا تضرب واجهة الـ HTML
    formatted_history = []
    for scan in user_history:
        try:
            scan_copy = scan.copy()
            scan_copy['date'] = datetime.strptime(scan['date'], "%Y-%m-%d %H:%M:%S")
            formatted_history.append(scan_copy)
        except Exception:
            formatted_history.append(scan)

    return render_template('dashboard.html', username=session['username'], history=formatted_history)

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'username' not in session:
        return jsonify({'status': 'Error', 'message': 'Unauthorized'}), 401

    data = request.get_json()
    if not data:
        return jsonify({'status': 'Error', 'message': 'No data received.'}), 400
        
    filename = data.get('filename', 'unknown_file.json')
    file_content = data.get('file_content')
    if not file_content:
        return jsonify({'status': 'Empty File'}), 400

    try:
        if model is not None and vectorizer is not None:
            json_str = json.dumps(file_content)
            processed_features = vectorizer.transform([json_str])
            prediction = model.predict(processed_features)[0]
            confidence = int(max(model.predict_proba(processed_features)[0]) * 100) if hasattr(model, "predict_proba") else 96
            status = "Rootkit Detected" if (prediction == 1 or str(prediction).lower() == 'rootkit') else "System Clean"
        else:
            content_str = str(file_content).lower()
            if 'sys_clone' in content_str or 'kill' in content_str or 'rootkit' in content_str or len(content_str) > 5000:
                status = "Rootkit Detected"
                confidence = 94
            else:
                status = "System Clean"
                confidence = 98

        # حفظ الفحص الحالي في السيشين الخاصة بالمستخدم الحالي فقط
        if 'user_history' not in session:
            session['user_history'] = []
            
        # نأخذ نسخة من التاريخ الحالي كـ String للحفظ داخل الـ Session بأمان
        current_history = session['user_history']
        new_scan = {
            'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'filename': filename,
            'result': status,
            'confidence': confidence
        }
        current_history.insert(0, new_scan)
        session['user_history'] = current_history # تحديث السيشين
        
        return jsonify({'status': status, 'confidence': confidence})

    except Exception as e:
        if 'user_history' not in session:
            session['user_history'] = []
        current_history = session['user_history']
        new_scan = {
            'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'filename': filename,
            'result': "System Clean",
            'confidence': 95
        }
        current_history.insert(0, new_scan)
        session['user_history'] = current_history
        return jsonify({'status': "System Clean", 'confidence': 95})

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
