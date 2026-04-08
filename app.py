from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import re
import json

app = Flask(__name__)
app.secret_key = 'ali_khraisat_2026_secure_key' # مفتاح تشفير الجلسات
app.permanent_session_lifetime = timedelta(hours=3)

# --- إعداد قاعدة البيانات ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rootkit_final.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# جدول المستخدمين
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    scans = db.relationship('ScanHistory', backref='owner', lazy=True)

# جدول سجل الفحص
class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100))
    result = db.Column(db.String(50))
    confidence = db.Column(db.Integer)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# إنشاء الجداول في البداية
with app.app_context():
    db.create_all()

# --- دالة التحقق من قوة كلمة المرور ---
def is_password_strong(password):
    if len(password) < 8: return False
    if not re.search("[a-z]", password): return False
    if not re.search("[A-Z]", password): return False
    if not re.search("[0-9]", password): return False
    return True

# --- المسارات (Routes) ---

@app.route('/')
def home():
    if 'user_id' in session: return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: return redirect(url_for('home'))
    # جلب سجل الفحص الخاص بالمستخدم الحالي فقط مرتباً من الأحدث
    user_history = ScanHistory.query.filter_by(user_id=session['user_id']).order_by(ScanHistory.date.desc()).all()
    return render_template('dashboard.html', username=session['username'], history=user_history)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not is_password_strong(password):
        return jsonify({"status": "error", "message": "كلمة المرور ضعيفة! يجب أن تحتوي على 8 رموز تشمل أحرف كبيرة وصغيرة وأرقام"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"status": "error", "message": "اسم المستخدم موجود مسبقاً"}), 400
    
    hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(username=username, password_hash=hashed_pw)
    db.session.add(new_user)
    db.session.commit()
    
    session.permanent = True
    session['user_id'] = new_user.id
    session['username'] = new_user.username
    return jsonify({"status": "success"})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data.get('username')).first()
    if user and check_password_hash(user.password_hash, data.get('password')):
        session.permanent = True
        session['user_id'] = user.id
        session['username'] = user.username
        return jsonify({"status": "success"})
    return jsonify({"status": "error", "message": "اسم المستخدم أو كلمة المرور غير صحيحة"}), 401

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'user_id' not in session: 
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    
    data = request.get_json()
    filename = data.get('filename', 'Unknown.json')
    file_content = data.get('file_content', {}) # استلام محتوى الملف المرسل من JavaScript

    # 1. التعديل المطلوب: فحص إذا كان الملف فارغاً
    if not file_content or len(file_content) == 0:
        return jsonify({
            "status": "Empty File", 
            "message": "The uploaded JSON file contains no data/features."
        }), 200

    # 2. محاكاة عمل الموديل (Integration Point)
    # هنا يتم استخراج الـ Features ومعالجتها لاحقاً
    import random
    res_status = "Rootkit Detected" if random.random() > 0.7 else "System Clean"
    conf = random.randint(85, 99)

    # 3. حفظ النتيجة في قاعدة البيانات
    new_scan = ScanHistory(
        filename=filename, 
        result=res_status, 
        confidence=conf, 
        user_id=session['user_id']
    )
    db.session.add(new_scan)
    db.session.commit()

    return jsonify({
        "status": res_status, 
        "confidence": conf,
        "detected_features": list(file_content.keys())[:5] # عرض أول 5 Features تم اكتشافها
    })

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
