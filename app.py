from flask_sqlalchemy import SQLAlchemy
import joblib
import json
from datetime import datetime
from datetime import datetime, timedelta
import os
import re

app = Flask(__name__)
# مفتاح أمان لتفعيل الـ session
app.secret_key = os.environ.get("SECRET_KEY", "rootkit_guard_secure_key_2026")

# إعداد قاعدة بيانات SQLite محلية مدمجة تلقائياً
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
# إعداد قاعدة البيانات السحابية (Supabase)
DATABASE_URL = os.environ.get("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL or 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# تعريف جدول المستخدمين في قاعدة البيانات
# تعريف جدول المستخدمين المطور مع ميزات الأمان الجديدة
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    
    # حقول تتبع محاولات تسجيل الدخول الفاشلة للحماية من Brute-Force
    failed_attempts = db.Column(db.Integer, default=0)
    lockout_until = db.Column(db.DateTime, nullable=True)

# 1. تحميل الموديل والـ Vectorizer أول ما يشتغل السيرفر
# تحميل موديلات الذكاء الاصطناعي
try:
    model = joblib.load('syscall_model.pkl')
    vectorizer = joblib.load('vectorizer.pkl')
    print("AI Engine Status: ONLINE & LOADED SUCCESSFULLY")
    print("AI Engine Status: ONLINE")
except Exception as e:
    print(f"CRITICAL ERROR: Could not load AI models: {e}")
    model = None
    vectorizer = None
    print(f"Error loading ML models: {e}")
    model, vectorizer = None, None

# سجل الفحوصات المؤقت في الذاكرة
history_log = []

# دالة برمجية للتحقق من قوة كلمة المرور باستخدام الـ Regular Expressions (Regex)
def is_password_strong(password):
    if len(password) < 6:
        return False, "Password must be at least 6 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one capital letter (A-Z)."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_+\-=\[\]\\]", password):
        return False, "Password must contain at least one special character (e.g. @, #, $, %, etc.)."
    return True, "Strong password"

@app.route('/')
def home():
    if 'username' in session:
@@ -52,19 +68,40 @@ def login():
            password = request.form.get('password')
            is_ajax = False

        # البحث عن المستخدم في قاعدة البيانات والتأكد من كلمته السرية
        user = User.query.filter_by(username=username).first()

        if user and user.password == password:
            session['username'] = username
            if is_ajax:
                return jsonify({'status': 'success'})
            return redirect(url_for('dashboard'))
        if user:
            # 1. التحقق مما إذا كان الحساب مقفلاً حالياً
            if user.lockout_until and datetime.utcnow() < user.lockout_until:
                remaining_time = int((user.lockout_until - datetime.utcnow()).total_seconds())
                msg = f"Account locked due to 3 failed attempts. Try again in {remaining_time} seconds."
                return jsonify({'status': 'fail', 'message': msg}) if is_ajax else render_template('login.html', error=msg)
            
            # 2. التحقق من صحة كلمة المرور
            if user.password == password:
                # تصفير عداد المحاولات الفاشلة عند الدخول الناجح
                user.failed_attempts = 0
                user.lockout_until = None
                db.session.commit()
                
                session['username'] = username
                return jsonify({'status': 'success'}) if is_ajax else redirect(url_for('dashboard'))
            else:
                # زيادة عداد الفشل عند كتابة كلمة مرور خاطئة لاسم مستخدم موجود
                user.failed_attempts += 1
                if user.failed_attempts >= 3:
                    # قفل الحساب لمدة 5 دقائق (يمكنك تعديل المدة كما تحب)
                    user.lockout_until = datetime.utcnow() + timedelta(minutes=5)
                    msg = "Too many failed attempts. Account locked for 5 minutes."
                else:
                    msg = f"Invalid Password! {3 - user.failed_attempts} attempts remaining."
                
                db.session.commit()
                return jsonify({'status': 'fail', 'message': msg}) if is_ajax else render_template('login.html', error=msg)
        else:
            msg = 'Invalid Username or Password!'
            if is_ajax:
                return jsonify({'status': 'fail', 'message': msg})
            return render_template('login.html', error=msg)
            # إذا كان اسم المستخدم غير مسجل أصلاً في النظام
            msg = "Username does not exist!"
            return jsonify({'status': 'fail', 'message': msg}) if is_ajax else render_template('login.html', error=msg)

    return render_template('login.html')

@@ -85,15 +122,21 @@ def register():
            msg = 'Please fill in all fields.'
            return jsonify({'status': 'fail', 'message': msg}) if is_ajax else msg

        # التحقق إذا كان اسم المستخدم محجوزاً مسبقاً
        # التحقق من قوة كلمة المرور قبل تسجيل الحساب
        is_valid, validation_msg = is_password_strong(password)
        if not is_valid:
            if is_ajax:
                return jsonify({'status': 'fail', 'message': validation_msg})
            return render_template('login.html', error=validation_msg)

        # التحقق من وجود المستخدم مسبقاً
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            msg = 'Username already exists! Choose another one.'
            if is_ajax:
                return jsonify({'status': 'fail', 'message': msg})
            return render_template('login.html', error=msg)

        # إضافة المستخدم الجديد لقاعدة البيانات
        new_user = User(username=username, password=password)
        try:
            db.session.add(new_user)
@@ -128,51 +171,33 @@ def dashboard():
@app.route('/analyze', methods=['POST'])
def analyze():
    if model is None or vectorizer is None:
        return jsonify({'status': 'Error', 'message': 'AI Engine is offline. Check model files.'}), 500

        return jsonify({'status': 'Error', 'message': 'AI Engine offline.'}), 500
    data = request.get_json()
    if not data:
        return jsonify({'status': 'Error', 'message': 'No data provided.'}), 400

        return jsonify({'status': 'Error', 'message': 'No data.'}), 400
    filename = data.get('filename')
    file_content = data.get('file_content')

    if not file_content or file_content == {}:
        return jsonify({'status': 'Empty File', 'message': 'The JSON file contains no data/features.'}), 400
    if not file_content:
        return jsonify({'status': 'Empty File'}), 400

    try:
        json_str = json.dumps(file_content)
        processed_features = vectorizer.transform([json_str])
        prediction = model.predict(processed_features)[0]
        confidence = int(max(model.predict_proba(processed_features)[0]) * 100) if hasattr(model, "predict_proba") else 96
        status = "Rootkit Detected" if (prediction == 1 or str(prediction).lower() == 'rootkit') else "System Clean"

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

        return jsonify({'status': status, 'confidence': confidence})
    except Exception as e:
        return jsonify({'status': 'Error', 'message': f'Analysis failed during ML processing: {str(e)}'}), 500
        return jsonify({'status': 'Error', 'message': str(e)}), 500

# إنشاء قاعدة البيانات والجداول تلقائياً عند تشغيل السيرفر لأول مرة
with app.app_context():
    db.create_all()
