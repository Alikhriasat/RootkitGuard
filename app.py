import os
import re
import json
import joblib
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_super_secret_key_here'
# الاتصال بقاعدة بيانات Render أونلاين المتزامنة مع الـ pgAdmin
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# =========================================================
# 1. تعريف موديل قاعدة البيانات (User Model) مع التشفير بـ 256 حرفاً
# =========================================================
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(256), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)

# =========================================================
# 2. تحميل موديلات الذكاء الاصطناعي الجديدة (Random Forest Pipeline)
# =========================================================
model = None
vectorizer = None

print("=== STARTING AI MODEL CHECK ===")
try:
    print(f"Current Working Directory: {os.getcwd()}")
    # استدعاء الموديل الجديد والـ Vectorizer بدون الـ Selector القديم لتسريع الفحص
    if os.path.exists('rf_syscall_model.pkl'):
        model = joblib.load('rf_syscall_model.pkl')
        print("✔ 'rf_syscall_model.pkl' LOADED SUCCESSFULLY!")
        
    if os.path.exists('rf_vectorizer.pkl'):
        vectorizer = joblib.load('rf_vectorizer.pkl')
        print("✔ 'rf_vectorizer.pkl' LOADED SUCCESSFULLY!")
except Exception as e:
    print(f"Error loading ML models: {e}")
print("=== END OF AI MODEL CHECK ===")


# =========================================================
# 3. دالة تنظيف ومعالجة الـ Features النصية (من ملف predict_from_json)
# =========================================================
def clean_sequence(text):
    text = str(text).lower()
    text = text.replace("|", " ")
    text = re.sub(r"[^a-z0-9_ ]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


# =========================================================
# 4. الـ Routes الخاصة بنظام التشغيل والفحص (Detection & Backend)
# =========================================================

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/detect', methods=['POST'])
def detect():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file and file.filename.endswith('.json'):
        try:
            # قراءة ملف الـ JSON المرفوع من الموقع وتفكيكه
            content = file.read().decode('utf-8')
            data = json.loads(content)
            
            # استخراج سلسلة نداءات النظام (System Calls) بناءً على الهيكلية المرنة
            if isinstance(data, list) and len(data) > 0:
                sequence = data[0].get('sequence', '')
                sample_name = data[0].get('name', 'Uploaded Sample')
            elif isinstance(data, dict):
                sequence = data.get('sequence', '')
                sample_name = data.get('name', 'Uploaded Sample')
            else:
                sequence = ''
                sample_name = 'Unknown'

            if not sequence:
                return jsonify({'error': 'No syscall sequence found in JSON structure.'}), 400

            # تطبيق دالة المعالجة والتنظيف المستوردة من ملف predict_from_json
            cleaned = clean_sequence(sequence)
            
            # تحويل النصوص والـ Features إلى تمثيل رقمي ممرر للموديل مباشرة
            X_transformed = vectorizer.transform([cleaned])
            
            # التنبؤ النهائي عبر موديل الـ Random Forest الجديد
            prediction = model.predict(X_transformed)[0]
            
            # إرسال النتيجة إلى واجهة المستخدم الرسومية في الموقع
            return jsonify({
                'filename': file.filename,
                'sample_name': sample_name,
                'prediction': str(prediction),  # تعيد النتيجة الحقيقية (Rootkit / Normal)
                'status': 'success'
            })

        except Exception as e:
            return jsonify({'error': f'Failed to process JSON file: {str(e)}'}), 500
            
    return jsonify({'error': 'Invalid file type. Please upload a valid .json file.'}), 400


# =========================================================
# 5. الـ Routes الخاصة بنظام الحماية وتشفير الحسابات (Auth System)
# =========================================================

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user_exists = User.query.filter_by(username=username).first()
        if user_exists:
            flash('Username already exists!', 'danger')
            return redirect(url_for('register'))
        
        # تشفير كلمة المرور بحماية عالية لتتطابق مع الـ 256 حرفاً في الداتابيز الفعالة
        hashed_password = generate_password_hash(password, method='scrypt')
        new_user = User(username=username, password=hashed_password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
            
    return render_template('login.html')


# =========================================================
# 6. نقطة انطلاق السيرفر ومزامنة الجداول تلقائياً عند التشغيل
# =========================================================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # إنشاء جدول الـ user بحجمه الجديد تلقائياً إذا تم تصفيره
        print("Database sync completed.")
    app.run(debug=True)
