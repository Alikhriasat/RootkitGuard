from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import joblib
import json
from datetime import datetime
import os

app = Flask(__name__)
# مفتاح أمان لتفعيل الـ session (تأمين تسجيل الدخول)
app.secret_key = os.environ.get("SECRET_KEY", "rootkit_guard_secure_key_2026")

# 1. تحميل الموديل والـ Vectorizer أول ما يشتغل السيرفر
try:
    model = joblib.load('syscall_model.pkl')
    vectorizer = joblib.load('vectorizer.pkl')
    print("AI Engine Status: ONLINE & LOADED SUCCESSFULY")
except Exception as e:
    print(f"CRITICAL ERROR: Could not load AI models: {e}")
    model = None
    vectorizer = None

# سجل الفحوصات المؤقت في الذاكرة
history_log = []

# مستخدم افتراضي لتجربة النظام (يمكنك تعديله أو ربطه بقاعدة بياناتك لاحقاً)
DEFAULT_USER = "Ali"
DEFAULT_PASS = "123456"

@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if username == DEFAULT_USER and password == DEFAULT_PASS:
            session['username'] = username
            return jsonify({'status': 'success'})
        else:
            return jsonify({'status': 'fail', 'message': 'Invalid Security Credentials!'})
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
    # التأكد من جهوزية محرك الذكاء الاصطناعي
    if model is None or vectorizer is None:
        return jsonify({'status': 'Error', 'message': 'AI Engine is offline. Check model files.'}), 500

    data = request.get_json()
    filename = data.get('filename')
    file_content = data.get('file_content')

    # 2. فحص إذا كان محتوى ملف الـ JSON فارغاً
    if not file_content or file_content == {}:
        return jsonify({'status': 'Empty File', 'message': 'The JSON file contains no data/features.'}), 400

    try:
        # 3. معالجة البيانات (Feature Extraction) وتحويل الـ JSON لنص للـ Vectorizer
        json_str = json.dumps(file_content)
        processed_features = vectorizer.transform([json_str])
        
        # 4. التوقع الفعلي بواسطة موديل الآلة (Machine Learning Prediction)
        prediction = model.predict(processed_features)[0]
        
        # 5. حساب نسبة التأكيد (Confidence)
        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(processed_features)[0]
            confidence = int(max(probabilities) * 100)
        else:
            confidence = 96  # قيمة الافتراضية عالية إذا كان الموديل قطعي (مثل Decision Tree)

        # 6. تحديد الحالة بناءً على مخرجات الموديل (1 = مصاب، 0 = سليم)
        if prediction == 1 or str(prediction).lower() == 'rootkit':
            status = "Rootkit Detected"
        else:
            status = "System Clean"

        # 7. إضافة الفحص إلى السجل ليظهر في الـ Dashboard
        new_scan = {
            'date': datetime.now(),
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

if __name__ == '__main__':
    app.run(debug=True)
