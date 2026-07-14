import os
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bleach  # لتنظيف المدخلات ومنع ثغرات XSS

app = Flask(__name__)

# 1. إعدادات جدار الحماية وحماية الاتصال (CORS)
# حدد نطاق موقعك فقط (مثلاً رابط الـ GitHub Pages الخاص بك) لمنع أي موقع غريب من إرسال طلبات للسيرفر
ALLOWED_ORIGINS = [
    "https://1-brl.github.io",  # استبدله برابط موقعك الحقيقي على جيت هاب
    "http://127.0.0.1:5500"     # للتجربة المحلية فقط أثناء التطوير
]
CORS(app, origins=ALLOWED_ORIGINS)

# 2. حماية قاعدة البيانات
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# 3. منع هجمات DDoS والـ Spam (Rate Limiting)
# يمنع هذا الإجراء المخترقين من إرسال آلاف الرسائل في ثوانٍ لتعطيل السيرفر
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per hour"], # الحد الأقصى الافتراضي لأي طلب
    storage_uri="memory://"
)

# نماذج قواعد البيانات الآمنة
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(50), nullable=False)
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

class Confession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

with app.app_context():
    db.create_all()

# دالة لتنظيف وتطهير النصوص المدخلة قبل حفظها في قاعدة البيانات
def sanitize_input(text):
    if not text:
        return ""
    # إزالة أي وسوم HTML أو أكواد جافاسكريبت قد تُحقن في الرسائل
    return bleach.clean(text, tags=[], attributes={}, strip=True).strip()

# --- مسارات الـ API المحمية ---

@app.route('/api/messages', methods=['GET'])
@limiter.limit("30 per minute") # حد أقصى لجلب الرسائل لمنع الضغط على السيرفر
def get_messages():
    messages = Message.query.order_by(Message.id.desc()).limit(50).all()
    return jsonify([{
        'sender': msg.sender,
        'text': msg.text,
        'timestamp': msg.timestamp
    } for msg in reversed(messages)])

@app.route('/api/messages', methods=['POST'])
@limiter.limit("5 per minute") # حماية صارمة لمنع إرسال رسائل عشوائية (Spam)
def send_message():
    data = request.json
    if not data or 'sender' not in data or 'text' not in data:
        return jsonify({'error': 'Bad Request'}), 400
    
    # تنظيف المدخلات لمنع الـ XSS
    clean_sender = sanitize_input(data['sender'])
    clean_text = sanitize_input(data['text'])
    
    if not clean_sender or not clean_text or len(clean_text) > 500:
         return jsonify({'error': 'Invalid Input or message too long'}), 400
    
    new_msg = Message(sender=clean_sender, text=clean_text)
    db.session.add(new_msg)
    db.session.commit()
    return jsonify({'success': True}), 201

@app.route('/api/confessions', methods=['POST'])
@limiter.limit("3 per minute") # تقييد إرسال الاعترافات لمنع الإغراق
def add_confession():
    data = request.json
    if not data or 'text' not in data:
        return jsonify({'error': 'Bad Request'}), 400
    
    clean_text = sanitize_input(data['text'])
    if not clean_text or len(clean_text) > 1000:
         return jsonify({'error': 'Invalid Input'}), 400
    
    new_conf = Confession(text=clean_text)
    db.session.add(new_conf)
    db.session.commit()
    return jsonify({'success': True}), 201

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)