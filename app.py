# =======================================================
#               app.py (V2.0 最终升级版)
# =======================================================
import os
import io
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date
from sqlalchemy.exc import IntegrityError
import pandas as pd
from werkzeug.utils import secure_filename

# --- App & DB Initialization ---
app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', f'sqlite:///{os.path.join(os.path.dirname(os.path.abspath(__file__)), "task_management.db")}')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-very-secure-v2-secret-key')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- Database Models (V2.0) ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='employee')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(100)) # 改为文本字段
    assignee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    due_date = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending')
    priority = db.Column(db.String(20), default='平') # 新增：任务级别
    progress = db.Column(db.Integer, default=0) # 新增：完成进度
    remarks = db.Column(db.Text) # 新增：备注
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    assignee = db.relationship('User', foreign_keys=[assignee_id])
    creator = db.relationship('User', foreign_keys=[creator_id])

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Main Routes ---
@app.route('/')
def index():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and check_password_hash(user.password_hash, request.form.get('password')):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('用户名或密码错误', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    template = 'director_dashboard.html' if current_user.role == 'director' else 'employee_dashboard.html'
    employees = User.query.filter_by(role='employee').all() if current_user.role == 'director' else []
    return render_template(template, employees=employees)

# --- API Endpoints ---
@app.route('/api/tasks', methods=['GET', 'POST'])
@login_required
def handle_tasks():
    if request.method == 'POST': # Create Task
        if current_user.role != 'director': return jsonify({'success': False, 'message': '权限不足'}), 403
        data = request.get_json()
        new_task = Task(
            title=data['title'],
            description=data['description'],
            category=data.get('category'),
            assignee_id=data['assignee_id'],
            due_date=datetime.strptime(data['due_date'], '%Y-%m-%d'),
            priority=data['priority'],
            remarks=data.get('remarks'),
            creator_id=current_user.id
        )
        db.session.add(new_task)
        db.session.commit()
        return jsonify({'success': True, 'message': '任务创建成功'})

    # GET Tasks
    query = Task.query
    if current_user.role == 'employee':
        query = query.filter_by(assignee_id=current_user.id)
    
    tasks = query.order_by(Task.due_date.asc()).all()
    return jsonify([{
        'id': t.id, 'title': t.title, 'description': t.description,
        'category': t.category, 'assignee': t.assignee.name,
        'creator': t.creator.name, 'due_date': t.due_date.strftime('%Y-%m-%d'),
        'status': t.status, 'priority': t.priority, 'progress': t.progress,
        'remarks': t.remarks, 'created_at': t.created_at.strftime('%Y-%m-%d %H:%M')
    } for t in tasks])

@app.route('/api/tasks/<int:task_id>/status', methods=['POST'])
@login_required
def update_task_status(task_id):
    task = Task.query.get_or_404(task_id)
    if current_user.role != 'director' and task.assignee_id != current_user.id:
        return jsonify({'success': False, 'message': '权限不足'}), 403
    
    data = request.get_json()
    task.status = data.get('status', task.status)
    task.progress = data.get('progress', task.progress)
    if int(task.progress) == 100:
        task.status = 'completed'
    elif task.status == 'completed' and int(task.progress) < 100:
        task.status = 'in_progress'

    db.session.commit()
    return jsonify({'success': True, 'new_status': task.status})

@app.route('/api/users/change_password', methods=['POST'])
@login_required
def change_password():
    data = request.get_json()
    if not check_password_hash(current_user.password_hash, data['old_password']):
        return jsonify({'success': False, 'message': '旧密码不正确'})
    if data['new_password'] != data['confirm_password']:
        return jsonify({'success': False, 'message': '两次输入的新密码不一致'})
    
    current_user.password_hash = generate_password_hash(data['new_password'])
    db.session.commit()
    return jsonify({'success': True, 'message': '密码修改成功'})

@app.route('/api/director/reset_password', methods=['POST'])
@login_required
def reset_password():
    if current_user.role != 'director': return jsonify({'success': False, 'message': '权限不足'}), 403
    data = request.get_json()
    user = User.query.get_or_404(data['user_id'])
    user.password_hash = generate_password_hash(data['new_password'])
    db.session.commit()
    return jsonify({'success': True, 'message': f"员工 {user.name} 的密码已重置"})

@app.route('/api/director/employees', methods=['GET'])
@login_required
def get_employees():
    if current_user.role != 'director': return jsonify({'success': False, 'message': '权限不足'}), 403
    employees = User.query.filter_by(role='employee').all()
    return jsonify([{'id': e.id, 'name': e.name, 'username': e.username} for e in employees])

# --- Utility & Initialization ---
def init_db():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', password_hash=generate_password_hash('admin123'), name='科室主任', role='director')
            db.session.add(admin)
        if not User.query.filter_by(username='employee1').first():
            emp1 = User(username='employee1', password_hash=generate_password_hash('password'), name='张三', role='employee')
            db.session.add(emp1)
        db.session.commit()

# --- App Runner ---
if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)