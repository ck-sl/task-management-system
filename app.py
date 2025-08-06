# --- START OF FILE app.py (CORRECTED) ---
import os
import io
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date, timedelta
from sqlalchemy.exc import IntegrityError
import pandas as pd

# --- App & DB Initialization ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-secure-default-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///task_management.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "请先登录以访问此页面。"
login_manager.login_message_category = "info"

# --- Database Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='employee') # 'director' or 'employee'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    assigned_tasks = db.relationship('Task', foreign_keys='Task.assignee_id', backref='assignee', lazy=True)
    created_tasks = db.relationship('Task', foreign_keys='Task.creator_id', backref='creator', lazy=True)

class TaskCategory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    tasks = db.relationship('Task', backref='category', lazy=True)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    category_id = db.Column(db.Integer, db.ForeignKey('task_category.id'), nullable=False)
    assignee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    due_date = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending') # pending, in_progress, completed, overdue
    completion_status = db.Column(db.String(30)) # on_time, completed_late, overdue_incomplete
    completed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='notifications')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Main Routes ---
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
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
    # Update overdue tasks on dashboard load for accuracy
    update_overdue_tasks()
    if current_user.role == 'director':
        return redirect(url_for('director_dashboard'))
    return redirect(url_for('employee_dashboard'))

@app.route('/director')
@login_required
def director_dashboard():
    if current_user.role != 'director':
        flash('您没有权限访问此页面。', 'danger')
        return redirect(url_for('dashboard'))
    
    stats = {
        'total_tasks': Task.query.count(),
        'pending_tasks': Task.query.filter(Task.status.in_(['pending', 'in_progress'])).count(),
        'completed_tasks': Task.query.filter_by(status='completed').count(),
        'overdue_tasks': Task.query.filter(Task.status == 'overdue').count()
    }
    employees = User.query.filter_by(role='employee').order_by(User.name).all()
    categories = TaskCategory.query.order_by(TaskCategory.name).all()
    
    return render_template('director_dashboard.html', **stats, employees=employees, categories=categories)

@app.route('/employee')
@login_required
def employee_dashboard():
    if current_user.role != 'employee':
        flash('您没有权限访问此页面。', 'danger')
        return redirect(url_for('dashboard'))
        
    my_tasks = Task.query.filter_by(assignee_id=current_user.id)
    stats = {
        'total_tasks': my_tasks.count(),
        'pending_tasks': my_tasks.filter(Task.status.in_(['pending', 'in_progress'])).count(),
        'completed_tasks': my_tasks.filter_by(status='completed').count(),
        'overdue_tasks': my_tasks.filter_by(status='overdue').count()
    }
    categories = TaskCategory.query.order_by(TaskCategory.name).all()
    unread_notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).order_by(Notification.created_at.desc()).all()

    return render_template('employee_dashboard.html', **stats, categories=categories, unread_notifications=unread_notifications)

# --- API Endpoints ---
@app.route('/api/get_tasks')
@login_required
def get_tasks():
    today = date.today()
    query = Task.query
    if current_user.role == 'employee':
        query = query.filter_by(assignee_id=current_user.id)
    
    tasks = query.order_by(Task.due_date.asc()).all()
    task_list = []
    for task in tasks:
        days_left = (task.due_date.date() - today).days
        urgency = 'normal'
        if task.status != 'completed':
            if task.status == 'overdue' or days_left < 0: urgency = 'overdue'
            elif days_left == 0: urgency = 'today'
            elif days_left == 1: urgency = 'tomorrow'
            elif days_left <= 3: urgency = 'soon'

        task_list.append({
            'id': task.id, 'title': task.title, 'description': task.description,
            'category': task.category.name if task.category else "N/A",
            'assignee': task.assignee.name if task.assignee else "N/A",
            'creator': task.creator.name if task.creator else "N/A",
            'due_date': task.due_date.strftime('%Y-%m-%d'), 'status': task.status,
            'completion_status': task.completion_status, 'created_at': task.created_at.strftime('%Y-%m-%d %H:%M'),
            'urgency': urgency, 'days_left': days_left
        })
    return jsonify(task_list)

@app.route('/api/get_task_details/<int:task_id>')
@login_required
def get_task_details(task_id):
    task = Task.query.get_or_404(task_id)
    # Security check
    if current_user.role != 'director' and task.assignee_id != current_user.id:
        return jsonify({'success': False, 'message': '无权查看此任务'}), 403
    
    return jsonify({
        'success': True, 'id': task.id, 'title': task.title, 'description': task.description,
        'category': task.category.name, 'assignee': task.assignee.name, 'creator': task.creator.name,
        'due_date': task.due_date.strftime('%Y-%m-%d'), 'status': task.status, 'completion_status': task.completion_status,
        'created_at': task.created_at.strftime('%Y-%m-%d %H:%M'),
        'completed_at': task.completed_at.strftime('%Y-%m-%d %H:%M') if task.completed_at else '-'
    })

@app.route('/api/create_task', methods=['POST'])
@login_required
def create_task():
    data = request.get_json()
    if not all(k in data for k in ['title', 'assignee_id', 'category_id', 'due_date']):
        return jsonify({'success': False, 'message': '缺少必要字段'}), 400
    
    # Director can create for others, employee can only create for self
    if current_user.role != 'director' and int(data['assignee_id']) != current_user.id:
        return jsonify({'success': False, 'message': '权限不足'}), 403

    try:
        due_date = datetime.strptime(data['due_date'], '%Y-%m-%d')
        new_task = Task(
            title=data['title'], description=data.get('description', ''),
            category_id=data['category_id'], assignee_id=data['assignee_id'],
            creator_id=current_user.id, due_date=due_date
        )
        db.session.add(new_task)
        # Create notification for assignee
        noti = Notification(user_id=data['assignee_id'], message=f'您收到一个新任务: {new_task.title}')
        db.session.add(noti)
        db.session.commit()
        return jsonify({'success': True, 'message': '任务创建成功'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/update_task_status', methods=['POST'])
@login_required
def update_task_status():
    data = request.get_json()
    task = Task.query.get_or_404(data['task_id'])
    if task.assignee_id != current_user.id and current_user.role != 'director':
        return jsonify({'success': False, 'message': '权限不足'}), 403
    
    task.status = data['status']
    if task.status == 'completed':
        task.completed_at = datetime.utcnow()
        task.completion_status = 'on_time' if task.completed_at.date() <= task.due_date.date() else 'completed_late'
    else: # Re-opening a task
        task.completed_at = None
        task.completion_status = None
    
    db.session.commit()
    return jsonify({'success': True})
    
@app.route('/api/add_employee', methods=['POST'])
@login_required
def add_employee():
    if current_user.role != 'director':
        return jsonify({'success': False, 'message': '只有主任才能添加员工'}), 403
    data = request.get_json()
    try:
        new_user = User(
            name=data['name'],
            username=data['username'],
            password_hash=generate_password_hash(data['password']),
            role='employee'
        )
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'success': True, 'message': '员工添加成功'})
    except IntegrityError:
        db.session.rollback()
        return jsonify({'success': False, 'message': '用户名已存在'}), 409
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/categories', methods=['GET', 'POST'])
@login_required
def handle_categories():
    if current_user.role != 'director':
        return jsonify({'success': False, 'message': '权限不足'}), 403
    
    if request.method == 'POST':
        data = request.get_json()
        try:
            category = TaskCategory(name=data['name'])
            db.session.add(category)
            db.session.commit()
            return jsonify({'success': True, 'category': {'id': category.id, 'name': category.name}})
        except IntegrityError:
            db.session.rollback()
            return jsonify({'success': False, 'message': '该类别已存在'}), 409
    else: # GET
        categories = TaskCategory.query.all()
        return jsonify([{'id': c.id, 'name': c.name} for c in categories])

@app.route('/api/categories/<int:category_id>', methods=['DELETE'])
@login_required
def delete_category(category_id):
    if current_user.role != 'director':
        return jsonify({'success': False, 'message': '权限不足'}), 403
    
    category = TaskCategory.query.get_or_404(category_id)
    if category.tasks:
        return jsonify({'success': False, 'message': '无法删除，该类别下仍有关联任务'}), 400
    
    db.session.delete(category)
    db.session.commit()
    return jsonify({'success': True, 'message': '类别已删除'})

@app.route('/api/mark_notifications_read', methods=['POST'])
@login_required
def mark_notifications_read():
    data = request.get_json()
    if 'notification_ids' in data and data['notification_ids']:
        Notification.query.filter(
            Notification.user_id == current_user.id,
            Notification.id.in_(data['notification_ids'])
        ).update({'is_read': True}, synchronize_session=False)
        db.session.commit()
    return jsonify({'success': True})

@app.route('/api/export_tasks')
@login_required
def export_tasks():
    if current_user.role != 'director':
        return redirect(url_for('dashboard'))

    tasks = Task.query.order_by(Task.due_date.desc()).all()
    status_map = {'pending': '待处理', 'in_progress': '进行中', 'completed': '已完成', 'overdue': '已逾期'}
    completion_map = {'on_time': '按时完成', 'completed_late': '逾期完成', 'overdue_incomplete': '逾期未完成', None: '-'}

    data = [{
        '任务标题': t.title, '任务描述': t.description, '任务类别': t.category.name,
        '负责人': t.assignee.name, '创建者': t.creator.name,
        '创建日期': t.created_at.strftime('%Y-%m-%d'), '截止日期': t.due_date.strftime('%Y-%m-%d'),
        '状态': status_map.get(t.status), '完成情况': completion_map.get(t.completion_status),
        '完成日期': t.completed_at.strftime('%Y-%m-%d %H:%M') if t.completed_at else ''
    } for t in tasks]

    df = pd.DataFrame(data)
    output = io.BytesIO()
    df.to_excel(output, index=False, sheet_name='任务台账')
    output.seek(0)
    
    return send_file(output, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                     as_attachment=True, download_name=f'科室任务台账_{datetime.now().strftime("%Y%m%d")}.xlsx')

# --- Utility Functions ---
def update_overdue_tasks():
    with app.app_context():
        now = datetime.utcnow()
        overdue_tasks = Task.query.filter(Task.due_date < now, Task.status.in_(['pending', 'in_progress'])).all()
        for task in overdue_tasks:
            task.status = 'overdue'
            task.completion_status = 'overdue_incomplete'
            noti = Notification(user_id=task.assignee_id, message=f'任务 "{task.title}" 已逾期！')
            db.session.add(noti)
        if overdue_tasks:
            db.session.commit()

def init_db():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', password_hash=generate_password_hash('admin123'), name='科室主任', role='director')
            db.session.add(admin)
        if not User.query.filter_by(username='employee1').first():
            emp1 = User(username='employee1', password_hash=generate_password_hash('password'), name='张三', role='employee')
            db.session.add(emp1)
        if not User.query.filter_by(username='employee2').first():
            emp2 = User(username='employee2', password_hash=generate_password_hash('password'), name='李四', role='employee')
            db.session.add(emp2)
        
        default_categories = ['日常工作', '项目A', '项目B', '培训学习', '会议纪要']
        for cat_name in default_categories:
            if not TaskCategory.query.filter_by(name=cat_name).first():
                db.session.add(TaskCategory(name=cat_name))
        db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        init_db()
    # use_reloader=False is important when using a scheduler to avoid running it twice.
    app.run(debug=True, host='0.0.0.0', port=5000)