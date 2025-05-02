import os
from flask import (Flask, request, render_template, redirect, url_for,
                   flash, session, abort, get_flashed_messages, send_from_directory,
                   jsonify)
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import FlaskForm
# Импорты для регистрации/логина/форм
from wtforms import StringField, SubmitField, TextAreaField, PasswordField, BooleanField, HiddenField, IntegerField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, NumberRange
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
# Конец импортов
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import datetime
from urllib.parse import urlparse # Для безопасного редиректа
# --- CSRF Защита (Раскомментируйте и установите, если нужно) ---
# from flask_wtf.csrf import CSRFProtect
# --- Конец CSRF ---
from dotenv import load_dotenv # Загрузчик переменных из .env
from markupsafe import Markup # Импорт для пользовательского фильтра
# --- Импорт MetaData для соглашений об именовании ---
from sqlalchemy import MetaData
# --- Импорт для очистки файлов ---
import os

# --- ЗАГРУЗКА ПЕРЕМЕННЫХ ИЗ .env ---
load_dotenv()
# ------------------------------------

# --- Конфигурация ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = 'uploads'
THUMBNAIL_FOLDER = os.path.join('static', 'thumbnails')
STATIC_FOLDER = os.path.join(BASE_DIR, 'static')
ALLOWED_VIDEO_EXTENSIONS = {'mp4', 'mov', 'avi', 'mkv', 'webm'}
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
# TODO: Добавить ALLOWED_COVER_EXTENSIONS

app = Flask(__name__, static_folder=STATIC_FOLDER)

# --- БЕЗОПАСНАЯ ЗАГРУЗКА SECRET_KEY ---
SECRET_KEY = os.environ.get('FLASK_SECRET_KEY')
if not SECRET_KEY:
    is_development = os.environ.get('FLASK_ENV') == 'development' or os.environ.get('FLASK_DEBUG') == '1'
    if is_development:
        print("\n" + "="*50); print("ПРЕДУПРЕЖДЕНИЕ: FLASK_SECRET_KEY не установлена!"); print("Используется ВРЕМЕННЫЙ ключ."); print(f"Пример генерации: python -c 'import secrets; print(secrets.token_hex(24))'"); print("="*50 + "\n")
        SECRET_KEY = 'temporary-unsafe-dev-key-replace-me!'
    else: raise ValueError("Критическая ошибка: FLASK_SECRET_KEY не установлена!")
app.config['SECRET_KEY'] = SECRET_KEY
# -----------------------------------------

# --- ПАРОЛИ АДМИНА ---
ADMIN_GRANT_PASSWORD_CONFIG = os.environ.get('ADMIN_GRANT_PASSWORD')
EMERGENCY_LOGIN_USERNAME_CONFIG = os.environ.get('EMERGENCY_LOGIN_USER')
# -----------------------------------------

# --- ПРОВЕРКА КОНФИГУРАЦИИ ---
is_dev_check = os.environ.get('FLASK_ENV') == 'development' or os.environ.get('FLASK_DEBUG') == '1'
if not ADMIN_GRANT_PASSWORD_CONFIG and is_dev_check: print("\n" + "="*50); print("ПРЕДУПРЕЖДЕНИЕ: ADMIN_GRANT_PASSWORD не установлена!"); print("Функция grant_admin будет недоступна."); print("="*50 + "\n")
if not EMERGENCY_LOGIN_USERNAME_CONFIG and ADMIN_GRANT_PASSWORD_CONFIG and is_dev_check: print("\n" + "="*50); print("ПРЕДУПРЕЖДЕНИЕ: EMERGENCY_LOGIN_USER не установлена!"); print("Функция emergency_admin_login не будет работать."); print("="*50 + "\n")
# -----------------------------------------

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['THUMBNAIL_FOLDER'] = THUMBNAIL_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024 # 1 GB

# --- CSRF Защита ---
# csrf = CSRFProtect(app)
# --- Конец CSRF ---

# --- SQLAlchemy + Migrate ---
convention = {"ix": 'ix_%(column_0_label)s',"uq": "uq_%(table_name)s_%(column_0_name)s","ck": "ck_%(table_name)s_%(constraint_name)s","fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s","pk": "pk_%(table_name)s"}; metadata = MetaData(naming_convention=convention)
db = SQLAlchemy(app, metadata=metadata); migrate = Migrate(app, db, render_as_batch=True)
# --- Flask-Login ---
login_manager = LoginManager(app); login_manager.login_view = 'login'; login_manager.login_message = 'Пожалуйста, войдите.'; login_manager.login_message_category = 'info'
# --- Создание папок ---
if not os.path.exists(UPLOAD_FOLDER): os.makedirs(UPLOAD_FOLDER)
if not os.path.exists(THUMBNAIL_FOLDER): os.makedirs(THUMBNAIL_FOLDER)
if not os.path.exists(os.path.join(STATIC_FOLDER, 'images')): os.makedirs(os.path.join(STATIC_FOLDER, 'images'))
# --- Фильтр nl2br ---
def nl2br(value):
    if value: return Markup(str(value).replace('\n', '<br>\n'))
    return ''
app.jinja_env.filters['nl2br'] = nl2br
# ----------------------------------------------------

# --- Модели Базы Данных ---
subscriptions = db.Table('subscriptions', db.Column('subscriber_id', db.Integer, db.ForeignKey('user.id', name='fk_subscriptions_subscriber_id_user'), primary_key=True), db.Column('channel_id', db.Integer, db.ForeignKey('channel.id', name='fk_subscriptions_channel_id_channel'), primary_key=True))
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True); username = db.Column(db.String(64), index=True, unique=True, nullable=False); email = db.Column(db.String(120), index=True, unique=True, nullable=False); password_hash = db.Column(db.String(128)); is_admin_role = db.Column(db.Boolean, default=False, nullable=False)
    channel = db.relationship('Channel', back_populates='owner', uselist=False, cascade="all, delete-orphan"); subscribed_channels = db.relationship('Channel', secondary=subscriptions, back_populates='subscribers', lazy='dynamic')
    comments = db.relationship('Comment', back_populates='author', lazy='dynamic')
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password) if self.password_hash else False
    def get_id(self): return str(self.id)
    @property
    def is_admin(self): return self.is_admin_role
    def __repr__(self): return f'<User {self.username}>'
class Channel(db.Model):
    id = db.Column(db.Integer, primary_key=True); name = db.Column(db.String(100), nullable=False, unique=True, index=True); description = db.Column(db.Text, nullable=True); cover_filename = db.Column(db.String(255), nullable=True); created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False); owner = db.relationship('User', back_populates='channel')
    videos = db.relationship('Video', back_populates='channel', lazy='dynamic', cascade="all, delete-orphan"); subscribers = db.relationship('User', secondary=subscriptions, back_populates='subscribed_channels', lazy='dynamic')
    @property
    def subscriber_count(self):
        try: return self.subscribers.count()
        except Exception as e: app.logger.error(f"Error counting subscribers: {e}", exc_info=True); return 0
    def __repr__(self): return f'<Channel {self.name}>'
class Video(db.Model):
    id = db.Column(db.Integer, primary_key=True); filename = db.Column(db.String(255), unique=True, nullable=False, index=True); title = db.Column(db.String(200), nullable=False); description = db.Column(db.Text, nullable=True); upload_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow); like_count = db.Column(db.Integer, default=0); thumbnail_filename = db.Column(db.String(255), nullable=True)
    comments = db.relationship('Comment', back_populates='video', cascade="all, delete-orphan") # Убран lazy='dynamic'
    channel_id = db.Column(db.Integer, db.ForeignKey('channel.id'), nullable=False, index=True); channel = db.relationship('Channel', back_populates='videos')
    def __repr__(self): return f'<Video {self.filename}>'
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True); text = db.Column(db.Text, nullable=False); timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow); video_id = db.Column(db.Integer, db.ForeignKey('video.id', name='fk_comment_video_id_video'), nullable=False); user_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_comment_user_id_user'), nullable=False)
    author = db.relationship('User', back_populates='comments')
    video = db.relationship('Video', back_populates='comments')
    def __repr__(self): author_username = self.author.username if self.author else 'Unknown'; return f'<Comment {self.id} by {author_username}>'
# --- Загрузчик пользователя ---
@login_manager.user_loader
def load_user(user_id):
    try: return User.query.options(db.joinedload(User.channel)).get(int(user_id))
    except ValueError: return None
    except Exception as e: app.logger.error(f"Error loading user: {e}", exc_info=True); return None
# --- Формы ---
class RegistrationForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired(), Length(min=3, max=64)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Повторите пароль', validators=[DataRequired(), EqualTo('password', message='Пароли должны совпадать.')])
    submit = SubmitField('Зарегистрироваться')
    def validate_username(self, username):
        user = User.query.filter(User.username.ilike(username.data)).first()
        if user: raise ValidationError('Это имя пользователя уже занято.')
    def validate_email(self, email):
        user = User.query.filter(User.email.ilike(email.data)).first()
        if user: raise ValidationError('Этот email уже зарегистрирован.')
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember_me = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')
class CommentForm(FlaskForm):
    comment_text = TextAreaField('Комментарий', validators=[DataRequired(), Length(min=1, max=500)])
    submit = SubmitField('Отправить')
class GrantAdminForm(FlaskForm):
    password = PasswordField('Пароль админа', validators=[DataRequired()])
    submit = SubmitField('Получить права')
class EmergencyAdminLoginForm(FlaskForm):
    password = PasswordField('Пароль админа', validators=[DataRequired()])
    submit = SubmitField('Аварийный вход')
class ChannelForm(FlaskForm):
    name = StringField('Название', validators=[DataRequired(), Length(min=3, max=100)])
    description = TextAreaField('Описание', validators=[Length(max=1000)])
    submit = SubmitField('Сохранить')
    def set_editing_id(self, channel_id): self._editing_channel_id = channel_id
    def validate_name(self, name):
        query = Channel.query.filter(Channel.name.ilike(name.data))
        if hasattr(self, '_editing_channel_id') and self._editing_channel_id: query = query.filter(Channel.id != self._editing_channel_id)
        if query.first(): raise ValidationError('Название занято.')
class AdminSetRoleForm(FlaskForm):
    user_id = HiddenField('ID', validators=[DataRequired()])
    is_admin = BooleanField('Админ')
    submit_role = SubmitField('Сохранить')
class AdminEditChannelForm(FlaskForm):
    channel_id = HiddenField('ID', validators=[DataRequired()])
    name = StringField('Название', validators=[DataRequired(), Length(min=3, max=100)])
    description = TextAreaField('Описание', validators=[Length(max=1000)])
    submit_channel = SubmitField('Сохранить')
    def set_editing_id(self, channel_id): self._editing_channel_id = channel_id
    def validate_name(self, name):
        query = Channel.query.filter(Channel.name.ilike(name.data))
        if hasattr(self, '_editing_channel_id') and self._editing_channel_id: query = query.filter(Channel.id != self._editing_channel_id)
        if query.first(): raise ValidationError('Название занято.')
class AdminManageSubscriptionForm(FlaskForm):
    channel_id = HiddenField('ID', validators=[DataRequired()])
    username = StringField('Имя подписчика', validators=[DataRequired()])
    submit_subscribe = SubmitField('Подписать')
    submit_unsubscribe = SubmitField('Отписать')
class AdminEditVideoForm(FlaskForm):
    video_id = HiddenField('ID', validators=[DataRequired()])
    title = StringField('Название', validators=[DataRequired(), Length(max=200)])
    description = TextAreaField('Описание', validators=[Length(max=5000)])
    like_count = IntegerField('Лайки', validators=[DataRequired(), NumberRange(min=0)], default=0)
    submit_video = SubmitField('Сохранить')
class UserVideoEditForm(FlaskForm):
    video_id = HiddenField('ID', validators=[DataRequired()])
    title = StringField('Название', validators=[DataRequired(), Length(max=200)])
    description = TextAreaField('Описание', validators=[Length(max=5000)])
    submit = SubmitField('Сохранить')
# --- Декораторы и Функции ---
def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user or not current_user.is_admin_role:
            flash('Доступ запрещен.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function
def allowed_file(filename, allowed_extensions):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions
@app.context_processor
def inject_common_data():
    def is_subscribed_to(channel):
        if not current_user.is_authenticated or not channel: return False
        return current_user.subscribed_channels.filter(subscriptions.c.channel_id == channel.id).count() > 0
    return dict(now=datetime.utcnow, current_user=current_user, is_subscribed_to=is_subscribed_to)

# --- Маршруты ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            user = User(username=form.username.data, email=form.email.data)
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            flash('Успешно! Теперь войдите.', 'success')
            flash('Создайте канал.', 'info')
            login_user(user)
            return redirect(url_for('manage_channel'))
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка: {e}', 'danger')
            app.logger.error(f"Reg error: {e}", exc_info=True)
    return render_template('register.html', title='Регистрация', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.options(db.joinedload(User.channel)).filter(User.email.ilike(form.email.data)).first()
        if user is None or not user.check_password(form.password.data):
            flash('Неверные данные.', 'danger')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        flash(f'Привет, {user.username}!', 'success')
        next_page = request.args.get('next')
        if next_page and urlparse(next_page).netloc == '':
            if urlparse(next_page).path == url_for('manage_channel') and user.channel:
                return redirect(url_for('index'))
            return redirect(next_page)
        else:
            if user.channel is None:
                flash('Создайте канал.', 'info')
                return redirect(url_for('manage_channel'))
            else:
                return redirect(url_for('index'))
    return render_template('login.html', title='Вход', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли.', 'info')
    return redirect(url_for('index'))

@app.route('/my_channel/edit', methods=['GET', 'POST'])
@login_required
def manage_channel():
    channel = current_user.channel
    form = ChannelForm(obj=channel)
    if channel: form.set_editing_id(channel.id)
    if form.validate_on_submit():
        try:
            if channel is None:
                channel = Channel(owner=current_user)
                db.session.add(channel)
                msg = 'Канал создан!'
            else:
                msg = 'Канал обновлен!'
            form.populate_obj(channel)
            db.session.commit()
            flash(msg, 'success')
            return redirect(url_for('studio'))
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка: {e}', 'danger')
            app.logger.error(f"Channel manage error: {e}", exc_info=True)
    elif request.method == 'POST':
        flash('Исправьте ошибки.', 'warning')
    page_title = "Редактирование" if channel else "Создание"
    form.submit.label.text = "Сохранить" if channel else "Создать"
    return render_template('manage_channel.html', title=page_title, form=form, channel=channel)

@app.route('/studio')
@login_required
def studio():
    channel = current_user.channel
    if channel is None:
        flash('Создайте канал.', 'info')
        return redirect(url_for('manage_channel'))
    videos_list = channel.videos.order_by(Video.upload_date.desc()).all()
    return render_template('studio.html', title=f"Студия '{channel.name}'", channel=channel, videos_list=videos_list)

@app.route('/upload_video', methods=['GET', 'POST'])
@login_required
def upload_video():
    channel = current_user.channel
    if channel is None:
        flash('Невозможно загрузить видео, канал не найден.', 'danger')
        return redirect(url_for('manage_channel'))
    if request.method == 'POST':
        if 'file' not in request.files or 'thumbnail' not in request.files:
            flash('Нужны оба файла: видео и обложка.', 'danger'); return redirect(request.url)
        video_file = request.files['file']; thumbnail_file = request.files['thumbnail']
        video_title = request.form.get('title', '').strip(); video_description = request.form.get('description', '').strip()
        if not video_file.filename or not thumbnail_file.filename:
            flash('Выберите файлы видео и обложки.', 'danger'); return redirect(request.url)
        if not video_title:
            flash('Необходимо указать название видео.', 'danger'); return redirect(request.url)
        if not (allowed_file(video_file.filename, ALLOWED_VIDEO_EXTENSIONS) and allowed_file(thumbnail_file.filename, ALLOWED_IMAGE_EXTENSIONS)):
            flash('Неверный тип файла.', 'warning'); return redirect(request.url)
        video_filename_secure = secure_filename(video_file.filename); thumbnail_filename_secure = secure_filename(thumbnail_file.filename)
        final_video_filename = video_filename_secure; final_thumbnail_filename = thumbnail_filename_secure
        vid_counter, thumb_counter = 1, 1
        while True:
            video_filepath = os.path.join(app.config['UPLOAD_FOLDER'], final_video_filename)
            exists_in_fs = os.path.exists(video_filepath); exists_in_db = Video.query.filter_by(filename=final_video_filename).first() is not None
            if not exists_in_fs and not exists_in_db:
                break
            name, ext = os.path.splitext(video_filename_secure); final_video_filename = f"{name}_{vid_counter}{ext}"; vid_counter += 1
        while True:
            thumbnail_filepath = os.path.join(app.config['THUMBNAIL_FOLDER'], final_thumbnail_filename)
            if not os.path.exists(thumbnail_filepath):
                break
            name, ext = os.path.splitext(thumbnail_filename_secure); final_thumbnail_filename = f"{name}_{thumb_counter}{ext}"; thumb_counter += 1
        video_filepath = os.path.join(app.config['UPLOAD_FOLDER'], final_video_filename); thumbnail_filepath = os.path.join(app.config['THUMBNAIL_FOLDER'], final_thumbnail_filename); saved_video_path = None; saved_thumb_path = None
        try:
            video_file.save(video_filepath); saved_video_path = video_filepath
            thumbnail_file.save(thumbnail_filepath); saved_thumb_path = thumbnail_filepath
        except Exception as fe:
            if saved_video_path and os.path.exists(saved_video_path):
                try: os.remove(saved_video_path)
                except Exception as er: app.logger.error(f"Cleanup fail (video): {er}",exc_info=True)
            if saved_thumb_path and os.path.exists(saved_thumb_path):
                try: os.remove(saved_thumb_path)
                except Exception as er: app.logger.error(f"Cleanup fail (thumb): {er}",exc_info=True)
            flash(f'Ошибка сохранения: {fe}','danger');return redirect(request.url)
        try:
            new_video = Video(filename=final_video_filename, title=video_title, description=video_description, thumbnail_filename=final_thumbnail_filename, channel_id=channel.id)
            db.session.add(new_video); db.session.commit()
            flash(f'Видео "{video_title}" загружено!', 'success'); return redirect(url_for('studio'))
        except Exception as dbe:
            db.session.rollback()
            if saved_video_path and os.path.exists(saved_video_path):
                try: os.remove(saved_video_path)
                except Exception as er: app.logger.error(f"Cleanup fail (video DB err): {er}",exc_info=True)
            if saved_thumb_path and os.path.exists(saved_thumb_path):
                try: os.remove(saved_thumb_path)
                except Exception as er: app.logger.error(f"Cleanup fail (thumb DB err): {er}",exc_info=True)
            flash(f'Ошибка БД: {dbe}', 'danger'); app.logger.error(f"DB Error saving video: {dbe}", exc_info=True); return redirect(request.url)
    return render_template('upload_video.html', title="Загрузка видео")

@app.route('/')
def index():
    search_query = request.args.get('query', '', type=str).strip()
    videos_list = []
    try:
        query = Video.query.options(db.joinedload(Video.channel).joinedload(Channel.owner))
        if search_query:
            search_pattern = f'%{search_query}%'
            query = query.join(Channel).join(User).filter(
                Video.title.ilike(search_pattern) |
                Video.description.ilike(search_pattern) |
                Channel.name.ilike(search_pattern) |
                User.username.ilike(search_pattern)
            )
            count = query.count()
            if count == 0:
                flash(f'По запросу "{search_query}" нет видео.', 'info')
        videos_list = query.order_by(Video.upload_date.desc()).all()
    except Exception as e:
        app.logger.exception(f"DB Error index: {e}")
        flash("Ошибка загрузки видео.", 'danger')
    return render_template('index.html', videos_list=videos_list, search_query=search_query)


@app.route('/watch/<path:filename>')
def watch_video(filename):
    safe_filename = secure_filename(filename)
    video = Video.query.options(
        db.joinedload(Video.channel).joinedload(Channel.owner),
        db.selectinload(Video.comments).joinedload(Comment.author)
    ).filter_by(filename=safe_filename).first_or_404()

    video_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
    if not os.path.exists(video_path) or not os.path.isfile(video_path):
        flash(f'Файл видео "{safe_filename}" не найден!', 'warning')
        app.logger.warning(f"Video file missing: {video_path}")

    comments = sorted(video.comments, key=lambda c: c.timestamp, reverse=True)

    comment_form = CommentForm()
    is_currently_liked = False
    if current_user.is_authenticated:
        session_key = f'liked_videos_{current_user.id}'
        is_currently_liked = video.id in set(session.get(session_key, []))

    return render_template('watch.html', video=video, comments=comments, comment_form=comment_form, is_currently_liked=is_currently_liked)

@app.route('/channel/<int:channel_id>')
def channel_page(channel_id):
    channel_obj = Channel.query.options(db.joinedload(Channel.owner)).get_or_404(channel_id)
    videos_list = channel_obj.videos.order_by(Video.upload_date.desc()).all()
    return render_template('channel.html', title=f"Канал {channel_obj.name}", channel=channel_obj, videos_list=videos_list)

@app.route('/add_comment/<path:filename>', methods=['POST'])
@login_required
def add_comment(filename):
    safe_filename = secure_filename(filename)
    video = Video.query.filter_by(filename=safe_filename).first()
    if not video:
        flash('Видео нет.', 'danger')
        return redirect(url_for('index'))
    form = CommentForm()
    if form.validate_on_submit():
        try:
            new_comment = Comment(text=form.comment_text.data, video_id=video.id, user_id=current_user.id)
            db.session.add(new_comment)
            db.session.commit()
            flash('Комментарий добавлен.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка коммента: {e}', 'danger')
            app.logger.error(f"Comment add error: {e}", exc_info=True)
    else:
        for field, errors in form.errors.items():
            label_text = getattr(getattr(form, field, None), 'label', None)
            field_name = label_text.text if label_text else field
            flash(f"Ошибка '{field_name}': {', '.join(errors)}", 'warning')
    return redirect(url_for('watch_video', filename=safe_filename))

@app.route('/like_video/<path:filename>', methods=['POST'])
@login_required
def like_video(filename):
    safe_filename = secure_filename(filename)
    video = Video.query.filter_by(filename=safe_filename).first()
    if not video: return jsonify({'success': False, 'message': 'Видео нет'}), 404
    session_key = f'liked_videos_{current_user.id}'
    liked_videos_in_session = set(session.get(session_key, []))
    is_liked_after_action = False; action_message = ""
    try:
        if video.id in liked_videos_in_session:
            video.like_count = max(0, (video.like_count or 0) - 1); liked_videos_in_session.remove(video.id); is_liked_after_action = False; action_message = "Лайк убран"
        else:
            video.like_count = (video.like_count or 0) + 1; liked_videos_in_session.add(video.id); is_liked_after_action = True; action_message = "Лайк добавлен"
        session[session_key] = list(liked_videos_in_session); session.modified = True; db.session.commit()
        return jsonify({'success': True, 'new_like_count': video.like_count, 'liked': is_liked_after_action, 'message': action_message})
    except Exception as e:
        db.session.rollback(); app.logger.error(f"Like error: {e}", exc_info=True); return jsonify({'success': False, 'message': 'Ошибка БД'}), 500

@app.route('/subscribe/<int:channel_id>', methods=['POST'])
@login_required
def subscribe(channel_id):
    channel_to_subscribe = Channel.query.get_or_404(channel_id)
    if channel_to_subscribe.owner_id == current_user.id:
        flash('Нельзя подписаться на себя.', 'warning'); return redirect(url_for('channel_page', channel_id=channel_id))

    if is_subscribed_to(channel_to_subscribe):
        flash('Уже подписаны.', 'info'); return redirect(url_for('channel_page', channel_id=channel_id))
    try:
        current_user.subscribed_channels.append(channel_to_subscribe); db.session.commit(); flash(f'Подписались на "{channel_to_subscribe.name}"!', 'success')
    except Exception as e:
        db.session.rollback(); flash(f'Ошибка подписки: {e}', 'danger'); app.logger.error(f"Sub error: {e}", exc_info=True)
    return redirect(url_for('channel_page', channel_id=channel_id))

@app.route('/unsubscribe/<int:channel_id>', methods=['POST'])
@login_required
def unsubscribe(channel_id):
    channel_to_unsubscribe = Channel.query.get_or_404(channel_id)

    if not is_subscribed_to(channel_to_unsubscribe):
        flash('Не были подписаны.', 'info'); return redirect(url_for('channel_page', channel_id=channel_id))
    try:
        current_user.subscribed_channels.remove(channel_to_unsubscribe); db.session.commit(); flash(f'Отписались от "{channel_to_unsubscribe.name}".', 'success')
    except Exception as e:
        db.session.rollback(); flash(f'Ошибка отписки: {e}', 'danger'); app.logger.error(f"Unsub error: {e}", exc_info=True)
    return redirect(url_for('channel_page', channel_id=channel_id))

@app.route('/my_video/edit/<int:video_id>', methods=['GET', 'POST'])
@login_required
def edit_my_video(video_id):
    video = Video.query.get_or_404(video_id)
    if not current_user.channel or video.channel_id != current_user.channel.id:
        flash('Нет прав.', 'danger'); app.logger.warning(f"User {current_user.id} tried edit video {video_id}"); return redirect(url_for('studio'))
    form = UserVideoEditForm(obj=video)
    if form.validate_on_submit():
        try:
            video.title = form.title.data; video.description = form.description.data; db.session.commit(); flash(f'Видео "{video.title}" обновлено.', 'success'); return redirect(url_for('studio'))
        except Exception as e:
            db.session.rollback(); flash(f'Ошибка обновления: {e}', 'danger'); app.logger.error(f"Edit own video error: {e}", exc_info=True)
    elif request.method == 'POST':
        flash('Исправьте ошибки.', 'warning')
    return render_template('edit_my_video.html', title="Редактирование", form=form, video=video)


@app.route('/my_video/delete/<int:video_id>', methods=['POST'])
@login_required
def delete_my_video(video_id):
    video = Video.query.get_or_404(video_id)
    if not current_user.channel or video.channel_id != current_user.channel.id:
        flash('Нет прав.', 'danger'); app.logger.warning(f"User {current_user.id} tried DELETE video {video_id}"); return redirect(url_for('studio'))
    filename_to_delete = video.filename; thumbnail_to_delete = video.thumbnail_filename; title_deleted = video.title
    try:
        db.session.delete(video); db.session.commit(); flash(f'Видео "{title_deleted}" удалено.', 'success')
        video_filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename_to_delete)
        if filename_to_delete and os.path.exists(video_filepath):
            try:
                os.remove(video_filepath); app.logger.info(f"User deleted video: {video_filepath}")
            except Exception as er:
                flash(f'Файл видео не удален: {er}', 'warning'); app.logger.warning(f"Fail delete video file: {er}", exc_info=True)
        if thumbnail_to_delete:
            thumbnail_filepath = os.path.join(app.config['THUMBNAIL_FOLDER'], thumbnail_to_delete)
            if os.path.exists(thumbnail_filepath):
                try:
                    os.remove(thumbnail_filepath); app.logger.info(f"User deleted thumb: {thumbnail_filepath}")
                except Exception as er:
                    flash(f'Файл обложки не удален: {er}', 'warning'); app.logger.warning(f"Fail delete thumb file: {er}", exc_info=True)
    except Exception as dbe:
        db.session.rollback(); flash(f'Ошибка удаления БД: {dbe}', 'danger'); app.logger.error(f"Error deleting own video DB: {dbe}", exc_info=True)
    return redirect(url_for('studio'))

# --- АДМИНКА (ИСПРАВЛЕНА ОБРАБОТКА ФОРМ) ---
@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin_panel():
    set_role_form = AdminSetRoleForm()
    edit_channel_form = AdminEditChannelForm()
    sub_form = AdminManageSubscriptionForm()
    edit_video_form = AdminEditVideoForm()

    if request.method == 'POST':
        action_type = request.form.get('action_type')

        if action_type == 'set_role' and set_role_form.validate_on_submit():
            user_to_modify = User.query.get(set_role_form.user_id.data)
            new_role = set_role_form.is_admin.data
            if user_to_modify:
                if user_to_modify.id == current_user.id and not new_role:
                    flash('Вы не можете снять права с себя.', 'danger')
                else:
                    try:
                        user_to_modify.is_admin_role = new_role
                        db.session.commit()
                        role_str = "назначены" if new_role else "сняты"
                        flash(f'Права админа для {user_to_modify.username} {role_str}.', 'success')
                    except Exception as e:
                        db.session.rollback()
                        flash(f'Ошибка роли: {e}', 'danger')
                        app.logger.error(f"Admin role error: {e}", exc_info=True)
            else:
                flash('Пользователь не найден.', 'warning')
        elif action_type == 'set_role':
             for field, errors in set_role_form.errors.items():
                 label = getattr(set_role_form, field).label.text if hasattr(getattr(set_role_form, field), 'label') else field
                 flash(f"Ошибка формы роли, '{label}': {', '.join(errors)}", 'warning')


        elif action_type == 'edit_channel':
             channel_id_from_post = request.form.get('channel_id')
             if channel_id_from_post:
                 try: # Добавляем try-except на случай если channel_id_from_post не число
                    edit_channel_form.set_editing_id(int(channel_id_from_post))
                 except ValueError:
                    flash('Неверный ID канала в форме.', 'danger')
                    return redirect(url_for('admin_panel')) # Прерываем обработку

             if edit_channel_form.validate_on_submit():
                 channel_to_edit = Channel.query.get(edit_channel_form.channel_id.data)
                 if channel_to_edit:
                     try:
                         channel_to_edit.name = edit_channel_form.name.data # Обновляем явно
                         channel_to_edit.description = edit_channel_form.description.data # Обновляем явно
                         db.session.commit()
                         flash(f'Канал "{channel_to_edit.name}" обновлен.', 'success')
                     except Exception as e:
                         db.session.rollback()
                         flash(f'Ошибка обновления канала: {e}', 'danger')
                         app.logger.error(f"Admin channel edit error: {e}", exc_info=True)
                 else:
                     flash('Канал для ред. не найден (ID из формы).', 'warning')
             else:
                  for field, errors in edit_channel_form.errors.items():
                     label = getattr(edit_channel_form, field).label.text if hasattr(getattr(edit_channel_form, field), 'label') else field
                     flash(f"Ошибка формы канала, '{label}': {', '.join(errors)}", 'warning')


        elif action_type == 'manage_subscription' and sub_form.validate_on_submit():
             channel = Channel.query.get(sub_form.channel_id.data)
             user_to_manage = User.query.filter(User.username.ilike(sub_form.username.data)).first()

             if not channel: flash('Канал не найден.', 'warning')
             elif not user_to_manage: flash(f'Пользователь "{sub_form.username.data}" не найден.', 'warning')
             elif channel.owner_id == user_to_manage.id: flash('Владелец не м.б. подписчиком.', 'warning')
             else:
                 is_currently_subscribed = user_to_manage.subscribed_channels.filter(subscriptions.c.channel_id == channel.id).count() > 0
                 app.logger.info(f"Admin sub check: User '{user_to_manage.username}' subbed to '{channel.name}'? {is_currently_subscribed}")

                 try:
                     if sub_form.submit_subscribe.data:
                         if not is_currently_subscribed:
                             user_to_manage.subscribed_channels.append(channel)
                             db.session.commit()
                             flash(f'{user_to_manage.username} подписан на {channel.name}.', 'success')
                             app.logger.info(f"Admin SUBscribed '{user_to_manage.username}' to '{channel.name}'.")
                         else:
                             flash(f'{user_to_manage.username} уже был подписан.', 'info')
                     elif sub_form.submit_unsubscribe.data:
                          if is_currently_subscribed:
                              user_to_manage.subscribed_channels.remove(channel)
                              db.session.commit()
                              flash(f'{user_to_manage.username} отписан от {channel.name}.', 'success')
                              app.logger.info(f"Admin UNsubscribed '{user_to_manage.username}' from '{channel.name}'.")
                          else:
                              flash(f'{user_to_manage.username} не был подписан.', 'info')
                 except Exception as e:
                     db.session.rollback()
                     flash(f'Ошибка подписки: {e}', 'danger')
                     app.logger.error(f"Admin sub error: {e}", exc_info=True)
        elif action_type == 'manage_subscription':
             for field, errors in sub_form.errors.items():
                 label = getattr(sub_form, field).label.text if hasattr(getattr(sub_form, field), 'label') else field
                 flash(f"Ошибка формы подписки, '{label}': {', '.join(errors)}", 'warning')


        elif action_type == 'edit_video' and edit_video_form.validate_on_submit():
            video_to_edit = Video.query.get(edit_video_form.video_id.data)
            if video_to_edit:
                 try:
                     video_to_edit.title = edit_video_form.title.data
                     video_to_edit.description = edit_video_form.description.data
                     video_to_edit.like_count = edit_video_form.like_count.data
                     db.session.commit()
                     flash(f'Видео "{video_to_edit.title}" обновлено (лайки: {video_to_edit.like_count}).', 'success')
                 except Exception as e:
                     db.session.rollback()
                     flash(f'Ошибка обновления видео: {e}', 'danger')
                     app.logger.error(f"Admin video edit error: {e}", exc_info=True)
            else:
                flash('Видео для ред. не найдено (ID из формы).', 'warning')
        elif action_type == 'edit_video':
             for field, errors in edit_video_form.errors.items():
                 if field == 'video_id' and len(edit_video_form.errors) == 1:
                     continue
                 label = getattr(edit_video_form, field).label.text if hasattr(getattr(edit_video_form, field), 'label') else field
                 flash(f"Ошибка формы видео, '{label}': {', '.join(errors)}", 'warning')

        elif action_type == 'delete_video':
             video_id_to_delete = request.form.get('video_id')
             video_to_delete = Video.query.get(video_id_to_delete)
             if video_to_delete:
                 filename_to_delete = video_to_delete.filename
                 thumbnail_to_delete = video_to_delete.thumbnail_filename
                 title_deleted = video_to_delete.title
                 try:
                     db.session.delete(video_to_delete)
                     db.session.commit()
                     flash(f'Видео "{title_deleted}" удалено админом.', 'success')
                     video_filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename_to_delete)
                     if filename_to_delete and os.path.exists(video_filepath):
                         try: os.remove(video_filepath); app.logger.info(f"Admin deleted video: {video_filepath}")
                         except Exception as er: flash(f'Файл видео не удален админом: {er}', 'warning'); app.logger.warning(f"Fail admin delete video: {er}", exc_info=True)
                     if thumbnail_to_delete:
                         thumbnail_filepath = os.path.join(app.config['THUMBNAIL_FOLDER'], thumbnail_to_delete)
                         if os.path.exists(thumbnail_filepath):
                             try: os.remove(thumbnail_filepath); app.logger.info(f"Admin deleted thumb: {thumbnail_filepath}")
                             except Exception as er: flash(f'Файл обложки не удален админом: {er}', 'warning'); app.logger.warning(f"Fail admin delete thumb: {er}", exc_info=True)
                 except Exception as dbe:
                     db.session.rollback(); flash(f'Ошибка удаления БД админом: {dbe}', 'danger'); app.logger.error(f"Admin delete video DB error: {dbe}", exc_info=True)
             else: flash('Видео для удаления админом не найдено.', 'warning')

        elif action_type not in ['set_role', 'edit_channel', 'manage_subscription', 'edit_video', 'delete_video']:
             flash('Неизвестное действие админки.', 'warning')

        return redirect(url_for('admin_panel'))

    # --- GET запрос админ-панели ---
    try:
        users = User.query.order_by(User.username).all()
        channels = Channel.query.options(db.joinedload(Channel.owner)).order_by(Channel.name).all()
        videos = Video.query.options(db.joinedload(Video.channel).joinedload(Channel.owner)).order_by(Video.upload_date.desc()).all()
    except Exception as e:
        users, channels, videos = [], [], []
        app.logger.exception(f"DB Error loading admin: {e}")
        flash(f"Ошибка чтения данных.", 'danger')

    return render_template('admin.html', title="Панель Администратора", users=users, channels=channels, videos=videos,
                           set_role_form=set_role_form, edit_channel_form=edit_channel_form,
                           sub_form=sub_form, edit_video_form=edit_video_form)
# --- КОНЕЦ АДМИНКИ ---

@app.route('/grant_admin', methods=['GET', 'POST'])
@login_required
def grant_admin():
    if not ADMIN_GRANT_PASSWORD_CONFIG:
        flash('Функция не настроена.', 'warning'); return redirect(url_for('index'))
    if current_user.is_admin_role:
        flash('Вы уже админ.', 'info'); return redirect(url_for('admin_panel'))
    form = GrantAdminForm()
    if form.validate_on_submit():
        if form.password.data == ADMIN_GRANT_PASSWORD_CONFIG:
            try:
                current_user.is_admin_role = True; db.session.commit(); flash('Права даны! Войдите снова.', 'success'); logout_user(); return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback(); flash(f'Ошибка роли: {e}', 'danger'); app.logger.error(f"Grant admin error: {e}", exc_info=True)
        else:
            flash('Неверный пароль.', 'danger')
    return render_template('grant_admin.html', title='Получить права', form=form)

@app.route('/emergency_admin_login', methods=['GET', 'POST'])
def emergency_admin_login():
    if current_user.is_authenticated: return redirect(url_for('index'))
    missing_configs = [v for v, c in [('ADMIN_GRANT_PASSWORD', ADMIN_GRANT_PASSWORD_CONFIG), ('EMERGENCY_LOGIN_USER', EMERGENCY_LOGIN_USERNAME_CONFIG)] if not c]
    if missing_configs:
        flash(f'Функция не настроена ({", ".join(missing_configs)}).', 'danger'); return redirect(url_for('index'))
    form = EmergencyAdminLoginForm()
    if form.validate_on_submit():
        if form.password.data == ADMIN_GRANT_PASSWORD_CONFIG:
            emergency_user = User.query.filter_by(username=EMERGENCY_LOGIN_USERNAME_CONFIG).first()
            if not emergency_user:
                flash(f'Пользователь "{EMERGENCY_LOGIN_USERNAME_CONFIG}" не найден.', 'danger'); app.logger.error(f"Emergency user not found")
            elif not emergency_user.is_admin_role:
                flash(f'Пользователь "{EMERGENCY_LOGIN_USERNAME_CONFIG}" не админ.', 'danger'); app.logger.warning(f"Emergency user not admin")
            else:
                try:
                    login_user(emergency_user); flash(f'Аварийный вход: {emergency_user.username}!', 'success'); return redirect(url_for('admin_panel'))
                except Exception as e:
                    flash(f'Ошибка входа: {e}', 'danger'); app.logger.error(f"Emergency login error: {e}", exc_info=True)
        else:
            flash('Неверный пароль.', 'danger')
    return render_template('emergency_login.html', title='Аварийный вход', form=form)

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    safe_filename = secure_filename(filename)
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], safe_filename, conditional=True)
    except FileNotFoundError:
        app.logger.warning(f"404 file access: {safe_filename}"); abort(404)

@app.errorhandler(404)
def page_not_found(e):
    app.logger.info(f"404 Not Found: {request.url}")
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    original_exception = getattr(e, "original_exception", e)
    app.logger.error(f"500 Internal Error: {original_exception}", exc_info=True)
    try:
        db.session.rollback(); app.logger.info("DB rollback attempt on 500.")
    except Exception as re:
        app.logger.error(f"Rollback error on 500 handler: {re}", exc_info=True)
    try:
        return render_template('500.html', error=original_exception), 500
    except Exception as te:
        app.logger.error(f"Error rendering 500 template: {te}", exc_info=True)
        return "<h1>500 - Internal Server Error</h1><p>An error occurred while trying to display the error page.</p>", 500

if __name__ == '__main__':
    is_debug = os.environ.get('FLASK_DEBUG') == '1' or os.environ.get('FLASK_ENV') == 'development'
    app.run(debug=is_debug, host='0.0.0.0', port=5000)