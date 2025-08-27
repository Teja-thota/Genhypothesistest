from __future__ import annotations
import os, secrets, time
from datetime import datetime, timedelta
from functools import wraps
from flask_migrate import Migrate
#from flask_migrate import Migrate, upgrade
#from sqlalchemy.dialects.postgresql import JSON

from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import JSON 

# -------------------- App Setup --------------------
app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

db_url = os.environ.get("DATABASE_URL")
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = db_url or "sqlite:///app.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# -------------------- Models --------------------
class PendingUser(db.Model):
    __tablename__ = "pending_users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class User(db.Model):
    __tablename__ = "users"  # Avoid reserved keyword
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    plain_password = db.Column(db.String(50))  # store only for admin display
    chosen_subject = db.Column(db.String(20))  # 'HTML' or 'Java'
    subscription_end = db.Column(db.DateTime)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved_at = db.Column(db.DateTime, nullable=True)

class Exam(db.Model):
    __tablename__ = "exams"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    subject = db.Column(db.String(50), nullable=False)  # HTML or Java
    duration_minutes = db.Column(db.Integer, default=30)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Question(db.Model):
    __tablename__ = "questions"
    id = db.Column(db.Integer, primary_key=True)
    exam_id = db.Column(db.Integer, db.ForeignKey('exams.id'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    option_a = db.Column(db.Text, nullable=False)
    option_b = db.Column(db.Text, nullable=False)
    option_c = db.Column(db.Text, nullable=False)
    option_d = db.Column(db.Text, nullable=False)
    correct = db.Column(db.String(1), nullable=False)  # 'A','B','C','D'
    exam = db.relationship("Exam", backref=db.backref("questions", cascade="all, delete-orphan"))

class Result(db.Model):
    __tablename__ = "results"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    exam_id = db.Column(db.Integer, db.ForeignKey('exams.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    total = db.Column(db.Integer, nullable=False)
    answers = db.Column(JSON, nullable=True) 
    duration_seconds = db.Column(db.Integer, default=0)
    taken_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship("User")
    exam = db.relationship("Exam")

class Query(db.Model):
    __tablename__ = "queries"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship("User")

# -------------------- Helpers --------------------
def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]

def verify_csrf(token):
    return token and session.get("csrf_token") == token

app.jinja_env.globals['csrf_token'] = csrf_token

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return User.query.get(uid)

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        u = current_user()
        if not u or not u.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return wrapper
# -------------------- Routes --------------------
@app.route("/")
def index():
    # fixed for PostgreSQL reserved keywords
    top = db.session.query(User.username, db.func.max(Result.score).label('best'))\
        .join(Result, User.id == Result.user_id)\
        .group_by(User.username)\
        .order_by(db.desc('best')).limit(5).all()
    return render_template("index.html", top=top)

@app.route("/signup", methods=["GET","POST"])
def signup():
    if request.method == "POST":
        if not verify_csrf(request.form.get("csrf_token")):
            abort(400)
        name = request.form.get("name","").strip()
        email = request.form.get("email","").strip()
        msg = request.form.get("message","").strip()
        if not name or not email:
            flash("Name and email required", "error")
            return redirect(url_for("signup"))
        p = PendingUser(name=name, email=email, message=msg)
        db.session.add(p)
        db.session.commit()
        flash("Request received. Please pay UPI and wait for admin approval.", "success")
        return redirect(url_for("index"))
    return render_template("signup_pending.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        if not verify_csrf(request.form.get("csrf_token")):
            abort(400)
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session.clear()
            session["user_id"] = user.id
            flash("Welcome!", "success")
            if user.is_admin:
                return redirect(url_for("admin_index"))
            else:
                return redirect(url_for("dashboard"))
        flash("Invalid credentials", "error")
    return render_template("login.html")


#---------------------Admin Routes--------------------
@app.route("/admin")
@admin_required
def admin_index():
    pending_users = PendingUser.query.order_by(PendingUser.created_at.desc()).all()
    exams = Exam.query.order_by(Exam.created_at.desc()).all()
    return render_template("admin/index.html", pending_users=pending_users, exams=exams)


@app.route("/admin/create_exam", methods=["GET", "POST"])
@admin_required
def create_exam():
    if request.method == "POST":
        title = request.form.get("title")
        subject = request.form.get("subject")
        duration = request.form.get("duration", 30)
        new_exam = Exam(title=title, subject=subject, duration_minutes=duration)
        db.session.add(new_exam)
        db.session.commit()
        #flash("Exam created successfully!", "success")
        return redirect(url_for("admin_index"))
    return render_template("admin/create_exam.html")

@app.route("/admin/exam/<int:exam_id>")
@admin_required
def exam_detail(exam_id):
    exam = Exam.query.get_or_404(exam_id)
    questions = exam.questions  # fetch all questions for this exam
    return render_template("admin/exam_detail.html", exam=exam, questions=questions)

@app.route("/admin/exam/<int:exam_id>/add_question", methods=["GET", "POST"])
@admin_required
def add_question(exam_id):
    exam = Exam.query.get_or_404(exam_id)
    if request.method == "POST":
        # Get form data
        text = request.form.get("text")
        option_a = request.form.get("option_a")
        option_b = request.form.get("option_b")
        option_c = request.form.get("option_c")
        option_d = request.form.get("option_d")
        correct = request.form.get("correct", "").upper()

        # Validate correct option
        if correct not in ("A", "B", "C", "D"):
            flash("Correct option must be A, B, C, or D", "error")
            return redirect(url_for("add_question", exam_id=exam.id))

        # Create and save question
        q = Question(
            exam_id=exam.id,
            text=text,
            option_a=option_a,
            option_b=option_b,
            option_c=option_c,
            option_d=option_d,
            correct=correct
        )
        db.session.add(q)
        db.session.commit()
        flash("Question added successfully!", "success")
        return redirect(url_for("exam_detail", exam_id=exam.id))

    # Render the add_question.html template
    return render_template("admin/add_question.html", exam=exam)



@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("Logged out", "info")
    return redirect(url_for("index"))

# -------------------- User Routes --------------------
@app.route("/dashboard")
@login_required
def dashboard():
    u = current_user()
    now = datetime.utcnow()
    has_access = u.subscription_end and u.subscription_end >= now
    if has_access and not u.chosen_subject:
        return redirect(url_for("choose_subject"))
    exams = []
    if has_access and u.chosen_subject:
        exams = Exam.query.filter_by(is_active=True, subject=u.chosen_subject).order_by(Exam.created_at.desc()).all()
    results = Result.query.filter_by(user_id=u.id).order_by(Result.taken_at.desc()).all()
    return render_template("dashboard.html", user=u, has_access=has_access, exams=exams, results=results)

@app.route("/choose_subject", methods=["GET","POST"])
@login_required
def choose_subject():
    u = current_user()
    if u.chosen_subject:
        flash("Subject already chosen.", "info")
        return redirect(url_for("dashboard"))
    if request.method=="POST":
        subj = request.form.get("subject")
        if subj not in ("HTML","Java"):
            flash("Invalid subject", "error")
            return redirect(url_for("choose_subject"))
        u.chosen_subject = subj
        db.session.commit()
        #flash(f"Subject set to {subj}", "success")
        return redirect(url_for("dashboard"))
    return render_template("choose_subject.html")

@app.route("/exam/<int:exam_id>", methods=["GET","POST"])
@login_required
def exam_view(exam_id):
    u = current_user()
    exam = Exam.query.get_or_404(exam_id)

    # check if user already attempted this exam
    existing_result = Result.query.filter_by(user_id=u.id, exam_id=exam.id).first()
    if existing_result:
        return redirect(url_for("dashboard"))

    # check exam eligibility
    if not exam.is_active:
        abort(404)
    if not u.subscription_end or u.subscription_end < datetime.utcnow():
        return redirect(url_for("dashboard"))
    if not u.chosen_subject or u.chosen_subject != exam.subject:
        return redirect(url_for("dashboard"))

    questions = exam.questions

    if request.method == "POST":
        if not verify_csrf(request.form.get("csrf_token")):
            abort(400)

        score = 0
        total = len(questions)
        user_answers = {}

        for q in questions:
            ans = request.form.get(f"q{q.id}", "")
            user_answers[str(q.id)] = ans  # store selected answer
            if ans and ans.upper().strip() == q.correct.upper().strip():
                score += 1

        start_ts = session.pop(f"exam_start_{exam.id}", int(time.time()))
        duration = max(0, int(time.time()) - int(start_ts))

        # save result with answers JSON
        r = Result(
            user_id=u.id,
            exam_id=exam.id,
            score=score,
            total=total,
            duration_seconds=duration,
            answers=user_answers   # <-- NEW
        )
        db.session.add(r)
        db.session.commit()

        return redirect(url_for("dashboard"))

    # GET request -> load exam page
    session[f"exam_start_{exam.id}"] = int(time.time())
    return render_template("exam_page.html", exam=exam, questions=questions)

@app.route("/admin/pending_users", methods=["GET", "POST"])
@admin_required
def pending_users():
    pending_users_list = PendingUser.query.order_by(PendingUser.created_at.desc()).all()
    approved_users = session.pop("approved_users", [])

    if request.method == "POST":
        csrf_token_val = request.form.get("csrf_token")
        if not verify_csrf(csrf_token_val):
            abort(400)

        selected_ids = [int(pid) for pid in request.form.getlist("approve")]
        newly_approved = []

        for pid in selected_ids:
            p = PendingUser.query.get(pid)
            if p:
                # Make a unique username
                base_username = p.name.replace(" ", "").lower()
                username = base_username
                counter = 1
                while User.query.filter_by(username=username).first():
                    username = f"{base_username}{counter}"
                    counter += 1

                # Ensure email is unique
                if User.query.filter_by(email=p.email).first():
                    flash(f"User with email {p.email} already exists.", "error")
                    db.session.delete(p)
                    db.session.commit()
                    continue

                # Generate password & hash
                password = "User@" + secrets.token_hex(3)
                hashed_pw = generate_password_hash(password)

                new_user = User(
                    username=username,
                    email=p.email,
                    plain_password=password,
                    password_hash=hashed_pw,
                    subscription_end=datetime.utcnow() + timedelta(days=10),
                    is_admin=False,
                    approved_at=datetime.utcnow()
                )

                db.session.add(new_user)
                db.session.delete(p)

                newly_approved.append({
                    "username": username,
                    "password": password,
                    "approved_at": new_user.approved_at.strftime('%Y-%m-%d %H:%M'),
                    "id": new_user.id
                })

        try:
            db.session.commit()
            #flash(f"{len(newly_approved)} user(s) approved successfully!", "success")
        except Exception as e:
            db.session.rollback()
            #flash(f"Error approving users: {e}", "danger")

        session["approved_users"] = newly_approved
        return redirect(url_for("pending_users"))

    return render_template(
        "admin/pending_users.html",
        pending_users=pending_users_list,
        approved_users=approved_users
    )

@app.route("/admin/all_users")
@admin_required
def all_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template("admin/all_users.html", users=users)


@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    try:
        db.session.delete(user)
        db.session.commit()
        #flash(f"User {user.username} has been permanently deleted.", "success")
    except Exception as e:
        db.session.rollback()
        #flash(f"Error deleting user: {e}", "danger")
    return redirect(url_for("all_users"))

@app.route("/admin/disapprove_user/<int:user_id>", methods=["POST"])
@admin_required
def disapprove_user(user_id):
    user = User.query.get_or_404(user_id)
    p = PendingUser(
        name=user.username,
        email=user.email,
        message="Disapproved by admin",
        created_at=datetime.utcnow()
    )
    db.session.add(p)
    db.session.delete(user)

    try:
        db.session.commit()
        #flash(f"User {user.username} disapproved and moved back to pending list.", "success")
    except Exception as e:
        db.session.rollback()
        #flash(f"Error disapproving user: {e}", "danger")

    return redirect(url_for("all_users"))



@app.route("/profile")
@login_required
def profile():
    u = current_user()
    return render_template("profile.html", user=u)

@app.route("/history")
@login_required
def history():
    u = current_user()
    results = Result.query.filter_by(user_id=u.id).order_by(Result.taken_at.desc()).all()
    return render_template("history.html", results=results)

if __name__ == "__main__":
    app.run(debug=True)

# -------------------- Auto-create DB & Admin --------------------
with app.app_context():
    db.create_all()

    admin_username = "admin1"
    admin_email = "thotateja314@gmail.com"
    admin_password = "Admin@143"

    existing = User.query.filter_by(username=admin_username).first()
    if not existing:
        hashed = generate_password_hash(admin_password)
        admin = User(
            username=admin_username,
            email=admin_email,
            password_hash=hashed,
            plain_password=admin_password,  # store for display
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
        print(f"✅ Admin account created: {admin_username} / {admin_password}")
    else:
        print("ℹ️ Admin already exists")
