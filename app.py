import os

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    abort,
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError


app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv(
    "SECRET_KEY",
    "local-development-key-change-before-deployment",
)

# Local development gets a fresh database with the new school structure.
# Render will use PostgreSQL when DATABASE_URL is configured.
database_url = os.getenv("DATABASE_URL")

if not database_url:
    os.makedirs(app.instance_path, exist_ok=True)
    database_url = "sqlite:///" + os.path.join(
        app.instance_path,
        "schools.db",
    )

if database_url.startswith("postgres://"):
    database_url = database_url.replace(
        "postgres://",
        "postgresql://",
        1,
    )

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"


# --------------------------------------------------
# DATABASE MODELS
# --------------------------------------------------

class School(db.Model):
    __tablename__ = "schools"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    created_at = db.Column(
        db.DateTime,
        server_default=db.func.now(),
        nullable=False,
    )


class Admin(UserMixin, db.Model):
    __tablename__ = "admins"

    id = db.Column(db.Integer, primary_key=True)

    school_id = db.Column(
        db.Integer,
        db.ForeignKey("schools.id"),
        nullable=False,
    )

    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(
        db.String(254),
        unique=True,
        nullable=False,
    )
    password_hash = db.Column(db.String(255), nullable=False)

    school = db.relationship("School", backref="admins")


class Student(db.Model):
    __tablename__ = "students"

    id = db.Column(db.Integer, primary_key=True)

    school_id = db.Column(
        db.Integer,
        db.ForeignKey("schools.id"),
        nullable=False,
    )

    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(254), nullable=False)
    phone = db.Column(db.String(30), nullable=False)
    course = db.Column(db.String(120), nullable=False)
    department = db.Column(db.String(120), nullable=False)

    __table_args__ = (
        db.UniqueConstraint(
            "school_id",
            "email",
            name="uq_student_school_email",
        ),
    )


# --------------------------------------------------
# LOGIN MANAGER
# --------------------------------------------------

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Admin, int(user_id))


# --------------------------------------------------
# DATABASE SETUP
# --------------------------------------------------

def setup_database():
    with app.app_context():
        db.create_all()


# --------------------------------------------------
# HOME
# --------------------------------------------------

@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    return redirect(url_for("login"))


# --------------------------------------------------
# SCHOOL REGISTRATION
# --------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        school_name = request.form.get("school_name", "").strip()
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not all([
            school_name,
            full_name,
            email,
            password,
            confirm_password,
        ]):
            flash("Please complete every field.", "error")
            return render_template("register.html")

        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")
            return render_template("register.html")

        if password != confirm_password:
            flash("The passwords do not match.", "error")
            return render_template("register.html")

        if Admin.query.filter_by(email=email).first():
            flash("An account with that email already exists.", "error")
            return render_template("register.html")

        school = School(name=school_name)

        admin = Admin(
            school=school,
            full_name=full_name,
            email=email,
            password_hash=generate_password_hash(password),
        )

        try:
            db.session.add(school)
            db.session.add(admin)
            db.session.commit()

        except IntegrityError:
            db.session.rollback()
            flash(
                "Registration could not be completed. Please check your details.",
                "error",
            )
            return render_template("register.html")

        login_user(admin)
        flash("Your school account has been created!", "success")
        return redirect(url_for("index"))

    return render_template("register.html")


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        admin = Admin.query.filter_by(email=email).first()

        if admin and check_password_hash(admin.password_hash, password):
            login_user(admin)
            flash("Welcome back!", "success")
            return redirect(url_for("index"))

        flash("Invalid email or password.", "error")

    return render_template("login.html")


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


# --------------------------------------------------
# SCHOOL DASHBOARD
# --------------------------------------------------

@app.route("/dashboard")
@login_required
def index():
    search = request.args.get("search", "").strip()

    query = Student.query.filter_by(
        school_id=current_user.school_id
    )

    if search:
        query = query.filter(
            or_(
                Student.full_name.ilike(f"%{search}%"),
                Student.email.ilike(f"%{search}%"),
                Student.phone.ilike(f"%{search}%"),
                Student.course.ilike(f"%{search}%"),
                Student.department.ilike(f"%{search}%"),
            )
        )

    students = query.order_by(Student.id.desc()).all()

    return render_template(
        "index.html",
        students=students,
        total_students=Student.query.filter_by(
            school_id=current_user.school_id
        ).count(),
        search=search,
        edit_student=None,
    )


# --------------------------------------------------
# ADD STUDENT
# --------------------------------------------------

@app.route("/add-student", methods=["POST"])
@login_required
def add_student():
    full_name = request.form.get("full_name", "").strip()
    email = request.form.get("email", "").strip().lower()
    phone = request.form.get("phone", "").strip()
    course = request.form.get("course", "").strip()
    department = request.form.get("department", "").strip()

    if not all([full_name, email, phone, course, department]):
        flash("Please complete every student field.", "error")
        return redirect(url_for("index"))

    duplicate = Student.query.filter_by(
        school_id=current_user.school_id,
        email=email,
    ).first()

    if duplicate:
        flash("This school already has a student with that email.", "error")
        return redirect(url_for("index"))

    student = Student(
        school_id=current_user.school_id,
        full_name=full_name,
        email=email,
        phone=phone,
        course=course,
        department=department,
    )

    try:
        db.session.add(student)
        db.session.commit()
        flash("Student added successfully!", "success")

    except IntegrityError:
        db.session.rollback()
        flash("The student could not be added.", "error")

    return redirect(url_for("index"))


# --------------------------------------------------
# EDIT STUDENT
# --------------------------------------------------

@app.route(
    "/edit-student/<int:student_id>",
    methods=["GET", "POST"],
)
@login_required
def edit_student(student_id):
    student = Student.query.filter_by(
        id=student_id,
        school_id=current_user.school_id,
    ).first_or_404()

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        course = request.form.get("course", "").strip()
        department = request.form.get("department", "").strip()

        if not all([full_name, email, phone, course, department]):
            flash("Please complete every student field.", "error")
            return redirect(
                url_for("edit_student", student_id=student.id)
            )

        duplicate = Student.query.filter(
            Student.school_id == current_user.school_id,
            Student.email == email,
            Student.id != student.id,
        ).first()

        if duplicate:
            flash("Another student at your school uses that email.", "error")
            return redirect(
                url_for("edit_student", student_id=student.id)
            )

        student.full_name = full_name
        student.email = email
        student.phone = phone
        student.course = course
        student.department = department

        try:
            db.session.commit()
            flash("Student details updated!", "success")

        except IntegrityError:
            db.session.rollback()
            flash("The changes could not be saved.", "error")

        return redirect(url_for("index"))

    students = Student.query.filter_by(
        school_id=current_user.school_id
    ).order_by(Student.id.desc()).all()

    return render_template(
        "index.html",
        students=students,
        total_students=len(students),
        search="",
        edit_student=student,
    )


# --------------------------------------------------
# DELETE STUDENT
# --------------------------------------------------

@app.route(
    "/delete-student/<int:student_id>",
    methods=["POST"],
)
@login_required
def delete_student(student_id):
    student = Student.query.filter_by(
        id=student_id,
        school_id=current_user.school_id,
    ).first_or_404()

    db.session.delete(student)
    db.session.commit()

    flash("Student deleted successfully!", "success")
    return redirect(url_for("index"))


# --------------------------------------------------
# HEALTH CHECK
# --------------------------------------------------

@app.route("/health")
def health():
    return "Student Management System is running!"


setup_database()


if __name__ == "__main__":
    app.run(debug=True) 