from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user
)
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)

app.config["SECRET_KEY"] = "student-management-secret-key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///students.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


# -------------------------
# ADMIN
# -------------------------

class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(80),
        unique=True,
        nullable=False
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False
    )


# -------------------------
# STUDENT
# -------------------------

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    full_name = db.Column(
        db.String(120),
        nullable=False
    )

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False
    )

    phone = db.Column(
        db.String(30),
        nullable=False
    )

    course = db.Column(
        db.String(120),
        nullable=False
    )

    department = db.Column(
        db.String(120),
        nullable=False
    )


# -------------------------
# LOGIN MANAGER
# -------------------------

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Admin, int(user_id))


# -------------------------
# DATABASE SETUP
# -------------------------

def setup_database():

    with app.app_context():

        db.create_all()

        admin = Admin.query.filter_by(
            username="admin"
        ).first()

        if admin is None:

            admin = Admin(
                username="admin",
                password_hash=generate_password_hash(
                    "admin123"
                )
            )

            db.session.add(admin)
            db.session.commit()


# -------------------------
# HOME
# -------------------------

@app.route("/")
@login_required
def index():

    students = Student.query.order_by(
        Student.id.desc()
    ).all()

    return render_template(
        "index.html",
        students=students,
        total_students=len(students)
    )


# -------------------------
# LOGIN
# -------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        admin = Admin.query.filter_by(
            username=username
        ).first()

        if admin and check_password_hash(
            admin.password_hash,
            password
        ):

            login_user(admin)

            flash(
                "Login successful!",
                "success"
            )

            return redirect(
                url_for("index")
            )

        flash(
            "Invalid username or password.",
            "error"
        )

    return render_template(
        "login.html"
    )


# -------------------------
# LOGOUT
# -------------------------

@app.route("/logout")
@login_required
def logout():

    logout_user()

    return redirect(
        url_for("login")
    )


# -------------------------
# ADD STUDENT
# -------------------------

@app.route(
    "/add-student",
    methods=["POST"]
)
@login_required
def add_student():

    full_name = request.form.get(
        "full_name",
        ""
    ).strip()

    email = request.form.get(
        "email",
        ""
    ).strip().lower()

    phone = request.form.get(
        "phone",
        ""
    ).strip()

    course = request.form.get(
        "course",
        ""
    ).strip()

    department = request.form.get(
        "department",
        ""
    ).strip()

    if not all([
        full_name,
        email,
        phone,
        course,
        department
    ]):

        flash(
            "Please fill in all fields.",
            "error"
        )

        return redirect(
            url_for("index")
        )

    existing = Student.query.filter_by(
        email=email
    ).first()

    if existing:

        flash(
            "A student with this email already exists.",
            "error"
        )

        return redirect(
            url_for("index")
        )

    student = Student(
        full_name=full_name,
        email=email,
        phone=phone,
        course=course,
        department=department
    )

    db.session.add(student)
    db.session.commit()

    flash(
        "Student added successfully!",
        "success"
    )

    return redirect(
        url_for("index")
    )

# -----------------------------------
# EDIT STUDENT
# -----------------------------------

@app.route(
    "/edit-student/<int:student_id>",
    methods=["GET", "POST"]
)
@login_required
def edit_student(student_id):

    student = db.get_or_404(
        Student,
        student_id
    )

    if request.method == "POST":

        full_name = request.form.get(
            "full_name",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        phone = request.form.get(
            "phone",
            ""
        ).strip()

        course = request.form.get(
            "course",
            ""
        ).strip()

        department = request.form.get(
            "department",
            ""
        ).strip()

        if not all([
            full_name,
            email,
            phone,
            course,
            department
        ]):

            flash(
                "Please fill in all fields.",
                "error"
            )

            return redirect(
                url_for(
                    "edit_student",
                    student_id=student.id
                )
            )

        duplicate = Student.query.filter(
            Student.email == email,
            Student.id != student.id
        ).first()

        if duplicate:

            flash(
                "Another student already uses this email.",
                "error"
            )

            return redirect(
                url_for(
                    "edit_student",
                    student_id=student.id
                )
            )

        student.full_name = full_name
        student.email = email
        student.phone = phone
        student.course = course
        student.department = department

        db.session.commit()

        flash(
            "Student updated successfully!",
            "success"
        )

        return redirect(
            url_for("index")
        )

    students = Student.query.order_by(
        Student.id.desc()
    ).all()

    return render_template(
        "index.html",
        students=students,
        total_students=Student.query.count(),
        search="",
        edit_student=student
    )


# -------------------------
# DELETE STUDENt
# -------------------------

@app.route(
    "/delete-student/<int:student_id>",
    methods=["POST"]
)
@login_required
def delete_student(student_id):

    student = db.get_or_404(
        Student,
        student_id
    )

    db.session.delete(student)
    db.session.commit()

    flash(
        "Student deleted successfully!",
        "success"
    )

    return redirect(
        url_for("index")
    )


# -------------------------
# HEALTH CHECK
# -------------------------

@app.route("/health")
def health():

    return "Student Management System is running!"


# -------------------------
# START
# -------------------------

setup_database()

if __name__ == "__main__":
    app.run(debug=True)