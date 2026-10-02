import os

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
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
from werkzeug.security import (
    generate_password_hash,
    check_password_hash,
)
from sqlalchemy import or_, inspect, text
from sqlalchemy.exc import IntegrityError


app = Flask(__name__)

# ==================================================
# CONFIGURATION
# ==================================================

app.config["SECRET_KEY"] = os.getenv(
    "SECRET_KEY",
    "local-development-key-change-before-deployment",
)

database_url = os.getenv("DATABASE_URL")

if not database_url:
    os.makedirs(app.instance_path, exist_ok=True)

    database_url = (
        "sqlite:///"
        + os.path.join(
            app.instance_path,
            "schools.db",
        )
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


# ==================================================
# OWNER ACCOUNT
# ==================================================

OWNER_EMAIL = os.getenv(
    "OWNER_EMAIL",
    "owner@local.test",
)

OWNER_PASSWORD = os.getenv(
    "OWNER_PASSWORD",
    "owner12345",
)


# ==================================================
# DATABASE MODELS
# ==================================================

class School(db.Model):
    __tablename__ = "schools"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    name = db.Column(
        db.String(150),
        nullable=False,
    )

    created_at = db.Column(
        db.DateTime,
        server_default=db.func.now(),
        nullable=False,
    )


class Admin(UserMixin, db.Model):
    __tablename__ = "admins"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    school_id = db.Column(
        db.Integer,
        db.ForeignKey("schools.id"),
        nullable=False,
    )

    full_name = db.Column(
        db.String(120),
        nullable=False,
    )

    email = db.Column(
        db.String(254),
        unique=True,
        nullable=False,
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False,
    )

    must_change_password = db.Column(
        db.Boolean,
        nullable=False,
        default=False,
        server_default="false",
    )

    school = db.relationship(
        "School",
        backref="admins",
    )


class Student(db.Model):
    __tablename__ = "students"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    school_id = db.Column(
        db.Integer,
        db.ForeignKey("schools.id"),
        nullable=False,
    )

    full_name = db.Column(
        db.String(120),
        nullable=False,
    )

    email = db.Column(
        db.String(254),
        nullable=False,
    )

    phone = db.Column(
        db.String(30),
        nullable=False,
    )

    course = db.Column(
        db.String(120),
        nullable=False,
    )

    department = db.Column(
        db.String(120),
        nullable=False,
    )

    __table_args__ = (
        db.UniqueConstraint(
            "school_id",
            "email",
            name="uq_student_school_email",
        ),
    )


# ==================================================
# LOGIN MANAGER
# ==================================================

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(
        Admin,
        int(user_id),
    )


# ==================================================
# DATABASE SETUP
# ==================================================

def setup_database():

    with app.app_context():

        db.create_all()

        inspector = inspect(db.engine)

        admin_columns = {
            column["name"]
            for column in inspector.get_columns("admins")
        }

        if "must_change_password" not in admin_columns:

            with db.engine.begin() as connection:

                connection.execute(
                    text(
                        """
                        ALTER TABLE admins
                        ADD COLUMN must_change_password
                        BOOLEAN NOT NULL DEFAULT FALSE
                        """
                    )
                )


# ==================================================
# OWNER SESSION
# ==================================================

def owner_logged_in():
    return session.get(
        "owner_logged_in",
        False,
    )


# ==================================================
# FORCE FIRST-LOGIN PASSWORD CHANGE
# ==================================================

@app.before_request
def enforce_password_change():

    if not current_user.is_authenticated:
        return None

    if not current_user.must_change_password:
        return None

    allowed_endpoints = {
        "change_password",
        "logout",
        "static",
    }

    if request.endpoint in allowed_endpoints:
        return None

    return redirect(
        url_for("change_password")
    )


# ==================================================
# HOME
# ==================================================

@app.route("/")
def home():

    if current_user.is_authenticated:
        return redirect(
            url_for("index")
        )

    return redirect(
        url_for("login")
    )


# ==================================================
# PUBLIC REGISTRATION DISABLED
# ==================================================

@app.route("/register")
def register():

    flash(
        "School registration is currently by approval only. Please contact the administrator.",
        "error",
    )

    return redirect(
        url_for("login")
    )


# ==================================================
# SCHOOL LOGIN
# ==================================================

@app.route(
    "/login",
    methods=["GET", "POST"],
)
def login():

    if current_user.is_authenticated:

        if current_user.must_change_password:
            return redirect(
                url_for("change_password")
            )

        return redirect(
            url_for("index")
        )

    if request.method == "POST":

        email = request.form.get(
            "email",
            "",
        ).strip().lower()

        password = request.form.get(
            "password",
            "",
        )

        admin = Admin.query.filter_by(
            email=email,
        ).first()

        if admin and check_password_hash(
            admin.password_hash,
            password,
        ):

            login_user(admin)

            if admin.must_change_password:

                return redirect(
                    url_for("change_password")
                )

            flash(
                "Welcome back!",
                "success",
            )

            return redirect(
                url_for("index")
            )

        flash(
            "Invalid email or password.",
            "error",
        )

    return render_template(
        "login.html"
    )


# ==================================================
# FIRST-LOGIN PASSWORD CHANGE
# ==================================================

@app.route(
    "/change-password",
    methods=["GET", "POST"],
)
@login_required
def change_password():

    if not current_user.must_change_password:

        return redirect(
            url_for("index")
        )

    if request.method == "POST":

        new_password = request.form.get(
            "new_password",
            "",
        )

        confirm_password = request.form.get(
            "confirm_password",
            "",
        )

        if len(new_password) < 8:

            flash(
                "Your new password must contain at least 8 characters.",
                "error",
            )

            return render_template(
                "change_password.html"
            )

        if new_password != confirm_password:

            flash(
                "The passwords do not match.",
                "error",
            )

            return render_template(
                "change_password.html"
            )

        current_user.password_hash = generate_password_hash(
            new_password
        )

        current_user.must_change_password = False

        db.session.commit()

        flash(
            "Your password has been changed successfully!",
            "success",
        )

        return redirect(
            url_for("index")
        )

    return render_template(
        "change_password.html"
    )


# ==================================================
# SCHOOL LOGOUT
# ==================================================

@app.route("/logout")
@login_required
def logout():

    logout_user()

    flash(
        "You have been logged out.",
        "success",
    )

    return redirect(
        url_for("login")
    )


# ==================================================
# OWNER LOGIN
# ==================================================

@app.route(
    "/owner-login",
    methods=["GET", "POST"],
)
def owner_login():

    if owner_logged_in():

        return redirect(
            url_for("owner_dashboard")
        )

    if request.method == "POST":

        email = request.form.get(
            "email",
            "",
        ).strip().lower()

        password = request.form.get(
            "password",
            "",
        )

        if (
            email == OWNER_EMAIL.lower()
            and password == OWNER_PASSWORD
        ):

            session["owner_logged_in"] = True

            return redirect(
                url_for("owner_dashboard")
            )

        flash(
            "Invalid owner login.",
            "error",
        )

    return render_template(
        "owner_login.html"
    )


# ==================================================
# OWNER LOGOUT
# ==================================================

@app.route("/owner-logout")
def owner_logout():

    session.pop(
        "owner_logged_in",
        None,
    )

    return redirect(
        url_for("owner_login")
    )


# ==================================================
# OWNER DASHBOARD
# ==================================================

@app.route("/owner")
def owner_dashboard():

    if not owner_logged_in():

        return redirect(
            url_for("owner_login")
        )

    schools = School.query.order_by(
        School.id.desc()
    ).all()

    return render_template(
        "owner.html",
        schools=schools,
    )


# ==================================================
# OWNER CREATES SCHOOL
# ==================================================

@app.route(
    "/owner/create-school",
    methods=["POST"],
)
def owner_create_school():

    if not owner_logged_in():

        return redirect(
            url_for("owner_login")
        )

    school_name = request.form.get(
        "school_name",
        "",
    ).strip()

    admin_name = request.form.get(
        "admin_name",
        "",
    ).strip()

    email = request.form.get(
        "email",
        "",
    ).strip().lower()

    password = request.form.get(
        "password",
        "",
    )

    if not all([
        school_name,
        admin_name,
        email,
        password,
    ]):

        flash(
            "Please complete every field.",
            "error",
        )

        return redirect(
            url_for("owner_dashboard")
        )

    if len(password) < 8:

        flash(
            "The school password must contain at least 8 characters.",
            "error",
        )

        return redirect(
            url_for("owner_dashboard")
        )

    existing_admin = Admin.query.filter_by(
        email=email,
    ).first()

    if existing_admin:

        flash(
            "That administrator email is already in use.",
            "error",
        )

        return redirect(
            url_for("owner_dashboard")
        )

    school = School(
        name=school_name,
    )

    admin = Admin(
        school=school,
        full_name=admin_name,
        email=email,
        password_hash=generate_password_hash(
            password,
        ),
        must_change_password=True,
    )

    try:

        db.session.add(school)
        db.session.add(admin)
        db.session.commit()

        flash(
            f"{school_name} has been approved and its account was created.",
            "success",
        )

    except IntegrityError:

        db.session.rollback()

        flash(
            "The school account could not be created.",
            "error",
        )

    return redirect(
        url_for("owner_dashboard")
    )


# ==================================================
# OWNER EDITS SCHOOL
# ==================================================

@app.route(
    "/owner/edit-school/<int:school_id>",
    methods=["GET", "POST"],
)
def owner_edit_school(school_id):

    if not owner_logged_in():

        return redirect(
            url_for("owner_login")
        )

    school = db.get_or_404(
        School,
        school_id,
    )

    admin = Admin.query.filter_by(
        school_id=school.id,
    ).first()

    if request.method == "POST":

        school_name = request.form.get(
            "school_name",
            "",
        ).strip()

        admin_name = request.form.get(
            "admin_name",
            "",
        ).strip()

        email = request.form.get(
            "email",
            "",
        ).strip().lower()

        if not all([
            school_name,
            admin_name,
            email,
        ]):

            flash(
                "Please complete every field.",
                "error",
            )

            return redirect(
                url_for(
                    "owner_edit_school",
                    school_id=school.id,
                )
            )

        if admin:

            duplicate_email = Admin.query.filter(
                Admin.email == email,
                Admin.id != admin.id,
            ).first()

            if duplicate_email:

                flash(
                    "That administrator email is already in use.",
                    "error",
                )

                return redirect(
                    url_for(
                        "owner_edit_school",
                        school_id=school.id,
                    )
                )

        school.name = school_name

        if admin:

            admin.full_name = admin_name
            admin.email = email

        try:

            db.session.commit()

            flash(
                "School account updated successfully!",
                "success",
            )

        except IntegrityError:

            db.session.rollback()

            flash(
                "The school account could not be updated.",
                "error",
            )

        return redirect(
            url_for("owner_dashboard")
        )

    return render_template(
        "owner_edit.html",
        school=school,
        admin=admin,
    )


# ==================================================
# OWNER RESETS SCHOOL PASSWORD
# ==================================================

@app.route(
    "/owner/reset-password/<int:school_id>",
    methods=["POST"],
)
def owner_reset_password(school_id):

    if not owner_logged_in():

        return redirect(
            url_for("owner_login")
        )

    school = db.get_or_404(
        School,
        school_id,
    )

    admin = Admin.query.filter_by(
        school_id=school.id,
    ).first()

    new_password = request.form.get(
        "new_password",
        "",
    )

    if admin is None:

        flash(
            "This school has no administrator account.",
            "error",
        )

        return redirect(
            url_for("owner_dashboard")
        )

    if len(new_password) < 8:

        flash(
            "The new password must contain at least 8 characters.",
            "error",
        )

        return redirect(
            url_for("owner_dashboard")
        )

    admin.password_hash = generate_password_hash(
        new_password,
    )

    admin.must_change_password = True

    db.session.commit()

    flash(
        f"Password reset successfully for {school.name}. The school must choose a new password at next login.",
        "success",
    )

    return redirect(
        url_for("owner_dashboard")
    )


# ==================================================
# OWNER DELETES SCHOOL
# ==================================================

@app.route(
    "/owner/delete-school/<int:school_id>",
    methods=["POST"],
)
def owner_delete_school(school_id):

    if not owner_logged_in():

        return redirect(
            url_for("owner_login")
        )

    school = db.get_or_404(
        School,
        school_id,
    )

    school_name = school.name

    Student.query.filter_by(
        school_id=school.id,
    ).delete(
        synchronize_session=False
    )

    Admin.query.filter_by(
        school_id=school.id,
    ).delete(
        synchronize_session=False
    )

    db.session.delete(school)

    db.session.commit()

    flash(
        f"{school_name} has been deleted.",
        "success",
    )

    return redirect(
        url_for("owner_dashboard")
    )


# ==================================================
# SCHOOL DASHBOARD
# ==================================================

@app.route("/dashboard")
@login_required
def index():

    search = request.args.get(
        "search",
        "",
    ).strip()

    query = Student.query.filter_by(
        school_id=current_user.school_id,
    )

    if search:

        query = query.filter(
            or_(
                Student.full_name.ilike(
                    f"%{search}%"
                ),

                Student.email.ilike(
                    f"%{search}%"
                ),

                Student.phone.ilike(
                    f"%{search}%"
                ),

                Student.course.ilike(
                    f"%{search}%"
                ),

                Student.department.ilike(
                    f"%{search}%"
                ),
            )
        )

    students = query.order_by(
        Student.id.desc()
    ).all()

    total_students = Student.query.filter_by(
        school_id=current_user.school_id,
    ).count()

    return render_template(
        "index.html",
        students=students,
        total_students=total_students,
        search=search,
        edit_student=None,
    )


# ==================================================
# ADD STUDENT
# ==================================================

@app.route(
    "/add-student",
    methods=["POST"],
)
@login_required
def add_student():

    full_name = request.form.get(
        "full_name",
        "",
    ).strip()

    email = request.form.get(
        "email",
        "",
    ).strip().lower()

    phone = request.form.get(
        "phone",
        "",
    ).strip()

    course = request.form.get(
        "course",
        "",
    ).strip()

    department = request.form.get(
        "department",
        "",
    ).strip()

    if not all([
        full_name,
        email,
        phone,
        course,
        department,
    ]):

        flash(
            "Please complete every student field.",
            "error",
        )

        return redirect(
            url_for("index")
        )

    duplicate = Student.query.filter_by(
        school_id=current_user.school_id,
        email=email,
    ).first()

    if duplicate:

        flash(
            "This school already has a student with that email.",
            "error",
        )

        return redirect(
            url_for("index")
        )

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

        flash(
            "Student added successfully!",
            "success",
        )

    except IntegrityError:

        db.session.rollback()

        flash(
            "The student could not be added.",
            "error",
        )

    return redirect(
        url_for("index")
    )


# ==================================================
# EDIT STUDENT
# ==================================================

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

        full_name = request.form.get(
            "full_name",
            "",
        ).strip()

        email = request.form.get(
            "email",
            "",
        ).strip().lower()

        phone = request.form.get(
            "phone",
            "",
        ).strip()

        course = request.form.get(
            "course",
            "",
        ).strip()

        department = request.form.get(
            "department",
            "",
        ).strip()

        if not all([
            full_name,
            email,
            phone,
            course,
            department,
        ]):

            flash(
                "Please complete every student field.",
                "error",
            )

            return redirect(
                url_for(
                    "edit_student",
                    student_id=student.id,
                )
            )

        duplicate = Student.query.filter(
            Student.school_id == current_user.school_id,
            Student.email == email,
            Student.id != student.id,
        ).first()

        if duplicate:

            flash(
                "Another student at your school uses that email.",
                "error",
            )

            return redirect(
                url_for(
                    "edit_student",
                    student_id=student.id,
                )
            )

        student.full_name = full_name
        student.email = email
        student.phone = phone
        student.course = course
        student.department = department

        try:

            db.session.commit()

            flash(
                "Student details updated!",
                "success",
            )

        except IntegrityError:

            db.session.rollback()

            flash(
                "The changes could not be saved.",
                "error",
            )

        return redirect(
            url_for("index")
        )

    students = Student.query.filter_by(
        school_id=current_user.school_id,
    ).order_by(
        Student.id.desc()
    ).all()

    return render_template(
        "index.html",
        students=students,
        total_students=len(students),
        search="",
        edit_student=student,
    )


# ==================================================
# DELETE STUDENT
# ==================================================

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

    flash(
        "Student deleted successfully!",
        "success",
    )

    return redirect(
        url_for("index")
    )


# ==================================================
# HEALTH CHECK
# ==================================================

@app.route("/health")
def health():

    return "Student Management System is running!"


# ==================================================
# DATABASE START
# ==================================================

setup_database()


# ==================================================
# RUN APP
# ==================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )