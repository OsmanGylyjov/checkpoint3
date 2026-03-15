import os
import secrets
from datetime import datetime

from flask import Flask, render_template, redirect, url_for, flash, request, send_from_directory
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField, FileField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, scoped_session
import segno
from PIL import Image


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "app.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
QR_FOLDER = os.path.join(BASE_DIR, "static", "qrcodes")
TXT_FOLDER = os.path.join(BASE_DIR, "saved_notes")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(QR_FOLDER, exist_ok=True)
os.makedirs(TXT_FOLDER, exist_ok=True)


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(16))
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


login_manager = LoginManager(app)
login_manager.login_view = "login"


engine = create_engine(f"sqlite:///{DB_PATH}", echo=False, connect_args={"check_same_thread": False})
SessionLocal = scoped_session(sessionmaker(bind=engine, autoflush=False, autocommit=False))
Base = declarative_base()


class User(Base, UserMixin):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    security_code = Column(String(32), nullable=False)  # secure per-user code
    profile_picture = Column(String(255), nullable=True)
    medical_records = relationship("MedicalRecord", back_populates="user", cascade="all, delete-orphan")

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class MedicalRecord(Base):
    __tablename__ = "medical_records"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    full_name = Column(String(255), nullable=False)
    passport_number = Column(String(64), nullable=False)
    conditions = Column(Text, nullable=True)
    medications = Column(Text, nullable=True)
    allergies = Column(Text, nullable=True)
    emergency_contact = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    note_filename = Column(String(255), nullable=False)
    qr_filename = Column(String(255), nullable=False)

    user = relationship("User", back_populates="medical_records")


Base.metadata.create_all(bind=engine)


@login_manager.user_loader
def load_user(user_id: str):
    db = SessionLocal()
    try:
        return db.get(User, int(user_id))
    finally:
        db.close()


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=255)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6, max=64)])
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match")],
    )
    submit = SubmitField("Create account")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log in")


class ProfileForm(FlaskForm):
    full_name = StringField("Full name", validators=[DataRequired(), Length(max=255)])
    profile_picture = FileField("Profile photo")
    submit = SubmitField("Save profile")


class MedicalForm(FlaskForm):
    full_name = StringField("Full name", validators=[DataRequired(), Length(max=255)])
    passport_number = StringField("Passport / ID number", validators=[DataRequired(), Length(max=64)])
    conditions = TextAreaField("Medical conditions", validators=[Length(max=2000)])
    medications = TextAreaField("Medications", validators=[Length(max=2000)])
    allergies = TextAreaField("Allergies", validators=[Length(max=2000)])
    emergency_contact = StringField("Emergency contact (name & phone)", validators=[Length(max=255)])
    submit = SubmitField("Generate QR")


def save_profile_picture(file_storage, user_id: int) -> str:
    if not file_storage:
        return ""
    filename = secure_filename(file_storage.filename)
    if not filename:
        return ""
    name, ext = os.path.splitext(filename)
    if not ext:
        ext = ".jpg"
    new_filename = f"user_{user_id}{ext.lower()}"
    path = os.path.join(UPLOAD_FOLDER, new_filename)
    image = Image.open(file_storage)
    image.thumbnail((256, 256))
    image.save(path)
    return new_filename


def generate_secure_code() -> str:
    return secrets.token_urlsafe(12)


def build_medical_text(record: MedicalRecord) -> str:
    lines = [
        f"Name: {record.full_name}",
        f"Passport / ID: {record.passport_number}",
        f"Emergency contact: {record.emergency_contact or '—'}",
        "",
        "Medical conditions:",
        record.conditions or "None reported",
        "",
        "Medications:",
        record.medications or "None reported",
        "",
        "Allergies:",
        record.allergies or "None reported",
        "",
        f"Generated at: {record.created_at.isoformat()}",
        f"Security code: {record.user.security_code}",
    ]
    return "\n".join(lines)


def save_note_and_qr(record: MedicalRecord) -> None:
    note_filename = f"record_{record.id}.txt"
    note_path = os.path.join(TXT_FOLDER, note_filename)
    text = build_medical_text(record)
    with open(note_path, "w", encoding="utf-8") as f:
        f.write(text)

    qr_filename = f"record_{record.id}.png"
    qr_path = os.path.join(QR_FOLDER, qr_filename)
    qr = segno.make(text)
    qr.save(qr_path, scale=5)

    record.note_filename = note_filename
    record.qr_filename = qr_filename


@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    form = RegisterForm()
    if form.validate_on_submit():
        db = SessionLocal()
        try:
            existing = db.query(User).filter_by(email=form.email.data.lower()).first()
            if existing:
                flash("This email is already registered.", "danger")
                return redirect(url_for("login"))
            user = User(
                email=form.email.data.lower(),
                security_code=generate_secure_code(),
            )
            user.set_password(form.password.data)
            db.add(user)
            db.commit()
            flash("Account created. Please log in.", "success")
            return redirect(url_for("login"))
        finally:
            db.close()
    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    form = LoginForm()
    if form.validate_on_submit():
        db = SessionLocal()
        try:
            user = db.query(User).filter_by(email=form.email.data.lower()).first()
            if not user or not user.check_password(form.password.data):
                flash("Invalid email or password.", "danger")
                return redirect(url_for("login"))
            login_user(user)
            flash("Logged in successfully.", "success")
            return redirect(url_for("dashboard"))
        finally:
            db.close()
    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    db = SessionLocal()
    try:
        records = (
            db.query(MedicalRecord)
            .filter_by(user_id=current_user.id)
            .order_by(MedicalRecord.created_at.desc())
            .all()
        )
    finally:
        db.close()
    return render_template("dashboard.html", records=records)


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    form = ProfileForm()
    db = SessionLocal()
    try:
        user = db.get(User, current_user.id)
        if request.method == "GET":
            if user:
                form.full_name.data = user.email.split("@")[0]
        if form.validate_on_submit():
            if request.files.get("profile_picture"):
                filename = save_profile_picture(request.files["profile_picture"], user.id)
                if filename:
                    user.profile_picture = filename
            db.commit()
            flash("Profile updated.", "success")
            return redirect(url_for("dashboard"))
    finally:
        db.close()
    return render_template("profile.html", form=form)


@app.route("/medical/new", methods=["GET", "POST"])
@login_required
def create_medical():
    form = MedicalForm()
    if form.validate_on_submit():
        db = SessionLocal()
        try:
            record = MedicalRecord(
                user_id=current_user.id,
                full_name=form.full_name.data,
                passport_number=form.passport_number.data,
                conditions=form.conditions.data,
                medications=form.medications.data,
                allergies=form.allergies.data,
                emergency_contact=form.emergency_contact.data,
                note_filename="",
                qr_filename="",
            )
            db.add(record)
            db.commit()

            save_note_and_qr(record)
            db.commit()

            flash("Medical information saved and QR code generated.", "success")
            return redirect(url_for("dashboard"))
        finally:
            db.close()
    return render_template("medical_form.html", form=form)


@app.route("/medical/<int:record_id>")
def view_medical(record_id: int):
    db = SessionLocal()
    try:
        record = db.get(MedicalRecord, record_id)
        if not record:
            flash("Record not found.", "danger")
            return redirect(url_for("index"))
    finally:
        db.close()
    return render_template("medical_view.html", record=record)


@app.route("/medical/<int:record_id>/note")
def download_note(record_id: int):
    db = SessionLocal()
    try:
        record = db.get(MedicalRecord, record_id)
        if not record:
            flash("Record not found.", "danger")
            return redirect(url_for("index"))
        return send_from_directory(
            TXT_FOLDER,
            record.note_filename,
            as_attachment=True,
            download_name=record.note_filename,
        )
    finally:
        db.close()


@app.route("/medical/<int:record_id>/qr")
def view_qr(record_id: int):
    db = SessionLocal()
    try:
        record = db.get(MedicalRecord, record_id)
        if not record:
            flash("Record not found.", "danger")
            return redirect(url_for("index"))
        return send_from_directory(QR_FOLDER, record.qr_filename)
    finally:
        db.close()


@app.context_processor
def inject_user_profile_picture():
    picture_url = None
    if current_user.is_authenticated and current_user.profile_picture:
        picture_url = url_for("static", filename=f"uploads/{current_user.profile_picture}")
    return {"profile_picture_url": picture_url, "current_year": datetime.utcnow().year}


if __name__ == "__main__":
    app.run(debug=True)

