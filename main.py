import os
import smtplib
import random
from datetime import date

from flask import Flask, abort, render_template, redirect, url_for, flash, request, jsonify, session
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import (
    UserMixin, login_user, LoginManager, current_user,
    logout_user, AnonymousUserMixin
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, EmailCheck, CommentForm

########################################
# Flask Application Setup
########################################

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("APP_SECKEY")
ckeditor = CKEditor(app)
Bootstrap5(app)

########################################
# Email Configuration
########################################
SMTP_SERVER = "smtp.mail.yahoo.com"  # For Yahoo
SENDER_EMAIL = "fatkhiddinkhan@yahoo.com"
SENDER_PASSWORD =  os.environ.get("APP_PASSWORD") # <- add you app password from yahoo, or any email service
TO_EMAIL = None  # This will be updated dynamically

########################################
# Flask-Login Configuration
########################################
from flask_login import LoginManager
login_manager = LoginManager()

########################################
# Database Setup
########################################

class Base(DeclarativeBase):
    """
    Base class for SQLAlchemy's Declarative model.
    """
    pass

# Configure SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", 'sqlite:///posts.db')
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# Initialize Flask-Login
login_manager.init_app(app)

########################################
# Models
########################################

class User(db.Model, UserMixin):
    """
    User model for storing user information.
    Inherits from db.Model and UserMixin for Flask-Login.
    """
    __tablename__ = "user_data"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(100), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)

    # Relationship: A user can have many posts and comments.
    posts: Mapped[list] = db.relationship('BlogPost', backref='author')
    comments = relationship("Comment", back_populates="comment_author")


class BlogPost(db.Model):
    """
    BlogPost model for storing blog post details.
    """
    __tablename__ = "blog_posts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    user_id: Mapped[int] = mapped_column(db.Integer, db.ForeignKey('user_data.id'))

    # Relationship: A blog post can have many comments.
    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    """
    Comment model for storing user comments on blog posts.
    """
    __tablename__ = "comments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)

    # Relationship to User
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("user_data.id"))
    comment_author = relationship("User", back_populates="comments")

    # Relationship to BlogPost
    post_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")


# Create all database tables
with app.app_context():
    db.create_all()

########################################
# Flask-Login User Loader
########################################

@login_manager.user_loader
def load_user(user_id):
    """
    Callback function required by Flask-Login to load a user by user_id.
    """
    return User.query.get(int(user_id))

########################################
# Decorators
########################################

def admin_required(func):
    """
    Decorator to restrict access to admin-only routes.
    Only accessible if current_user is authenticated and user_id = 1.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return abort(403)
        if current_user.id != 1:
            return abort(403)
        return func(*args, **kwargs)
    return wrapper


def random_number():
    """
    Generates a random 6-digit numeric code as a string.
    """
    return ''.join(random.choices('0123456789', k=6))

########################################
# Routes
########################################

@app.route('/register', methods=["GET", "POST"])
def register():
    """
    Register route to create a new user.
    Hashes the user's password using Werkzeug security.
    """
    reg_form = RegisterForm()

    if reg_form.validate_on_submit():
        email = reg_form.email.data
        password = reg_form.password.data
        name = reg_form.name.data

        # Hash user's password for secure storage.
        hashed_password = generate_password_hash(
            password=password,
            method="scrypt",
            salt_length=16
        )

        try:
            new_user = User(
                email=email,
                password=hashed_password,
                name=name
            )
            db.session.add(new_user)
            db.session.commit()

            # Retrieve the newly created user to proceed with email confirmation.
            user = User.query.filter_by(email=email).first()
            return redirect(url_for("check_email", user_id=user.id))

        except IntegrityError:
            # Handle case when email is already registered.
            db.session.rollback()
            flash("Email already registered. Please log in instead.", "error")
            return redirect(url_for("login"))

    return render_template("register.html", form=reg_form)


@app.route("/email-check/<int:user_id>", methods=["POST", "GET"])
def check_email(user_id):
    """
    Route for email confirmation using a random pass code.
    Sends an email to the user with the generated pass code.
    """
    form = EmailCheck()
    user = db.get_or_404(User, user_id)

    # Use session to store a unique pass code for the user.
    session_key = f"pass_code_{user_id}"
    server = None

    # Generate a new code only if it doesn't exist for this user.
    if session_key not in session:
        session[session_key] = random_number()
        try:
            print(f"📧 Preparing to send email to {user.email} with code: {session[session_key]}")

            # Create Email Content
            subject = "Confirm Your Email"
            body = f"Hello {user.name}\nYour Pass Code is: {session[session_key]}"
            TO_EMAIL = user.email

            # Assemble Email Message
            msg = MIMEMultipart()
            msg["From"] = SENDER_EMAIL
            msg["To"] = TO_EMAIL
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain"))

            # Connect to SMTP server
            print("🔌 Connecting to SMTP server...")
            server = smtplib.SMTP(SMTP_SERVER)
            server.starttls()
            print("🔑 Logging in to email server...")
            server.login(SENDER_EMAIL, SENDER_PASSWORD)

            # Send the email
            print("📤 Sending email...")
            server.sendmail(SENDER_EMAIL, TO_EMAIL, msg.as_string())
            print(f"✅ Email successfully sent to {user.email}")

        except Exception as e:
            print(f"❌ Email Error: {e}")
        finally:
            if server:
                server.quit()

    # Handle form submission
    if form.validate_on_submit():
        try:
            num = int(form.code.data)

            # Compare input code with the session code.
            print("Session code is:", session.get(session_key))
            print("User input is:", form.code.data)
            if session.get(session_key) == str(num):
                print("✅ Pass Code Verified!")
                session.pop(session_key)
                login_user(user)
                return redirect(url_for("get_all_posts"))
            else:
                flash("❌ Pass Code is incorrect, please try again!")
        except ValueError:
            flash("❌ Please enter only digits (123456)")

    return render_template("email_check.html", form=form)


@app.route('/login', methods=["POST", "GET"])
def login():
    """
    Login route for existing users to authenticate.
    """
    log_form = LoginForm()

    if log_form.validate_on_submit():
        email = log_form.email.data
        user = User.query.filter_by(email=email).first()

        # Check if user exists and password is correct.
        if user and check_password_hash(user.password, log_form.password.data):
            login_user(user)
            print(user.id)
            return redirect(url_for("get_all_posts"))

        elif not user:
            flash("The email does not exist, please try again!")
            return redirect(url_for("login"))
        else:
            flash("Password is incorrect, please try again!")
            return redirect(url_for("login"))

    return render_template("login.html", form=log_form)


@app.route('/logout')
def logout():
    """
    Logout route to terminate user session.
    """
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    """
    Home route to display all blog posts.
    """
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    user_id = current_user.id if current_user.is_authenticated else None
    print(user_id)
    return render_template(
        "index.html",
        all_posts=posts,
        user_id=user_id
    )


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    """
    Displays a single blog post by post_id and handles posting of comments.
    """
    form = CommentForm()
    requested_post = db.get_or_404(BlogPost, post_id)

    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))

        new_comment = Comment(
            text=form.comment.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()

    return render_template(
        "post.html",
        form=form,
        post=requested_post,
        user_id=current_user.id if current_user.is_authenticated else None
    )


@app.route("/new-post", methods=["GET", "POST"])
@admin_required
def add_new_post():
    """
    Route for admins to create a new blog post.
    Only accessible by admin (user_id=1).
    """
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_required
def edit_post(post_id):
    """
    Route for admins to edit an existing blog post by post_id.
    """
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )

    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, is_edit=True)


@app.route("/delete/<int:post_id>")
@admin_required
def delete_post(post_id):
    """
    Route for admins to delete a blog post by post_id.
    """
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    """
    Displays the About page.
    """
    return render_template("about.html")


@app.route("/contact")
def contact():
    """
    Displays the Contact page.
    """
    return render_template("contact.html")


if __name__ == "__main__":
    # Run the application in debug mode for development.
    app.run(debug=False, port=5002)
