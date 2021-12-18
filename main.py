from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
import hashlib



app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False,
                    base_url=None)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# flask login ###
login_manager = LoginManager()
login_manager.init_app(app)

# CONFIGURE TABLES


class Users(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="commenter")
    gravatar_url = db.Column(db.String(250), nullable=False)


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship("Users", back_populates="posts")
    comments = relationship("Comment", back_populates="blog_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    commenter_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    commenter = relationship("Users", back_populates="comments")
    blog_post = relationship("BlogPost", back_populates="comments")
    blog_post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))


db.create_all()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_anonymous and current_user.id == 1:
            return f(*args, **kwargs)
        abort(403, description="not authorised")
    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user_email = request.form["email"]
        user = Users.query.filter_by(email=user_email).first()
        if user is None:
            password = request.form["password"]
            salted_pass = generate_password_hash(password)
            # gravatar_url = hashlib.md5(password.encode('utf-8')).hexdigest()
            new_user = Users(email=user_email, password=salted_pass, name=request.form["name"])
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)

            # login_user(new_user)
            return redirect(url_for('get_all_posts'))
        flash("user already exists")
        # form = LoginForm()
        return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user_email = request.form["email"]
        user = Users.query.filter_by(email=user_email).first()
        if user:
            input_password = request.form["password"]
            if check_password_hash(user.password, input_password):
                login_user(user)
                return redirect(url_for('get_all_posts'))
            flash('Wrong password')
            return redirect(url_for("login"))
        flash('Wrong user')
        return redirect(url_for("login"))

    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>",methods=["POST", "GET"])
# @admin_only
def show_post(post_id):
    commentform = CommentForm()
    if commentform.validate_on_submit():
        if not current_user.is_authenticated:
            form = LoginForm()
            flash("you need to login or register to comment")
            return render_template("login.html", form=form)
        new_comment = Comment(text=commentform.comment_text.data, commenter_id=current_user.id, blog_post_id=post_id)
        db.session.add(new_comment)
        db.session.commit()
    commentform.comment_text.data = ""
    requested_post = BlogPost.query.get(post_id)
    return render_template("post.html", post=requested_post, form=commentform)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post")
@admin_only
def add_new_post():
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


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
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
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
