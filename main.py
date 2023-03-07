import flask_login
from functools import wraps
from flask import Flask, render_template, redirect, url_for, flash, request, g, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy import Table, Column, Integer, ForeignKey
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user, login_manager, \
    login_url
from forms import CreatePostForm, RegisterUserForm, LoginUserForm, LeaveComment
from flask_gravatar import Gravatar
from flask_ckeditor import CKEditor, CKEditorField

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager = flask_login.LoginManager()
login_manager.init_app(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog2.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES

class BlogPost(db.Model):  # Parent
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    child_id = db.Column(db.Integer, db.ForeignKey('User_Blog.id'))
    child = relationship("UserBlog", back_populates="parents")
    comment_rel = relationship("Comment", back_populates="Post_child")


class UserBlog(UserMixin, db.Model):  # Child
    __tablename__ = "User_Blog"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    parents = relationship("BlogPost", back_populates="child")
    comment_rel = relationship("Comment", back_populates="User_child")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author = db.Column(db.String(250), nullable=False)
    User_id = db.Column(db.Integer, db.ForeignKey('User_Blog.id'))
    User_child = relationship("UserBlog", back_populates="comment_rel")
    Post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    Post_child = relationship("BlogPost", back_populates="comment_rel")


#with app.app_context():
#    db.create_all()


gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


def admin_only(function):
    @login_required
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if current_user.id == 1:
            return function(*args, **kwargs)
        else:
            logout_user()
            return abort(403)

    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return UserBlog.query.get(user_id)


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    register_form = RegisterUserForm()
    if register_form.validate_on_submit():
        if UserBlog.query.filter_by(email=register_form.email.data).first() is not None:
            return redirect(url_for("login", error="You've already registered with that email, sign up instead"))
        else:
            new_user_blog_object = UserBlog(email=register_form.email.data,
                                            password=generate_password_hash(password=register_form.password.data,
                                                                            method="pbkdf2:sha256", salt_length=8),
                                            name=register_form.name.data
                                            )
            db.session.add(new_user_blog_object)
            db.session.commit()
            login_user(new_user_blog_object)
            return redirect("/")
    else:
        return render_template("register.html", form=register_form)


@app.route('/login', methods=["GET", "POST"])
def login():
    error = request.args.get("error")
    if error is None:
        error = ""
    login_form = LoginUserForm()
    if login_form.validate_on_submit():
        user_object = UserBlog.query.filter_by(email=login_form.email.data).first()
        if user_object is None:
            return render_template("login.html", form=login_form, error="User doesn't exist")
        else:
            password = login_form.password.data
            if check_password_hash(pwhash=user_object.password, password=password):
                login_user(user_object)
                return redirect("/")
            else:
                return render_template("login.html", form=login_form, error="Incorrect password")
    else:
        return render_template("login.html", form=login_form, error=error)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    all_comments = Comment.query.filter_by(Post_id=post_id).all()
    all_users = db.session.query(UserBlog).all()
    form = LeaveComment()
    if form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment_object = Comment(text=form.comment.data,
                                         author=current_user.name,
                                         User_id=current_user.id,
                                         Post_id=post_id)
            db.session.add(new_comment_object)
            db.session.commit()
            return redirect("/")
        else:
            return redirect(url_for("login", error="You need to register or login to comment"))
    return render_template("post.html", post=requested_post, comments=all_comments, form=form, all_users = all_users)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=form.author.data,
            date=date.today().strftime("%B %d, %Y"),
            child_id=current_user.id
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
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
    app.run(debug=False, host='0.0.0.0', port=5000)
