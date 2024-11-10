from datetime import datetime, date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy.exc import IntegrityError
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
import os
from werkzeug.exceptions import NotFound

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("flask_key")
ckeditor = CKEditor(app)
Bootstrap5(app)

year = datetime.now().year
app.jinja_env.globals["year"] = year


class Base(DeclarativeBase):
    pass

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///posts.db")
db = SQLAlchemy(model_class=Base)
db.init_app(app)


class User(UserMixin,db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    name: Mapped[str] = mapped_column(String(1000))
    password: Mapped[str] = mapped_column(String(250))
    posts = relationship("BlogPost", back_populates='author')
    comments = relationship("Comment", back_populates='author')

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    comments = relationship("Comment", back_populates="comment_author")
    
class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    author = relationship('User', back_populates='comments')
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    time: Mapped[str] = mapped_column(String(250), nullable=False)
    post_id: Mapped[str] = mapped_column(Integer, ForeignKey("blog_posts.id"))
    comment_author = relationship('BlogPost', back_populates='comments')
    text: Mapped[str] = mapped_column(Text, nullable=False)


login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User,user_id)

with app.app_context():
    db.create_all()
    try:
        db.get_or_404(User,1)
    except NotFound:
        new_user = User(
                email=os.environ.get('email'),
                name = os.environ.get('username'),
                password = generate_password_hash(os.environ.get('password'), method="pbkdf2:sha256", salt_length=8)
            )
        db.session.add(new_user)
        db.session.commit()


def admin_only(function):
    @wraps(function)
    def admin(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id != 1 :
            return abort(403)
        return function(*args, **kwargs)
    return admin

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


@app.route('/register', methods=['GET','POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        try:
            email = form.email.data
            name = (form.name.data).title()
            password = form.password.data
            re_pass = form.re_password.data
            if password != re_pass:
                flash("Your password entries do not match. Please try again")
            else:
                new_user = User(
                    email=email,
                    name = name,
                    password = generate_password_hash(password, method="pbkdf2:sha256", salt_length=8)
                )
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user)
                return redirect(url_for('get_all_posts', name=name))
        except IntegrityError:
            flash("This email address is associated with an active account. Please, login to continue.")
            return redirect(url_for('login'))
    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        try:
            email = form.email.data
            user = db.session.execute(db.select(User).where(User.email == email)).scalar()
            password_input = form.password.data
            if check_password_hash(user.password, password_input):
                login_user(user)
                return redirect(url_for('get_all_posts', logged_in=current_user.is_authenticated))
            else:
                flash("Password incorrect. Please, try again")
        except AttributeError:
            flash("The email address that you entered, is not associated with an active account. Please, try again")
            return redirect(url_for('login'))
    return render_template("login.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    posts = db.session.execute(db.select(BlogPost)).scalars().all()
    return render_template("index.html", 
                           all_posts=posts, 
                           logged_in = current_user.is_authenticated, 
                           admin=db.get_or_404(User,1)
                           )


@app.route("/post/<int:post_id>", methods=['GET','POST'])
def show_post(post_id):
    if request.method == 'POST':
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        else:
            form = CommentForm()
            if form.validate_on_submit():
                new_comment = Comment(
                text = form.comment_text.data,
                author_id = current_user.id,
                post_id = post_id,
                date = date.today().strftime("%B %d, %Y"),
                time = datetime.now().strftime("%I:%M %p")
                )
                db.session.add(new_comment)
                db.session.commit()
            return redirect(url_for("show_post", post_id=post_id))

    
    requested_post = db.get_or_404(BlogPost, post_id)
    comment_form = CommentForm()
    return render_template("post.html", 
                           post=requested_post,
                           comments = requested_post.comments,
                           logged_in=current_user.is_authenticated, 
                           admin=db.get_or_404(User,1),
                           form = comment_form
                           )


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
            author= current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
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
        return redirect(url_for("show_post", post_id=post_id))
    return render_template("make-post.html", form=edit_form, is_edit=True, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts', logged_in=current_user.is_authenticated))


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)

@app.route('/edit_comment/<int:post_id>/<int:comment_id>', methods=['GET','POST'])
@login_required
def edit_comment(comment_id, post_id):
    comment = db.get_or_404(Comment, comment_id)
    requested_post = db.get_or_404(BlogPost, post_id)
    edit_form = CommentForm(
        comment_text = comment.text
    )
    if edit_form.validate_on_submit():
        comment.text = edit_form.comment_text.data
        db.session.commit()
        return redirect(url_for("show_post", post_id = post_id))
    return render_template("post.html", 
                            post=requested_post,
                            comments = requested_post.comments,
                            logged_in=current_user.is_authenticated, 
                            admin=db.get_or_404(User,1),
                            form = edit_form
                            )

@app.route('/delete_comment/<post_id>/<comment_id>', methods = ['GET','POST'])
def delete_comment(comment_id, post_id):
    comment = db.get_or_404(Comment, comment_id)
    db.session.delete(comment)
    db.session.commit()
    requested_post = db.get_or_404(BlogPost, post_id)
    form = Comment()
    return redirect(url_for('show_post', post_id=post_id))


if __name__ == "__main__":
    app.run(debug=False)