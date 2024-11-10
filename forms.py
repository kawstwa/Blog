from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, Email, Length
from flask_ckeditor import CKEditorField


# WTForm for creating a blog post
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


# TODO: Create a RegisterForm to register new users
class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[Email()])
    name = StringField("Name", validators=[DataRequired()])
    password = PasswordField(label='Password', validators=[Length(min=8, message="Please, enter a password of at least 8 characters")])
    re_password = PasswordField('Re-Enter Password', validators=[DataRequired()])
    submit = SubmitField('Submit')

# TODO: Create a LoginForm to login existing users
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[Email()])
    password = PasswordField('Password')
    submit = SubmitField('Submit')


# TODO: Create a CommentForm so users can leave comments below posts
class CommentForm(FlaskForm):
    comment_text = CKEditorField("Leave a comment", validators=[DataRequired()])
    submit = SubmitField("Submit")