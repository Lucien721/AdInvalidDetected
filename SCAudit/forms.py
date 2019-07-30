from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, IntegerField
from wtforms.validators import DataRequired
from flask_wtf.file import FileField, FileAllowed, FileRequired


class RegisterForm(FlaskForm):
    # 域初始化时，第一个参数是设置label属性的
    username = StringField('User Name', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    phoneNumber = StringField('Phone Number', validators=[DataRequired()])


class LoginForm(FlaskForm):
    # 域初始化时，第一个参数是设置label属性的
    username = StringField('User Name', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])


class advertsForm(FlaskForm):
    # 域初始化时，第一个参数是设置label属性的
    advertName = StringField('Advert Name', validators=[DataRequired()])
    amount = StringField('Amount', validators=[DataRequired()])
    clickNumber = IntegerField('ClickNumber', validators=[DataRequired()])


class publishForm(FlaskForm):
    # 域初始化时，第一个参数是设置label属性的
    advertImage = FileField('Advert Image', validators=[
        FileRequired(),
        FileAllowed(['jpg', 'png'], 'Images only!')
    ])
