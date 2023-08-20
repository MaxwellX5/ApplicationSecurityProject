from wtforms import Form, StringField, IntegerField, validators
from wtforms.fields import EmailField, SubmitField, PasswordField, BooleanField, IntegerField, DecimalField, FloatField, TextAreaField, FileField, SelectField
from wtforms.validators import InputRequired, Length, ValidationError, DataRequired, NumberRange, Regexp
from wtforms.widgets import PasswordInput
from flask_wtf import FlaskForm
from firebaseconfig import db_ref
from flask_wtf.file import FileField, FileRequired, FileAllowed
import decimal, re
import phonenumbers
from flask import session
from DBRetrieve import get_user_attribute_encrypted, get_user_attribute_unencrypted
from inputfiltering import filter_input
from werkzeug.datastructures import MultiDict
from sexyencryption import decrypt
def positive_integer(form, field):
    if field.data < 0:
        raise ValidationError('Value must be a positive integer.')
class CreateProductForm(FlaskForm):
    product_id = IntegerField('Product ID', validators=[DataRequired(), positive_integer])
    product_name = StringField('Product Name', validators=[DataRequired()])
    product_price = IntegerField('Product Price', validators=[DataRequired(), positive_integer])



class CreateMissionForm(FlaskForm):
    mission_name = StringField('Mission Name', [validators.DataRequired(),validators.Length(max=50, message="Mission name cannot exceed 50 characters")])
    mission_reward = IntegerField('Mission Reward', [validators.DataRequired(), validators.NumberRange(min=0, max=100000, message='Mission reward must be between 0 and 100,000')])
    mission_requirement = StringField('Mission Requirement', [validators.DataRequired(), validators.Length(max=150, message='Mission Requirement cannot exceed 150 characters.')])
    mission_time = StringField('Mission Time', [validators.DataRequired()])

class MissionEvidenceForm(FlaskForm):
    # mission_evidence = StringField('Mission Evidence', [validators.DataRequired()])
    mission_evidence = FileField("Image", validators=[DataRequired()])
    submit = SubmitField("Submit")

class CreateRejectionForm(FlaskForm):
    rejection_reason = StringField('Rejection Reason', [validators.DataRequired()])

# custom validator for no more than 2 decimal places
class AmountValidator:
    def __call__(self, form, field):
        value = field.data
        if value is None:
            raise ValidationError('This field is required.')
        try:
            d = decimal.Decimal(str(value))
            if d.as_tuple().exponent < -2:
                raise ValidationError('Value cannot have more than 2 decimal places.')
            pattern = re.compile(r'^\d+(\.\d+)?$')
            if not pattern.match(str(value)):
                raise ValidationError('Please enter a valid number.')
            if d < 1 or d > 200000:
                raise ValidationError('Please enter a number between $1 and $200,000.')
        except ValueError:
            raise ValidationError('Please enter a valid number.')
    

# form not used anyomre, only for csrf token
class DonationForm(FlaskForm):
    amount = FloatField('Amount (SGD)', render_kw={"placeholder": "Any amount between $1 and $200,000"}, validators=[InputRequired(), AmountValidator()])
    comment = TextAreaField('Comment', render_kw={"placeholder": "Leave a message for others to see!", "rows": "3"}, validators=[validators.Length(min=0, max=500)])
    anonymous = BooleanField('Anonymous', default=False)


class UploadForm(FlaskForm):
    image = FileField('Image', validators=[
        FileRequired(),
        FileAllowed(['jpg', 'png', 'Images only!'])
    ])
    submit = SubmitField('Upload')

class CreateUserForm(FlaskForm):
    first_name = StringField('First Name', [validators.DataRequired()])
    last_name = StringField('Last Name', [validators.DataRequired()])
    username = StringField('Username', [validators.DataRequired()])
    email = EmailField('Email', [validators.DataRequired()])
    phone_num = StringField('Phone Number', [validators.Length(min=10,max=12), validators.DataRequired()])
    address = StringField('Address', [validators.DataRequired()])
    postal_code = StringField('Postal Code', [validators.Length(min=6, max=6), validators.DataRequired()])
    password = StringField('Password', [validators.Length(min=8, max=100), validators.DataRequired(),
                                        validators.EqualTo('confirm_password', message="Passwords Must Match")],
                           widget=PasswordInput(hide_value=False))
    confirm_password = StringField('Re-enter Password', [validators.Length(min=8, max=100), validators.DataRequired(),
                                                         validators.EqualTo('password',
                                                                            message="Passwords Must Match")],
                                   widget=PasswordInput(hide_value=False))
    submit = SubmitField("Submit")


    def validate_username(self, username):
        users_ref = db_ref.child("users")
        low_username = username.data.lower()
        query_result = users_ref.get()
        found = False
        for user_id, user_data in query_result.items():
            try:
                if user_data['lower_username']:
                    if decrypt(user_data["lower_username"]) == low_username:
                        found = True
            except:
                pass
        if found:
            raise ValidationError('Username already exists.')

    def validate_email(self, email):
        email_pattern = r'^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email.data):
            raise ValidationError('Invalid email address.')
        users_ref = db_ref.child("users")
        low_email = email.data.lower()
        query_result = users_ref.get()
        found = False
        for user_id, user_data in query_result.items():
            try:
                if user_data['lower_email']:
                    if decrypt(user_data["lower_email"]) == low_email:
                        found = True
            except:
                pass
        if found:
            raise ValidationError('Email address already exists. Please choose a different one.')

    def validate_phone_num(self, phone_num):
        try:
            parsed_phone_num = phonenumbers.parse(phone_num.data, None)
            if not phonenumbers.is_valid_number(parsed_phone_num):
                raise ValidationError('Invalid phone number.')
            users_ref = db_ref.child("users")
            query_result = users_ref.order_by_child('phone_num').equal_to(phone_num.data).get()
            found = False
            for user_id, user_data in query_result.items():
                try:
                    if user_data['phone_num']:
                        if decrypt(user_data["phone_num"]) == phone_num.data:
                            found = True
                except:
                    pass
            if found:
                raise ValidationError('Phone number already exists. Please choose a different one.')
        except phonenumbers.phonenumberutil.NumberParseException:
            raise ValidationError('Invalid phone number.')

    def validate_address(self, address):
        users_ref = db_ref.child("users")
        low_address = address.data.lower()
        query_result = users_ref.get()
        found = False
        for user_id, user_data in query_result.items():
            try:
                if user_data['lower_address']:
                    if decrypt(user_data["lower_address"]) == low_address:
                        found = True
            except:
                pass
        if found:
            raise ValidationError('Address already exists. Please choose a different one.')
    def validate_postal_code(self, postal_code):
        users_ref = db_ref.child("users")
        query_result = users_ref.get()
        if not postal_code.data.isdigit():
            raise ValidationError('Invalid postal code.')
        found = False
        for user_id, user_data in query_result.items():
            try:
                if user_data['postal_code']:
                    if decrypt(user_data["postal_code"]) == postal_code.data:
                        found = True
            except:
                pass
        if found:
            raise ValidationError('Postal code already exists. Please choose a different one.')
    def validate_password(self, password):
        lower = 0
        upper = 0
        special = 0
        number = 0
        for char in password.data:
            if char.isupper():
                upper += 1
            elif char.islower():
                lower += 1
            elif char.isalpha() == False and char.isnumeric() == False:
                special += 1
            elif char.isnumeric():
                number += 1
        if lower != 0 and upper != 0 and special != 0 and number != 0:
            pass
        else:
            raise ValidationError("Password should contain lowercase, uppercase, number and special characters")

class CreateStaffForm(FlaskForm):
    first_name = StringField('First Name', [validators.DataRequired()])
    last_name = StringField('Last Name', [validators.DataRequired()])
    username = StringField('Username', [validators.DataRequired()])
    email = EmailField('Email', [validators.Email(), validators.DataRequired()])
    phone_num = StringField('Phone Number', [validators.Length(min=10,max=12), validators.DataRequired()])
    password = StringField('Password', [validators.Length(min=8, max=100), validators.DataRequired(),
                                        validators.EqualTo('confirm_password', message="Passwords Must Match")],
                           widget=PasswordInput(hide_value=False))
    confirm_password = StringField('Re-enter Password', [validators.Length(min=8, max=100), validators.DataRequired(),
                                                         validators.EqualTo('password',
                                                                            message="Passwords Must Match")],
                                   widget=PasswordInput(hide_value=False))
    role = SelectField('Role', choices=[
        'Admin',
        'Leaderboard Manager',
        'Product Manager',
        'Mission Manager'
    ], validators=[validators.DataRequired()])
    submit = SubmitField("Submit")

    def validate_username(self, username):
        users_ref = db_ref.child("users")
        low_username = username.data.lower()
        query_result = users_ref.get()
        found = False
        for user_id, user_data in query_result.items():
            try:
                if user_data['lower_username']:
                    if decrypt(user_data["lower_username"]) == low_username:
                        found = True
            except:
                pass
        if found:
            raise ValidationError('Username is already taken.')
    def validate_email(self, email):
        email_pattern = r'^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email.data):
            raise ValidationError('Invalid email address.')

        users_ref = db_ref.child("users")
        low_email = email.data.lower()
        query_result = users_ref.get()
        found = False
        for user_id, user_data in query_result.items():
            try:
                if user_data['lower_email']:
                    if decrypt(user_data["lower_email"]) == low_email:
                        found = True
            except:
                pass
        if found:
            raise ValidationError(
                'That email already exists. Please choose a different one.')

    def validate_phone_num(self, phone_num):
        try:
            parsed_phone_num = phonenumbers.parse(phone_num.data, None)
            if not phonenumbers.is_valid_number(parsed_phone_num):
                raise ValidationError('Invalid phone number.')
            users_ref = db_ref.child("users")
            query_result = users_ref.get()
            found = False
            for user_id, user_data in query_result.items():
                try:
                    if user_data['phone_num']:
                        print(decrypt(user_data["phone_num"]), phone_num.data)
                        if decrypt(user_data["phone_num"]) == phone_num.data:
                            found = True
                except:
                    pass
            if found:
                raise ValidationError('Phone number already exists. Please choose a different one.')
        except phonenumbers.phonenumberutil.NumberParseException:
            raise ValidationError('Invalid phone number.')

    def validate_password(self, password):
        lower = 0
        upper = 0
        special = 0
        number = 0
        for char in password.data:
            if char.isupper():
                upper += 1
            elif char.islower():
                lower += 1
            elif char.isalpha() == False and char.isnumeric() == False:
                special += 1
            elif char.isnumeric():
                number += 1
        if lower != 0 and upper != 0 and special != 0 and number != 0:
            pass
        else:
            raise ValidationError("Password should contain lowercase, uppercase, number and special characters")
class LoginForm(FlaskForm):
    email = StringField('Email', [validators.DataRequired()])
    password = StringField('Password',[validators.Length(max=100), validators.DataRequired()], widget=PasswordInput(hide_value=False))
    checkbox = BooleanField("Remember Me")

class ProfileForm(FlaskForm):
    first_name = StringField('First Name', [validators.DataRequired()])
    last_name = StringField('Last Name', [validators.DataRequired()])
    username = StringField('Username', [validators.DataRequired()])
    #email = EmailField('Email', [validators.Email(), validators.DataRequired()])
    phone_num = StringField('Phone Number', [validators.Length(min=10, max=12), validators.DataRequired()])
    address = StringField('Address', [validators.DataRequired()])
    postal_code = StringField('Postal Code', [validators.Length(min=6, max=6), validators.DataRequired()])
    pfp = FileField("Profile Picture", [validators.Optional(),
                                    FileAllowed(["jpg", "jpeg", "png"],
                                                message="File uploaded is not in an accepted format")])

    submit = SubmitField("Submit")

    def validate_username(self, username):
        users_ref = db_ref.child("users")
        query_result = users_ref.order_by_child('username').equal_to(username.data.lower()).get()
        if query_result:
            if username.data == get_user_attribute_encrypted(session['id'], 'username'):
                pass
            else:
                raise ValidationError('Username is already taken.')


    def validate_phone_num(self, phone_num):
        try:
            parsed_phone_num = phonenumbers.parse(phone_num.data, None)
            if not phonenumbers.is_valid_number(parsed_phone_num):
                raise ValidationError('Invalid phone number.')
            users_ref = db_ref.child("users")
            query_result = users_ref.order_by_child('phone_num').equal_to(phone_num.data).get()
            if query_result:
                if phone_num.data == get_user_attribute_encrypted(session['id'], 'phone_num'):
                    pass
                else:
                    raise ValidationError('Phone number already exists. Please choose a different one.')
        except phonenumbers.phonenumberutil.NumberParseException:
            raise ValidationError('Invalid phone number.')

    def validate_address(self, address):
        users_ref = db_ref.child("users")
        query_result = users_ref.order_by_child('address').equal_to(address.data.lower()).get()
        if query_result:
            if address.data == get_user_attribute_encrypted(session['id'], 'address'):
                pass
            else:
                raise ValidationError('Address already exists. Please choose a different one.')

    def validate_postal_code(self, postal_code):
        users_ref = db_ref.child("users")
        query_result = users_ref.order_by_child('postal_code').equal_to(postal_code.data.lower()).get()
        if postal_code.data.isdigit() == False:
            raise ValidationError('Invalid postal code.')
        if query_result:
            if postal_code.data == get_user_attribute_encrypted(session['id'], 'postal_code'):
                pass
            else:
                raise ValidationError('Postal code already exists. Please choose a different one.')


class ResetPassForm(FlaskForm):
    email = StringField('Email', [validators.DataRequired()])

class ChangePasswordForm(FlaskForm):
    currentpassword = StringField('Current Password', [validators.Length(max=100), validators.DataRequired()], widget=PasswordInput(hide_value=False))
    newpassword = StringField('Enter New Password', [validators.Length(min=8, max=100), validators.DataRequired(),validators.EqualTo('repassword', message="Passwords Must Match")],widget=PasswordInput(hide_value=False))
    repassword = StringField('Re-enter New Password', [validators.Length(min=8, max=100), validators.DataRequired(),validators.EqualTo('newpassword',message="Passwords Must Match")],widget=PasswordInput(hide_value=False))
    def validate_newpassword(self, password):
        lower = 0
        upper = 0
        special = 0
        number = 0
        for char in password.data:
            if char.isupper():
                upper += 1
            elif char.islower():
                lower += 1
            elif char.isalpha() == False and char.isnumeric() == False:
                special += 1
            elif char.isnumeric():
                number += 1
        if lower != 0 and upper != 0 and special != 0 and number != 0:
            pass
        else:
            raise ValidationError("Password should contain lowercase, uppercase, number and special characters")

class TwoFactorForm(FlaskForm):
    otp = StringField('OTP', [validators.Length(min=6, max=6), validators.DataRequired()])
    def validate_otp(self, otp):
        if otp.data.isdigit() == False:
            raise ValidationError('Invalid OTP')

class DeleteAccountForm(FlaskForm):
    password = StringField('Enter Password',[validators.Length(max=100), validators.DataRequired()], widget=PasswordInput(hide_value=False))
    checkbox = BooleanField("Yes, delete my account", [validators.DataRequired()])

class ResetPasswordForm(FlaskForm):
    newpassword = StringField('Password', [validators.Length(min=8, max=100), validators.DataRequired(),
                                        validators.EqualTo('repassword', message="Passwords Must Match")],
                           widget=PasswordInput(hide_value=False))
    repassword = StringField('Re-enter Password', [validators.Length(min=8, max=100), validators.DataRequired(),
                                                         validators.EqualTo('newpassword',
                                                                            message="Passwords Must Match")],
                                   widget=PasswordInput(hide_value=False))
    def validate_newpassword(self, password):
        lower = 0
        upper = 0
        special = 0
        number = 0
        for char in password.data:
            if char.isupper():
                upper += 1
            elif char.islower():
                lower += 1
            elif char.isalpha() == False and char.isnumeric() == False:
                special += 1
            elif char.isnumeric():
                number += 1
        if lower != 0 and upper != 0 and special != 0 and number != 0:
            pass
        else:
            raise ValidationError("Password should contain lowercase, uppercase, number and special characters")
