from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Regexp, ValidationError


class PasswordComplexity:
    """Custom WTForms validator that enforces password strength requirements."""
    
    def __init__(self, min_score=3, message=None):
        self.min_score = min_score
        self.message = message
    
    def __call__(self, form, field):
        from app.utils.security import is_password_strong_enough
        
        is_valid, error_msg = is_password_strong_enough(field.data, self.min_score)
        if not is_valid:
            raise ValidationError(self.message or error_msg)


class RegistrationForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=3, max=64),
            Regexp(
                r"^[A-Za-z0-9_]+$",
                message="Username can only contain letters, numbers, and underscores.",
            ),
        ],
    )
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Length(min=8, message="Password must be at least 8 characters."),
            PasswordComplexity(min_score=3),  # Require "Good" strength for account passwords
        ],
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match.")],
    )
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log In")


class UploadForm(FlaskForm):
    file = FileField("File", validators=[FileRequired(message="Please choose a file.")])
    encryption_password = PasswordField(
        "Encryption Password",
        validators=[
            DataRequired(),
            Length(min=8, message="Use at least 8 characters — this protects the file itself."),
            PasswordComplexity(min_score=3),  # Require "Good" strength for encryption keys
        ],
    )
    confirm_password = PasswordField(
        "Confirm Encryption Password",
        validators=[DataRequired(), EqualTo("encryption_password", message="Passwords must match.")],
    )
    submit = SubmitField("Encrypt & Upload")


class DecryptForm(FlaskForm):
    encryption_password = PasswordField(
        "Encryption Password", validators=[DataRequired()]
    )
    submit = SubmitField("Decrypt")


class TOTPCodeForm(FlaskForm):
    code = StringField(
        "6-digit code",
        validators=[
            DataRequired(),
            Length(min=6, max=6, message="Enter the 6-digit code from your authenticator app."),
            Regexp(r"^\d{6}$", message="Code must be 6 digits."),
        ],
    )
    submit = SubmitField("Verify")


class DisableTOTPForm(FlaskForm):
    password = PasswordField("Current Password", validators=[DataRequired()])
    submit = SubmitField("Disable Two-Factor Authentication")


class BackupCodeForm(FlaskForm):
    code = StringField(
        "Backup Recovery Code",
        validators=[
            DataRequired(),
            Length(min=8, max=12, message="Enter your backup recovery code (e.g. ABCD-1234)."),
        ],
    )
    submit = SubmitField("Verify Backup Code")


class ForgotPasswordForm(FlaskForm):
    email = StringField(
        "Email Address",
        validators=[DataRequired(), Email(), Length(max=120)],
    )
    submit = SubmitField("Send Password Reset Link")


class ResetPasswordForm(FlaskForm):
    password = PasswordField(
        "New Password",
        validators=[
            DataRequired(),
            Length(min=8, message="Password must be at least 8 characters."),
            PasswordComplexity(min_score=3),  # Require "Good" strength for password resets
        ],
    )
    confirm_password = PasswordField(
        "Confirm New Password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match.")],
    )
    submit = SubmitField("Reset Password")


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("Current Password", validators=[DataRequired(message="Enter current password.")])
    new_password = PasswordField(
        "New Password",
        validators=[
            DataRequired(message="Enter new password."),
            Length(min=8, message="Password must be at least 8 characters."),
            PasswordComplexity(min_score=3),
        ],
    )
    confirm_new_password = PasswordField(
        "Confirm New Password",
        validators=[DataRequired(message="Please confirm your new password."), EqualTo("new_password", message="Passwords must match.")],
    )
    submit = SubmitField("Update Password")


