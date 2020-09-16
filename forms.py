from flask_wtf import FlaskForm
from wtforms import *
from wtforms.validators import *
from wtforms.fields import *
from werkzeug.utils import secure_filename

class LoginForm(FlaskForm):
	username = StringField('Username', validators=[DataRequired()])
	password = PasswordField('Password', validators=[DataRequired()])
	submit = SubmitField('Sign In')

class AddEventForm(FlaskForm):
	eventname = StringField('Event Name', validators = [DataRequired()])
	eventroute = StringField('Event Route', validators = [DataRequired()])
	submit = SubmitField('Submit')

class SetIPsForm(FlaskForm):
	ips = StringField('Ips', validators = [DataRequired()])
	submit = SubmitField('Submit')

class SetFormNames(FlaskForm):
	form_name = StringField('Form Name', validators = [DataRequired()])
	folder_name = StringField('Folder Name', validators = [DataRequired()])
	submit = SubmitField('Submit')

class SetPasswdsNames(FlaskForm):
	title = StringField('Title', validators = [DataRequired()])
	passwd = StringField('Password', validators = [DataRequired()])
	submit = SubmitField('Submit')

class SetUploadFilesForms(FlaskForm):
	file_name = StringField('File Name with extension', validators = [DataRequired()])
	file = FileField('File Upload', validators = [DataRequired()])
	submit = SubmitField('Submit')

class TSTSetupForm(FlaskForm):
	subname = StringField('Subject Name', validators = [DataRequired()])
	answers = StringField('Answers', validators = [DataRequired()])
	passwd = StringField('Jar Password', validators = [DataRequired()])
	submit = SubmitField('Submit')

class TSTUploadForm(FlaskForm):
	tst_file = FileField('TST Upload', validators = [DataRequired()])
	submit = SubmitField('Submit')

class SetTeamsForm(FlaskForm):
	teams = TextAreaField('Teams', render_kw={"rows": 5, "cols": 40})
	submit = SubmitField('Submit')
