from flask import Flask, redirect, url_for,render_template, abort
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.file import FileRequired, FileAllowed
from flask_wtf.csrf import CSRFProtect
from wtforms import FileField, SubmitField, StringField, PasswordField
from wtforms.validators import InputRequired
from sqlalchemy import exists, or_
from secrets import choice, token_urlsafe
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import UserMixin, login_user, LoginManager, logout_user, login_required, current_user
from flask_uploads import configure_uploads, IMAGES, UploadSet
import string
import datetime
import smtplib
import os
from email.message import EmailMessage
from dotenv import load_dotenv
from PIL import Image
from mimetypes import guess_type
import numpy as np

load_dotenv()

EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['UPLOADED_IMAGES_DEST'] = 'static/assets/StallLogos'
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 5
csrf = CSRFProtect(app)
db = SQLAlchemy(app)

images = UploadSet('images', IMAGES)
configure_uploads(app, images)

alphabets = string.ascii_letters + string.digits + string.punctuation

order_number = 1

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return Account.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')

class SignUpForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired()])
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    repassword = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Sign-Up')

class ForgetPassForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired()])
    submit = SubmitField('Reset Password')

class ResetPassForm(FlaskForm):
    password = PasswordField('Password', validators=[InputRequired()])
    repassword = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Reset Password')

class AddStallForm(FlaskForm):
    stall_name = StringField('Stall Name', validators=[InputRequired()])
    logo = FileField('Logo', validators=[FileRequired(), FileAllowed(images, 'Images only!')])
    submit = SubmitField('Add Stall')

def send_email(email, subject, message):
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = email
    msg['X-Priority'] = '2'
    msg.set_content(message)

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)

        smtp.send_message(msg)

class Account(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    user_email = db.Column(db.String, unique=True, nullable=False)
    pass_hash = db.Column(db.String, nullable=False)
    salt = db.Column(db.String(64), nullable=False)
    is_stallowner = db.Column(db.Boolean, nullable=False)
    stall_id = db.Column(db.Integer, unique=True)
    logged_in = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False) # Username of guy who ordered
    stall_id = db.Column(db.Integer)
    food_id = db.Column(db.Integer)
    order_id = db.Column(db.Integer, unique=True)

    def __repr__(self):
        return '<Order %r>' % self.order_id

class Confirmation_Route(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False)
    route = db.Column(db.String(100), unique=True, nullable=False)
    time_created = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    email = db.Column(db.String, nullable=False)
    pass_hash = db.Column(db.String, nullable=False)
    salt = db.Column(db.String(64), nullable=False)
    is_stallowner = db.Column(db.Boolean, nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False)

    def __repr__(self):
	    return '<Route %r>' % self.route

class Reset_Route(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    route = db.Column(db.String(100), unique=True, nullable=False)
    time_created = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    email = db.Column(db.String, nullable=False)

    def __repr__(self):
	    return '<Route %r>' % self.route

class Stall(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    stall_name = db.Column(db.String, unique=True)
    filename = db.Column(db.String, unique=True)
    
    def __repr__(self):
	    return '<Stall %r>' % self.id

class Food(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    stall_id = db.Column(db.Integer, db.ForeignKey(Stall.id), nullable=False)
    collecting_time = db.Column(db.DateTime, nullable=False)

    def __repr__(self):
	    return '<Food %r>' % self.id

# Login page
@app.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        new_username = form.username.data
        new_password = form.password.data

        new_username = new_username.strip()

        # disgusting code to check if account alr exists
        account_query = Account.query.filter_by(username=new_username).first()

        if not account_query: # Username doesnt exist
            return render_template('login.html', incorrect=True, form=form)

        salt = account_query.salt
        new_password = salt[:32] + new_password + salt[32:]

        result = check_password_hash(account_query.pass_hash, new_password)

        if result:
            login_user(account_query)
            return redirect('/')

        return render_template('login.html', incorrect=True, form=form)

    return render_template('login.html', incorrect=False, form=form)

@app.route('/SignUp', methods=['POST', 'GET'])
def signup():
    form = SignUpForm() 
    if form.validate_on_submit(): # Post
        new_username = form.username.data
        new_password = form.password.data
        re_password = form.repassword.data
        new_email = form.email.data

        new_username = new_username.strip()
        new_email = new_email.strip()

        # disgusting code to check if username alr exists
        account_exists = db.session.query(exists().where(or_(Account.user_email==new_email,Account.username==new_username))).scalar()

        valid_email = True

        if len(new_email)<16 or new_email[len(new_email)-16:]!="@students.edu.sg" or ' ' in new_email:
            valid_email = False

        if account_exists: # Username or email taken
            return render_template('SignUp.html', username_taken=True, password_correct=(new_password==re_password), pass_len=(len(new_password)>7), whitespace = (' ' in new_password), valid_email=valid_email, form=form)

        if new_password!=re_password: # Password entered wrongly
            return render_template('SignUp.html', username_taken=False, password_correct=False, pass_len=(len(new_password)>7), whitespace = (' ' in new_password), valid_email=valid_email, form=form)

        if len(new_password) < 8:
            return render_template('SignUp.html', username_taken=False, password_correct=True, pass_len=False, whitespace = (' ' in new_password), valid_email=valid_email, form=form)

        if ' ' in new_password:
            return render_template('SignUp.html', username_taken=False, password_correct=True, pass_len=True, whitespace=True, valid_email=valid_email, form=form)

        if not valid_email:
            return render_template('SignUp.html', username_taken=False, password_correct=True, pass_len=True, whitespace=False, valid_email=False, form=form)

        # Successful sign up

        # Send email

        # Generate unique confirmation route
        new_route = token_urlsafe()
        while db.session.query(exists().where(Confirmation_Route.route==new_route)).scalar():
            new_route = token_urlsafe()

        # Generate salt
        new_salt = ''.join(choice(alphabets) for _ in range(64))
        new_password = new_salt[:32] + new_password + new_salt[32:]
        new_confirmation_route = Confirmation_Route(is_admin=(new_username=="AMOS") ,is_stallowner=(new_username=="AMOS"), route=new_route, email=new_email, username=new_username, salt=new_salt, pass_hash=generate_password_hash(new_password, method = 'sha512'))

        # Stall owner and admin only if username is AMOS

        try:
            check_route = Confirmation_Route.query.filter_by(username=new_username)

            if check_route.first():
                check_route.delete()

            db.session.add(new_confirmation_route)
            db.session.commit()

            subj = "Verification for your Ande Canteen account"
            temp = "Hi "
            temp += new_username
            temp += "!\n\nYou have been registered!\nClick on the attached link to verify your AndeCanteen account\nNot you? Ignore this email and the account will not be created\nThis link will be removed after 5 minutes\n\nhttps://andecanteen.com/verify/"
            temp += new_route
            temp += "\n\nRegards,\nAndeCanteen"

            send_email(new_email, subj, temp)

            return 'An email has been sent to the email, verify your account there. The verification link will be removed after 5 minutes'
        except:
            return 'There was an issue logging in :(\nContact us if there are any problems!'

    return render_template('SignUp.html', username_taken=False, password_correct=True, pass_len=True, whitespace=False, valid_email=True, form=form)

@app.route('/logout', methods=['POST', 'GET'])
@login_required
def logout():
    curr_user = load_user(current_user.get_id())
    if curr_user.logged_in:
        curr_user.logged_in=False
        db.session.commit()

    logout_user()
    return redirect(url_for('login'))

# Home page
@app.route('/', methods=['POST', 'GET'])
@login_required
def HomePage():
    curr_user = load_user(current_user.get_id())
    if curr_user.logged_in:
        return render_template('HomePage.html', animate_gif=False, is_admin=curr_user.is_admin)

    curr_user.logged_in=True
    db.session.commit()
    return render_template('HomePage.html', animate_gif=True, is_admin=curr_user.is_admin)

# Checkout
@app.route('/checkout', methods=['POST', 'GET'])
@login_required
def checkout():
    return render_template('checkout.html')

@app.route('/AddStall', methods=['POST', 'GET'])
@login_required
def AddStall():
    curr_user = load_user(current_user.get_id())
    # Not admin
    if not curr_user.is_admin:
        abort(404)

    form = AddStallForm()

    if form.validate_on_submit():
        stall_name = form.stall_name.data
        logo = form.logo
        
        # Stall exists
        if db.session.query(exists().where(Stall.stall_name==stall_name)).scalar():
            return render_template('AddStall.html', form=form, stall_exists=True)

        type = guess_type(logo.data.filename) # Get the file ext
        type = type[0]

        # Checking for jpg/jpeg/png
        if len(type) != 10 and len(type) != 9:
            return render_template('AddStall.html', form=form, invalid_naming=True)

        if type[:5] != 'image':
            return render_template('AddStall.html', form=form, invalid_naming=True)

        file_ext = type[6:]

        if file_ext != 'png' and file_ext != 'jpeg':
            return render_template('AddStall.html', form=form, invalid_naming=True)

        # Make sure is correct naming
        if file_ext == 'jpeg': 
            file_ext = 'jpg'

        file_ext = '.' + file_ext

        # Get time so that filename is more likely to be unique
        suffix = datetime.datetime.utcnow().strftime("%y%m%d_%H%M%S")
        filename = secure_filename("_".join([secure_filename(stall_name), suffix]))
        random_string = ''.join(choice(string.ascii_letters+string.digits) for _ in range(15))

        # In case the filename exists, keep generating random strings
        while db.session.query(exists().where(Stall.filename==secure_filename(filename+random_string+file_ext))).scalar():
            random_string = ''.join(choice(string.ascii_letters+string.digits) for _ in range(15))

        filename = secure_filename(filename+random_string+file_ext)

        try:
            # Save image to our folder and add new stall
            
            # Remove any potential viruses
            # Load image
            im = Image.open(logo.data)                                     

            # Convert to format that cannot store IPTC/EXIF or comments, i.e. Numpy array
            na = np.array(im)                                                                       

            # Create new image from the Numpy array
            result = Image.fromarray(na)

            # Copy forward the palette, if any
            palette = im.getpalette()
            if palette != None:
                result.putpalette(palette)

            # Save result
            result.save('static/assets/StallLogos/'+filename)
            # images.save(logo.data, name=filename)
            new_stall = Stall(stall_name=stall_name, filename=filename)
            db.session.add(new_stall)
            db.session.commit()
        except:
            return 'There was an error adding the stall, make sure your file included was correct and a png/jpeg'

        return redirect('/')

    return render_template('AddStall.html', form=form, invalid_naming=False, stall_exists=False)

# Profile to edit username or password
@app.route('/Profile', methods=['POST', 'GET'])
@login_required
def Profile():
    return render_template('profile.html')

@app.route('/ForgetPass', methods=['POST', 'GET'])
def ForgetPass():
    form = ForgetPassForm()
    if form.validate_on_submit():
        email = form.email.data

        email = email.strip()

        account_query = Account.query.filter_by(user_email=email).first()
        if not(account_query) or ' ' in email:
            return render_template('ForgetPass.html', incorrect=True)

        try:
            new_route = token_urlsafe()
            while db.session.query(exists().where(Reset_Route.route==new_route)).scalar():
                new_route = token_urlsafe()

            new_reset = Reset_Route(email=email,route=new_route)

            check_route = Reset_Route.query.filter_by(email=email)

            if check_route.first():
                check_route.delete()

            db.session.add(new_reset)
            db.session.commit()

            subj = "Password reset link for your AndeCanteen account"

            temp = "Hi "
            temp += account_query.username
            temp += "!\n\nThe attached link is the link for your AndeCanteen account password reset\nNot you? Ignore this email and the password will not be resetted\nThis link will be removed after 5 minutes\n\nhttps://andecanteen.com/passreset/"
            temp += new_route
            temp += "\n\nRegards,\nAndeCanteen"

            send_email(email, subj, temp)

            return "An email has been sent to your email containing the password reset link"
        except:
            return "There was an error resetting your password :(\nTry connecting to a different network or contact us if there are any issues"

    return render_template('ForgetPass.html', incorrect=False, form=form)

@app.route('/passreset/<token>', methods=['POST', 'GET'])
def passreset(token):
    res = Reset_Route.query.filter_by(route=token)
    result = res.first()
    if not(result):
        abort(404)

    diff = datetime.datetime.utcnow()-result.time_created
    diff_minutes = (diff.days * 24 * 60) + (diff.seconds/60.0)
    if diff_minutes>=5.0:
        res.delete()
        db.session.commit()
        return 'This password reset link has expired. Please make a new one.'

    form = ResetPassForm()

    if form.validate_on_submit():
        password = form.password.data
        re_pass = form.repassword.data
        whitespace = ' ' in password
        password_correct = (password == re_pass)
        pass_len = (len(password)>=8)
        if whitespace or not(password_correct) or not(pass_len):
            return render_template("ChangePass.html", whitespace=whitespace, password_correct=password_correct, pass_len=pass_len, form=form)

        try:
            account = Account.query.filter_by(user_email=result.email).first()
            new_salt = ''.join(choice(alphabets) for _ in range(64))
            password = new_salt[:32] + password + new_salt[32:]
            account.salt = new_salt
            account.pass_hash = generate_password_hash(password, method = 'sha512')
            res.delete()
            db.session.commit()
            login_user(account)
            return redirect('/')
        except:
            res.delete()
            db.session.commit()
            return 'There was an error logging in :(\nContact us if there are any problems'

    return render_template("ChangePass.html", whitespace=False, password_correct=True, pass_len=True, form=form)


@app.route('/verify/<token>')
def confirm(token):
    res = Confirmation_Route.query.filter_by(route=token)
    result = res.first()
    if not(result):
        abort(404)

    if db.session.query(exists().where(Account.username==result.username)).scalar(): # Check if an account already exists
        res.delete()
        db.session.commit()
        abort(404)

    diff = datetime.datetime.utcnow()-result.time_created
    diff_minutes = (diff.days * 24 * 60) + (diff.seconds/60.0)
    if diff_minutes>=5.0:
        res.delete()
        db.session.commit()
        return 'This verification link has expired. Please make a new one.'

    try:
        new_account = Account(logged_in=False, is_admin=result.is_stallowner ,is_stallowner=result.is_stallowner, username=result.username, user_email=result.email, pass_hash=result.pass_hash, salt=result.salt)
        db.session.add(new_account)
        res.delete()
        db.session.commit()
        login_user(new_account)
        return redirect('/')
    except:
        res.delete()
        db.session.commit()
        return 'There was an error logging in :(\nContact us if there are any problems'
    
# Drink stall
# @app.route('/DrinkStall', methods=['POST', 'GET'])
# @login_required
# def DrinkStall():
#     return render_template('DrinkStall.html')

# # Stall owner
# @app.route('/StallOwner', methods=['POST', 'GET'])
# @login_required
# def StallOwner():
#     account = load_user(current_user.get_id())
#     if account.is_stallowner:
#         return render_template('StallOwner.html')
#     abort(404)


if __name__ == "__main__":
    app.run(debug=True)