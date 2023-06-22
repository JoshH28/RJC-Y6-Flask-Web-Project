from flask import Flask, redirect, url_for,render_template, abort
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import exists, or_
from secrets import choice
import flask_bcrypt
from flask_login import UserMixin, login_user, LoginManager, logout_user, login_required, current_user
from hashlib import sha512
import string
import smtplib
import os
from email.message import EmailMessage
from dotenv import load_dotenv
from models import User, Order, Stall, Food
from forms import LoginForm, SignUpForm, ForgetPassForm, ResetPassForm
from sqlalchemy.orm import Session
from sqlalchemy import select, or_
from sqlalchemy.sql import exists
from connect import engine
from itsdangerous import URLSafeTimedSerializer
# from gevent.pywsgi import WSGIServer

if os.name != "nt":
    os.chdir(os.path.dir(__file__))

load_dotenv()

EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['WTF_CSRF_SECRET_KEY'] = os.getenv("SECRET_CSRF_KEY")
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 5
csrf = CSRFProtect(app)

session = Session(bind=engine)

alphabets = string.ascii_letters + string.digits + string.punctuation

def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def confirm_token(token, expiration=300): # 5 mins
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=expiration)
    except:
        return False
    return email

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.session_protection = "basic"

@login_manager.user_loader
def load_user(user_id):
    return session.get(User, int(user_id))

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

# Login page
@app.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        new_username = form.username.data
        new_password = form.password.data

        new_username = new_username.strip()

        # check if User alr exists
        User_query = session.scalars(select(User).where(User.username==new_username)).first()

        if not User_query: # Username doesnt exist
            return render_template('login.html', incorrect=True, form=form)

        salt = User_query.salt
        salt2 = User_query.salt2
        salt3 = User_query.salt3
        salt4 = User_query.salt4
        salt5 = User_query.salt5

        new_password = salt[:32] + new_password + salt[32:]
        new_password = sha512(new_password.encode('utf-8')).hexdigest()

        new_password += salt2
        new_password = sha512(new_password.encode('utf-8')).hexdigest()

        new_password += salt3
        new_password = sha512(new_password.encode('utf-8')).hexdigest()

        new_password += salt4
        new_password = sha512(new_password.encode('utf-8')).hexdigest()

        new_password += salt5
        new_password = sha512(new_password.encode('utf-8')).hexdigest()

        result = flask_bcrypt.check_password_hash(User_query.pass_hash, new_password)

        if result:
            if current_user.is_authenticated:
                logout_user()
            login_user(User_query, remember=True)
            return redirect('/')

        return render_template('login.html', incorrect=True, form=form)

    return render_template('login.html', incorrect=False, form=form)

@app.route('/SignUp', methods=['POST', 'GET'])
def signup():
    form = SignUpForm() 
    if form.validate_on_submit(): # Post
        new_username = form.username.data
        new_password = form.password.data
        new_email = form.email.data

        new_username = new_username.strip()

        # check if username alr exists
        User_exists = session.query(exists().where(or_(User.user_email==new_email,User.username==new_username))).scalar()

        if User_exists: # Username or email taken
            return render_template('SignUp.html', username_taken=True, form=form)

        # Generate salt
        new_salt = ''.join(choice(alphabets) for _ in range(64))
        new_salt2 = ''.join(choice(alphabets) for _ in range(64))
        new_salt3 = ''.join(choice(alphabets) for _ in range(64))
        new_salt4 = ''.join(choice(alphabets) for _ in range(64))
        new_salt5 = ''.join(choice(alphabets) for _ in range(64))

        new_password = new_salt[:32] + new_password + new_salt[32:]
        new_password = sha512(new_password.encode('utf-8')).hexdigest()

        new_password += new_salt2
        new_password = sha512(new_password.encode('utf-8')).hexdigest()

        new_password += new_salt3
        new_password = sha512(new_password.encode('utf-8')).hexdigest()

        new_password += new_salt4
        new_password = sha512(new_password.encode('utf-8')).hexdigest()

        new_password += new_salt5
        new_password = sha512(new_password.encode('utf-8')).hexdigest()

        token = generate_confirmation_token(new_email)
        new_User = User(username=new_username, user_email=new_email, pass_hash=flask_bcrypt.generate_password_hash(new_password, 10), salt=new_salt, salt2=new_salt2, salt3=new_salt3, salt4=new_salt4, salt5=new_salt5)
        session.add(new_User)
        session.commit()

        subj = "Verification for your Coding Checklist account"
        temp = "Hi "
        temp += new_username
        temp += "!\n\nYou have been registered!\nClick on the attached link to verify your Coding Checklist Account\nNot you? Ignore this email and the account will not be created\nThis link will be removed after 5 minutes\n\nhttps://codingchecklist.com/verify/"
        temp += token
        temp += "\n\nRegards,\nCoding Checklist"

        send_email(new_email, subj, temp)

        return 'An email has been sent to the email, verify your account there. The verification link will be removed after 5 minutes'
        # except:
            # return 'There was an issue logging in :(\nContact us if there are any problems!'

    return render_template('SignUp.html', username_taken=False, form=form)

@app.route('/logout', methods=['POST', 'GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Checkout
@app.route('/checkout', methods=['POST', 'GET'])
@login_required
def checkout():
    return render_template('checkout.html')

# Profile to edit username or password
@app.route('/profile', methods=['POST', 'GET'])
@login_required
def profile():
    return render_template('profile.html')

@app.route('/orders', methods=['POST', 'GET'])
@login_required
def orders():
    return render_template('orders.html')

@app.route('/ForgetPass', methods=['POST', 'GET'])
def ForgetPass():
    form = ForgetPassForm()
    if form.validate_on_submit():
        email = form.email.data

        User_query = session.scalars(select(User).where(User.user_email==email)).first()
        if not User_query:
            return render_template('ForgetPass.html', incorrect=True)

        try:
            new_route = generate_confirmation_token(email)

            subj = "Password reset link for your Coding Checklist account"
            temp = "Hi "
            temp += User_query.username
            temp += "!\n\nThe attached link is the link for your Coding Checklist account password reset\nNot you? Ignore this email and the password will not be resetted\nThis link will be removed after 5 minutes\n\nhttps://codingchecklist.com/passreset/"
            temp += new_route
            temp += "\n\nRegards,\nCoding Checklist"

            send_email(email, subj, temp)

            return "An email has been sent to your email containing the password reset link"
        except:
            return "There was an error resetting your password :(\nTry connecting to a different network or contact us if there are any issues"

    return render_template('ForgetPass.html', incorrect=False, form=form)

@app.route('/passreset/<token>', methods=['POST', 'GET'])
def passreset(token):
    try:
        email = confirm_token(token)
    except:
        abort(404)

    user = session.scalars(select(User).where(User.user_email==email)).first()

    form = ResetPassForm()

    if form.validate_on_submit():
        new_password = form.password.data
        try:
            new_salt = ''.join(choice(alphabets) for _ in range(64))
            new_salt2 = ''.join(choice(alphabets) for _ in range(64))
            new_salt3 = ''.join(choice(alphabets) for _ in range(64))
            new_salt4 = ''.join(choice(alphabets) for _ in range(64))
            new_salt5 = ''.join(choice(alphabets) for _ in range(64))

            new_password = new_salt[:32] + new_password + new_salt[32:]
            new_password = sha512(new_password.encode('utf-8')).hexdigest()

            new_password += new_salt2
            new_password = sha512(new_password.encode('utf-8')).hexdigest()

            new_password += new_salt3
            new_password = sha512(new_password.encode('utf-8')).hexdigest()

            new_password += new_salt4
            new_password = sha512(new_password.encode('utf-8')).hexdigest()

            new_password += new_salt5
            new_password = sha512(new_password.encode('utf-8')).hexdigest()

            user.salt = new_salt
            user.salt2 = new_salt2
            user.salt3 = new_salt3
            user.salt4 = new_salt4
            user.salt5 = new_salt5

            user.pass_hash = flask_bcrypt.generate_password_hash(new_password, 10)
            session.commit()

            return 'Password reset successful!'
        except:
            return 'There was an error logging in :(\nContact us if there are any problems'

    return render_template("ChangePass.html", form=form)

@app.route('/verify/<token>')
def confirm(token):
    try:
        email = confirm_token(token)
        if email == False:
            abort(404)
    except:
        abort(404)
    
    user = session.scalars(select(User).where(User.user_email==email)).first()
    if user.confirmed:
        return 'Account already confirmed. Please Login.'
    else:
        user.confirmed = True
        session.commit()
        return 'Account successfully created!'

# Home page
@app.route('/', methods=['POST', 'GET'])
@login_required
def HomePage():
    return render_template('HomePage.html', stalls=session.query(Stall).all())

# Stall page
@app.route('/<stall_name>', methods=['POST', 'GET'])
@login_required
def StallPage(stall_name):
    stall_name2 = stall_name.replace('_', ' ')
    stall = session.scalars(select(Stall).where(Stall.stall_name==stall_name2)).first()
    if not stall:
        abort(404)

    return render_template('stall.html', food_items=stall.food_items)
    
if __name__ == "__main__":
    # http_server = WSGIServer(("0.0.0.0",85),app)
    # http_server.serve_forever()
    app.run(debug=True)