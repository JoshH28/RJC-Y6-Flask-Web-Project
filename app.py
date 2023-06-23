from flask import Flask, redirect, url_for,render_template, abort, request
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
from forms import LoginForm, SignUpForm, ForgetPassForm, ResetPassForm, CheckoutForm, ChangePassForm
from sqlalchemy.orm import Session
from sqlalchemy import select, or_
from sqlalchemy.sql import exists
from connect import engine
from itsdangerous import URLSafeTimedSerializer
# from gevent.pywsgi import WSGIServer

if os.name != "nt":
    os.chdir(os.path.dirname(__file__))

load_dotenv()

EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['WTF_CSRF_SECRET_KEY'] = os.getenv("SECRET_CSRF_KEY")
app.config['SECURITY_PASSWORD_SALT'] = os.getenv("SECURITY_PASSWORD_SALT")
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
        if not User_query:
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

        subj = "Verification for your Anderson Orders account"
        temp = "Hi "
        temp += new_username
        temp += "!\n\nYou have been registered!\nClick on the attached link to verify your Anderson Orders Account\nNot you? Ignore this email and the account will not be created\nThis link will be removed after 5 minutes\n\nhttps://{}/verify/".format(request.headers.get("X-Forwarded-Host"))
        temp += token
        temp += "\n\nRegards,\nAnderson Orders"

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
    form = CheckoutForm()
    if form.validate_on_submit():
        new_order = Order(food_orders=current_user.food_orders)
        # session.add(new_order)
        current_user.orders.append(new_order)
        current_user.food_orders = ""
        session.commit()
        return redirect('/')
    subtotal = 0
    food_ordered = []
    for item in current_user.food_orders.splitlines():
        temp = item.split('|')
        subtotal += int(temp[0]) * float(temp[2])
        food_ordered.append((temp[0], temp[1], temp[2], temp[3]))
    return render_template('checkout.html', food_ordered=food_ordered, subtotal=subtotal, form=form)

# Profile to edit username or password
@app.route('/profile', methods=['POST', 'GET'])
@login_required
def profile():
    form = ChangePassForm()
    if form.validate_on_submit():
        current_pass = form.current_password.data
        new_password = form.password.data

        salt = current_user.salt
        salt2 = current_user.salt2
        salt3 = current_user.salt3
        salt4 = current_user.salt4
        salt5 = current_user.salt5

        current_pass = salt[:32] + current_pass + salt[32:]
        current_pass = sha512(current_pass.encode('utf-8')).hexdigest()

        current_pass += salt2
        current_pass = sha512(current_pass.encode('utf-8')).hexdigest()

        current_pass += salt3
        current_pass = sha512(current_pass.encode('utf-8')).hexdigest()

        current_pass += salt4
        current_pass = sha512(current_pass.encode('utf-8')).hexdigest()

        current_pass += salt5
        current_pass = sha512(current_pass.encode('utf-8')).hexdigest()

        result = flask_bcrypt.check_password_hash(current_user.pass_hash, current_pass)

        if not result:
            return render_template('profile.html', user=current_user, form=form, incorrect_pass=True)

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

        current_user.salt = new_salt
        current_user.salt2 = new_salt2
        current_user.salt3 = new_salt3
        current_user.salt4 = new_salt4
        current_user.salt5 = new_salt5

        current_user.pass_hash = flask_bcrypt.generate_password_hash(new_password, 10)
        session.commit()

    return render_template('profile.html', user=current_user, form=form, incorrect_pass=False)

@app.route('/orders', methods=['POST', 'GET'])
@login_required
def orders():
    orders = []
    for order in current_user.orders:
        temp = order.food_orders
        curr = []
        for item in temp.splitlines():
            qty, food, cost, stall = item.split('|')
            curr.append((int(qty), food, float(cost), stall))
        orders.append(curr)
    return render_template('orders.html', orders=orders)

@app.route('/ForgetPass', methods=['POST', 'GET'])
def ForgetPass():
    form = ForgetPassForm()
    if form.validate_on_submit():
        email = form.email.data

        User_query = session.scalars(select(User).where(User.user_email==email)).first()
        if not User_query:
            return render_template('ForgetPass.html', incorrect=True, form=form)

        try:
            new_route = generate_confirmation_token(email)

            subj = "Password reset link for your Anderson Orders account"
            temp = "Hi "
            temp += User_query.username
            temp += "!\n\nThe attached link is the link for your Anderson Orders account password reset\nNot you? Ignore this email and the password will not be resetted\nThis link will be removed after 5 minutes\n\nhttps://{}/passreset/".format(request.headers.get("X-Forwarded-Host"))
            temp += new_route
            temp += "\n\nRegards,\nAnderson Orders"

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
@app.route('/<stall_name>')
@login_required
def StallPage(stall_name):
    stall_name2 = stall_name.replace('_', ' ')
    stall = session.scalars(select(Stall).where(Stall.stall_name==stall_name2)).first()
    if not stall:
        abort(404)
    
    return render_template('stall.html', food_items=stall.food_items)

@app.route('/add-to-cart/<food_id>')
@login_required
def add_to_cart(food_id):
    food = session.scalars(select(Food).where(Food.id==food_id)).first()
    if not food:
        abort(404)
    food_orders = current_user.food_orders
    new_order = ""
    exists = False
    for item in food_orders.splitlines():
        temp = item.split('|')
        if food.food_name == temp[1]:
            new_order += str(int(temp[0])+1) + '|' + temp[1] + '|' + temp[2] + '|' + temp[3] + '\n'
            exists = True
        else:
            new_order += item + '\n'
    
    if exists:
        current_user.food_orders = new_order
    else:
        current_user.food_orders = food_orders + (f"1|{food.food_name}|{food.cost}|{food.stall.stall_name}\n")
    session.commit()
    return redirect('../' + food.stall.stall_name.replace(' ', '_'))

@app.route('/increase-quantity/<index>')
@login_required
def increase_quantity(index):
    food_orders = current_user.food_orders
    new_order = ""
    for i, item in enumerate(food_orders.splitlines()):
        temp = item.split('|')
        if i == int(index):
            new_order += str(int(temp[0])+1) + '|' + temp[1] + '|' + temp[2] + '|' + temp[3] + '\n'
        else:
            new_order += item + '\n'
    current_user.food_orders = new_order
    session.commit()
    return redirect('../checkout')
    
@app.route('/decrease-quantity/<index>')
@login_required
def decrease_quantity(index):
    food_orders = current_user.food_orders
    new_order = ""
    for i, item in enumerate(food_orders.splitlines()):
        temp = item.split('|')
        if i == int(index):
            if int(temp[0]) == 1:
                continue
            new_order += str(int(temp[0])-1) + '|' + temp[1] + '|' + temp[2] + '|' + temp[3] + '\n'
        else:
            new_order += item + '\n'
    current_user.food_orders = new_order
    session.commit()
    return redirect('../checkout')
    
if __name__ == "__main__":
    # http_server = WSGIServer(("0.0.0.0",2011),app)
    # http_server.serve_forever()
    app.run(debug=True)