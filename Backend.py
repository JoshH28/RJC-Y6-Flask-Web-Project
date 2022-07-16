from flask import Flask, redirect, url_for, request, render_template, flash, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exists
from secrets import choice
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, logout_user, login_required, current_user
import string
import datetime
import smtplib
import os
from email.message import EmailMessage
from dotenv import load_dotenv

load_dotenv()

EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
db = SQLAlchemy(app)

alphabets = string.ascii_letters + string.digits + string.punctuation

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return Account.query.get(int(user_id))

class Account(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200), unique=True, nullable=False)
    user_email = db.Column(db.String(200), unique=True, nullable=False)
    pass_hash = db.Column(db.String(300), nullable=False)
    salt = db.Column(db.String(50), nullable=False)
    is_stallowner = db.Column(db.Boolean, nullable=False)
    stall_id = db.Column(db.Integer, unique=True)
    # Skip these for now
    # is_admin = db.Column(db.Boolean)

    def __repr__(self):
        return '<User %r>' % self.username

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False) # Username of guy who ordered
    stall_id = db.Column(db.Integer, unique=True)
    food_id = db.Column(db.Integer, unique=True)
    order_id = db.Column(db.Integer, unique=True)

    def __repr__(self):
        return '<Order %r>' % self.order_id

class Confirmation_Route(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200), unique=True, nullable=False)
    route = db.Column(db.String(100), unique=True, nullable=False)
    time_created = db.Column(db.DateTime, default=datetime.datetime.utcnow()) 
    email = db.Column(db.String(200), unique=True, nullable=False)
    pass_hash = db.Column(db.String(300), nullable=False)
    salt = db.Column(db.String(50), nullable=False)
    is_stallowner = db.Column(db.Boolean, nullable=False)

    def __repr__(self):
	    return '<Route %r>' % self.route

class Stall(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    stall_id = db.Column(db.Integer, unique=True)

    def __repr__(self):
	    return '<Route %r>' % self.route

class Food(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    food_id = db.Column(db.Integer, unique=True)
    stall_id = db.Column(db.Integer, unique=True)

    def __repr__(self):
	    return '<Route %r>' % self.route

# Login page
@app.route('/', methods=['POST', 'GET'])
def login():
    if request.method == "POST": # Post
        new_username = request.form.get('username')
        new_password = request.form.get('password')

        # disgusting code to check if account alr exists
        account_query = Account.query.filter_by(username=new_username).first()

        if not account_query: # Username doesnt exist
            return render_template('login.html', incorrect=True)

        salt = account_query.salt
        new_password += salt

        result = check_password_hash(account_query.pass_hash, new_password)

        if result:
            login_user(account_query)
            return redirect(url_for('HomePage'))
        else:
            return render_template('login.html', incorrect=True)

    else: # Get
        return render_template('login.html', incorrect=False)

@app.route('/SignUp', methods=['POST', 'GET'])
def signup():
    if request.method == "POST": # Post
        new_username = request.form.get('username')
        new_password = request.form.get('password')
        re_password = request.form.get('repassword')
        new_email = request.form.get('email')

        # disgusting code to check if username alr exists
        account_exists = db.session.query(exists().where(Account.username==new_username)).scalar()

        if account_exists: # Username taken
            return render_template('SignUp.html', username_taken=True, password_correct=(new_password==re_password), pass_len=(len(new_password)>7), whitespace = (' ' in new_password))

        if new_password!=re_password: # Password entered wrongly
            return render_template('SignUp.html', username_taken=False, password_correct=False, pass_len=(len(new_password)>7), whitespace = (' ' in new_password))

        if len(new_password) < 8:
            return render_template('SignUp.html', username_taken=False, password_correct=True, pass_len=False, whitespace = (' ' in new_password))
        
        if ' ' in new_password:
            return render_template('SignUp.html', username_taken=False, password_correct=True, pass_len=True, whitespace=False)

        # Successful sign up
        
        # Send email
        
        new_route = ''.join(choice(string.ascii_letters) for _ in range(30))
        while db.session.query(exists().where(Confirmation_Route.route==new_route)).scalar():
            new_route = ''.join(choice(string.ascii_letters) for _ in range(30))
            
        new_salt = ''.join(choice(alphabets) for _ in range(50))
        new_password += new_salt
        new_confirmation_route = Confirmation_Route(is_stallowner=True, route=new_route, email=new_email, username=new_username, salt=new_salt, pass_hash=generate_password_hash(new_password, method = 'sha512'))

        # Everyone auto stall owner for now

        try:
            db.session.add(new_confirmation_route)
            db.session.commit()
            flash("Success!")

            message = EmailMessage()
            message['Subject'] = "Verification for your Ande Canteen account"
            message['From'] = EMAIL_ADDRESS
            message['To'] = new_email
            temp = ("You have been registered!\nNot you? Ignore this email and the account will not be created\nEnter\nAndeCanteen.com/verify/")
            temp += new_route
            temp += "\nThis link will be removed after 5 minutes"
            message.set_content(temp)
            
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
                smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)

                smtp.send_message(message)

            return 'An email has been sent to the email, verify your account there. The verification link will be removed after 5 minutes'
        except:
            return 'There was an issue logging in :(\nContact us if there are any problems!'

    else: # Get
        return render_template('SignUp.html', username_taken=False, password_correct=True, pass_len=True)

@app.route('/logout', methods=['POST', 'GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Home page
@app.route('/HomePage', methods=['POST', 'GET'])
@login_required
def HomePage():
    return render_template('HomePage.html')

# Drink stall
@app.route('/DrinkStall')
@login_required
def DrinkStall():
    return render_template('DrinkStall.html')

# Checkout
@app.route('/checkout')
@login_required
def cart():
    return render_template('checkout.html')

# Stall owner
@app.route('/StallOwner')
@login_required
def StallOwner():
    account = load_user(current_user.get_id())
    if account.is_stallowner:
        return render_template('StallOwner.html')
    abort(404)
    
@app.route('/verify/<token>')
def confirm(token):
    res = Confirmation_Route.query.filter_by(route=token)
    result = res.first()
    if not(result) or db.session.query(exists().where(Account.username==result.username)).scalar():
        abort(404)

    diff = datetime.datetime.utcnow()-result.time_created
    diff_minutes = (diff.days * 24 * 60) + (diff.seconds/60.0)
    if diff_minutes>=5:
        res.delete()
        db.session.commit()
        return 'There was an error logging in :(\nContact us if there are any problems'
    else:
        try:
            new_account = Account(is_stallowner=result.is_stallowner, username=result.username, user_email=result.email, pass_hash=result.pass_hash, salt=result.salt)
            db.session.add(new_account)
            res.delete()
            db.session.commit()
            flash('Success!')
            login_user(new_account)
            return redirect(url_for('HomePage'))
        except:
            res.delete()
            db.session.commit()
            return 'There was an error logging in :(\nContact us if there are any problems'

if __name__ == "__main__":
    app.run(debug=True)
