from flask import Flask, redirect, url_for, request, render_template, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exists
from secrets import choice
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, logout_user, login_required
import string

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SECRET_KEY'] = 'AMOS'
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
    pass_hash = db.Column(db.String(300), nullable=False)
    salt = db.Column(db.String(50), nullable=False)
    # Skip these for now
    # stall_id = db.Column(db.Integer, unique=True, primary_key=True)
    # is_admin = db.Column(db.Boolean)
    # is_stall = db.Column(db.Boolean)
    # orders = db.relationship('Order', backref='person', lazy=True)

    def __repr__(self):
        return '<User %r>' % self.username

# Skip this for now
# class Order(db.Model):
#     username = db.Column(db.String(100), unique=True, nullable=False)
#     stall_id = db.Column(db.Integer, unique=True, primary_key=True)
#     food_id = db.Column(db.Integer, unique=True, primary_key=True)
#     order_id = db.Column(db.Integer, unique=True, primary_key=True)

#     def __repr__(self):
#         return '<Order %r>' % self.order_id

# Login page
@app.route('/', methods=['POST', 'GET'])
def login():
    if request.method == "POST": # Post
        new_username = request.form['username']
        new_password = request.form['password']

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

@app.route('/SignUp.html', methods=['POST', 'GET'])
def signup():
    if request.method == "POST": # Post
        new_username = request.form['username']
        new_password = request.form['password']
        re_password = request.form['repassword']
        new_email = request.form['email']

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
        new_salt = ''.join(choice(alphabets) for i in range(50))
        new_password += new_salt
        new_account = Account(username=new_username, pass_hash=generate_password_hash(new_password, method = 'sha512'), salt=new_salt)

        try:
            db.session.add(new_account)
            db.session.commit()
            flash("Account made successfully!")
            login_user(new_account)
            return redirect(url_for('HomePage'))
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
@app.route('/HomePage.html', methods=['POST', 'GET'])
@login_required
def HomePage():
    return render_template('HomePage.html')

# Drink stall
@app.route('/DrinkStall.html')
@login_required
def DrinkStall():
    return render_template('DrinkStall.html')

# Cart
@app.route('/cart.html')
@login_required
def cart():
    return render_template('cart.html')

if __name__ == "__main__":
    app.run(debug=True)
