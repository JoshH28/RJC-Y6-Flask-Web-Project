from flask import Flask, redirect, url_for, request, render_template
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exists

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
db = SQLAlchemy(app)

class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200), unique=True, nullable=False)
    password = db.Column(db.String(300), nullable=False)
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
        account_exists = db.session.query(exists().where(Account.username==new_username and Account.password==new_password)).scalar()

        if account_exists:
            return redirect('/HomePage.html')

        # Incorrect username and password combination
        return render_template('login.html', incorrect=True)

        # new_account = Account(username=new_username, password=new_password)

        # try:
        #     db.session.add(new_account)
        #     db.session.commit()
        #     return redirect('/HomePage.html')
        # except:
        #     return 'There was an issue logging in :(\nContact us if there are any problems!'

    else: # Get
        return render_template('login.html', incorrect=False)


# Home page
@app.route('/HomePage.html')
def HomePage():
    return render_template('HomePage.html')

# Drink stall
@app.route('/DrinkStall.html')
def DrinkStall():
    return render_template('DrinkStall.html')

# Cart
@app.route('/cart.html')
def cart():
    return render_template('cart.html')

if __name__ == "__main__":
    app.run(debug=True)
