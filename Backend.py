from flask import Flask, redirect, url_for, request, render_template
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
db = SQLAlchemy(app)

class Account(db.Model):
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(300), nullable=False)
    stall_id = db.Column(db.Integer, unique=True, primary_key=True)
    is_admin = db.Column(db.Boolean)
    is_stall = db.Column(db.Boolean)
    orders = db.relationship('Order', backref='person', lazy=True)

    def __repr__(self):
        return '<User %r>' % self.username

class Order(db.Model):
    username = db.Column(db.String(100), unique=True, nullable=False)
    stall_id = db.Column(db.Integer, unique=True, primary_key=True)
    food_id = db.Column(db.Integer, unique=True, primary_key=True)
    order_id = db.Column(db.Integer, unique=True, primary_key=True)

    def __repr__(self):
        return '<Order %r>' % self.order_id

@app.route('/')
def index():
    return render_template('base.html')

if __name__ == "__main__":
    app.run(Debug=True)
