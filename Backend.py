from flask import Flask, redirect, url_for, request
from flask_wtf import FlaskForm
from wtforms import Form, BooleanField, StringField, SubmitField, validators
from wtforms.validators import DataRequired
import os

class RegistrationForm(Form):
  userMail = StringField('Student Email', [validators.Length(min=20, max=75)])
  confirmDecision = BooleanField('I confirm that I want to order this.', [validators.InputRequired()])

my_secret = os.environ['mysecretkey']

app = Flask('app')

app.config['SECRET_KEY'] = my_secret

from jinja2 import Environment, PackageLoader, select_autoescape
env = Environment(
    loader=PackageLoader("main"),
    autoescape=select_autoescape()
)
#no spaces in url (%20)
@app.route('/')
def main():
  template = env.get_template('base.html')
  return template.render()

@app.route('/register/', methods=['GET', 'POST'])
def register():
  form = RegistrationForm(request.form);
  if (request.method == 'POST') and form.validate():
    print(str(form.userMail) + "has tried to register!")
    redirect(url_for('hello/' + form.userMail))
  template = env.get_template('register.html')
  return template.render()

@app.route('/penged')
def penged():
  template = env.get_template('pengcheng.html')
  return template.render()

@app.route('/hello/<user>/')
def hellouser(user):
  template = env.get_template('hellouser.html')
  return template.render(username=user)

@app.route('/d_dx')
def d_dx():
    template = env.get_template('d_dx.html')
    return template.render()

app.run(host='0.0.0.0', port=8080)
