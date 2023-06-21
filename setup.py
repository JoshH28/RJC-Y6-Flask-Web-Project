import os
import subprocess

if os.path.exists('database.db'):
    os.remove('database.db')

subprocess.call('python connect.py')
subprocess.call('python create_tables.py')

from sqlalchemy.orm import Session
from connect import engine
from models import User

session = Session(engine)

new_username = 'haydendoo'
new_password = 'qqqqqqqq'
new_email = 'haydenhow@gmail.com'

import string
from secrets import choice
alphabets = string.ascii_letters + string.digits + string.punctuation

new_salt = ''.join(choice(alphabets) for _ in range(64))
new_salt2 = ''.join(choice(alphabets) for _ in range(64))
new_salt3 = ''.join(choice(alphabets) for _ in range(64))
new_salt4 = ''.join(choice(alphabets) for _ in range(64))
new_salt5 = ''.join(choice(alphabets) for _ in range(64))

from hashlib import sha512

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

import flask_bcrypt

new_User = User(username=new_username, user_email=new_email, pass_hash=flask_bcrypt.generate_password_hash(new_password, 10), salt=new_salt, salt2=new_salt2, salt3=new_salt3, salt4=new_salt4, salt5=new_salt5, confirmed=True)
session.add(new_User)
session.commit()

subprocess.call('python app.py')