import os
import subprocess

if os.path.exists('database.db'):
    os.remove('database.db')

subprocess.call('python connect.py')
subprocess.call('python create_tables.py')

from sqlalchemy.orm import Session
from connect import engine
from models import User, Stall, Food, Order

session = Session(engine)

f = open("stall_and_food_data.txt", "r")

no_of_stalls = int(f.readline().strip())

for _ in range(no_of_stalls):
    stall_name = f.readline().strip()
    stall_dir  = f.readline().strip()
    no_of_food = int(f.readline().strip())
    new_stall = Stall(stall_name=stall_name, image_directory=stall_dir)
    for i in range(no_of_food):
        food_name = f.readline().strip()
        image_dir = f.readline().strip()
        cost = float(f.readline().strip())
        new_food = Food(food_name=food_name, image_directory=image_dir, cost=cost)
        session.add(new_food)
        new_stall.food_items.append(new_food)
    session.add(new_stall)

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