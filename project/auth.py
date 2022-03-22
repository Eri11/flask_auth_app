from calendar import c
from unittest import result
from flask import Blueprint, render_template, redirect, url_for, request, flash
#from werkzeug.security import generate_password_hash, check_password_hash
#this is for SIMMETRICAL

import base64 
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Random import get_random_bytes

from flask_login import login_user, login_required, logout_user
from password_strength import PasswordPolicy
from password_strength import PasswordStats
from .models import User
from . import db

auth = Blueprint('auth', __name__)

policy = PasswordPolicy.from_names(
    length=8,  # min length: 8
    uppercase=1,  # need min. 2 uppercase letters
    numbers=1,  # need min. 2 digits
    special=1,  # need min. 2 special characters
    # nonletters=2,  # need min. 2 non-letter characters (digits, specials, anything)
    strength=0.66, #need a password that scires at least 0.66 with its entropy bits
)



@auth.route('/login')
def login():
    return render_template('login.html')

@auth.route('/login', methods=['POST'])
def login_post():
    # login code goes here
       
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()
    # check if the user actually exists

    #Fixed IV
    iv =  'mysupersecretaiv'.encode('utf-8') #16 char for AES128   

    key = 'mysecretpassword'.encode('utf-8') #16 char for AES128

    
    def decryptPass(password,key, iv):
        
        cipherpass = base64.b64decode(password).decode('utf-8')
        cipher = AES.new(key, AES.MODE_CFB, iv)
        
        result = cipher.decrypt(cipherpass)

        return result

    decryptedpass = decryptPass(password,key,iv)
    print(f"Encrypted PWD: {decryptedpass}")
            
        
    # take the user-supplied password, hash it, and compare it to the hashed password in the database
    if not user or decryptedpass != password :
        flash('Usuario y Contraseña no coinciden, intenta de nuevo.')
        return redirect(url_for('auth.login')) # if the user doesn't exist or password is wrong, reload the page

    # if the above check passes, then we know the user has the right credentials
    login_user(user, remember=remember)
    return redirect(url_for('main.profile'))

@auth.route('/signup')
def signup():
    return render_template('signup.html')

@auth.route('/signup', methods=['POST'])
def signup_post():
    # code to validate and add user to database goes here
    name = request.form.get('name')
    lastname = request.form.get('lastname')
    address = request.form.get('address')
    tel = request.form.get('tel')
    
    email = request.form.get('email')
    password = request.form.get('password')
    
    stats = PasswordStats(password)
    checkpolicy = policy.test(password)

    user = User.query.filter_by(email=email).first() # if this returns a user, then the email already exists in database

    if user: # if a user is found, we want to redirect back to signup page so user can try again
        flash('El correo electrónico ya existe')
        return redirect(url_for('auth.signup'))

    
    if stats.strength() < 0.66:
        print(stats.strength())
        flash("La contraseña no es lo suficientemente compleja. Evite usar caraceres consecutivos y palabras fáciles de adivinar.")
        return redirect(url_for('auth.signup'))
    else:
        print(stats.strength()) #remover en produccion

        #Fixed IV
        iv =  'mysupersecretaiv'.encode('utf-8') #16 char for AES128   

        key = 'mysecretpassword'.encode('utf-8') #16 char for AES128

        
        def encryptPass(password,key, iv):
            password = password.encode('utf-8')
            cipher = AES.new(key, AES.MODE_CFB, iv)
            cipherpass = cipher.encrypt(password)

            result = base64.b64encode(cipherpass).decode('utf-8')
            return result

        encryptedpass = encryptPass(password,key,iv)
        print(f"Encrypted PWD: {encryptedpass}")
               
        # create a new user with the form data. Hash the password so the plaintext version isn't saved.
        new_user = User(name=name, lastname=lastname, address=address, tel=tel, email=email, password=encryptedpass)

        # add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('auth.login'))

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))