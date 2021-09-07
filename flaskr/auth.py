#this file is a blueprint file that contains the functions that will register
#new users, login and logout of the users will be implemented here

import functools
from flask import (
    Blueprint, session, request, url_for, redirect, flash, g, render_template
)
from werkzeug.security import generate_password_hash, check_password_hash
from flaskr.db import get_db
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from flaskr.blockchain import blockchain
import binascii

def bin2hex(binStr):
    return binascii.hexlify(binStr)

def hex2bin(hexStr):
    return binascii.unhexlify(hexStr)

bp = Blueprint('auth', __name__, url_prefix='/auth')



@bp.route('/register', methods=('GET','POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if request.form.get('checkCandidate'):
            candidate = 1
        else: 
            candidate = 0
        db = get_db()
        error = None
        #---------------------------------------------------------------------
        #Generating and writing the keys for encryption and digital signature
        #generate pub and priv key
        private_key = rsa.generate_private_key(65537, 2048, default_backend())
        public_key = private_key.public_key()

        pem = private_key.private_bytes(
            serialization.Encoding.PEM, 
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
        with open("keys/"+username+"private.pem", "wb") as prv_file:
            prv_file.write(pem)
        
        publicpem = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open("keys/"+username+"public.pem", "wb") as prv_file:
            prv_file.write(publicpem)
        #---------------------------------------------------------------------
        if not username:
            error = 'User Name required'
        elif not password:
            error = 'Password is required'
        elif db.execute(
            'SELECT id from user where username = ?', (username,)
        ).fetchone() is not None:
            error = 'User {} is already registered'.format(username)

        if error is None:
            db.execute(
                'INSERT INTO user (username,password,is_candidate,publickey,votecoins,votecollection) VALUES (?,?,?,?,?,?)',
                (username, generate_password_hash(password), candidate,publicpem,1,0)
            )
            db.commit()
            transaction = {'sender': 'Election Organisation',
                           'receiver': username,
                           'amount': 1
            }
            thash = blockchain.hash(transaction)
            blockchain.addTransaction("Election Organisation", username, 1,thash,0,candidate)
            return redirect(url_for('auth.login'))

        flash(error)
    return render_template('auth/register.html')


#This function handles the login of the users
@bp.route('/login', methods = ('GET','POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        user = db.execute(
            'SELECT * from user WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Incorrect username'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password'
        else:
            error = None

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        flash(error)

    return render_template('auth/login.html')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * from user WHERE id = ?', (user_id,)
        ).fetchone()

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)

    return wrapped_view
