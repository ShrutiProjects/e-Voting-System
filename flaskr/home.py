from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for
)
from werkzeug.exceptions import abort
from werkzeug.security import generate_password_hash, check_password_hash
from flaskr.auth import login_required
from flaskr.db import get_db
from flaskr.blockchain import blockchain
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding,utils
from cryptography.hazmat.primitives import serialization, hashes
bp = Blueprint('home', __name__)

@bp.route('/')
def index():
    db = get_db()
    posts = db.execute(
        'SELECT username, publickey, votecollection'
        ' FROM user WHERE is_candidate = 1'
    ).fetchall()
    return render_template('home/index.html', posts=posts)

@bp.route('/vote', methods=('GET', 'POST'))
@login_required
def vote():
    db = get_db()
    candidates = db.execute(
        'SELECT username FROM user WHERE is_candidate = 1'
    )
    votes = db.execute(
        'SELECT username, votecollection FROM user WHERE is_candidate = 1'
    )
    current_users_votecoins = db.execute(
        'SELECT username,votecoins,password FROM user WHERE username = ?', (g.user['username'],)
    ).fetchone()
    if current_users_votecoins['votecoins'] > 0:
        if request.method == 'POST':
            privatekey = request.form['private_key']
            selected_candidate =  request.form['select_candidate']
            
            error = None

            if not privatekey:
                error = 'Password is required.'

            elif not check_password_hash(current_users_votecoins['password'], privatekey):
                error = 'Incorrect password'

            if error is not None:
                flash(error)
            #this section will be needing updation for using the blockchain
            else:
                current_votes = 0
                for vote in votes:
                    if vote['username'] == selected_candidate:
                        current_votes = vote['votecollection']
                        break
                current_votes = current_votes + 1
                db.execute(
                    'UPDATE user SET votecollection = ? WHERE username = ?', (current_votes,selected_candidate,)
                )
                db.commit()
                transaction = {'sender': g.user['username'],
                            'receiver': selected_candidate,
                            'amount': 1
                }
                thash = blockchain.hash(transaction)
                print("Hash of the transaction is: "+thash)
                f = open("keys/"+g.user['username']+"private.pem", "rb")
                private_key =  serialization.load_pem_private_key(
                    f.read(), None, default_backend()
                )
                thash_bytes = str.encode(thash)
                print("thash bytes are : ") 
                print(thash_bytes)
                #encrypt_thash = "IAMTHEGREATEST"
                public_key =  private_key.public_key()
                encrypt_thash = private_key.sign(
                    thash_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                print("Encrypted transaction hash is : ")
                print(encrypt_thash)
                original = public_key.verify(
                    encrypt_thash,
                    thash_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                print("Original transaction hash  is : ") 
                print(original)
                db.execute(
                    'UPDATE user SET votecoins = ? WHERE username = ?', (current_users_votecoins['votecoins'] - 1,g.user['username'],)
                )
                db.commit()
                blockchain.addTransaction(g.user['username'], selected_candidate, 1, encrypt_thash,current_votes,0)
                return redirect(url_for('home.index'))
    else:
        return redirect(url_for('home.index'))

    return render_template('home/vote.html',candidates = candidates)


#connecting a new node in the network
@bp.route('/connect_node', methods = ['POST'])
def connect_node():
    if request.method == 'POST':
        nodedetails = request.form['nodeaddress']    
        blockchain.addNode(nodedetails)
        response = {'message':f'All the nodes are connected. Now the Votecoin Blockchain now contains the ',
                    'totalNodes': list(blockchain.nodes)}
        return redirect(url_for('home.index'))
