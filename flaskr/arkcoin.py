# first blockchain file now creating a cryptocurrency 

import datetime
import hashlib
import json
from flask import Flask, jsonify, request, render_template, url_for, flash, redirect
import requests
from uuid import uuid4
from urllib.parse import urlparse
from flask_sqlalchemy import SQLAlchemy
from Crypto.PublicKey import RSA
import Crypto
from Crypto import Random
import ast
from flask_login import login_user, current_user, logout_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired,Length, Email, EqualTo, ValidationError


#Generating and writing the keys for encryption and digital signature
random_generator = Random.new().read
key = RSA.generate(1024, random_generator) #generate pub and priv key
publickey = key.publickey()
f = open('my_rsa_public.pem', 'wb')
f.write(key.publickey().exportKey('PEM'))
f.close()
f = open('my_rsa_private.pem', 'wb')
f.write(key.exportKey('PEM'))
f.close()

#creating flask web app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uid = db.Column(db.String(100), unique=True, nullable=False)
    public_key = db.Column(db.String(1000), unique=True, nullable=False)
    
    def __repr__(self):
        return f"User('{self.public_key}')"
    
class RegistrationForm(FlaskForm):
    uid = StringField(u'UID', validators=[DataRequired(), Length(min=2, max=20)])
    submit = SubmitField(u'Sign up')
    
    def validate_uid(self, uid):
        user = User.query.filter_by(uid=uid.data).first()
        if user:
            raise ValidationError('User is already registered!')
    
    
class LoginForm(FlaskForm):
    email = StringField('email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember me')
    submit = SubmitField('Login')

    
#blockchain building code
class Blockchain:
    
    def __init__(self):
        self.chain = []
        self.transactions = []
        self.total_votes = 100
        self.transactions.append({'sender': 'Parent Block',
                                  'receiver': 'Election Organiser',
                                  'amount': self.total_votes})
        self.createBlock(proof = 1, prevHash = '0')
        self.nodes = set()
        
    def createBlock(self, proof, prevHash):
        block = {'index': len(self.chain) + 1, 
                 'timestamp': str(datetime.datetime.now()),
                 'proof': proof,
                 'prevHash': prevHash,
                 #'data': "dumb"
                 'transactions': self.transactions
                 }
        self.transactions = []
        self.chain.append(block)
        return block
    
    def getPrevBlock(self):
        return self.chain[-1]
    
    def proofOfWork(self, prevProof):
        newProof = 1
        checkProof = False
        while checkProof is False:
            hashOperation = hashlib.sha256(str(newProof**2 - prevProof**2).encode()).hexdigest()
            if hashOperation[:4] == '0000':
                checkProof = True
            else:
                newProof += 1
        return newProof
    
    def hash(self, block):
        encodedBlock = json.dumps(block, sort_keys = True).encode()
        return hashlib.sha256(encodedBlock).hexdigest()
    
    def isChainValid(self, chain):
        prevBlock = chain[0]
        blockIndex = 1
        while blockIndex < len(chain):
            block = chain[blockIndex]
            if block['prevHash'] != self.hash(prevBlock):
                return False
            prevProof = prevBlock['proof']
            proof = block['proof']
            hashOperation = hashlib.sha256(str(proof**2 - prevProof**2).encode()).hexdigest()
            if hashOperation[:4] != '0000':
                return False
            prevBlock = block
            blockIndex += 1
        return True
    
    #some changes may be required to be made to this functions
    #this function is used to create users into the database and candidates in the db
    def createUser(self, user_name, uid, candidate):
        if self.total_votes < 1:
            return "Cannot do that, all users have been registered"
        public_key = hashlib.sha256((user_name + uid).encode())
        self.addTransaction('Election Commision', public_key, 1)
        self.total_votes -= 1
        return "Success"
        
    def addTransaction(self, sender, receiver, amount):
        self.transactions.append({'sender': sender,
                                  'receiver': receiver,
                                  'amount': amount})
        prevBlock = self.getPrevBlock()
        return prevBlock['index'] + 1
    
    def addNode(self, address):
        parsedUrl = urlparse(address)
        self.nodes.add(parsedUrl.netloc)
    
    def replaceChain(self):
        network = self.nodes
        longestChain = None
        maxLength = len(self.chain)
        for node in network:
            response = requests.get(f'http://{node}/getChain')
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                if length > maxLength and self.isChainValid(chain):
                    maxLength = length
                    longestChain = chain
        if longestChain:
            self.chain = longestChain
            return True
        return False
    


#creating an address for the node on the port 5000

nodeAddress = str(uuid4()).replace('-', '')

#creating a blockchain object
blockchain = Blockchain()

#mining a new block
@app.route('/mineBlock', methods = ['GET'])

def mineBlock():
    prevBlock = blockchain.getPrevBlock()
    prevProof = prevBlock['proof']
    proof = blockchain.proofOfWork(prevProof)
    prevHash = blockchain.hash(prevBlock)
    blockchain.addTransaction(sender = nodeAddress, receiver = 'Akshay', amount = 10)
    block = blockchain.createBlock(proof, prevHash)
    response = {'message':'You have successfully mined the block!',
                'index': block['index'],
                'timestamp': block['timestamp'],
                'proof': block['proof'],
                'prevHash': block['prevHash'],
                'transactions': block['transactions']}
    return jsonify(response), 200

#getting a full blockchain
@app.route('/getChain', methods = ['GET'])
def getChain():
    response = {'chain': blockchain.chain,
                'length': len(blockchain.chain)}
    return jsonify(response), 200

#verifying the blockchain
@app.route('/isValid', methods = ['GET'])
def isValid():
    response = {'message':''}
    if blockchain.isChainValid(blockchain.chain):
        response['message'] = 'The blockchain is valid'
    else:
        response['message'] =  'The blockchain is not valid'
    return jsonify(response), 200

#Adding a new transaction to the blockchain
@app.route('/addTransaction', methods = ['POST'])
def addTransaction():
    json = request.get_json()
    transactionKeys = ['sender','receiver','amount']
    if not all (key in json for key in transactionKeys):
        return 'some elements in the transaction are missing', 400
    index = blockchain.addTransaction(json['sender'], json['receiver'], json['amount'])
    response = {'message':f'This transaction will be added to Block {index}'}
    return jsonify(response), 201

#registering new user
@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(uid=form.uid.data, email=form.email.data)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created, you can now login.', 'success') 
        return redirect(url_for('login'))
    return render_template('register.html', title = 'register', form = form)

#connecting a new node in the network
@app.route('/connectNode', methods = ['POST'])
def connectNode():
    json = request.get_json()
    nodes = json.get('nodes') #nodes
    if nodes == None:
        return 'No node', 400
    for node in nodes:
        blockchain.addNode(node)
    response = {'message':f'All the nodes are connected. Now the Arkcoin Blockchain now contains the ',
                'totalNodes': list(blockchain.nodes)}
    return jsonify(response), 201

#replacing the chain by the longest chain if needed
@app.route('/replaceChain', methods = ['GET'])
def replaceChain():
    response = {'message':'','chain':None}
    if blockchain.replaceChain():
        response['message'] = 'The blockchain was replaced and updated'
        response['chain'] = blockchain.chain
    else:
        response['message'] =  'All good the blockchain was already the longest'
        response['chain'] = blockchain.chain
    return jsonify(response), 200

#running the app
app.run(host = '0.0.0.0', port = 5000)