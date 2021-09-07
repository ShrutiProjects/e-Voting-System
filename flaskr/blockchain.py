import datetime
import hashlib
import json
from flask import Flask, jsonify, request, render_template, url_for, flash, redirect, send_file
import requests
from uuid import uuid4
from urllib.parse import urlparse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding,utils
from cryptography.hazmat.primitives import serialization, hashes
import ast
import functools
from flask import (
    Blueprint, session, request, url_for, redirect, flash, g, render_template
)
from werkzeug.security import generate_password_hash, check_password_hash
from flaskr.db import get_db
import binascii

bp = Blueprint('chain', __name__, url_prefix='/chain')

def bin2hex(binStr):
    return binascii.hexlify(binStr)

def hex2bin(hexStr):
    return binascii.unhexlify(hexStr)

#blockchain building code
class Blockchain:
    
    def __init__(self):
        with open("chain.json") as infile:
           d = json.load(infile)
        self.chain = d
        self.transactions = []
        self.total_votes = 100
        if len(self.chain) == 0:
            self.transactions.append({'sender': 'Parent Block',
                                    'receiver': 'Election Organiser',
                                    'amount': self.total_votes,
                                    'encrypted_hash': "This is the genesis block",
                                    'receiver_balance': 0
            })
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
        
    def addTransaction(self, sender, receiver, amount, encrypted_hash,receiver_balance,is_candidate):
        if sender != "Election Organisation":
            senderkey = open("keys/"+g.user['username']+"public.pem", "rb")
            transaction = {
                'sender': sender,
                'receiver': receiver,
                'amount': amount
            }
            thash = self.hash(transaction)
            thash_bytes = str.encode(thash)
            public_key =  serialization.load_pem_public_key(
                senderkey.read(),
                default_backend()
            )
            public_key.verify(
                    encrypted_hash,
                    thash_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
            )
        else:
            thash = encrypted_hash
        #encryptash = bin2hex(encrypted_hash)
        self.transactions.append({'sender': sender,
                                  'receiver': receiver,
                                  'amount': amount,
                                  'encrypted_hash': thash,
                                  'receiver_balance': receiver_balance,
                                  'is_candidate': is_candidate
                                })
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
            response = requests.get(f'http://{node}/chain/getChain')
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


#following are the routes of the chain blueprint

nodeAddress = str(uuid4()).replace('-', '')

#creating a blockchain object
blockchain = Blockchain()

#mining a new block
@bp.route('/mineBlock', methods = ['GET'])
def mineBlock():
    prevBlock = blockchain.getPrevBlock()
    prevProof = prevBlock['proof']
    proof = blockchain.proofOfWork(prevProof)
    prevHash = blockchain.hash(prevBlock)
    #blockchain.addTransaction(sender = nodeAddress, receiver = 'Akshay', amount = 10, encrypted_hash = 'random')
    block = blockchain.createBlock(proof, prevHash)
    response = {'message':'You have successfully mined the block!',
                'index': block['index'],
                'timestamp': block['timestamp'],
                'proof': block['proof'],
                'prevHash': block['prevHash'],
                'transactions': block['transactions']}
    with open("chain.json", 'w') as outfile:
       json.dump(blockchain.chain, outfile)
    return jsonify(response), 200

#getting a full blockchain
@bp.route('/getChain', methods = ['GET'])
def getChain():
    response = {'chain': blockchain.chain,
                'length': len(blockchain.chain)}
    return jsonify(response), 200

#verifying the blockchain
@bp.route('/isValid', methods = ['GET'])
def isValid():
    response = {'message':''}
    if blockchain.isChainValid(blockchain.chain):
        response['message'] = 'The blockchain is valid'
    else:
        response['message'] =  'The blockchain is not valid'
    return jsonify(response), 200

#Adding a new transaction to the blockchain
@bp.route('/addTransaction', methods = ['POST'])
def addTransaction():
    json = request.get_json()
    transactionKeys = ['sender','receiver','amount','encrypted_hash','receiver_balance','is_candidate']
    if not all (key in json for key in transactionKeys):
        return 'some elements in the transaction are missing', 400
    index = blockchain.addTransaction(json['sender'], json['receiver'], json['amount'], json['encrypted_hash'],json['receiver_balance'],json['is_candidate'])
    response = {'message':f'This transaction will be added to Block {index}'}
    return jsonify(response), 201

#replacing the chain by the longest chain if needed
@bp.route('/replaceChain', methods = ['GET'])
def replaceChain():
    db = get_db()
    for node in blockchain.nodes:
        print(node)
    response = {'message':'','chain':None}
    if blockchain.replaceChain():
        response['message'] = 'The blockchain was replaced and updated'
        response['chain'] = blockchain.chain
        #here we create the database from the blockchain
        for block in blockchain.chain:
            if block['index'] == 1:
                continue
            for transaction in block['transactions']:
                print(transaction)
                if transaction['sender'] == "Election Organisation": #if first time user registered in the blockchain
                    #check if the user already exists in the local database
                    print('new user adding')
                    query_result = db.execute(
                        'SELECT username FROM user where username = ?', (transaction['receiver'],)
                    ).fetchone()
                    #if he does not exist then create a new entry in the local database
                    if not query_result:
                        print('user does not exist :'+transaction['receiver'])
                        db.execute(
                            'INSERT INTO user (username,password,is_candidate,publickey,votecoins,votecollection) VALUES (?,?,?,?,?,?)',
                            (transaction['receiver'], "random", transaction['is_candidate'] ,"do not need it",1,0)
                        )
                        db.commit()
                    #if he does exist there is not need to do anything
                #if there is a votecoin transaction from the user to user
                else:
                    #fetch the receiver from the database
                    print('user to user transaction')
                    query_result = db.execute(
                        'SELECT username,votecollection FROM user where username = ?', (transaction['receiver'],)
                    ).fetchone()
                    #fetch the sender from the database
                    query_result_sender = db.execute(
                        'SELECT username,votecoins FROM user where username = ?', (transaction['sender'],)
                    ).fetchone()
                    #if the sender does not exist
                    if not query_result_sender:
                        #create a new entry for the sender
                        print('user does not exist')
                        db.execute(
                            'INSERT INTO user (username,password,is_candidate,publickey,votecoins,votecollection) VALUES (?,?,?,?,?,?)',
                            (transaction['sender'], "random", transaction['is_candidate'],"do not need it",0,0)
                        )
                        #if the receiver does not exist create an entry in the database
                        if not query_result:
                            print('user does not exist')
                            db.execute(
                                'INSERT INTO user (username,password,is_candidate,publickey,votecoins,votecollection) VALUES (?,?,?,?,?,?)',
                                (transaction['receiver'], "random", 1 ,"do not need it",0,1)
                            )
                        #if the receiver does exist increase the votecollection count for the receiver
                        else:
                            print('receiver exists')
                            db.execute(
                                'UPDATE user SET votecollection = ?,is_candidate = ? WHERE username = ?', (transaction['receiver_balance'],1,query_result['username'],)
                            )
                        db.commit()
                    #if the sender does exist
                    else:
                        print('sender exists')
                        db.execute(
                            'UPDATE user SET votecoins = ? WHERE username = ?', (0,query_result_sender['username'],)
                        )
                        #if the receiver does not exist create an entry in the database
                        if not query_result:
                            print('receiver does not exist')
                            db.execute(
                                'INSERT INTO user (username,password,is_candidate,publickey,votecoins,votecollection) VALUES (?,?,?,?,?,?)',
                                (transaction['receiver'], "random", 1 ,"do not need it",0,1)
                            )
                        #if the receiver does exist increase the votecollection count for the receiver
                        else:
                            print('receiver does exist')
                            db.execute(
                                'UPDATE user SET votecollection = ?,is_candidate = ? WHERE username = ?', (transaction['receiver_balance'],1,query_result['username'],)
                            )
                        db.commit()

    else:
        response['message'] =  'All good the blockchain was already the longest'
        response['chain'] = blockchain.chain
    return jsonify(response), 200