#this is the first flask tutorial  file I am going to use here
#thisis going to be awesome
#let's kill it

from flask import Flask
app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Hello world!'

if __name__ == "__main__":
    app.run(debug=True)