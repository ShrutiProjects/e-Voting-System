#The application factory, this also tells flask that flaskr is to  be treated as a
#package

import os
from flask import Flask
from uuid import uuid4

def create_app(test_config=None):
    #create and configure the application
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY = 'dev',
        DATABASE = os.path.join(app.instance_path, 'flaskr.sqlite')
    )
    if test_config is  None:
        #load the instance config ,if it exists, when not testing
        app.config.from_pyfile('config.py', silent = True)
    else:
        #load the test config if passed in
        app.config.from_mapping(test_config)

    #ensure the instance forlder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    #a simple page that says hello
    @app.route('/hello')
    def hello_world():
        return 'Hello world!'

    from . import db
    db.init_app(app)

    from . import auth
    app.register_blueprint(auth.bp)

    from . import blockchain
    app.register_blueprint(blockchain.bp)

    from . import home
    app.register_blueprint(home.bp)
    app.add_url_rule('/', endpoint = 'index')

    return app
