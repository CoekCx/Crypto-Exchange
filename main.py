# <editor-fold desc="Imports">

import json

import jsonpickle
from flask import request, abort, session
from flask_swagger import swagger
from flask_swagger_ui import get_swaggerui_blueprint
from Crypto.Hash import keccak

from app import app, db
from models.user import User
from models.transactions import Deposit, Transfer, Send
from models.wallet import Wallet
from models.card import valid_card

# </editor-fold>


# <editor-fold desc="Database and Session Setup">

try:
    with app.app_context():
        db.create_all()
        session['user'], session['is_verified'] = None, None
except:  # NOQA
    pass

# </editor-fold>


# <editor-fold desc="Swagger Setup">


SWAGGER_URL = '/swagger'
API_URL = '/static/swagger.json'
SWAGGER_UI_BLUEPRINT = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "DRS-Group-1-Python-Flask"
    }
)
app.register_blueprint(SWAGGER_UI_BLUEPRINT, url_prefix=SWAGGER_URL)


# </editor-fold>


# <editor-fold desc="Routes">

# <editor-fold desc="User Routes">


@app.route('/user/login', methods=['POST'])
def login():
    data = parse_form_data(request.data)
    email, password = data['email'], data['password']

    if check_login_status():
        abort(UNAUTHORISED)

    if not check_user_exists(email) or not authenticate_password(email, password):
        abort(UNAUTHORISED)

    user = User.query.filter_by(email=email).first()
    session['user'] = user.user_id
    session['is_verified'] = 'True' if user.is_verified else 'False'
    return OK_RESPONSE(user)


@app.route('/user/logout', methods=['POST'])
def logout():
    if not check_login_status():
        abort(UNAUTHORISED)

    data = parse_form_data(request.data)
    email = data['email']

    if not authenticate_email(email):
        abort(UNAUTHORISED)

    session['user'], session['is_verified'] = None, None
    return OK_RESPONSE()


# </editor-fold>

# <editor-fold desc="Transaction Routes">


# </editor-fold>

# </editor-fold>


# <editor-fold desc="Responses and Error Handlers">


OK_RESPONSE = lambda data=None: app.response_class(response=jsonpickle.encode(data if not None else {}),  # NOQA
                                                   status=200,
                                                   mimetype='application/json')

# error codes
BAD_REQUEST = 400
UNAUTHORISED = 401
NOT_FOUND = 404
INTERNAL_SERVER_ERROR = 500


@app.errorhandler(400)
def handle_400_error(_error):
    """Return a http 400 error to client"""
    return app.response_class(response=jsonpickle.encode({'error': 'Bad Request'}),
                              status=400,
                              mimetype='application/json')


@app.errorhandler(401)
def handle_401_error(_error):
    """Return a http 401 error to client"""
    return app.response_class(response=jsonpickle.encode({'error': 'Unauthorised'}),
                              status=401,
                              mimetype='application/json')


@app.errorhandler(404)
def handle_404_error(_error):
    """Return a http 404 error to client"""
    return app.response_class(response=jsonpickle.encode({'error': 'Not Found'}),
                              status=404,
                              mimetype='application/json')


@app.errorhandler(500)
def handle_500_error(_error):
    """Return a http 500 error to client"""
    return app.response_class(response=jsonpickle.encode({'error': 'Internal Server Error'}),
                              status=500,
                              mimetype='application/json')


# </editor-fold>


# <editor-fold desc="Utility">


def check_login_status() -> bool:
    """
    :return: True if there is someone logged-in, False if not
    """
    with app.app_context():
        if 'user' not in session or session['user'] is None or \
                'is_verified' not in session or session['is_verified'] is None:
            return False
        return True


def authenticate_email(user_email: str) -> bool:
    """
    :param user_email: email to match with logged-in user's email
    :return: True if the email of the currently logged-in user matches the provided email, False if not
    """
    try:
        with app.app_context():
            user = User.query.filter_by(user_id=session['user']).first()
            if user.email != user_email:
                return False

        return True
    except:  # NOQA
        return False


def authenticate_password(email: str, password: str) -> bool:
    """
    :param email: user email
    :param password: user password
    :return: True if the password of the user, with the provided email, matches the provided password, False if not
    """
    try:
        with app.app_context():
            user = User.query.filter_by(email=email).first()
            if user.password != hash_text(password):
                return False

        return True
    except:  # NOQA
        return False


def check_user_exists(user_email: str) -> bool:
    """
    :param user_email: Email for which to find user
    :return: True if user with provided email exists, False if not
    """
    try:
        with app.app_context():
            user = User.query.filter_by(email=user_email).first()
            if not isinstance(user, User):
                return False

        return True
    except:  # NOQA
        return False


def parse_form_data(form_data) -> dict:
    """
    Parses data from form
    :param form_data: Form data
    :return: Parsed data in dictionary
    """
    parsed_data = {}

    string_data = ''.join(chr(i) for i in form_data)  # Convert ascii values to string
    json_data = json.loads(string_data)  # Convert string data to list of dictionaries

    # TODO:
    #  Delete commented code in case it isn't needed after testing with real front
    # Parse dictionary data
    # temp_value = None
    # for field in json_data:
    #     for key, value in json_data.items():
    #         if key == 'name':
    #             temp_value = value
    #         else:
    #             parsed_data[temp_value] = value

    return json_data


def hash_text(text: str) -> str:
    """
    Hashes text using the keccak 256 algorithm
    :param text: Text that's going to be hashed
    :return: Hashed string
    """
    a_byte_array = bytearray(text, "utf8")
    hashed_text = keccak.new(digest_bits=256)
    hashed_text.update(a_byte_array)
    return hashed_text.hexdigest()


# </editor-fold>

if __name__ == '__main__':
    app.run()
