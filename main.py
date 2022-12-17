# <editor-fold desc="Imports">

import json
from datetime import datetime
from random import randint

import jsonpickle
from flask import request, abort, session
from Crypto.Hash import keccak
from pycoingecko import CoinGeckoAPI

from app import app, db
from models.user import User
from models.transactions import Deposit, Transfer, Send, Verification
from models.wallet import Wallet
from models.card import valid_card, Card
from static.constants import CRYPTO_NAME_MAP

# </editor-fold>


# <editor-fold desc="Database and Session Setup">


try:
    with app.app_context():
        db.create_all()
except:  # NOQA
    pass


# </editor-fold>


# <editor-fold desc="Routes">

# <editor-fold desc="User Routes">


@app.route('/user/login', methods=['POST'])
def login():
    data = parse_request_data(request.data)
    email, password = data['email'], data['password']

    if check_login_status():
        abort(UNAUTHORISED)

    if not check_user_exists(email) or not authenticate_password(email, password):
        abort(UNAUTHORISED)

    user = User.query.filter_by(email=email).first()
    session['user'] = user.user_id
    return OK_RESPONSE(user)


@app.route('/user/logout', methods=['POST'])
def logout():
    if not check_login_status():
        abort(UNAUTHORISED)

    data = parse_request_data(request.data)
    email = data['email']

    if not authenticate_email(email):
        abort(UNAUTHORISED)

    session['user'] = None
    return OK_RESPONSE()


@app.route('/user/register', methods=['POST'])
def register():
    if check_login_status():
        abort(UNAUTHORISED)

    data = parse_request_data(request.data)
    new_user: User = User()

    if check_user_exists(data['email']):
        abort(BAD_REQUEST)

    # fill user data
    new_user.user_id = hash_text(data['email'])
    new_user.is_verified = False
    new_user.name = data['name']
    new_user.last_name = data['last_name']
    new_user.address = data['address']
    new_user.city = data['city']
    new_user.country = data['country']
    new_user.phone_number = data['phone_number']
    new_user.email = data['email']
    new_user.password = hash_text(data['password'])

    # create corresponding wallet for the new user
    wallet: Wallet = Wallet()
    wallet.user_id = new_user.user_id

    # save new entities to db
    db.session.add(new_user)
    db.session.add(wallet)
    db.session.commit()

    return OK_RESPONSE()


@app.route('/user/verify', methods=['PUT'])
def verify():
    if not check_login_status():
        abort(UNAUTHORISED)

    data = parse_request_data(request.data)
    email = data['email']
    card = Card(
        data['card_number'],
        data['card_name'],
        data['card_expiration_date'],
        data['card_security_code']
    )

    if not check_user_exists(email):
        abort(BAD_REQUEST)

    if not authenticate_email(email):
        abort(UNAUTHORISED)

    user = get_logged_in_user()
    if user.is_verified:
        abort(BAD_REQUEST)

    if card != valid_card:
        abort(BAD_REQUEST)

    user.is_verified = True
    verification: Verification = Verification()
    verification.id = user.user_id
    verification.user = user.email
    db.session.add(verification)
    db.session.commit()

    return OK_RESPONSE()


@app.route('/user/profile', methods=['PUT'])
def update_profile():
    if not check_login_status():
        abort(UNAUTHORISED)

    data = parse_request_data(request.data)
    email = data['email']

    if not authenticate_email(email):
        abort(UNAUTHORISED)

    user = get_logged_in_user()
    user.name = data['name']
    user.last_name = data['last_name']
    user.address = data['address']
    user.city = data['city']
    user.country = data['country']
    user.phone_number = data['phone_number']

    db.session.commit()
    return OK_RESPONSE()


@app.route('/user/wallet', methods=['GET'])
def get_wallet():
    if not check_login_status():
        abort(UNAUTHORISED)

    email = request.args.get('email')
    if not authenticate_email(email):
        abort(UNAUTHORISED)

    wallet: Wallet = get_logged_in_users_wallet()
    return OK_RESPONSE(wallet)


# </editor-fold>

# <editor-fold desc="Transaction Routes">


@app.route('/transaction/deposit', methods=['POST'])
def deposit():
    if not check_login_status():
        abort(UNAUTHORISED)

    data = parse_request_data(request.data)
    email, amount = data['email'], data['amount']

    if not authenticate_email(email) or not check_verification_status():
        abort(UNAUTHORISED)
    if amount <= 0:
        abort(BAD_REQUEST)

    # deposit funds
    has_failed = deposit_funds(amount)
    if has_failed:
        abort(BAD_REQUEST)

    # add transaction to db
    deposit = create_deposit_transaction(amount)  # NOQA 3104
    db.session.add(deposit)

    db.session.commit()
    return OK_RESPONSE()


@app.route('/transaction/send', methods=['POST'])
def send():
    if not check_login_status():
        abort(UNAUTHORISED)

    data = parse_request_data(request.data)
    email_sender, email_receiver = data['email_sender'], data['email_receiver']
    amount, currency = data['amount'], data['currency']

    if not authenticate_email(email_sender) or not check_verification_status():
        abort(UNAUTHORISED)
    if not check_user_exists(email_receiver) or \
            amount <= 0 or \
            authenticate_email(email_receiver):  # can't send funds to self
        abort(BAD_REQUEST)

    # send funds
    has_failed = send_funds(email_receiver, currency, amount)
    if has_failed:
        abort(BAD_REQUEST)

    # add transaction to db
    transaction = create_send_transaction(email_receiver, currency, amount)
    db.session.add(transaction)

    db.session.commit()
    return OK_RESPONSE()


@app.route('/transaction/transfer', methods=['POST'])
def transfer():
    if not check_login_status():
        abort(UNAUTHORISED)

    data = parse_request_data(request.data)
    email, amount_from = data['email'], data['amount']
    currency_from, currency_to = data['currency_from'], data['currency_to']

    if not authenticate_email(email) or not check_verification_status():
        abort(UNAUTHORISED)
    if amount_from <= 0 or currency_from == currency_to:
        abort(BAD_REQUEST)

    # transfer funds
    has_failed, amount_to = transfer_funds(amount_from, currency_from, currency_to)
    if has_failed:
        abort(BAD_REQUEST)

    # add transaction to db
    transaction = create_transfer_transaction(amount_from, amount_to, currency_from, currency_to)
    db.session.add(transaction)

    db.session.commit()
    return OK_RESPONSE()


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


@app.errorhandler(Exception)
def handle_500_error(_error):
    """Return a http 500 error to client"""
    return app.response_class(response=jsonpickle.encode({'error': 'Internal Server Error'}),
                              status=500,
                              mimetype='application/json')


# </editor-fold>


# <editor-fold desc="Utility">


# <editor-fold desc="Getters">


def get_user(email: str) -> User:
    """Returns user with the provided email"""
    return User.query.filter_by(email=email).first()


def get_logged_in_user() -> User:
    """Returns logged-in user"""
    return User.query.filter_by(user_id=session['user']).first()


def get_users_wallet(email: str) -> Wallet:
    """Returns wallet of the user with the provided email"""
    user = get_user(email)
    return Wallet.query.filter_by(user_id=user.user_id).first()


def get_logged_in_users_wallet() -> Wallet:
    """Returns logged-in user's wallet"""
    user = get_logged_in_user()
    return Wallet.query.filter_by(user_id=user.user_id).first()


def get_transactions(transaction_type: str) -> list[object]:
    """
    :param transaction_type: values = ['deposit', 'transfer', 'send']
    :return: list of logged-in user's transactions
    """
    user = get_logged_in_user()

    if transaction_type == 'deposit':
        return Deposit.query.filter_by(user=user.email).all()
    if transaction_type == 'transfer':
        return Transfer.query.filter_by(user=user.email).all()
    if transaction_type == 'send':
        return Send.query.filter_by(sender=user.email).all()

    return []


# </editor-fold>


# <editor-fold desc="Authentication">


def check_login_status() -> bool:
    """
    :return: True if there is someone logged-in, False if not
    """
    with app.app_context():
        if 'user' not in session or session['user'] is None:
            return False
        return True


def check_verification_status() -> bool:
    """
    :return: True if the logged-in user is verified, False if not
    """
    user = get_logged_in_user()
    return user.is_verified


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


# </editor-fold>


# <editor-fold desc="Transaction">

# <editor-fold desc="Deposit">


def deposit_funds(amount: float) -> bool:
    """
    Deposits funds to logged-in user's wallet
    :return: True if failed to deposit funds, else False
    """
    try:
        wallet: Wallet = get_logged_in_users_wallet()
        wallet.usd_balance += amount

        return False
    except:  # NOQA
        return True


# noinspection PyTypeChecker
# noinspection GrazieInspection
def create_deposit_transaction(amount: float) -> Deposit:
    """Creates a Deposit transaction object"""
    user: User = get_logged_in_user()
    deposit = Deposit()  # NOQA 3104

    deposit.id = get_hashed_transaction_id(user.email)
    deposit.user = user.email
    deposit.amount = amount

    return deposit


# </editor-fold>

# <editor-fold desc="Send">


def send_funds(email_receiver: str, currency: str, amount: float) -> bool:
    """
    Sends funds from one logged-in account to another
    :return: True if failed to send funds, else False
    """
    try:
        wallet_sender: Wallet = get_logged_in_users_wallet()
        wallet_receiver: Wallet = get_users_wallet(email_receiver)

        # check if user has sufficient funds in that currency to send
        if wallet_sender.__getattribute__(currency) < amount:
            return True

        # equalize funds
        wallet_sender.__setattr__(currency, wallet_sender.__getattribute__(currency) - amount)
        wallet_receiver.__setattr__(currency, wallet_receiver.__getattribute__(currency) + amount)

        return False
    except:  # NOQA
        return True


# noinspection PyTypeChecker
# noinspection GrazieInspection
def create_send_transaction(email_receiver: str, currency: str, amount: float) -> Send:
    """Creates a Send transaction object"""
    user_sender: User = get_logged_in_user()
    user_receiver: User = get_user(email_receiver)

    send = Send()  # NOQA 3104

    # fill in data
    send.id = get_hashed_transaction_id(user_sender.email, user_receiver.email, amount)
    send.sender = user_sender.email
    send.currency = CRYPTO_NAME_MAP[currency]
    send.receiver = user_receiver.email
    send.amount = amount
    send.date = datetime.utcnow()

    return send


# </editor-fold>

# <editor-fold desc="Transfer">


def transfer_funds(amount_from: float, currency_from: str, currency_to: str) -> (bool, float):
    """
    Transfer funds from one currency to another
    :return: True if failed to transfer funds, else False
    """
    try:
        wallet: Wallet = get_logged_in_users_wallet()

        # check if user has sufficient funds in that currency to transfer
        if wallet.__getattribute__(currency_from) < amount_from:
            return True, 0

        # equalize funds
        amount_to = convert(currency_from, currency_to, amount_from)
        wallet.__setattr__(currency_from, wallet.__getattribute__(currency_from) - amount_from)
        wallet.__setattr__(currency_to, wallet.__getattribute__(currency_to) + amount_to)

        return False, amount_to
    except:  # NOQA
        return True, 0


# noinspection PyTypeChecker
def create_transfer_transaction(amount_from: float, amount_to: float, currency_from: str, currency_to: str) -> Transfer:
    """Creates a Transfer transaction object"""
    user: User = get_logged_in_user()

    transfer = Transfer()  # NOQA 3104

    # fill in data
    transfer.id = get_hashed_transaction_id(user.email, amount=amount_from)
    transfer.user = user.email
    transfer.from_currency = CRYPTO_NAME_MAP[currency_from]
    transfer.to_currency = CRYPTO_NAME_MAP[currency_to]
    transfer.from_amount = amount_from
    transfer.to_amount = amount_to

    return transfer


# </editor-fold>

# </editor-fold>


# <editor-fold desc="Other">


def parse_request_data(request_data) -> dict:
    """
    Parses data from form
    :param request_data: Form data
    :return: Parsed data in dictionary
    """

    string_data = ''.join(chr(i) for i in request_data)  # Convert ascii values to string
    json_data = json.loads(string_data)  # Convert string data to list of dictionaries

    # TODO:
    #  Delete commented code in case it isn't needed after testing with real front
    # Parse dictionary data
    # parsed_data = {}
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


def get_hashed_transaction_id(user_1: str, user_2: str = '', amount='') -> str:
    """
    Generate random hash value for transactions
    :param user_1: Email of user (sending user in the case of fund sending)
    :param user_2: Email of receiving user in the case of fund sending
    :param amount: Amount of funds being transferred in the case of a transfer
    :return: Hash string which is meant to be used as the transaction ID
    """
    random_value = randint(1, 100000000000)
    return hash_text(f'{user_1}{user_2}{amount}{random_value}')


def get_crypto_prices() -> {str: {str: float}}:
    """
    Gets crypto prices from the CoinGeckoAPI api
    :return: Example return value {'bitcoin': {'usd': 3461.27}, 'ethereum': {'usd': 106.92}, 'ripple': {'usd': 106.92},
             'tether': {'usd': 106.92}, 'dogecoin': {'usd': 106.92}}
    """
    cg = CoinGeckoAPI()
    return cg.get_price(ids=['bitcoin', 'ethereum', 'ripple', 'tether', 'dogecoin'], vs_currencies='usd')


def convert(currency_from: str, currency_to: str, amount: float) -> float:
    """
    Converts one currency to another
    :param currency_from: Currency you're converting from (Expected values are attribute names from the wallet model)
    :param currency_to: Currency you're converting to (Expected values are attribute names from the wallet model)
    :param amount: Amount of the currency you're converting from
    :return: Amount of the currency you're converting to
    """
    attribute_price_mapping = {
        'btc_balance': 'bitcoin',
        'eth_balance': 'ethereum',
        'xrp_balance': 'ripple',
        'tth_balance': 'tether',
        'dog_balance': 'dogecoin'
    }

    prices = get_crypto_prices()

    f_curr_usd_value = 1 if currency_from == 'usd_balance' else prices[attribute_price_mapping[currency_from]]['usd']
    t_curr_usd_value = 1 if currency_to == 'usd_balance' else prices[attribute_price_mapping[currency_to]]['usd']

    return round((f_curr_usd_value / t_curr_usd_value) * amount, 7)


# </editor-fold>


# </editor-fold>

if __name__ == '__main__':
    app.run(debug=True)
