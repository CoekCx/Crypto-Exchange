# <editor-fold desc="Imports">

import jsonpickle
from flask import request, abort
from flask_cors import cross_origin

from common import *
from models.card import valid_card, Card
from models.transactions import Verification
from models.user import User
from models.wallet import Wallet

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
@cross_origin()
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
@cross_origin()
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
@cross_origin()
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
@cross_origin()
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
@cross_origin()
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
@cross_origin()
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
@cross_origin()
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
    has_succeded = deposit_funds(email, amount)
    if not has_succeded:
        abort(BAD_REQUEST)

    # add transaction to db
    transaction = create_deposit_transaction(amount)  # NOQA 3104
    db.session.add(transaction)

    db.session.commit()
    return OK_RESPONSE()


@app.route('/transaction/send', methods=['POST'])
@cross_origin()
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

    # add transaction to db
    transaction = create_send_transaction(email_receiver, currency, amount)
    db.session.add(transaction)

    db.session.commit()
    start_mining_transaction('send', transaction.id)
    return OK_RESPONSE()


@app.route('/transaction/transfer', methods=['POST'])
@cross_origin()
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
    amount_to = convert(currency_from, currency_to, amount_from)

    # add transaction to db
    transaction = create_transfer_transaction(amount_from, amount_to, currency_from, currency_to)
    db.session.add(transaction)

    db.session.commit()
    start_mining_transaction('transfer', transaction.id)
    return OK_RESPONSE()


@app.route('/transaction/history/<string:transaction_type>')
@cross_origin()
def history(transaction_type: str):
    if not check_login_status():
        abort(UNAUTHORISED)

    data = request.args
    email = data['email']

    if not authenticate_email(email) or not check_verification_status():
        abort(UNAUTHORISED)

    transactions = fetch_transactions(transaction_type)
    transactions = filter_transactions(transactions, transaction_type, data)
    sort_transactions(transactions, data)

    return OK_RESPONSE(transactions)


# </editor-fold>

# <editor-fold desc="Utility">


@app.route('/crypto')
@cross_origin()
def exchange_rate():
    return OK_RESPONSE(get_crypto_prices())


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


if __name__ == '__main__':
    start_hashing_process()
    app.run(debug=True)
