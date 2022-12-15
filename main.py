import json

import jsonpickle
from flask import request

from app import app, db
from models.user import User
from models.transactions import Deposit, Transfer, Send
from models.wallet import Wallet
from models.card import valid_card

BAD_RESPONSE = app.response_class(response=jsonpickle.encode({}),
                                  status=401,
                                  mimetype='application/json')

try:
    with app.app_context():
        db.create_all()
except:  # NOQA
    pass


@app.route('/user/login')
def login():
    data = parse_form_data(request.data)

    response = app.response_class(response=jsonpickle.encode(data),
                                  status=200,
                                  mimetype='application/json')


# <editor-fold desc="Utility">


def parse_form_data(form_data) -> dict:
    """
    Parses data from form
    :param form_data: Form data
    :return: Parsed data in dictionary
    """
    parsed_data = {}

    string_data = ''.join(chr(i) for i in form_data)  # Convert ascii values to string
    json_data = json.loads(string_data)  # Convert string data to list of dictionaries

    # Parse dictionary data
    temp_value = None
    for field in json_data:
        for key, value in field.items():
            if key == 'name':
                temp_value = value
            else:
                parsed_data[temp_value] = value

    return parsed_data


# </editor-fold>

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run()
