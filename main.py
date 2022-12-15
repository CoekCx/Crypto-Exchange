import json

import jsonpickle
from flask import request
from flask_swagger import swagger
from flask_swagger_ui import get_swaggerui_blueprint

from app import app, db
from models.user import User
from models.transactions import Deposit, Transfer, Send
from models.wallet import Wallet
from models.card import valid_card

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

    return response


# <editor-fold desc="Swagger">


# Add a route for serving the Swagger UI
@app.route("/swagger")
def swagger_ui():
    return swagger(app)


# Add a route for serving the Swagger UI
@app.route("/docs")
def docs():
    # Create a blueprint for rendering the Swagger UI
    swagger_ui_blueprint = get_swaggerui_blueprint(
        "/swagger",
        "/swagger.json",
        config={
            "app_name": "My Flask App"
        }
    )
    return swagger_ui_blueprint


# </editor-fold>


# <editor-fold desc="Error Handlers">


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
    app.run()
