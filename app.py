# <editor-fold desc="Imports">

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_toastr import Toastr
from flask_swagger_ui import get_swaggerui_blueprint

# </editor-fold>


# <editor-fold desc="App Setup">


app = Flask(__name__)
app.secret_key = 'hW7@56v5Le#LI$Vg'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'  # set relative path to db
db: SQLAlchemy = SQLAlchemy(app)  # initialise db with settings from app
toastr = Toastr()
toastr.init_app(app)  # initialize toastr on the app

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
