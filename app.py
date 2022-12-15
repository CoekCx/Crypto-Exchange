from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_toastr import Toastr

app = Flask(__name__)
app.secret_key = 'hW7@56v5Le#LI$Vg'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'  # set relative path to db
db: SQLAlchemy = SQLAlchemy(app)  # initialise db with settings from app
toastr = Toastr()
toastr.init_app(app)  # initialize toastr on the app
