from app import db


class User(db.Model):
    user_id = db.Column(db.String, primary_key=True)
    is_verified = db.Column(db.Boolean, nullable=False, default=False)
    name = db.Column(db.String(200), nullable=False)
    last_name = db.Column(db.String(200), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    city = db.Column(db.String(200), nullable=False)
    country = db.Column(db.String(200), nullable=False)
    phone_number = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f'<User {self.user_id}>'
