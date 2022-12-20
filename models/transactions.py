from datetime import datetime

from app import db


class Deposit(db.Model):
    id = db.Column(db.String, primary_key=True)
    user = db.Column(db.String, nullable=False)
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.String, default=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))

    def __repr__(self):
        return f'<Transaction.Deposit {self.id}>'


class Transfer(db.Model):
    id = db.Column(db.String, primary_key=True)
    user = db.Column(db.String, nullable=False)
    from_currency = db.Column(db.String, nullable=False)
    from_amount = db.Column(db.Float, nullable=False)
    to_currency = db.Column(db.String, nullable=False)
    to_amount = db.Column(db.Float, nullable=False)
    state = db.Column(db.String, nullable=False, default='Processing')
    date = db.Column(db.String, default=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))

    def __repr__(self):
        return f'<Transaction.Transfer {self.id}>'


class Send(db.Model):
    id = db.Column(db.String, primary_key=True)
    sender = db.Column(db.String, nullable=False)
    receiver = db.Column(db.String, nullable=False)
    currency = db.Column(db.String, nullable=False)
    amount = db.Column(db.Float, nullable=False)
    state = db.Column(db.String, nullable=False, default='Processing')
    date = db.Column(db.String, default=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))

    def __repr__(self):
        return f'<Transaction.Send {self.id}>'


class Verification(db.Model):
    id = db.Column(db.String, primary_key=True)
    user = db.Column(db.String, nullable=False)
    date = db.Column(db.String, default=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))

    def __repr__(self):
        return f'<Transaction.Verification {self.id}>'
