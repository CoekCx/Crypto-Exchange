from app import db


class Wallet(db.Model):
    user_id = db.Column(db.String, primary_key=True)

    usd_balance = db.Column(db.Float, default=0)

    btc_balance = db.Column(db.Float, default=0)
    btc_is_active = db.Column(db.Boolean, default=True)

    eth_balance = db.Column(db.Float, default=0)
    eth_is_active = db.Column(db.Boolean, default=True)

    xrp_balance = db.Column(db.Float, default=0)
    xrp_is_active = db.Column(db.Boolean, default=True)

    tth_balance = db.Column(db.Float, default=0)
    tth_is_active = db.Column(db.Boolean, default=True)

    dog_balance = db.Column(db.Float, default=0)
    dog_is_active = db.Column(db.Boolean, default=True)

    def __repr__(self):
        return f'<Wallet {self.user_id}>'
