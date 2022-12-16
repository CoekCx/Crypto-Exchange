from app import db


class Wallet(db.Model):
    user_id = db.Column(db.String, primary_key=True)
    usd_balance = db.Column(db.Float, default=0)
    btc_balance = db.Column(db.Float, default=0)
    eth_balance = db.Column(db.Float, default=0)
    xrp_balance = db.Column(db.Float, default=0)
    tth_balance = db.Column(db.Float, default=0)
    dog_balance = db.Column(db.Float, default=0)

    def __repr__(self):
        return f'<Wallet {self.user_id}>'
