class Card:
    def __init__(self, number, name, expiration_date, security_code):
        self.number: int = number
        self.name: str = name
        self.expiration_date: str = expiration_date
        self.security_code: int = security_code

    def __repr__(self):
        return f'''
        \tCard
        Number: {self.number}
        Name: {self.name}
        Expiration Date: {self.expiration_date}
        Security Code: {self.security_code}
        '''

    def __eq__(self, other):
        if isinstance(other, Card):
            if self.number == other.number \
                    and self.name == other.name \
                    and self.expiration_date == other.expiration_date \
                    and self.security_code == other.security_code:
                return True
        return False


valid_card = Card(4242424242424242, 'Name', '02/23', 123)
