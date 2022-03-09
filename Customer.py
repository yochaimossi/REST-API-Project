class Customer:

    def __init__(self, id_, name, city):
        self.id_ = id_
        self.name = name
        self.city = city

    def __repr__(self):
        return f'Customer(id_={self.id_}, name="{self.name}", city="{self.city}")'

    def __str__(self):
        return f'Customer[id_={self.id_}, name="{self.name}", city="{self.city}"]'