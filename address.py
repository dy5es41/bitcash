import pyqrcode

class address:
    def __init__(self, name, private_key, WIF_key , public_key , addr_legacy):
        self.name = name
        self.private = private_key
        self.WIF = WIF_key
        self.public = public_key
        self.address = addr_legacy
    
    def print(self):
        print('name: {}'.format(self.name))
        print('private_key: {}'.format(self.private)) 
        print('public_key: {}'.format(self.public)) 
        print('address(legacy): {}'.format(self.address)) 
        print('WIF: {}'.format(self.WIF))
        return

    def qrcode(self):
        qr = pyqrcode.create(self.address)
        qr.png('qrcode_{}.png'.format(self.name), scale = 10)
        return

