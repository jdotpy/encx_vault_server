from crypt_server.app import app
from crypt_server.models import User
from crypt_server.security import generate_uuid, RSA

from getpass import getpass

def add_user():
    user_name = input('Enter username:')
    token = generate_uuid()
    key = RSA({}, RSA.generate_key())
    private_key = key.get_key()
    public_key = key.get_public_key()
    print('New Token:', token)
    print('New Key:\n', private_key)
    User(
        user_name=user_name,
        is_admin=True,
        public_key=public_key,
        token=token,
    ).save()
    

if __name__ == '__main__':
    add_user()

