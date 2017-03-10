from crypt_server.app import app
from crypt_server.models import User
from crypt_server.security import generate_uuid, RSA

from getpass import getpass

def add_user():
    user_name = input('Enter username:')
    user = User(
        user_name=user_name,
        is_admin=True,
        initialized=False,
    )
    token = user.regen_token()
    user.save()
    print('New Token:', token)
    print('Run command: "cli.py init" and have the above token ready')

if __name__ == '__main__':
    add_user()

