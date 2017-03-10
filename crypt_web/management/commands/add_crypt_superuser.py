from django.core.management.base import BaseCommand, CommandError
from crypt_web.models import User

class Command(BaseCommand):
    help = 'Creates a new crypt administrator'

    def handle(self, *args, **options):
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
